package com.happwner.data

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.Process
import android.util.Log
import androidx.core.content.edit
import org.json.JSONObject

class SettingsProvider : ContentProvider() {
	companion object {
		private const val TAG = "Happwner:Provider"
		const val METHOD_GET_SETTINGS = "getSettings"
		const val METHOD_SAVE_URL = "saveUrl"
		const val EXTRA_PACKAGE = "pkg"
		const val EXTRA_ORIGINAL_ID = "original_id"
		// Set by the hook: true when the calling app is patched rather than framework-hooked.
		// Absent means an older hook that predates the check - treated as patched.
		const val EXTRA_PATCHED = "patched"
		const val EXTRA_URL = "url"

		// The provider publishes these names, and they are the settings keys themselves: one
		// string, one definition, whichever side reads it.
		const val KEY_HWID = PrefsManager.PREF_CUSTOM_HWID
		const val KEY_ENABLED = PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION

		private val recordLock = Any()

		// Reads extras another app sent. A value of a class only the sender has throws on reading,
		// before Android 13 wherever it sits; the broadcast then counts as carrying nothing.
		inline fun <T> readUntrustedExtras(read: () -> T): T? = try {
			read()
		} catch (_: RuntimeException) {
			null
		}
	}

	override fun onCreate(): Boolean = true

	// IPC entry point: get-settings or save-url, called by the hooked/patched app
	override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
		val context = context ?: return null
		recordCallerAsPatched(context, extras)
		val prefs = PrefsManager.getSafePrefs(context)

		return when (method) {
			// Return the current HWID / intercept / unlock state
			METHOD_GET_SETTINGS -> Bundle().apply {
				val isActive = PrefsManager.isHwidSpoofActive(context)
				val custom = prefs.getString(KEY_HWID, "") ?: ""
				val hwidToSend = if (isActive) custom else ""
				putString(KEY_HWID, hwidToSend)
				putBoolean(KEY_ENABLED, isActive)
				putBoolean(PrefsManager.PREF_INTERCEPT_ENABLED,
					PrefsManager.isInterceptEnabled(context))
				putBoolean(PrefsManager.PREF_HOOK_HAPP_UNLOCK_SETTINGS,
					PrefsManager.isUnlockHookEnabled(context))
				putBoolean(PrefsManager.PREF_REDIRECT_INTENTS,
					PrefsManager.isRedirectIntentsEnabled(context))
			}
			// Persist a captured subscription URL into history and notify the UI
			METHOD_SAVE_URL -> {
				// UrlHistory does the appending: one line to a file, O(1) at any size, with its own
				// lock and its own rejection of line-break-bearing input.
				if (arg != null && UrlHistory.append(context, arg)) {
					context.sendBroadcast(Intent(ModuleIds.ACTION_URL_CAPTURED).apply {
						setPackage(context.packageName)
						putExtra("url", arg.trim())
					})
				}
				null
			}
			else -> null
		}
	}

	// Removes packages of the calling UID that turned out not to be patched.
	private fun dropStaleEntries(context: Context, callingUid: Int) {
		try {
			val pkgs = context.packageManager.getPackagesForUid(callingUid) ?: return
			val left = PrefsManager.dropLspatchEntries(PrefsManager.getSafePrefs(context), pkgs.toList())
				?: return
			Log.i(TAG, "Removed stale entries for ${pkgs.joinToString()}, $left app(s) left")
		} catch (throwable: Throwable) {
			Log.w(TAG, "Failed to drop stale entries", throwable)
		}
	}

	// Remember the calling (patched) app as the target. Second, independent path into the list:
	// the broadcast can be missed if the system holds Happwner, but a hook must reach the provider
	// or it has no settings to work with.
	private fun recordCallerAsPatched(context: Context, extras: Bundle?) {
		val callingUid = Binder.getCallingUid()
		if (callingUid == Process.myUid()) return
		if (callingUid < Process.FIRST_APPLICATION_UID) return

		val packages = context.packageManager
		val callingPkgs = try { packages.getPackagesForUid(callingUid) } catch (_: Throwable) { null }
		if (callingPkgs.isNullOrEmpty()) return

		// Same rule as LSPatchReceiver: a missing flag means an older hook, so it counts as patched -
		// but only while Xposed is off, since an active framework always sends the flag.
		val xposedActive = ModuleStatus.isModuleActive()
		val patched = when {
			extras != null && extras.containsKey(EXTRA_PATCHED) -> extras.getBoolean(EXTRA_PATCHED, true)
			else -> !xposedActive
		}
		if (!patched && xposedActive) {
			Log.i(TAG, "${callingPkgs.firstOrNull() ?: "uid:$callingUid"} is framework-hooked, not listing")
			// Same self-healing as in LSPatchReceiver: the caller reports it is not patched, so an
			// existing entry for it is wrong and gets dropped instead of lingering until uninstall.
			dropStaleEntries(context, callingUid)
			return
		}

		val ownPkg = context.packageName
		val prefs = PrefsManager.getSafePrefs(context)
		val existingApps = PrefsManager.lspatchApps(prefs)

		var hasNew = false
		for (pkg in callingPkgs) {
			if (pkg != null && pkg != ownPkg && !existingApps.contains(pkg)) {
				hasNew = true
				break
			}
		}
		if (!hasNew) return

		var anyAdded = false
		synchronized(recordLock) {
			val locked = PrefsManager.lspatchApps(prefs)
			val sigMapJson = prefs.getString(PrefsManager.PREF_LSPATCH_SIGNATURES, "{}") ?: "{}"
			val sigMap = try {
				JSONObject(sigMapJson)
			} catch (_: Throwable) {
				JSONObject()
			}

			for (pkg in callingPkgs) {
				if (pkg == null || pkg == ownPkg) continue
				if (locked.add(pkg)) {
					anyAdded = true
					val crc = PrefsManager.getSignatureCrc32(context, pkg)
					if (crc != null) sigMap.put(pkg, crc)
					Log.i(TAG, "Provider detected patched package: $pkg (uid=$callingUid)")
				}
			}

			if (anyAdded) {
				prefs.edit {
					putStringSet(PrefsManager.PREF_LSPATCH_APPS, locked)
					putString(PrefsManager.PREF_LSPATCH_SIGNATURES, sigMap.toString())

					if (!xposedActive && !prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)) {
						putBoolean(PrefsManager.PREF_LSPATCH_MODE, true)
					}
				}
			}
		}

		if (anyAdded) {
			// Signal the UI to refresh (if it is alive)
			context.sendBroadcast(Intent(ModuleIds.ACTION_REFRESH_UI).setPackage(ownPkg))
		}
	}

	// For apps that query settings directly (fallback)
	override fun query(uri: Uri, projection: Array<String>?, selection: String?,
		selectionArgs: Array<String>?, sortOrder: String?): Cursor? {
		val context = context ?: return null
		val prefs = PrefsManager.getSafePrefs(context)
		val cursor = MatrixCursor(arrayOf("key", "value"))
		val isActive = PrefsManager.isHwidSpoofActive(context)
		val custom = prefs.getString(KEY_HWID, "") ?: ""
		val hwidToSend = if (isActive) custom else ""
		// Explicit Any: rows mix String and Int, so pin the element type instead of an inferred one.
		cursor.addRow(arrayOf<Any>(KEY_HWID, hwidToSend))
		cursor.addRow(arrayOf<Any>(KEY_ENABLED, if (isActive) 1 else 0))
		cursor.addRow(arrayOf<Any>(PrefsManager.PREF_HOOK_HAPP_UNLOCK_SETTINGS,
			if (PrefsManager.isUnlockHookEnabled(context)) 1 else 0))
		return cursor
	}

	override fun getType(uri: Uri): String? = null
	override fun insert(uri: Uri, values: ContentValues?): Uri? = null
	override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0
	override fun update(uri: Uri, values: ContentValues?, selection: String?,
		selectionArgs: Array<String>?): Int = 0
}
