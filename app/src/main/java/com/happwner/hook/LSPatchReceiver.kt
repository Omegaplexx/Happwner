package com.happwner.hook

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.util.Log
import androidx.core.content.edit
import com.happwner.data.ModuleIds
import com.happwner.data.ModuleStatus
import com.happwner.data.PrefsManager
import com.happwner.data.SettingsProvider
import org.json.JSONObject

// Handles MODULE_LOADED: records the patched app and maybe enables LSPatch mode.
class LSPatchReceiver : BroadcastReceiver() {

	// Removes a package that turned out not to be patched, together with its stored signature.
	private fun dropStaleEntry(prefs: SharedPreferences, pkg: String) {
		try {
			val left = PrefsManager.dropLspatchEntries(prefs, listOf(pkg)) ?: return
			Log.i(ModuleIds.LOG_LSP, "Removed stale entry for $pkg, $left app(s) left")
		} catch (throwable: Throwable) {
			Log.w(ModuleIds.LOG_LSP, "Failed to drop stale entry for $pkg", throwable)
		}
	}

	override fun onReceive(context: Context, intent: Intent) {
		val action = intent.action
		Log.d(ModuleIds.LOG_LSP, "Receiver triggered with action: $action")

		if (action == ModuleIds.ACTION_MODULE_LOADED) {
			val pkg = SettingsProvider.readUntrustedExtras {
				intent.getStringExtra(SettingsProvider.EXTRA_PACKAGE)
			}

			if (pkg == null) {
				Log.w(ModuleIds.LOG_LSP, "Package name is null, aborting")
				return
			}
			if (pkg == context.packageName) {
				Log.d(ModuleIds.LOG_LSP, "Self-load detected, ignoring")
				return
			}

			// Only patched apps belong in the list; a missing flag means an older hook, so it counts
			// as patched. This gates the listing only - every hooked app still gets the settings reply.
			val hasFlag = intent.hasExtra(SettingsProvider.EXTRA_PATCHED)
			val xposedActive = ModuleStatus.isModuleActive()
			// Missing flag counts as patched only while Xposed is inactive - see SettingsProvider.
			val patched = if (hasFlag) {
				SettingsProvider.readUntrustedExtras {
					intent.getBooleanExtra(SettingsProvider.EXTRA_PATCHED, true)
				} ?: true
			} else {
				!xposedActive
			}
			val shouldList = patched || !xposedActive
			Log.d(ModuleIds.LOG_LSP, "MODULE_LOADED from $pkg: patched=$patched " +
				"xposedActive=$xposedActive -> shouldList=$shouldList")
			val prefs = PrefsManager.getSafePrefs(context)
			if (!shouldList) {
				Log.i(ModuleIds.LOG_LSP, "$pkg is framework-hooked, not listing")
				// The app reports it is not patched, so an existing entry is wrong: drop it now
				// instead of waiting for the uninstall or signature change MainActivity looks for.
				dropStaleEntry(prefs, pkg)
			} else {
				val apps = PrefsManager.lspatchApps(prefs)
				val sigMapJson = prefs.getString(PrefsManager.PREF_LSPATCH_SIGNATURES, "{}") ?: "{}"
				val sigMap = try { JSONObject(sigMapJson) } catch (_: Throwable) { JSONObject() }

				// Important: keep the signature CRC32, otherwise MainActivity drops the app from the list
				val crc = PrefsManager.getSignatureCrc32(context, pkg)
				Log.d(ModuleIds.LOG_LSP, "Signature CRC for $pkg: $crc")

				if (crc != null) {
					sigMap.put(pkg, crc)
				} else {
					Log.w(ModuleIds.LOG_LSP,
						"Could not get CRC for $pkg - this might cause auto-removal in UI")
				}

				val isNew = apps.add(pkg)
				Log.d(ModuleIds.LOG_LSP,
					"App in set: $pkg (Is new: $isNew). Current apps count: ${apps.size}")

				prefs.edit {
					putStringSet(PrefsManager.PREF_LSPATCH_APPS, apps)
					putString(PrefsManager.PREF_LSPATCH_SIGNATURES, sigMap.toString())

					if (!xposedActive) {
						// New app: enable the mode
						if (isNew) {
							putBoolean(PrefsManager.PREF_LSPATCH_MODE, true)
							Log.i(ModuleIds.LOG_LSP, "LSPatch mode auto-enabled due to new app: $pkg")
						// App already known but the mode is off: enable it
						} else if (!prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)) {
							putBoolean(PrefsManager.PREF_LSPATCH_MODE, true)
							Log.i(ModuleIds.LOG_LSP, "LSPatch mode restored for existing app: $pkg")
						}
					} else {
						// Xposed is active: record the app in the list, but leave lspatch_mode untouched
						Log.d(ModuleIds.LOG_LSP,
							"Xposed mode active, accumulating app but not flipping lspatch_mode")
					}
				}
			}

			// Tell MainActivity to refresh the UI
			context.sendBroadcast(Intent(ModuleIds.ACTION_REFRESH_UI).setPackage(context.packageName))
			Log.d(ModuleIds.LOG_LSP, "Sent REFRESH_UI broadcast")

			// Send the settings back in the reply
			PrefsManager.broadcastSettings(context)
		}
	}
}
