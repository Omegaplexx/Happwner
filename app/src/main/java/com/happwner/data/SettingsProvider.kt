package com.happwner.data

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import android.util.Log
import com.happwner.hook.ModuleStatus

class SettingsProvider : ContentProvider() {
    companion object {
        private const val TAG = "Happwner:Provider"
        const val METHOD_GET_SETTINGS = "getSettings"
        const val METHOD_SAVE_URL = "saveUrl"
        // The provider publishes these names, and they are the settings keys themselves: one
        // string, one definition, whichever side reads it.
        const val EXTRA_PACKAGE = "pkg"
        const val EXTRA_ORIGINAL_ID = "original_id"
        const val EXTRA_URL = "url"

        const val KEY_HWID = PrefsManager.PREF_CUSTOM_HWID
        const val KEY_ENABLED = PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION

        private val recordLock = Any()
    }

    override fun onCreate(): Boolean = true

    // IPC entry point: get-settings or save-url, called by the hooked/patched app
    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        val context = context ?: return null
        recordCallerAsPatched(context)
        val prefs = PrefsManager.getSafePrefs(context)

        return when (method) {
            // Return the current HWID / intercept / unlock state
            METHOD_GET_SETTINGS -> Bundle().apply {
                val isActive = PrefsManager.isHwidSpoofActive(context)
                val custom = prefs.getString(KEY_HWID, "") ?: ""
                val hwidToSend = if (isActive) custom else ""
                putString(KEY_HWID, hwidToSend)
                putBoolean(KEY_ENABLED, isActive)
                putBoolean(PrefsManager.PREF_INTERCEPT_ENABLED, prefs.getBoolean(PrefsManager.PREF_INTERCEPT_ENABLED, false))
                putBoolean(PrefsManager.PREF_HOOK_HAPP_UNLOCK_SETTINGS, PrefsManager.isUnlockHookEnabled(context))
            }
            // Persist a captured subscription URL into history and notify the UI
            METHOD_SAVE_URL -> {
                // UrlHistory does the appending: one line to a file, O(1) at any size, with its own
                // lock and its own rejection of line-break-bearing input.
                if (arg != null && UrlHistory.append(context, arg)) {
                    context.sendBroadcast(android.content.Intent(ModuleIds.ACTION_URL_CAPTURED).apply {
                        setPackage(context.packageName)
                        putExtra("url", arg.trim())
                    })
                }
                null
            }
            else -> null
        }
    }

    // Remember the calling (LSPatch-patched) app as the target
    private fun recordCallerAsPatched(context: Context) {
        val callingUid = android.os.Binder.getCallingUid()
        if (callingUid == android.os.Process.myUid()) return
        if (callingUid < android.os.Process.FIRST_APPLICATION_UID) return

        val pm = context.packageManager
        val callingPkgs = try { pm.getPackagesForUid(callingUid) } catch (_: Throwable) { null }
        if (callingPkgs.isNullOrEmpty()) return

        val ownPkg = context.packageName
        val prefs = PrefsManager.getSafePrefs(context)
        val existingApps = prefs.getStringSet("lspatch_apps", mutableSetOf()) ?: mutableSetOf()

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
            val locked = prefs.getStringSet("lspatch_apps", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
            val sigMapJson = prefs.getString(PrefsManager.PREF_LSPATCH_SIGNATURES, "{}") ?: "{}"
            val sigMap = try { org.json.JSONObject(sigMapJson) } catch (_: Throwable) { org.json.JSONObject() }

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
                val editor = prefs.edit()
                    .putStringSet("lspatch_apps", locked)
                    .putString(PrefsManager.PREF_LSPATCH_SIGNATURES, sigMap.toString())

                if (!ModuleStatus.isModuleActive() && !prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)) {
                    editor.putBoolean(PrefsManager.PREF_LSPATCH_MODE, true)
                }

                editor.apply()
            }
        }

        if (anyAdded) {
            // Signal the UI to refresh (if it is alive)
            context.sendBroadcast(android.content.Intent(ModuleIds.ACTION_REFRESH_UI).setPackage(ownPkg))
        }
    }

    // For apps that query settings directly (fallback)
    override fun query(uri: Uri, projection: Array<String>?, selection: String?, selectionArgs: Array<String>?, sortOrder: String?): Cursor? {
        val context = context ?: return null
        val prefs = PrefsManager.getSafePrefs(context)
        val cursor = MatrixCursor(arrayOf("key", "value"))
        val isActive = PrefsManager.isHwidSpoofActive(context)
        val custom = prefs.getString(KEY_HWID, "") ?: ""
        val hwidToSend = if (isActive) custom else ""
        // Named as Any: a row is a name and a value of whatever type, and left to infer, Kotlin
        // picks the nearest common supertype of String and Int and warns that reifying it will
        cursor.addRow(arrayOf<Any>(KEY_HWID, hwidToSend))
        cursor.addRow(arrayOf<Any>(KEY_ENABLED, if (isActive) 1 else 0))
        cursor.addRow(arrayOf<Any>(PrefsManager.PREF_HOOK_HAPP_UNLOCK_SETTINGS, if (PrefsManager.isUnlockHookEnabled(context)) 1 else 0))
        return cursor
    }

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<String>?): Int = 0
}
