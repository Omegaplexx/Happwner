package com.happwner

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import android.util.Log

class SettingsProvider : ContentProvider() {
    companion object {
        private const val TAG = "Happwner:Provider"
        const val AUTHORITY = "com.happwner.settings"
        val CONTENT_URI: Uri = Uri.parse("content://$AUTHORITY/settings")

        const val METHOD_GET_SETTINGS = "getSettings"
        const val METHOD_SAVE_URL = "saveUrl"
        const val KEY_HWID = "custom_hwid"
        const val KEY_ENABLED = "use_custom_hwid_substitution"

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
                putBoolean("intercept_enabled", prefs.getBoolean("intercept_enabled", false))
                putBoolean("hook_happ_unlock_settings", PrefsManager.isHappUnlockHookEnabled(context))
            }
            // Persist a captured subscription URL into history and notify the UI
            METHOD_SAVE_URL -> {
                if (arg != null) {
                    val history = prefs.getString("url_history_list", "") ?: ""
                    val list = if (history.isEmpty()) mutableListOf<String>() else history.split("|||").toMutableList()
                    list.add(0, arg)
                    prefs.edit().putString("url_history_list", list.joinToString("|||")).apply()

                    context.sendBroadcast(android.content.Intent("${context.packageName}.URL_CAPTURED").apply {
                        putExtra("url", arg)
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
            val sigMapJson = prefs.getString("lspatch_signatures", "{}") ?: "{}"
            val sigMap = org.json.JSONObject(sigMapJson)

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
                    .putString("lspatch_signatures", sigMap.toString())

                if (!ModuleStatus.isModuleActive() && !prefs.getBoolean("lspatch_mode", false)) {
                    editor.putBoolean("lspatch_mode", true)
                }

                editor.apply()
            }
        }

        if (anyAdded) {
            // Signal the UI to refresh (if it is alive)
            context.sendBroadcast(android.content.Intent("$ownPkg.REFRESH_UI"))
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
        cursor.addRow(arrayOf(KEY_HWID, hwidToSend))
        cursor.addRow(arrayOf(KEY_ENABLED, if (isActive) 1 else 0))
        cursor.addRow(arrayOf("hook_happ_unlock_settings", if (PrefsManager.isHappUnlockHookEnabled(context)) 1 else 0))
        return cursor
    }

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<String>?): Int = 0
}
