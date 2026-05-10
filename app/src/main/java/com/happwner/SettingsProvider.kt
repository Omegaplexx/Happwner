package com.happwner

import android.content.ContentProvider
import android.content.ContentValues
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
    }

    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        val context = context ?: return null
        val prefs = PrefsManager.getSafePrefs(context)

        return when (method) {
            METHOD_GET_SETTINGS -> Bundle().apply {
                putString(KEY_HWID, prefs.getString(KEY_HWID, ""))
                putBoolean(KEY_ENABLED, prefs.getBoolean(KEY_ENABLED, false))
                putBoolean("intercept_enabled", prefs.getBoolean("intercept_enabled", false))
            }
            METHOD_SAVE_URL -> {
                if (arg != null) {
                    val history = prefs.getString("url_history_list", "") ?: ""
                    val list = if (history.isEmpty()) mutableListOf<String>() else history.split("|||").toMutableList()
                    list.add(0, arg)
                    prefs.edit().putString("url_history_list", list.joinToString("|||")).apply()
                    
                    // Сигнализируем UI об обновлении (если он жив)
                    context.sendBroadcast(android.content.Intent("${context.packageName}.URL_CAPTURED").apply {
                        putExtra("url", arg)
                    })
                }
                null
            }
            else -> null
        }
    }

    // Для поддержки приложений, делающих прямой query к настройкам (fallback)
    override fun query(uri: Uri, projection: Array<String>?, selection: String?, selectionArgs: Array<String>?, sortOrder: String?): Cursor? {
        val context = context ?: return null
        val prefs = PrefsManager.getSafePrefs(context)
        val cursor = MatrixCursor(arrayOf("key", "value"))
        cursor.addRow(arrayOf(KEY_HWID, prefs.getString(KEY_HWID, "")))
        cursor.addRow(arrayOf(KEY_ENABLED, if (prefs.getBoolean(KEY_ENABLED, false)) 1 else 0))
        return cursor
    }

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<String>?): Int = 0
}
