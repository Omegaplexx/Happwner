package com.happwner

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log

object PrefsManager {
    private const val PREFS_NAME = "happ_prefs"
    private const val TAG = "Happwner:Prefs"

    fun getSafePrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    /**
     * Отправляет сигнал обновления и САМИ ДАННЫЕ.
     * На Android 11+ (без root) приложения часто не могут достучаться до ContentProvider 
     * из-за ограничений видимости пакетов (Package Visibility). 
     * Поэтому Broadcast становится единственным надежным способом доставки данных в RAM-кеш хука.
     */
    fun broadcastSettings(context: Context) {
        val prefs = getSafePrefs(context)
        val isEnabled = prefs.getBoolean("use_custom_hwid_substitution", false)
        val hwid = prefs.getString("custom_hwid", "")
        val isInterceptEnabled = prefs.getBoolean("intercept_enabled", false)

        Log.d(TAG, "Broadcasting settings: HWID=$hwid, Enabled=$isEnabled")
        
        val intent = Intent("${context.packageName}.SETTINGS_UPDATE").apply {
            putExtra("custom_hwid", hwid)
            putExtra("use_custom_hwid_substitution", isEnabled)
            putExtra("intercept_enabled", isInterceptEnabled)
            addFlags(0x01000000) // FLAG_RECEIVER_INCLUDE_BACKGROUND
        }
        context.sendBroadcast(intent)
    }

    fun fixSharedPrefs(context: Context) {
        broadcastSettings(context)
    }

    fun getSignatureCrc32(context: Context, pkgName: String): Long? {
        val pm = context.packageManager
        return try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pm.getPackageInfo(pkgName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkgName, PackageManager.GET_SIGNATURES)
            }
            
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.signingCertificateHistory
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }
            
            if (signatures != null && signatures.isNotEmpty()) {
                val crc = java.util.zip.CRC32()
                crc.update(signatures[0].toByteArray())
                crc.value
            } else null
        } catch (e: Exception) {
            null
        }
    }
}
