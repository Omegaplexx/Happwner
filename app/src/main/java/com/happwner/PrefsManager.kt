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

    const val HAPP_PKG_PRIMARY = "com.happproxy"
    const val HAPP_PKG_SECONDARY = "su.happ.proxyutility"

    fun getSafePrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    // Module is active if the Xposed hook is live or LSPatch mode is on
    fun isXposedActive(context: Context): Boolean {
        return ModuleStatus.isModuleActive() ||
            getSafePrefs(context).getBoolean("lspatch_mode", false)
    }

    // Robust install check: getPackageInfo, then launch intent, then applicationInfo
    fun isPackageInstalled(context: Context, pkg: String): Boolean {
        val pm = context.packageManager
        try {
            pm.getPackageInfo(pkg, 0)
            return true
        } catch (_: PackageManager.NameNotFoundException) {
            return false
        } catch (t: Throwable) {
            Log.w(TAG, "getPackageInfo($pkg) threw ${t.javaClass.simpleName}: ${t.message}")
        }
        try {
            if (pm.getLaunchIntentForPackage(pkg) != null) return true
        } catch (_: Throwable) {}
        try {
            pm.getApplicationInfo(pkg, 0)
            return true
        } catch (_: PackageManager.NameNotFoundException) {
        } catch (_: Throwable) {}
        return false
    }

    // Which Happ packages (primary/secondary) are currently installed
    fun installedHappPackages(context: Context): List<String> {
        val result = mutableListOf<String>()
        for (pkg in arrayOf(HAPP_PKG_PRIMARY, HAPP_PKG_SECONDARY)) {
            if (isPackageInstalled(context, pkg)) result.add(pkg)
        }
        return result
    }

    // Happ is active under Xposed (installed) or LSPatch (present in the patched set)
    fun isHappActiveForModule(context: Context): Boolean {
        if (ModuleStatus.isModuleActive() && installedHappPackages(context).isNotEmpty()) {
            return true
        }
        val lspatchApps = getSafePrefs(context).getStringSet("lspatch_apps", null) ?: return false
        return lspatchApps.contains(HAPP_PKG_PRIMARY) || lspatchApps.contains(HAPP_PKG_SECONDARY)
    }

    // HWID spoof: explicit user choice if set, otherwise default to Xposed-active
    fun isHwidSpoofEnabled(context: Context): Boolean {
        val p = getSafePrefs(context)
        if (p.contains("use_custom_hwid_substitution")) {
            return p.getBoolean("use_custom_hwid_substitution", false)
        }
        return isXposedActive(context)
    }

    // Spoof is live only when enabled AND a manual HWID was entered
    fun isHwidSpoofActive(context: Context): Boolean {
        if (!isHwidSpoofEnabled(context)) return false
        return getSafePrefs(context).getBoolean("use_custom_hwid_input", false)
    }

    // Unlock-settings hook: explicit choice if set, else default when module + Happ are active
    fun isHappUnlockHookEnabled(context: Context): Boolean {
        val p = getSafePrefs(context)
        if (p.contains("hook_happ_unlock_settings")) {
            return p.getBoolean("hook_happ_unlock_settings", false)
        }
        return isXposedActive(context) && isHappActiveForModule(context)
    }

    // Push the current HWID / intercept / unlock state to the hooked Happ process
    fun broadcastSettings(context: Context) {
        val prefs = getSafePrefs(context)
        val custom = prefs.getString("custom_hwid", "") ?: ""
        val isActive = isHwidSpoofActive(context)
        val hwidToSend = if (isActive) custom else ""
        val isInterceptEnabled = prefs.getBoolean("intercept_enabled", false)
        val isUnlockHookEnabled = isHappUnlockHookEnabled(context)

        Log.d(TAG, "Broadcasting settings: HWID=$hwidToSend, SpoofActive=$isActive, Unlock=$isUnlockHookEnabled")

        val intent = Intent("${context.packageName}.SETTINGS_UPDATE").apply {
            putExtra("custom_hwid", hwidToSend)
            putExtra("use_custom_hwid_substitution", isActive)
            putExtra("intercept_enabled", isInterceptEnabled)
            putExtra("hook_happ_unlock_settings", isUnlockHookEnabled)
            addFlags(0x01000000) // FLAG_RECEIVER_INCLUDE_BACKGROUND
        }
        context.sendBroadcast(intent)
    }

    fun fixSharedPrefs(context: Context) {
        broadcastSettings(context)
    }

    // CRC32 of the first signature: cheap and enough to detect a reinstall
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
