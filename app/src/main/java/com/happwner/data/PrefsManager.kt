package com.happwner.data

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import com.happwner.hook.ModuleStatus

object PrefsManager {
    private const val PREFS_NAME = "happ_prefs"
    private const val TAG = "Happwner:Prefs"

    const val HAPP_PKG_PRIMARY = "com.happproxy"
    const val HAPP_PKG_SECONDARY = "su.happ.proxyutility"
    const val V2RAYTUN_PKG = "com.v2raytun.android"
    const val INCY_PKG = "llc.itdev.incy"

    // Temporary test mode: every happ link goes through Happanion, the
    // built-in keys are skipped entirely. See HappanionBridge / MainActivity.
    const val PREF_FORCE_HAPPLIB = "force_happlib"

    // The settings themselves.
    const val PREF_APP_LANG = "app_lang"
    const val PREF_BRIDGE_ENABLED = "bridge_enabled"
    const val PREF_BRIDGE_WATCHDOG = "bridge_watchdog"
    const val PREF_CAPTURED_ID = "captured_id"
    const val PREF_CUSTOM_HWID = "custom_hwid"
    const val PREF_HOOK_HAPP_UNLOCK_SETTINGS = "hook_happ_unlock_settings"
    const val PREF_INTERCEPT_ENABLED = "intercept_enabled"
    const val PREF_LSPATCH_MODE = "lspatch_mode"
    const val PREF_LSPATCH_SIGNATURES = "lspatch_signatures"
    const val PREF_MONET_ACCENT = "monet_accent"
    const val PREF_SHOW_DUPLICATES = "show_duplicates"
    const val PREF_THEME_MODE = "theme_mode"
    const val PREF_USE_CUSTOM_HWID_INPUT = "use_custom_hwid_input"
    const val PREF_USE_CUSTOM_HWID_SUBSTITUTION = "use_custom_hwid_substitution"

    // All packages whose subscriptions the unlock hook can target
    private val UNLOCK_PKGS = arrayOf(HAPP_PKG_PRIMARY, HAPP_PKG_SECONDARY, V2RAYTUN_PKG)

    fun getSafePrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    // Module is active if the Xposed hook is live or LSPatch mode is on
    fun isXposedActive(context: Context): Boolean {
        return ModuleStatus.isModuleActive() ||
            getSafePrefs(context).getBoolean(PREF_LSPATCH_MODE, false)
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

    // Which unlock-target packages (Happ variants + v2RayTun) are currently installed
    fun installedUnlockPackages(context: Context): List<String> {
        val result = mutableListOf<String>()
        for (pkg in UNLOCK_PKGS) {
            if (isPackageInstalled(context, pkg)) result.add(pkg)
        }
        return result
    }

    // An unlock target is active under Xposed (installed) or LSPatch (present in the patched set)
    fun isUnlockTargetActiveForModule(context: Context): Boolean {
        if (ModuleStatus.isModuleActive() && installedUnlockPackages(context).isNotEmpty()) {
            return true
        }
        val lspatchApps = getSafePrefs(context).getStringSet("lspatch_apps", null) ?: return false
        return UNLOCK_PKGS.any { lspatchApps.contains(it) }
    }

    // HWID spoof: explicit user choice if set, otherwise default to Xposed-active
    fun isHwidSpoofEnabled(context: Context): Boolean {
        val p = getSafePrefs(context)
        if (p.contains(PREF_USE_CUSTOM_HWID_SUBSTITUTION)) {
            return p.getBoolean(PREF_USE_CUSTOM_HWID_SUBSTITUTION, false)
        }
        return isXposedActive(context)
    }

    // Spoof is live only when enabled AND a manual HWID was entered
    fun isHwidSpoofActive(context: Context): Boolean {
        if (!isHwidSpoofEnabled(context)) return false
        return getSafePrefs(context).getBoolean(PREF_USE_CUSTOM_HWID_INPUT, false)
    }

    // Unlock-settings hook: explicit choice if set, else default when module + an unlock target are active
    fun isUnlockHookEnabled(context: Context): Boolean {
        val p = getSafePrefs(context)
        if (p.contains(PREF_HOOK_HAPP_UNLOCK_SETTINGS)) {
            return p.getBoolean(PREF_HOOK_HAPP_UNLOCK_SETTINGS, false)
        }
        return isXposedActive(context) && isUnlockTargetActiveForModule(context)
    }

    // Push the current HWID / intercept / unlock state to the hooked process
    fun broadcastSettings(context: Context) {
        val prefs = getSafePrefs(context)
        val custom = prefs.getString(PREF_CUSTOM_HWID, "") ?: ""
        val isActive = isHwidSpoofActive(context)
        val hwidToSend = if (isActive) custom else ""
        val isInterceptEnabled = prefs.getBoolean(PREF_INTERCEPT_ENABLED, false)
        val unlockEnabled = isUnlockHookEnabled(context)

        Log.d(TAG, "Broadcasting settings: HWID=$hwidToSend, SpoofActive=$isActive, Unlock=$unlockEnabled")

        val intent = Intent(ModuleIds.ACTION_SETTINGS_UPDATE).apply {
            putExtra(PREF_CUSTOM_HWID, hwidToSend)
            putExtra(PREF_USE_CUSTOM_HWID_SUBSTITUTION, isActive)
            putExtra(PREF_INTERCEPT_ENABLED, isInterceptEnabled)
            putExtra(PREF_HOOK_HAPP_UNLOCK_SETTINGS, unlockEnabled)
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

    // Conversion mode: the single source of truth for the settings dialogs and for the real
    // pipeline (MainActivity, SubscriptionService -> LinkConverter).

    const val SCOPE_MANUAL = "manual"
    const val SCOPE_SERVER = "server"

    const val MODE_OFF = "off"
    const val MODE_SINGBOX = "singbox"
    const val MODE_MIHOMO = "mihomo"
    const val MODE_URI = "uri"

    data class ConversionFlags(
        val jsonToUri: Boolean,
        val xrayToSb: Boolean,
        val xrayToMihomo: Boolean,
        // No conversion mode works without decoding the body first, so any mode other than "off" forces this
        // on, matching the locked checkbox in the dialog; with the mode off it is the person's own choice.
        val base64Result: Boolean
    )

    // The person's own Base64 choice, kept apart from whatever the checkbox displays while a mode
    // locks it on. Defaults match 1.3: on for the manual flow, off for the background one.
    fun userBase64Choice(prefs: SharedPreferences, scope: String): Boolean =
        prefs.getBoolean("process_b64_$scope", scope == SCOPE_MANUAL)

    // The four booleans LinkConverter.convert/convertWithStats takes, derived
    // from process_mode_<scope> for one scope ("manual" or "server").
    fun conversionFlagsFor(prefs: SharedPreferences, scope: String): ConversionFlags {
        val mode = resolveConversionMode(prefs, scope)
        // Not forced by the mode any more: this says how the answer is wrapped,
        // and unwrapping the input happens regardless of what it says.
        val b64 = userBase64Choice(prefs, scope)
        return when (mode) {
            MODE_MIHOMO -> ConversionFlags(
                jsonToUri = false, xrayToSb = false, xrayToMihomo = true, base64Result = b64
            )
            MODE_SINGBOX -> ConversionFlags(
                jsonToUri = false, xrayToSb = true, xrayToMihomo = false, base64Result = b64
            )
            MODE_URI -> ConversionFlags(
                jsonToUri = true,
                xrayToSb = prefs.getBoolean("process_uri_drop_incompatible_$scope", false),
                xrayToMihomo = false,
                base64Result = b64
            )
            else -> ConversionFlags(
                jsonToUri = false, xrayToSb = false, xrayToMihomo = false, base64Result = b64
            )
        }
    }

    // Returns process_mode_<scope>, migrating once from the four independent flags the settings
    // screen used to expose. Idempotent: once the new key exists this only reads it.
    fun resolveConversionMode(prefs: SharedPreferences, scope: String): String {
        val key = "process_mode_$scope"
        prefs.getString(key, null)?.let { return it }

        val xrayToMihomo = prefs.getBoolean("process_mihomo_$scope", false)
        val xrayToSb = prefs.getBoolean("process_xray_$scope", false)
        val jsonToUriKey = if (scope == SCOPE_MANUAL) "process_manual" else "process_server"
        val jsonToUri = prefs.getBoolean(jsonToUriKey, scope == SCOPE_MANUAL)

        val mode = when {
            xrayToMihomo -> MODE_MIHOMO
            xrayToSb && !jsonToUri -> MODE_SINGBOX
            jsonToUri -> MODE_URI
            else -> MODE_OFF
        }

        val edit = prefs.edit().putString(key, mode)
        if (mode == MODE_URI && xrayToSb) {
            edit.putBoolean("process_uri_drop_incompatible_$scope", true)
        }
        edit.apply()
        return mode
    }
}
