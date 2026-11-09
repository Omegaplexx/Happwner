package com.happwner.data

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.edit
import com.happwner.client.HappanionBridge
import com.happwner.convert.ConversionFlags
import java.util.zip.CRC32
import org.json.JSONObject

object PrefsManager {
	private const val PREFS_NAME = "happ_prefs"
	private const val TAG = "Happwner:Prefs"

	const val HAPP_PKG_PRIMARY = "com.happproxy"
	const val HAPP_PKG_SECONDARY = "su.happ.proxyutility"
	const val V2RAYTUN_PKG = "com.v2raytun.android"
	const val INCY_PKG = "llc.itdev.incy"

	// Test mode: every happ link goes through Happanion, the built-in keys are skipped
	// entirely. See HappanionBridge / MainActivity.
	// The key installations already store the setting under: another would reset it.
	const val PREF_FORCE_HAPPANION = "force_happlib"

	// The settings, and the state the app keeps beside them.
	const val PREF_ANIM_MODE = "anim_mode"
	const val PREF_APP_LANG = "app_lang"
	const val PREF_BRIDGE_ENABLED = "bridge_enabled"
	const val PREF_BRIDGE_HINT_SHOWN = "bridge_hint_shown"
	const val PREF_BRIDGE_WATCHDOG = "bridge_watchdog"
	const val PREF_BRIDGE_LAN_MODE = "bridge_lan_mode"
	// Asks made turning the bridge on in the app: at most two, an allowed one counting as both.
	const val PREF_BRIDGE_BATTERY_ASKS = "bridge_battery_asks"
	const val PREF_BRIDGE_NOTIFICATION_ASKS = "bridge_notification_asks"
	const val PREF_CAPTURED_ID = "captured_id"
	const val PREF_CUSTOM_HWID = "custom_hwid"
	const val PREF_CUSTOM_USER_AGENT = "custom_user_agent"
	const val PREF_HOOK_HAPP_UNLOCK_SETTINGS = "hook_happ_unlock_settings"
	const val PREF_INTERCEPT_ENABLED = "intercept_enabled"
	const val PREF_LAST_URL = "last_url"
	const val PREF_LSPATCH_APPS = "lspatch_apps"
	const val PREF_LSPATCH_MODE = "lspatch_mode"
	const val PREF_LSPATCH_SIGNATURES = "lspatch_signatures"
	const val PREF_MONET_ACCENT = "monet_accent"
	// The key installations already store the setting under: another would reset it.
	const val PREF_PREFER_SUBSCRIPTION_UA = "prefer_sub_ua"
	const val PREF_REDIRECT_INTENTS = "redirect_intents"
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
		val packages = context.packageManager
		try {
			packages.getPackageInfo(pkg, 0)
			return true
		} catch (_: PackageManager.NameNotFoundException) {
			return false
		} catch (throwable: Throwable) {
			Log.w(TAG, "getPackageInfo($pkg) threw ${throwable.javaClass.simpleName}: ${throwable.message}")
		}
		try {
			if (packages.getLaunchIntentForPackage(pkg) != null) return true
		} catch (_: Throwable) {}
		try {
			packages.getApplicationInfo(pkg, 0)
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

	// An unlock target is active under Xposed (installed) or via a patcher (in the patched set)
	fun isUnlockTargetActiveForModule(context: Context): Boolean {
		if (ModuleStatus.isModuleActive()) {
			// Xposed answers for itself; the patched-apps list is not consulted at all, so a stale
			// entry can't make a framework-hooked app look patched.
			return installedUnlockPackages(context).isNotEmpty()
		}
		val apps = lspatchApps(getSafePrefs(context))
		return UNLOCK_PKGS.any { it in apps }
	}

	// The list of patched apps, as a copy to change and put back.
	fun lspatchApps(prefs: SharedPreferences): MutableSet<String> =
		prefs.getStringSet(PREF_LSPATCH_APPS, null)?.toMutableSet() ?: mutableSetOf()

	// Forgets packages that turned out not to be patched: out of lspatch_apps and the signature map,
	// and LSPatch mode goes off with the last of them, since it has nothing left to stand on. The
	// number of patched apps left, or null when none of these packages was listed.
	fun dropLspatchEntries(prefs: SharedPreferences, pkgs: Collection<String>): Int? {
		val apps = lspatchApps(prefs)
		if (!apps.removeAll(pkgs.toSet())) return null
		val sigMapJson = prefs.getString(PREF_LSPATCH_SIGNATURES, "{}") ?: "{}"
		val sigMap = try { JSONObject(sigMapJson) } catch (_: Throwable) { JSONObject() }
		pkgs.forEach { sigMap.remove(it) }
		prefs.edit {
			putStringSet(PREF_LSPATCH_APPS, apps)
			putString(PREF_LSPATCH_SIGNATURES, sigMap.toString())
			if (apps.isEmpty()) putBoolean(PREF_LSPATCH_MODE, false)
		}
		return apps.size
	}

	// Whether a subscription's own change-user-agent is followed - on by default, since a subscription
	// naming a User-Agent hands a shorter server list to anything else. Read straight from prefs so the
	// fetch path and the Bridge see the same answer.
	fun preferSubscriptionUa(prefs: SharedPreferences): Boolean =
		prefs.getBoolean(PREF_PREFER_SUBSCRIPTION_UA, true)

	// HWID spoof: explicit user choice if set, otherwise default to Xposed-active
	fun isHwidSpoofEnabled(context: Context): Boolean {
		val prefs = getSafePrefs(context)
		if (prefs.contains(PREF_USE_CUSTOM_HWID_SUBSTITUTION)) {
			return prefs.getBoolean(PREF_USE_CUSTOM_HWID_SUBSTITUTION, false)
		}
		return isXposedActive(context)
	}

	// Spoof is live only when enabled AND a manual HWID was entered
	fun isHwidSpoofActive(context: Context): Boolean {
		if (!isHwidSpoofEnabled(context)) return false
		return getSafePrefs(context).getBoolean(PREF_USE_CUSTOM_HWID_INPUT, false)
	}

	// The "send every link straight to Happanion" preference, corrected in place the moment it no
	// longer applies: with Happanion gone - removed, or never installed - every happ:// link would
	// fail instead of falling back to the built-in keys.
	fun isForceHappanionEnabled(context: Context): Boolean {
		val prefs = getSafePrefs(context)
		if (!prefs.getBoolean(PREF_FORCE_HAPPANION, false)) return false
		if (HappanionBridge.isCompatibleVersionInstalled(context)) return true
		prefs.edit { putBoolean(PREF_FORCE_HAPPANION, false) }
		return false
	}

	// Unlock-settings hook: explicit choice if set, else default when module + an unlock target are active
	fun isUnlockHookEnabled(context: Context): Boolean {
		val prefs = getSafePrefs(context)
		if (prefs.contains(PREF_HOOK_HAPP_UNLOCK_SETTINGS)) {
			return prefs.getBoolean(PREF_HOOK_HAPP_UNLOCK_SETTINGS, false)
		}
		return isXposedActive(context) && isUnlockTargetActiveForModule(context)
	}

	// Link interception, on until turned off: it only acts once Xposed or LSPatch runs the hook.
	fun isInterceptEnabled(context: Context): Boolean =
		getSafePrefs(context).getBoolean(PREF_INTERCEPT_ENABLED, true)

	// Links opened in a patched app go to the app chooser first; on until turned off, and like the
	// interception it only acts once Xposed or LSPatch runs the hook.
	fun isRedirectIntentsEnabled(context: Context): Boolean =
		getSafePrefs(context).getBoolean(PREF_REDIRECT_INTENTS, true)

	// A captured id may come from any app that sends the broadcast, so only a plausible one is
	// kept: short, and free of control characters - line breaks and the like, which Android refuses
	// in the x-hwid header the id is sent in.
	private const val MAX_ID_CHARS = 256
	fun isPlausibleId(id: String): Boolean =
		id.length in 1..MAX_ID_CHARS && id.none { it.isISOControl() }

	// Push the current HWID / intercept / unlock state to the hooked process
	fun broadcastSettings(context: Context) {
		val prefs = getSafePrefs(context)
		val custom = prefs.getString(PREF_CUSTOM_HWID, "") ?: ""
		val isActive = isHwidSpoofActive(context)
		val hwidToSend = if (isActive) custom else ""
		val unlockEnabled = isUnlockHookEnabled(context)

		Log.d(TAG, "Broadcasting settings: HWID=$hwidToSend, SpoofActive=$isActive, Unlock=$unlockEnabled")

		val intent = Intent(ModuleIds.ACTION_SETTINGS_UPDATE).apply {
			putExtra(PREF_CUSTOM_HWID, hwidToSend)
			putExtra(PREF_USE_CUSTOM_HWID_SUBSTITUTION, isActive)
			putExtra(PREF_INTERCEPT_ENABLED, isInterceptEnabled(context))
			putExtra(PREF_HOOK_HAPP_UNLOCK_SETTINGS, unlockEnabled)
			putExtra(PREF_REDIRECT_INTENTS, isRedirectIntentsEnabled(context))
		}
		context.sendBroadcast(intent)
	}

	// CRC32 of the first signature: cheap and enough to detect a reinstall
	fun getSignatureCrc32(context: Context, pkgName: String): Long? {
		val packages = context.packageManager
		return try {
			val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
				packages.getPackageInfo(pkgName, PackageManager.GET_SIGNING_CERTIFICATES)
			} else {
				@Suppress("DEPRECATION")
				packages.getPackageInfo(pkgName, PackageManager.GET_SIGNATURES)
			}

			val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
				packageInfo.signingInfo?.signingCertificateHistory
			} else {
				@Suppress("DEPRECATION")
				packageInfo.signatures
			}

			if (signatures != null && signatures.isNotEmpty()) {
				val crc = CRC32()
				crc.update(signatures[0].toByteArray())
				crc.value
			} else null
		} catch (_: Exception) {
			null
		}
	}

	// Conversion mode: the single source of truth for the settings dialogs and for the real
	// pipeline (MainActivity, SubscriptionService -> SubscriptionConverter).
	const val SCOPE_MANUAL = "manual"
	const val SCOPE_SERVER = "server"

	const val MODE_OFF = "off"
	const val MODE_SINGBOX = "singbox"
	const val MODE_MIHOMO = "mihomo"
	const val MODE_URI = "uri"

	// The keys one scope's conversion settings are stored under.
	fun conversionModeKey(scope: String): String = "process_mode_$scope"
	fun base64ChoiceKey(scope: String): String = "process_b64_$scope"
	fun uriDropIncompatibleKey(scope: String): String = "process_uri_drop_incompatible_$scope"
	fun uriDropMihomoKey(scope: String): String = "process_uri_drop_mihomo_$scope"

	// The person's own Base64 choice. Off in every scope unless they tick the box themselves.
	fun userBase64Choice(prefs: SharedPreferences, scope: String): Boolean =
		prefs.getBoolean(base64ChoiceKey(scope), false)

	// The ConversionFlags SubscriptionConverter.convertWithStats takes, derived from
	// process_mode_<scope> for one scope ("manual" or "server").
	fun conversionFlagsFor(prefs: SharedPreferences, scope: String): ConversionFlags {
		val mode = resolveConversionMode(prefs, scope)
		val b64 = userBase64Choice(prefs, scope)
		return when (mode) {
			MODE_MIHOMO -> ConversionFlags(
				jsonToUri = false, xrayToSingBox = false, xrayToMihomo = true, base64Result = b64
			)
			MODE_SINGBOX -> ConversionFlags(
				jsonToUri = false, xrayToSingBox = true, xrayToMihomo = false, base64Result = b64
			)
			MODE_URI -> ConversionFlags(
				jsonToUri = true,
				xrayToSingBox = prefs.getBoolean(uriDropIncompatibleKey(scope), false),
				xrayToMihomo = false,
				base64Result = b64,
				dropIncompatibleMihomo = prefs.getBoolean(uriDropMihomoKey(scope), false)
			)
			else -> ConversionFlags(
				jsonToUri = false, xrayToSingBox = false, xrayToMihomo = false, base64Result = b64
			)
		}
	}

	// Returns process_mode_<scope>, migrating once from the four independent flags the settings
	// screen used to expose. Idempotent: once the new key exists this only reads it.
	fun resolveConversionMode(prefs: SharedPreferences, scope: String): String {
		val key = conversionModeKey(scope)
		prefs.getString(key, null)?.let { return it }

		val xrayToMihomo = prefs.getBoolean("process_mihomo_$scope", false)
		val xrayToSingBox = prefs.getBoolean("process_xray_$scope", false)
		val jsonToUriKey = if (scope == SCOPE_MANUAL) "process_manual" else "process_server"
		val jsonToUri = prefs.getBoolean(jsonToUriKey, scope == SCOPE_MANUAL)

		val mode = when {
			xrayToMihomo -> MODE_MIHOMO
			xrayToSingBox && !jsonToUri -> MODE_SINGBOX
			jsonToUri -> MODE_URI
			else -> MODE_OFF
		}

		prefs.edit {
			putString(key, mode)
			if (mode == MODE_URI && xrayToSingBox) {
				putBoolean(uriDropIncompatibleKey(scope), true)
			}
		}
		return mode
	}
}
