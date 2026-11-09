package com.happwner.data

import org.junit.Assert.assertEquals
import org.junit.Test

// Installations already keep values under these names: a key renamed in the code would quietly
// reset its setting or lose its state, so each one is pinned to the name it is stored under.
class StoredKeysTest {

	@Test
	fun `every stored key keeps its name`() {
		val names = mapOf(
			PrefsManager.PREF_ANIM_MODE to "anim_mode",
			PrefsManager.PREF_APP_LANG to "app_lang",
			PrefsManager.PREF_BRIDGE_BATTERY_ASKS to "bridge_battery_asks",
			PrefsManager.PREF_BRIDGE_ENABLED to "bridge_enabled",
			PrefsManager.PREF_BRIDGE_HINT_SHOWN to "bridge_hint_shown",
			PrefsManager.PREF_BRIDGE_LAN_MODE to "bridge_lan_mode",
			PrefsManager.PREF_BRIDGE_NOTIFICATION_ASKS to "bridge_notification_asks",
			PrefsManager.PREF_BRIDGE_WATCHDOG to "bridge_watchdog",
			PrefsManager.PREF_CAPTURED_ID to "captured_id",
			PrefsManager.PREF_CUSTOM_HWID to "custom_hwid",
			PrefsManager.PREF_CUSTOM_USER_AGENT to "custom_user_agent",
			PrefsManager.PREF_FORCE_HAPPANION to "force_happlib",
			PrefsManager.PREF_HOOK_HAPP_UNLOCK_SETTINGS to "hook_happ_unlock_settings",
			PrefsManager.PREF_INTERCEPT_ENABLED to "intercept_enabled",
			PrefsManager.PREF_LAST_URL to "last_url",
			PrefsManager.PREF_LSPATCH_APPS to "lspatch_apps",
			PrefsManager.PREF_LSPATCH_MODE to "lspatch_mode",
			PrefsManager.PREF_LSPATCH_SIGNATURES to "lspatch_signatures",
			PrefsManager.PREF_MONET_ACCENT to "monet_accent",
			PrefsManager.PREF_PREFER_SUBSCRIPTION_UA to "prefer_sub_ua",
			PrefsManager.PREF_REDIRECT_INTENTS to "redirect_intents",
			PrefsManager.PREF_SHOW_DUPLICATES to "show_duplicates",
			PrefsManager.PREF_THEME_MODE to "theme_mode",
			PrefsManager.PREF_USE_CUSTOM_HWID_INPUT to "use_custom_hwid_input",
			PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION to "use_custom_hwid_substitution",
			PrefsManager.SCOPE_MANUAL to "manual",
			PrefsManager.SCOPE_SERVER to "server",
		)
		for ((key, name) in names) assertEquals(name, key)
	}

	@Test
	fun `each scope's conversion keys keep their names`() {
		for (scope in listOf(PrefsManager.SCOPE_MANUAL, PrefsManager.SCOPE_SERVER)) {
			assertEquals("process_mode_$scope", PrefsManager.conversionModeKey(scope))
			assertEquals("process_b64_$scope", PrefsManager.base64ChoiceKey(scope))
			assertEquals("process_uri_drop_incompatible_$scope", PrefsManager.uriDropIncompatibleKey(scope))
			assertEquals("process_uri_drop_mihomo_$scope", PrefsManager.uriDropMihomoKey(scope))
		}
	}
}
