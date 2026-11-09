package com.happwner.data

import android.content.InMemorySharedPreferences
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// The conversion mode and the flags derived from it.
class ConversionModeTest {

	private fun prefs(vararg entries: Pair<String, Any>): SharedPreferences =
		InMemorySharedPreferences().also { store ->
			val editor = store.edit()
			for ((k, value) in entries) when (value) {
				is Boolean -> editor.putBoolean(k, value)
				is String -> editor.putString(k, value)
				else -> throw IllegalArgumentException("unsupported: $value")
			}
			editor.apply()
		}

	@Test
	fun `the old switches resolve to a mode, mihomo first, and the defaults differ per scope`() {
		// The mihomo pass runs first and stops there, so a configuration with several switches on
		// behaves as mihomo.
		for (scope in listOf(PrefsManager.SCOPE_MANUAL, PrefsManager.SCOPE_SERVER)) {
			val store = prefs(
				"process_mihomo_$scope" to true,
				"process_xray_$scope" to true,
				(if (scope == PrefsManager.SCOPE_MANUAL) "process_manual" else "process_server") to true
			)
			assertEquals(scope, PrefsManager.MODE_MIHOMO, PrefsManager.resolveConversionMode(store, scope))
		}
		val manual = PrefsManager.SCOPE_MANUAL
		val singBox = prefs("process_xray_manual" to true, "process_manual" to false)
		assertEquals(PrefsManager.MODE_SINGBOX, PrefsManager.resolveConversionMode(singBox, manual))
		// "Convert, then emit URIs, dropping what sing-box cannot express".
		val dropping = prefs("process_xray_manual" to true, "process_manual" to true)
		assertEquals(PrefsManager.MODE_URI, PrefsManager.resolveConversionMode(dropping, manual))
		assertTrue("the drop-incompatible option is carried over", dropping.getBoolean("process_uri_drop_incompatible_manual", false))
		val flags = PrefsManager.conversionFlagsFor(dropping, manual)
		assertTrue(flags.jsonToUri)
		assertTrue("dropping is what xrayToSingBox means in URI mode", flags.xrayToSingBox)
		val plain = prefs("process_manual" to true)
		assertEquals(PrefsManager.MODE_URI, PrefsManager.resolveConversionMode(plain, manual))
		assertFalse(plain.getBoolean("process_uri_drop_incompatible_manual", false))
		// Nothing set at all: the manual flow converts, the background one leaves the body alone.
		assertEquals(PrefsManager.MODE_URI, PrefsManager.resolveConversionMode(prefs(), manual))
		assertEquals(PrefsManager.MODE_OFF, PrefsManager.resolveConversionMode(prefs(), PrefsManager.SCOPE_SERVER))
	}

	@Test
	fun `migration runs once per scope and then only reads`() {
		val store = prefs("process_mihomo_manual" to true, "process_xray_server" to true, "process_server" to false)
		assertEquals(PrefsManager.MODE_MIHOMO, PrefsManager.resolveConversionMode(store, PrefsManager.SCOPE_MANUAL))
		assertEquals(PrefsManager.MODE_SINGBOX, PrefsManager.resolveConversionMode(store, PrefsManager.SCOPE_SERVER))

		// The old switch going away must not move the mode again: the new key
		// is now the only source, which is what makes this callable anywhere.
		store.edit().putBoolean("process_mihomo_manual", false).apply()
		assertEquals(PrefsManager.MODE_MIHOMO, PrefsManager.resolveConversionMode(store, PrefsManager.SCOPE_MANUAL))

		// And an explicit choice is never re-derived from the old switches.
		store.edit().putString("process_mode_manual", PrefsManager.MODE_OFF).apply()
		store.edit().putBoolean("process_mihomo_manual", true).apply()
		assertEquals(PrefsManager.MODE_OFF, PrefsManager.resolveConversionMode(store, PrefsManager.SCOPE_MANUAL))
	}

	@Test
	fun `each mode sets exactly one conversion switch, and URI carries the drop option`() {
		val cases = mapOf(
			PrefsManager.MODE_MIHOMO to Triple(false, false, true),
			PrefsManager.MODE_SINGBOX to Triple(false, true, false),
			PrefsManager.MODE_URI to Triple(true, false, false),
			PrefsManager.MODE_OFF to Triple(false, false, false)
		)
		for ((mode, expected) in cases) {
			val flags = PrefsManager.conversionFlagsFor(
				prefs("process_mode_manual" to mode), PrefsManager.SCOPE_MANUAL
			)
			assertEquals("$mode jsonToUri", expected.first, flags.jsonToUri)
			assertEquals("$mode xrayToSingBox", expected.second, flags.xrayToSingBox)
			assertEquals("$mode xrayToMihomo", expected.third, flags.xrayToMihomo)
		}
		val with = prefs(
			"process_mode_manual" to PrefsManager.MODE_URI,
			"process_uri_drop_incompatible_manual" to true
		)
		assertTrue(PrefsManager.conversionFlagsFor(with, PrefsManager.SCOPE_MANUAL).xrayToSingBox)
	}

	@Test
	fun `the base64 choice is the person's own in every mode, and off in both scopes until ticked`() {
		// No mode forces the flag on or locks the checkbox: a wrapped answer can always be asked for.
		for (mode in listOf(PrefsManager.MODE_SINGBOX, PrefsManager.MODE_MIHOMO, PrefsManager.MODE_URI, PrefsManager.MODE_OFF)) {
			val off = prefs("process_mode_manual" to mode, "process_b64_manual" to false)
			assertFalse("$mode must not force base64", PrefsManager.conversionFlagsFor(off, PrefsManager.SCOPE_MANUAL).base64Result)
			val on = prefs("process_mode_manual" to mode, "process_b64_manual" to true)
			assertTrue("$mode must honour the choice", PrefsManager.conversionFlagsFor(on, PrefsManager.SCOPE_MANUAL).base64Result)
		}
		val manual = prefs("process_mode_manual" to PrefsManager.MODE_OFF)
		assertFalse(PrefsManager.userBase64Choice(manual, PrefsManager.SCOPE_MANUAL))
		val server = prefs("process_mode_server" to PrefsManager.MODE_OFF)
		assertFalse(PrefsManager.userBase64Choice(server, PrefsManager.SCOPE_SERVER))
		val ticked = prefs("process_b64_manual" to true)
		assertTrue(PrefsManager.userBase64Choice(ticked, PrefsManager.SCOPE_MANUAL))
	}
}
