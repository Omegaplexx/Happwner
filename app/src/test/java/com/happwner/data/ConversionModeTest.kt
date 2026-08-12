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
        InMemorySharedPreferences().also { p ->
            val e = p.edit()
            for ((k, v) in entries) when (v) {
                is Boolean -> e.putBoolean(k, v)
                is String -> e.putString(k, v)
                else -> throw IllegalArgumentException("unsupported: $v")
            }
            e.apply()
        }

    // --------------------------------------------------- migration mapping ----

    @Test
    fun `mihomo wins over everything else, as it did in the old pipeline`() {
        // The old converter ran the mihomo pass first and stopped there, so a configuration with
        // several switches on behaved as mihomo.
        for (scope in listOf(PrefsManager.SCOPE_MANUAL, PrefsManager.SCOPE_SERVER)) {
            val p = prefs(
                "process_mihomo_$scope" to true,
                "process_xray_$scope" to true,
                (if (scope == PrefsManager.SCOPE_MANUAL) "process_manual" else "process_server") to true
            )
            assertEquals(scope, PrefsManager.MODE_MIHOMO, PrefsManager.resolveConversionMode(p, scope))
        }
    }

    @Test
    fun `sing-box alone becomes sing-box`() {
        val p = prefs("process_xray_manual" to true, "process_manual" to false)
        assertEquals(PrefsManager.MODE_SINGBOX, PrefsManager.resolveConversionMode(p, PrefsManager.SCOPE_MANUAL))
    }

    @Test
    fun `sing-box together with JSON-to-URI survives as URI with dropping on`() {
        // The combination that used to mean "convert, then emit URIs, dropping what sing-box could
        // not express".
        val p = prefs("process_xray_manual" to true, "process_manual" to true)
        assertEquals(PrefsManager.MODE_URI, PrefsManager.resolveConversionMode(p, PrefsManager.SCOPE_MANUAL))
        assertTrue(
            "the drop-incompatible option must be carried over",
            p.getBoolean("process_uri_drop_incompatible_manual", false)
        )
        val flags = PrefsManager.conversionFlagsFor(p, PrefsManager.SCOPE_MANUAL)
        assertTrue(flags.jsonToUri)
        assertTrue("dropping is what xrayToSb means in URI mode", flags.xrayToSb)
    }

    @Test
    fun `plain JSON-to-URI becomes URI without dropping`() {
        val p = prefs("process_manual" to true)
        assertEquals(PrefsManager.MODE_URI, PrefsManager.resolveConversionMode(p, PrefsManager.SCOPE_MANUAL))
        assertFalse(p.getBoolean("process_uri_drop_incompatible_manual", false))
    }

    @Test
    fun `the 1_3 defaults are preserved per scope`() {
        // Nothing set at all: the manual flow defaulted to converting, the
        // background one to leaving the body alone.
        assertEquals(
            PrefsManager.MODE_URI,
            PrefsManager.resolveConversionMode(prefs(), PrefsManager.SCOPE_MANUAL)
        )
        assertEquals(
            PrefsManager.MODE_OFF,
            PrefsManager.resolveConversionMode(prefs(), PrefsManager.SCOPE_SERVER)
        )
    }

    @Test
    fun `migration runs once and then only reads`() {
        val p = prefs("process_mihomo_manual" to true)
        assertEquals(PrefsManager.MODE_MIHOMO, PrefsManager.resolveConversionMode(p, PrefsManager.SCOPE_MANUAL))

        // The old switch going away must not move the mode again: the new key
        // is now the only source, which is what makes this callable anywhere.
        p.edit().putBoolean("process_mihomo_manual", false).apply()
        assertEquals(PrefsManager.MODE_MIHOMO, PrefsManager.resolveConversionMode(p, PrefsManager.SCOPE_MANUAL))

        // And an explicit choice is never re-derived from the old switches.
        p.edit().putString("process_mode_manual", PrefsManager.MODE_OFF).apply()
        p.edit().putBoolean("process_mihomo_manual", true).apply()
        assertEquals(PrefsManager.MODE_OFF, PrefsManager.resolveConversionMode(p, PrefsManager.SCOPE_MANUAL))
    }

    @Test
    fun `the two scopes migrate independently`() {
        val p = prefs("process_mihomo_manual" to true, "process_xray_server" to true, "process_server" to false)
        assertEquals(PrefsManager.MODE_MIHOMO, PrefsManager.resolveConversionMode(p, PrefsManager.SCOPE_MANUAL))
        assertEquals(PrefsManager.MODE_SINGBOX, PrefsManager.resolveConversionMode(p, PrefsManager.SCOPE_SERVER))
    }

    // ------------------------------------------------------- derived flags ----

    @Test
    fun `the mode does not decide the base64 choice`() {
        // It used to: any mode forced the flag on and the dialog locked the checkbox, which left no
        // way to ask for a wrapped answer.
        for (mode in listOf(PrefsManager.MODE_SINGBOX, PrefsManager.MODE_MIHOMO, PrefsManager.MODE_URI)) {
            val off = prefs("process_mode_manual" to mode, "process_b64_manual" to false)
            assertFalse(
                "$mode must not force the answer into base64",
                PrefsManager.conversionFlagsFor(off, PrefsManager.SCOPE_MANUAL).base64Result
            )
            val on = prefs("process_mode_manual" to mode, "process_b64_manual" to true)
            assertTrue(
                "$mode must honour the choice when it is made",
                PrefsManager.conversionFlagsFor(on, PrefsManager.SCOPE_MANUAL).base64Result
            )
        }
    }

    @Test
    fun `with the mode off the base64 choice is the person's own`() {
        val off = prefs("process_mode_manual" to PrefsManager.MODE_OFF, "process_b64_manual" to false)
        assertFalse(PrefsManager.conversionFlagsFor(off, PrefsManager.SCOPE_MANUAL).base64Result)

        val on = prefs("process_mode_manual" to PrefsManager.MODE_OFF, "process_b64_manual" to true)
        assertTrue(PrefsManager.conversionFlagsFor(on, PrefsManager.SCOPE_MANUAL).base64Result)
    }

    @Test
    fun `the base64 default differs by scope, as it did in 1_3`() {
        val manual = prefs("process_mode_manual" to PrefsManager.MODE_OFF)
        assertTrue(PrefsManager.userBase64Choice(manual, PrefsManager.SCOPE_MANUAL))
        val server = prefs("process_mode_server" to PrefsManager.MODE_OFF)
        assertFalse(PrefsManager.userBase64Choice(server, PrefsManager.SCOPE_SERVER))
    }

    @Test
    fun `each mode sets exactly one conversion switch`() {
        val cases = mapOf(
            PrefsManager.MODE_MIHOMO to Triple(false, false, true),
            PrefsManager.MODE_SINGBOX to Triple(false, true, false),
            PrefsManager.MODE_URI to Triple(true, false, false),
            PrefsManager.MODE_OFF to Triple(false, false, false)
        )
        for ((mode, expected) in cases) {
            val f = PrefsManager.conversionFlagsFor(
                prefs("process_mode_manual" to mode), PrefsManager.SCOPE_MANUAL
            )
            assertEquals("$mode jsonToUri", expected.first, f.jsonToUri)
            assertEquals("$mode xrayToSb", expected.second, f.xrayToSb)
            assertEquals("$mode xrayToMihomo", expected.third, f.xrayToMihomo)
        }
    }

    @Test
    fun `URI mode carries the drop-incompatible option through as xrayToSb`() {
        val without = prefs("process_mode_manual" to PrefsManager.MODE_URI)
        assertFalse(PrefsManager.conversionFlagsFor(without, PrefsManager.SCOPE_MANUAL).xrayToSb)

        val with = prefs(
            "process_mode_manual" to PrefsManager.MODE_URI,
            "process_uri_drop_incompatible_manual" to true
        )
        assertTrue(PrefsManager.conversionFlagsFor(with, PrefsManager.SCOPE_MANUAL).xrayToSb)
    }
}
