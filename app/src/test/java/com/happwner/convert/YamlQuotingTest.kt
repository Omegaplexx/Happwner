package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Test

// Cover for the scalar quoting in MihomoYaml. Every case was produced by running the emitter's output
// through gopkg.in/yaml.v3, the parser mihomo uses: these are regressions, not style preferences.
class YamlQuotingTest {

    private fun emit(s: String): String {
        val m = YamlMap().set("k", s)
        return encodeYaml(m).removePrefix("k: ").trimEnd('\n')
    }

    private fun emitFlow(s: String): String {
        val m = YamlMap().set("k", YamlFlowSeq(listOf(s)))
        return encodeYaml(m).removePrefix("k: ").trimEnd('\n')
    }

    // ---- timestamps: yaml.v3's allowedTimestampFormats includes a bare "2006-1-2"

    @Test
    fun date_like_names_are_quoted() {
        // Unquoted these resolve to time.Time and mihomo rejects the config
        // with "'name' expected type 'string', got unconvertible type 'time.Time'".
        assertEquals("'2024-01-01'", emit("2024-01-01"))
        assertEquals("'2024-1-1'", emit("2024-1-1"))
        assertEquals("'2002-12-14'", emit("2002-12-14"))
        assertEquals("'2001-12-14t21:59:43.10-05:00'", emit("2001-12-14t21:59:43.10-05:00"))
    }

    // ---- numbers: yaml.v3 strips "_" then tries ParseInt, then ParseUint

    @Test
    fun underscore_separated_digits_are_quoted() {
        // yaml.v3 does plain := strings.Replace(in, "_", "", -1) first, so this
        // resolved to int 1000 while Kotlin's toLongOrNull said "not a number".
        assertEquals("'1_000'", emit("1_000"))
    }

    @Test
    fun integers_too_large_for_long_are_quoted() {
        // toLongOrNull overflows and returns null, but yaml.v3 falls through to
        // ParseUint and gets a uint64.
        assertEquals("'12345678901234567890'", emit("12345678901234567890"))
        assertEquals("'99999999999999999999999999'", emit("99999999999999999999999999"))
    }

    @Test
    fun alternative_bases_are_quoted() {
        assertEquals("'0x1f'", emit("0x1f"))
        assertEquals("'0o17'", emit("0o17"))
        assertEquals("'0b1011'", emit("0b1011"))
        assertEquals("'0123'", emit("0123"))   // leading zero is octal at base 0
    }

    // ---- line breaks: is_break in yaml.v3 covers NEL, LS and PS as well

    @Test
    fun unicode_line_breaks_are_escaped() {
        // Left literal these end the scalar and the value comes back as null.
        assertEquals("\"\\x85\"", emit("\u0085"))
        assertEquals("\"\\u2028\"", emit("\u2028"))
        assertEquals("\"\\u2029\"", emit("\u2029"))
    }

    // ---- flow context forbids more than block context does

    @Test
    fun flow_indicators_are_quoted_only_inside_flow() {
        // A comma is harmless as a mapping value and splits the item in a flow
        // sequence, which is why the two contexts quote differently.
        assertEquals("a,b", emit("a,b"))
        assertEquals("['a,b']", emitFlow("a,b"))
        assertEquals("a[b", emit("a[b"))
        assertEquals("['a[b']", emitFlow("a[b"))
        assertEquals("['a?b']", emitFlow("a?b"))
    }

    // ---- the merge key

    @Test
    fun merge_key_is_quoted() {
        assertEquals("'<<'", emit("<<"))
    }

    // ---- things that must stay plain, so the output keeps reading like a
    // hand-written mihomo config

    @Test
    fun ordinary_values_are_not_quoted() {
        assertEquals("h2", emit("h2"))
        assertEquals("http/1.1", emit("http/1.1"))
        assertEquals("chrome", emit("chrome"))
        assertEquals("www.cloudflare.com", emit("www.cloudflare.com"))
        assertEquals("xtls-rprx-vision", emit("xtls-rprx-vision"))
        assertEquals("[h2]", emitFlow("h2"))
    }
}
