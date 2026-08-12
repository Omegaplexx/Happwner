package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// The gate exists for a failure this suite cannot reproduce: Android's org.json recurses per nesting
// level with no limit, and the StackOverflowError it raises is an Error, which catch (Exception) misses.
class JsonDepthTest {

    // ------------------------------------------------------- the constant ----

    // Pins the headroom between real configurations and the limit: depth counts containers open at once,
    // not brackets in total, so a routing table of hundreds of rules costs no depth at all.
    @Test
    fun `the limit keeps an order of magnitude over real configurations`() {
        val deepestRealisticConfiguration = 12
        assertTrue(
            "MAX_DEPTH=${JsonDepth.MAX_DEPTH} leaves too little room over real " +
                "configurations (deepest measured: 9)",
            JsonDepth.MAX_DEPTH >= deepestRealisticConfiguration * 10
        )
    }

    @Test
    fun `a realistic configuration is nowhere near the limit`() {
        val cfg = """
            { "remarks": "Node", "outbounds": [{ "protocol": "vless", "tag": "proxy",
              "settings": { "vnext": [{ "address": "a.example.com", "port": 443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision" }] }] },
              "streamSettings": { "network": "ws", "security": "tls",
                "tlsSettings": { "serverName": "a.example.com", "alpn": ["h2", "http/1.1"] },
                "wsSettings": { "path": "/ws", "headers": { "Host": "a.example.com" } } } }],
              "routing": { "rules": [{ "type": "field", "domain": ["geosite:ru"], "outboundTag": "proxy" }] } }
        """.trimIndent()
        assertFalse(JsonDepth.exceedsMaxDepth(cfg))
        assertTrue("real configs are shallow", JsonDepth.maxNestingDepth(cfg) <= 12)
    }

    @Test
    fun `width costs no depth`() {
        // Ten thousand siblings, three levels deep.
        val rules = (1..10000).joinToString(",") { """{"outboundTag":"o$it"}""" }
        val wide = """{"routing":{"rules":[$rules]}}"""
        assertEquals(4, JsonDepth.maxNestingDepth(wide))
        assertFalse(JsonDepth.exceedsMaxDepth(wide))
    }

    // ------------------------------------------------------------ the bomb ----

    @Test
    fun `a nesting bomb is refused`() {
        val bomb = "[".repeat(10000) + "]".repeat(10000)
        assertTrue(JsonDepth.exceedsMaxDepth(bomb))
    }

    @Test
    fun `the converters refuse a nesting bomb instead of parsing it`() {
        val nest = "[".repeat(5000) + "]".repeat(5000)
        val bomb = """{"outbounds":[{"protocol":"vless","settings":{"vnext":$nest}}]}"""
        assertEquals(SingBoxConverter.Result.NotXray, SingBoxConverter.convert(bomb))
        assertEquals(
            SingBoxConverter.OutboundsResult.NotXray,
            SingBoxConverter.convertToOutbounds(bomb)
        )
        assertEquals(MihomoConverter.Result.NotXray, MihomoConverter.convert(bomb))
    }

    @Test
    fun `one bomb does not cost the rest of the subscription`() {
        // The regression the gate exists for: the overflow used to unwind out of the line loop and take every
        // other line with it. Run on a thread with Android's ordinary stack, since that is what decides it.
        val good = """{"remarks":"NodeA","outbounds":[{"protocol":"vless","tag":"o",""" +
            """"settings":{"vnext":[{"address":"a.example","port":443,""" +
            """"users":[{"id":"11111111-1111-1111-1111-111111111111"}]}]},""" +
            """"streamSettings":{"network":"tcp","security":"tls"}}]}"""
        val bomb = "{\"outbounds\":[" + "[".repeat(8000) + "]".repeat(8000) + "]}"
        val body = "$good\n$bomb\n$good"

        var out: String? = null
        var escaped: Throwable? = null
        val t = Thread(null, {
            try {
                out = LinkConverter.convert(body, xrayToSb = true)
            } catch (e: Throwable) {
                escaped = e
            }
        }, "depth-gate", 1024L * 1024)
        t.start()
        t.join()

        assertNull("nothing may escape the conversion: $escaped", escaped)
        assertEquals(
            "both good configurations must still convert",
            2,
            out!!.lines().count { it.startsWith("vless://") }
        )
        assertTrue("the bomb line is passed through untouched", out!!.contains("[[["))
    }

    // ------------------------------ the scanner cannot be walked out of step ----

    // Android's parser is far more lenient than JSON: it accepts single-quoted strings, unquoted
    // literals, and `//`, `#` and slash-star comments.
    @Test
    fun `a quote the parser does not treat as a string opening is not one here either`() {
        val deep = "[".repeat(400) + "]".repeat(400)

        // A quote inside a comment the parser skips whole.
        assertTrue(JsonDepth.exceedsMaxDepth("""{"a": /* " */ $deep}"""))
        assertTrue(JsonDepth.exceedsMaxDepth("{\"a\": 1, # \"\n \"b\": $deep}"))
        assertTrue(JsonDepth.exceedsMaxDepth("{\"a\": 1, // \"\n \"b\": $deep}"))

        // A double quote that is the content of a single-quoted string.
        assertTrue(JsonDepth.exceedsMaxDepth("""{"a":'"',"b":$deep}"""))

        // A double quote inside an unquoted literal.
        assertTrue(JsonDepth.exceedsMaxDepth("""{"a":ab"cd,"b":$deep}"""))
    }

    @Test
    fun `brackets inside strings and escapes are not containers`() {
        assertEquals(1, JsonDepth.maxNestingDepth("""{"a":"[[[[[[["}"""))
        assertEquals(1, JsonDepth.maxNestingDepth("""{"a":"\"[[[[["}"""))
        assertEquals(1, JsonDepth.maxNestingDepth("""{"a":'[[[[['}"""))
        // A backslash immediately before the closing quote escapes it, so the
        // string runs on - and the brackets after it are still string content.
        assertEquals(1, JsonDepth.maxNestingDepth("""{"a":"x\\", "b":"[[["}"""))
    }

    @Test
    fun `malformed input terminates instead of spinning`() {
        // Every character that ends an unquoted literal needs its own branch in the scanner;
        // without one it makes no progress and hangs the thread.
        for (s in listOf("\\", "\u000c", "\\\\\\", "{\\", "[\u000c", "{'", "\"", "/*", "/", "#")) {
            JsonDepth.maxNestingDepth(s)
        }
        assertEquals(0, JsonDepth.maxNestingDepth(""))
        // A stray closer must not push the counter negative and buy depth back.
        assertEquals(2, JsonDepth.maxNestingDepth("}]}]{[") + 0)
    }

    // ---------------------------------------- the one-sided contract itself ----

    // The guarantee the gate rests on: the scanner may report more depth than the parser recurses,
    // never less. Over-reporting costs a rejected input; under-reporting costs the overflow.
    @Test
    fun `the scanner never reports less depth than the parser recurses`() {
        val atoms = listOf(
            "{", "}", "[", "]", "\"", "'", "\\", "/", "*", "#", ":", ",", ";", "=", ">",
            " ", "\n", "\t", "a", "1", "null", "true", "/*", "*/", "//", "\\\"", "\\'", "\\u0022"
        )
        val rnd = java.util.Random(20260802)
        var parsed = 0
        repeat(20000) {
            val sb = StringBuilder()
            repeat(1 + rnd.nextInt(60)) { sb.append(atoms[rnd.nextInt(atoms.size)]) }
            val s = sb.toString()
            val scanner = JsonDepth.maxNestingDepth(s)
            val value = try { JSONTokener(s).nextValue() } catch (_: Exception) { return@repeat }
            parsed++
            val real = graphDepth(value)
            assertTrue(
                "scanner under-reported: $scanner < $real for ${s.take(80)}",
                scanner >= real
            )
        }
        assertTrue("the fuzz should actually parse something", parsed > 1000)
    }

    private fun graphDepth(v: Any?): Int = when (v) {
        is JSONObject -> 1 + (v.keys().asSequence().map { graphDepth(v.opt(it)) }.maxOrNull() ?: 0)
        is JSONArray -> 1 + ((0 until v.length()).map { graphDepth(v.opt(it)) }.maxOrNull() ?: 0)
        else -> 0
    }
}
