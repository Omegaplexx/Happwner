package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// What the "Result in Base64" setting decides, and what it does not. Base64 is a wrapper rather
// than a format.
class Base64ResultTest {

    private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

    private val config = """
        {"remarks":"S","outbounds":[{"protocol":"vless","tag":"g","settings":{"vnext":[{
        "address":"a.example.com","port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
        "streamSettings":{"network":"tcp","security":"tls",
        "tlsSettings":{"serverName":"a.example.com"}}}]}
    """.trimIndent().replace("\n", "")

    private fun wrap(s: String): String =
        android.util.Base64.encodeToString(s.toByteArray(), android.util.Base64.NO_WRAP)

    private fun unwrap(s: String): String =
        String(android.util.Base64.decode(s, android.util.Base64.DEFAULT))

    private fun looksWrapped(s: String): Boolean =
        s.isNotBlank() && !s.contains('\n') && Regex("^[A-Za-z0-9+/_-]+={0,2}$").matches(s.trim())

    private fun convert(body: String, wanted: Boolean, uri: Boolean = true, sb: Boolean = false) =
        LinkConverter.convert(body, jsonToUri = uri, base64Result = wanted, xrayToSb = sb)

    @Test
    fun `a plain subscription comes back plain when nothing is asked`() {
        val out = convert(config, wanted = false)
        assertTrue("a link was expected: $out", out.startsWith("vless://"))
        assertFalse(looksWrapped(out))
    }

    @Test
    fun `a plain subscription is wrapped when asked`() {
        val out = convert(config, wanted = true)
        assertTrue("the answer should be wrapped: $out", looksWrapped(out))
        assertTrue("and unwrap to the links", unwrap(out).startsWith("vless://"))
    }

    @Test
    fun `a wrapped subscription is read and comes back plain when nothing is asked`() {
        val out = convert(wrap(config), wanted = false)
        assertTrue("the input had to be read regardless of the setting: $out",
            out.startsWith("vless://"))
    }

    @Test
    fun `a wrapped subscription comes back wrapped when asked`() {
        val out = convert(wrap(config), wanted = true)
        assertTrue(looksWrapped(out))
        assertTrue(unwrap(out).startsWith("vless://"))
    }

    @Test
    fun `the padding of the input is the padding of the answer`() {
        val noPadding = android.util.Base64.encodeToString(
            config.toByteArray(),
            android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING
        )
        assertFalse("it arrived without padding",
            convert(noPadding, wanted = true).endsWith("="))

        // Padding only ever appears when the length calls for it, so what is being checked is that
        // it is not suppressed - and that is only visible on an answer whose length actually needs
        // it.
        val padded = android.util.Base64.encodeToString(config.toByteArray(), android.util.Base64.NO_WRAP)
        val answer = convert(padded, wanted = true)
        val plainAnswer = convert(padded, wanted = false)
        if (plainAnswer.toByteArray().size % 3 != 0) {
            assertTrue("it arrived padded, and this answer needs padding: $answer", answer.endsWith("="))
        } else {
            assertFalse("this answer needs no padding at all", answer.endsWith("="))
        }
    }

    @Test
    fun `the alphabet of the input is the alphabet of the answer`() {
        // Only an input that actually uses the 62nd or 63rd symbol says which alphabet it is
        // written in; for anything shorter the two are the same string and there is nothing to
        // copy.
        val telling = distinguishingConfig()
        val urlSafe = android.util.Base64.encodeToString(
            telling.toByteArray(), android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE
        )
        val standard = android.util.Base64.encodeToString(telling.toByteArray(), android.util.Base64.NO_WRAP)

        val fromUrlSafe = convert(urlSafe, wanted = true)
        assertTrue("url-safe in, url-safe out: $fromUrlSafe",
            fromUrlSafe.contains("-") || fromUrlSafe.contains("_"))
        assertFalse("and none of the standard-only symbols",
            fromUrlSafe.contains("+") || fromUrlSafe.contains("/"))

        val fromStandard = convert(standard, wanted = true)
        assertTrue("standard in, standard out: $fromStandard",
            fromStandard.contains("+") || fromStandard.contains("/"))
    }

    // A configuration whose encoded form uses the symbols the alphabets disagree on.
    private fun distinguishingConfig(): String {
        for (pad in 0..60) {
            val cfg = config.replace("\"remarks\":\"S\"", "\"remarks\":\"S" + "\u00ff".repeat(pad) + "\"")
            val std = android.util.Base64.encodeToString(cfg.toByteArray(), android.util.Base64.NO_WRAP)
            if (std.contains("+") || std.contains("/")) return cfg
        }
        throw AssertionError("no distinguishing payload could be built")
    }

    @Test
    fun `an input with no shape to copy gets the one every client reads`() {
        val out = convert(config, wanted = true)
        assertFalse("one line", out.contains('\n'))
        assertFalse("the standard alphabet", out.contains("-") || out.contains("_"))
    }

    @Test
    fun `every conversion mode can be asked for either shape`() {
        // The setting used to be locked on by any mode; each of them can now be
        // handed back wrapped or plain.
        for (sb in listOf(false, true)) {
            assertFalse(looksWrapped(convert(config, wanted = false, uri = !sb, sb = sb)))
            assertTrue(looksWrapped(convert(config, wanted = true, uri = !sb, sb = sb)))
        }
        val mihomoPlain = LinkConverter.convert(config, jsonToUri = false, base64Result = false,
            xrayToSb = false, xrayToMihomo = true)
        val mihomoWrapped = LinkConverter.convert(config, jsonToUri = false, base64Result = true,
            xrayToSb = false, xrayToMihomo = true)
        assertFalse(looksWrapped(mihomoPlain))
        assertTrue(looksWrapped(mihomoWrapped))
        assertEquals("the same document, only wrapped", mihomoPlain, unwrap(mihomoWrapped))
    }
}
