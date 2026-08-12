package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// Base64-wrapped subscription bodies. Panels wrap the body in base64, in either alphabet, padded or
// not, and often hard-wrapped at 64 or 76 columns.
class Base64BodyTest {

    private val config = """
        {"remarks":"N","outbounds":[{"protocol":"vless","tag":"n",
        "settings":{"vnext":[{"address":"a.example.com","port":443,
        "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
        "streamSettings":{"network":"tcp","security":"tls",
        "tlsSettings":{"serverName":"a.example.com"}}}]}
    """.trimIndent().replace("\n", "")

    private fun convert(body: String): String =
        LinkConverter.convert(body, jsonToUri = true, base64Result = false, xrayToSb = true)

    private fun assertDecoded(label: String, body: String) {
        val out = convert(body)
        assertTrue(
            "$label: expected a vless:// link, got ${out.take(80)}",
            out.startsWith("vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443")
        )
    }

    @Test
    fun `a body wrapped in either alphabet decodes`() {
        assertDecoded("standard padded", java.util.Base64.getEncoder().encodeToString(config.toByteArray()))
        assertDecoded("standard raw", java.util.Base64.getEncoder().withoutPadding().encodeToString(config.toByteArray()))
        assertDecoded("url-safe padded", java.util.Base64.getUrlEncoder().encodeToString(config.toByteArray()))
        assertDecoded("url-safe raw", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(config.toByteArray()))
    }

    @Test
    fun `hard-wrapped bodies decode, in either alphabet and either line ending`() {
        val std = java.util.Base64.getEncoder().encodeToString(config.toByteArray())
        val url = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(config.toByteArray())
        assertDecoded("standard, LF at 76", std.chunked(76).joinToString("\n"))
        assertDecoded("standard, CRLF at 64", std.chunked(64).joinToString("\r\n"))
        // The one a strict URL decoder rejects: it has no line-break handling.
        assertDecoded("url-safe, LF at 64", url.chunked(64).joinToString("\n"))
        assertDecoded("url-safe, CRLF at 76", url.chunked(76).joinToString("\r\n"))
    }

    @Test
    fun `a body that only looks like base64 is left alone`() {
        // Both alphabets at once is not a real encoding, so it must pass through
        // rather than be mangled into something that decodes to noise.
        val mixed = "abcd-efg+hij_klm/nop"
        assertEquals(mixed, convert(mixed))
        // Plain text stays plain text.
        val text = "just a line of text that is long enough"
        assertEquals(text, convert(text))
    }

    @Test
    fun `decoded noise is refused rather than emitted`() {
        // Valid base64 whose bytes are not UTF-8 text: decoding "succeeds" and
        // has to be rejected on the content, or the output becomes mojibake.
        val noise = java.util.Base64.getEncoder()
            .encodeToString(ByteArray(64) { (it * 7 + 0x80).toByte() })
        assertEquals(noise, convert(noise))
    }
}
