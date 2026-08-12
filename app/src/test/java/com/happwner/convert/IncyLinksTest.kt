package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Unwrapping `incy://add/` and `incy://import/`. What comes out of here goes straight into the URL
// field, so "could not read it" and "here is what it said" have to stay apart.
class IncyLinksTest {

    private fun b64(s: String) = java.util.Base64.getEncoder().encodeToString(s.toByteArray())
    private fun b64url(s: String) =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())

    // ------------------------------------------------------- what must work ----

    @Test
    fun `a plain link is returned as it stands`() {
        assertEquals(
            "https://example.com/sub?token=abc",
            IncyLinks.stripIncyPrefix("incy://add/https://example.com/sub?token=abc")
        )
        assertEquals(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443",
            IncyLinks.stripIncyPrefix("incy://import/vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443")
        )
    }

    @Test
    fun `a base64 payload decodes, in either alphabet`() {
        val url = "https://example.com/sub?a=1&b=2"
        assertEquals(url, IncyLinks.stripIncyPrefix("incy://import/" + b64(url)))
        assertEquals(url, IncyLinks.stripIncyPrefix("incy://import/" + b64url(url)))
        // Unpadded standard, which is what several panels emit.
        val raw = java.util.Base64.getEncoder().withoutPadding().encodeToString(url.toByteArray())
        assertEquals(url, IncyLinks.stripIncyPrefix("incy://import/$raw"))
    }

    @Test
    fun `a payload holding several links keeps all of them`() {
        val list = "vless://a@h1:443\nvless://b@h2:443\ntrojan://p@h3:443"
        assertEquals(list, IncyLinks.stripIncyPrefix("incy://import/" + b64(list)))
    }

    @Test
    fun `percent-encoding is undone first`() {
        assertEquals(
            "https://example.com/sub?a=1&b=2",
            IncyLinks.stripIncyPrefix("incy://add/https%3A%2F%2Fexample.com%2Fsub%3Fa%3D1%26b%3D2")
        )
    }

    @Test
    fun `the prefix match ignores case`() {
        assertEquals("https://example.com/", IncyLinks.stripIncyPrefix("INCY://ADD/https://example.com/"))
        assertTrue(IncyLinks.isIncyLink("Incy://Import/whatever"))
    }

    // ------------------------------------------------------ what must not ----

    @Test
    fun `text that is not a link is refused instead of becoming mojibake`() {
        // Each of these used to come back as a handful of replacement characters, because the
        // decoder skipped what it did not recognise and the UTF-8 read never failed.
        for (s in listOf(
            "incy://add/hello world!!!",
            "incy://import/zzzz zzzz zzzz",
            "incy://add/....................",
            "incy://import/@@@@@@@@@@@@",
            "incy://add/просто текст"
        )) {
            assertNull("expected a refusal for $s", IncyLinks.stripIncyPrefix(s))
        }
    }

    @Test
    fun `base64 that decodes to something other than a link is refused`() {
        // Valid base64, valid text, but not a link - it must not reach the URL
        // field as though it were one.
        assertNull(IncyLinks.stripIncyPrefix("incy://import/" + b64("just a sentence, not a link")))
        // Valid base64 of binary: not text at all.
        val binary = java.util.Base64.getEncoder()
            .encodeToString(ByteArray(32) { (it * 7 + 0x80).toByte() })
        assertNull(IncyLinks.stripIncyPrefix("incy://import/$binary"))
    }

    @Test
    fun `both alphabets at once is a coincidence, not an encoding`() {
        assertNull(IncyLinks.stripIncyPrefix("incy://import/abcd-efg+hij_klm/nop"))
    }

    @Test
    fun `non-incy input is refused`() {
        for (s in listOf(null, "", "   ", "https://example.com", "happ://add/x", "incy://add/", "incy://import/")) {
            assertNull("expected null for ${s?.take(24)}", IncyLinks.stripIncyPrefix(s))
        }
        assertTrue(!IncyLinks.isIncyLink("incy://crypt1/AAAA"))
    }
}
