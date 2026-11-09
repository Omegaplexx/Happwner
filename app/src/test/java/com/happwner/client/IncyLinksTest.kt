package com.happwner.client

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Unwrapping `incy://add/` and `incy://import/`. What comes out of here goes straight into the URL
// field, so "could not read it" and "here is what it said" have to stay apart.
class IncyLinksTest {

	private fun b64(text: String) = Base64.getEncoder().encodeToString(text.toByteArray())
	private fun b64url(text: String) =
		Base64.getUrlEncoder().withoutPadding().encodeToString(text.toByteArray())

	@Test
	fun `what a link carries comes back as it went in, in any case of the prefix`() {
		assertEquals(
			"https://example.com/sub?token=abc",
			IncyLinks.stripIncyPrefix("incy://add/https://example.com/sub?token=abc")
		)
		assertEquals(
			"vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443",
			IncyLinks.stripIncyPrefix(
				"incy://import/vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443")
		)
		val url = "https://example.com/sub?a=1&b=2"
		assertEquals(url, IncyLinks.stripIncyPrefix("incy://import/" + b64(url)))
		assertEquals(url, IncyLinks.stripIncyPrefix("incy://import/" + b64url(url)))
		// Unpadded standard, which is what several panels emit.
		val raw = Base64.getEncoder().withoutPadding().encodeToString(url.toByteArray())
		assertEquals(url, IncyLinks.stripIncyPrefix("incy://import/$raw"))
		val list = "vless://a@h1:443\nvless://b@h2:443\ntrojan://p@h3:443"
		assertEquals(list, IncyLinks.stripIncyPrefix("incy://import/" + b64(list)))
		// Percent-encoding is undone first.
		assertEquals(url, IncyLinks.stripIncyPrefix("incy://add/https%3A%2F%2Fexample.com%2Fsub%3Fa%3D1%26b%3D2"))
		assertEquals("https://example.com/", IncyLinks.stripIncyPrefix("INCY://ADD/https://example.com/"))
		assertTrue(IncyLinks.isIncyLink("Incy://Import/whatever"))
	}

	@Test
	fun `what is not a link is refused, not read into mojibake or into the URL field`() {
		// Text the decoder does not recognise must be refused, not read as UTF-8 into a handful of
		// replacement characters.
		for (text in listOf(
			"incy://add/hello world!!!",
			"incy://import/zzzz zzzz zzzz",
			"incy://add/....................",
			"incy://import/@@@@@@@@@@@@",
			"incy://add/просто текст",
			// Both alphabets at once is a coincidence, not an encoding.
			"incy://import/abcd-efg+hij_klm/nop",
			// Valid base64 and valid text, but no link; and valid base64 of binary, which is no text.
			"incy://import/" + b64("just a sentence, not a link"),
			"incy://import/" + Base64.getEncoder().encodeToString(ByteArray(32) { (it * 7 + 0x80).toByte() })
		)) {
			assertNull("expected a refusal for $text", IncyLinks.stripIncyPrefix(text))
		}
		for (text in listOf(null, "", "   ", "https://example.com", "happ://add/x", "incy://add/",
			"incy://import/")) {
			assertNull("expected null for ${text?.take(24)}", IncyLinks.stripIncyPrefix(text))
		}
		assertTrue(!IncyLinks.isIncyLink("incy://crypt1/AAAA"))
	}
}
