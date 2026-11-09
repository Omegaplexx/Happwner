package com.happwner.text

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// The shared text helpers past the common case: what a real subscription can also hand them -
// comments where a trailing comma is judged, IPv6 in brackets, unpadded base64, bare padding.
class TextCodecTest {

	@Test
	fun `a comma before a closer is dropped with comments between them`() {
		assertEquals("[1 \n]", stripJsonComments("[1, // note\n]"))
		assertEquals("{\"a\":1  }", stripJsonComments("{\"a\":1, /* note */ }"))
	}

	@Test
	fun `a comma stays where nothing closes after it`() {
		assertEquals("[1,", stripJsonComments("[1,"))
		assertEquals("[1, ", stripJsonComments("[1, /* never closed"))
	}

	@Test
	fun `a block comment keeps its lines and a lone slash is text`() {
		assertEquals("[1 \n]", stripJsonComments("[1 /* a\nb */]"))
		assertEquals("1/", stripJsonComments("1/"))
	}

	@Test
	fun `a bracketed ipv6 host splits from its port`() {
		assertEquals(HostPort("2001:db8::1", 443), splitHostPort("[2001:db8::1]:443"))
		assertEquals(HostPort("2001:db8::1", null), splitHostPort("[2001:db8::1]"))
		// Unbracketed, its colons cannot be told from a port's: kept whole, with none.
		assertEquals(HostPort("2001:db8::1", null), splitHostPort("2001:db8::1"))
		assertEquals(HostPort("::1", null), splitHostPort("[::1]:http"))
		assertEquals(HostPort("[2001:db8::1", null), splitHostPort("[2001:db8::1"))
		assertEquals(HostPort("", null), splitHostPort(null))
	}

	@Test
	fun `brackets come off only a bracketed host`() {
		assertEquals("::1", stripBrackets("[::1]"))
		assertEquals("::1", stripBrackets("::1"))
	}

	@Test
	fun `the first value with text wins`() {
		assertEquals("b", firstNonEmpty(null, "  ", " b "))
		assertEquals("", firstNonEmpty(null))
	}

	@Test
	fun `padding follows the length`() {
		assertEquals("QUJ=", padBase64("QUJ"))
		assertEquals("QU==", padBase64("QU"))
		assertEquals("QUJD", padBase64("QUJD"))
	}

	@Test
	fun `whitespace counts only when allowed`() {
		assertEquals(Base64Alphabet.EITHER, base64Alphabet("QU\nJD", allowWhitespace = true))
		assertNull(base64Alphabet("QU\nJD"))
		assertNull(base64Flag("= =\n"))
	}

	@Test
	fun `control characters other than tab and line breaks mark binary`() {
		assertTrue(hasBinaryControls("\u007f"))
		assertTrue(hasBinaryControls("a\u0001b"))
		assertFalse(hasBinaryControls("\tline\r\nnext"))
	}

	@Test
	fun `no bytes are no text`() {
		assertNull(decodeStrictUtf8(ByteArray(0)))
	}
}
