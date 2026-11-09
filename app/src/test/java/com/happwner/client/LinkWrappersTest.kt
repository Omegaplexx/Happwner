package com.happwner.client

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// How a link reaches the URL field from inside another: an add/import wrapper, or an http(s) URL
// carrying it as it is or percent-encoded, well-formed.
class LinkWrappersTest {

	private fun b64(text: String) = Base64.getEncoder().encodeToString(text.toByteArray())

	@Test
	fun `schemes and prefixes are found in any case, written out or with the colon encoded`() {
		assertEquals(21, indexOfScheme("https://x.example/?u=happ://crypt/a", "happ"))
		assertEquals(21, indexOfScheme("https://x.example/?u=happ%3A%2F%2Fcrypt%2Fa", "happ"))
		assertEquals(21, indexOfScheme("https://x.example/?u=happ%3a%2f%2fcrypt%2fa", "happ"))
		assertEquals(21, indexOfScheme("https://x.example/?u=HAPP://crypt/a", "happ"))
		assertEquals(-1, indexOfScheme("happ:/x", "happ"))
		assertEquals(-1, indexOfScheme("xhapp", "happ"))

		assertTrue(looksLikeSchemeLink("vless://x"))
		assertFalse(looksLikeSchemeLink("1abc://x"))
		assertFalse(looksLikeSchemeLink("plain text"))
		assertFalse(hasPrefixAndMore("happ://", "happ://"))
		assertTrue(hasPrefixAndMore("HAPP://x", "happ://"))
		assertTrue("  V2RAYTUN://crypt/x".trimmedStartsWith("v2raytun://crypt/"))
		assertFalse((null as String?).trimmedStartsWith("x"))

		assertTrue(IncyLinks.isCryptLink("incy://crypt1/abc"))
		assertFalse(IncyLinks.isCryptLink("incy://add/x"))
		assertFalse(IncyLinks.isCryptLink(null))
		assertTrue(V2RayTunLinks.isCryptLink("V2RAYTUN://CRYPT/abc"))
		assertTrue(V2RayTunLinks.isImportLink("v2raytun://import/x"))
		assertFalse(V2RayTunLinks.isImportLink("v2raytun://crypt/x"))
	}

	@Test
	fun `an embedded link is cut out as it stands, decoded once or twice, and only from an http(s) url that carries more than the scheme`() {
		val plain = "https://site.example/r?link=happ://crypt3/Ab+c/d==&x=1"
		assertEquals("happ://crypt3/Ab+c/d==", HappLinks.extractEmbeddedHappLink(plain))
		assertEquals("happ://crypt/Zz", HappLinks.extractEmbeddedHappLink("https://x.example/?l=HAPP://crypt/Zz"))
		val once = "https://site.example/r?link=happ%3A%2F%2Fcrypt3%2FAbC"
		assertEquals("happ://crypt3/AbC", HappLinks.extractEmbeddedHappLink(once))
		val twice = "https://site.example/r?link=happ%253A%252F%252Fcrypt3%252FAbC"
		assertEquals("happ://crypt3/AbC", HappLinks.extractEmbeddedHappLink(twice))
		assertNull(HappLinks.extractEmbeddedHappLink("happ://crypt/abc"))
		assertNull(HappLinks.extractEmbeddedHappLink("ftp://x.example/?l=happ://crypt/a"))
		assertNull(HappLinks.extractEmbeddedHappLink("https://x.example/?l=happ://"))
		assertNull(HappLinks.extractEmbeddedHappLink("https://x.example/nothing"))
		assertNull(HappLinks.extractEmbeddedHappLink("  "))
		assertNull(HappLinks.extractEmbeddedHappLink(null))

		// INCY and v2rayTun links are taken only in the shapes their apps open.
		val incy = "https://x.example/open?u=incy://add/https%3A%2F%2Fsub.example%2Fs"
		assertEquals("incy://add/https://sub.example/s", IncyLinks.extractEmbeddedIncyLink(incy))
		assertNull(IncyLinks.extractEmbeddedIncyLink("https://x.example/?u=incy://settings/x"))
		val v2ray = "https://x.example/?u=v2raytun://import/https://sub.example/s"
		assertEquals(
			"v2raytun://import/https://sub.example/s",
			V2RayTunLinks.extractEmbeddedV2RayLink(v2ray)
		)
	}

	@Test
	fun `a wrapper gives up the link it carries, decoded as it needs, and an empty or foreign one nothing`() {
		val url = "https://sub.example/s"
		assertEquals(url, HappLinks.stripAddPrefix("happ://add/$url"))
		assertEquals(url, HappLinks.stripAddPrefix("HAPP://ADD/$url"))
		assertEquals(url, HappLinks.stripAddPrefix("happ://add/https%3A%2F%2Fsub.example%2Fs"))
		assertEquals(url, HappLinks.stripAddPrefix("happ://add/" + b64(url)))
		assertEquals(url, V2RayTunLinks.stripImportPrefix("v2raytun://import/$url"))
		// Around something else it gives that back as it stands.
		assertEquals("hello", HappLinks.stripAddPrefix("happ://add/hello"))
		assertNull(HappLinks.stripAddPrefix("happ://add/"))
		assertNull(HappLinks.stripAddPrefix("happ://add/   "))
		assertNull(HappLinks.stripAddPrefix("happ://crypt/x"))
		assertNull(HappLinks.stripAddPrefix(null))
	}
}
