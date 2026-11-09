package com.happwner.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Recognising a happ:// link, and saying accurately why one cannot be read. The scheme is matched
// without regard to case, because links travel through clients and messengers that change it.
class HappLinkRecognitionTest {

	// A URI scheme is case-insensitive by RFC 3986, and every reader here treats it that way:
	// isOpenableHappLink and extractEmbeddedHappLink use ignoreCase, as do the v2rayTun and INCY decryptors.
	@Test
	fun `happ links are recognized whatever the scheme case, and the payload keeps its case`() {
		for (link in listOf(
			"happ://crypt5/AAAA", "HAPP://CRYPT5/AAAA",
			"Happ://Crypt5/AAAA", "happ://CRYPT5/AAAA", "happ://crypt6/AAAA", "Happ://Crypt7/AAAA"
		)) {
			assertTrue("isOpenableHappLink disagrees for $link", HappLinks.isOpenableHappLink(link))
			assertTrue(
				"decryptHappLink refused to even parse $link",
				HappCrypto.decryptHappLink(link) !is HappCrypto.HappLinkResult.NotHappLink
			)
		}
		// A different scheme is still not one of ours.
		assertTrue(
			HappCrypto.decryptHappLink("https://example.com/crypt5/AAAA")
				is HappCrypto.HappLinkResult.NotHappLink
		)
		// Only the prefix is matched loosely; lowercasing the payload would corrupt every base64 link.
		val upper = HappCrypto.decryptHappLink("HAPP://CRYPT5/AbCdEfGh")
		val lower = HappCrypto.decryptHappLink("happ://crypt5/AbCdEfGh")
		assertEquals("the same payload must reach the decryptor either way", lower.javaClass, upper.javaClass)

		assertTrue(HappLinks.isOpenableHappLink("happ://add/https://sub.example.com/a"))
		assertTrue(HappLinks.isOpenableHappLink("  happ://add/https://sub.example.com/a\n"))
		assertFalse(HappLinks.isOpenableHappLink("happ://add"))
	}

	// Every failure names itself: a version this build has no keys for, or a crypt5 marker it does
	// not carry, is said as such - both go on to Happanion, which runs Happ's own library.
	@Test
	fun `a version or a marker this build has no keys for is named as such`() {
		for ((link, mode) in listOf("happ://crypt6/AAAA" to "crypt6", "HAPP://CRYPT12/AAAA" to "crypt12",
			"happ://crypt1/AAAA" to "crypt1")) {
			val expected = HappCrypto.HappLinkResult.Error(mode, "unknown version")
			assertEquals(expected, HappCrypto.decryptHappLink(link))
		}
		val marker = HappCrypto.decryptHappLink("happ://crypt5/" + "Zz".repeat(40))
		assertTrue("expected an Error, got $marker", marker is HappCrypto.HappLinkResult.Error)
		val reason = (marker as HappCrypto.HappLinkResult.Error).reason
		assertTrue(reason, reason.startsWith("unknown crypt5 marker"))
	}

	// "Send every link" must not touch the built-in keys, so it needs the link's mode without
	// decrypting for it.
	@Test
	fun `a link's mode matches what a decryption would report, in any case, and is null for what is no crypt link`() {
		// A payload that parses far enough to carry a mode but decrypts to nothing useful - the mode
		// has to agree either way.
		for ((prefix, expected) in listOf(
			"happ://crypt/" to "crypt",
			"happ://crypt2/" to "crypt2",
			"happ://crypt3/" to "crypt3",
			"happ://crypt4/" to "crypt4",
			"happ://crypt5/" to "crypt5",
			"happ://crypt6/" to "crypt6"
		)) {
			val link = prefix + "Zz".repeat(40)
			assertEquals("happLinkMode disagreed for $prefix", expected, HappLinks.happLinkMode(link))

			val viaDecrypt = when (val result = HappCrypto.decryptHappLink(link)) {
				is HappCrypto.HappLinkResult.Decrypted -> result.mode
				is HappCrypto.HappLinkResult.Error -> result.mode
				HappCrypto.HappLinkResult.NotHappLink -> null
			}
			assertEquals("the label would change for $prefix: $expected vs $viaDecrypt", expected, viaDecrypt)
		}
		assertEquals("crypt5", HappLinks.happLinkMode("HAPP://CRYPT5/AAAA"))
		assertEquals("crypt2", HappLinks.happLinkMode("Happ://Crypt2/AAAA"))
		// Leading and trailing space is trimmed, as decryptHappLink does.
		assertEquals("crypt", HappLinks.happLinkMode("  happ://crypt/AAAA  "))
		for (text in listOf(
			null, "", "   ",
			"https://example.com",
			"happ://add/https://example.com",     // a happ link, but not a crypt one
			"happ://crypt5",                      // no payload separator
			"happ://crypt6",                      // nor here
			"happ://cryptX/AAAA",                 // not a version number
			"v2raytun://crypt/AAAA",
			"incy://crypt1/AAAA"
		)) {
			assertNull("expected null for ${text?.take(30)}", HappLinks.happLinkMode(text))
		}
	}
}
