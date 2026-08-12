package com.happwner.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Recognising a happ:// link, and saying accurately why one cannot be read. The scheme is matched
// without regard to case, because links travel through clients and messengers that change it.
class HappLinkRecognitionTest {

    // ------------------------------------------------ scheme case handling ----

    // A URI scheme is case-insensitive by RFC 3986, and almost everything here already treated it
    // that way: isOpenableHappLink and extractEmbeddedHappLink use ignoreCase, as do the v2rayTun
    // and INCY decryptors.
    @Test
    fun `happ links are recognised whatever the scheme case`() {
        for (link in listOf(
            "happ://crypt5/AAAA", "HAPP://CRYPT5/AAAA",
            "Happ://Crypt5/AAAA", "happ://CRYPT5/AAAA"
        )) {
            assertTrue(
                "isOpenableHappLink disagrees for $link",
                HappCrypto.isOpenableHappLink(link)
            )
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
    }
    @Test
    fun `the payload keeps its case because it is base64`() {
        // Only the prefix is matched loosely; lowercasing the payload would
        // corrupt every base64 link.
        val upper = HappCrypto.decryptHappLink("HAPP://CRYPT5/AbCdEfGh")
        val lower = HappCrypto.decryptHappLink("happ://crypt5/AbCdEfGh")
        assertEquals(
            "the same payload must reach the decryptor either way",
            lower.javaClass, upper.javaClass
        )
    }
    // ------------------------- the one failure the Happanion bridge can fix ----

    // MainActivity falls back to Happanion for exactly one failure: a crypt5 link whose marker
    // names a key this build does not carry.
    @Test
    fun `an unknown crypt5 marker is flagged not just described`() {
        // A well-formed crypt5 link whose marker is not in the table. The
        // payload only has to survive the shuffle and reach the marker lookup.
        val r = HappCrypto.decryptHappLink("happ://crypt5/" + "Zz".repeat(40))
        assertTrue("expected an Error, got $r", r is HappCrypto.HappLinkResult.Error)
        val err = r as HappCrypto.HappLinkResult.Error
        assertTrue(
            "the marker failure must be flagged, reason was ${err.reason}",
            err.unknownCrypt5Marker
        )
        assertEquals("crypt5", err.mode)
    }
    @Test
    fun `other failures are not flagged as a missing marker`() {
        // Too short to hold a marker at all: still an error, but not the one
        // Happanion could resolve, so routing it there would only add a delay.
        val short = HappCrypto.decryptHappLink("happ://crypt5/AA")
        assertTrue("expected an Error, got $short", short is HappCrypto.HappLinkResult.Error)
        assertFalse(
            "a malformed payload must not be mistaken for a missing key",
            (short as HappCrypto.HappLinkResult.Error).unknownCrypt5Marker
        )
        // And a mode that has no marker concept at all.
        val other = HappCrypto.decryptHappLink("happ://crypt/!!!!")
        if (other is HappCrypto.HappLinkResult.Error) {
            assertFalse(other.unknownCrypt5Marker)
        }
    }
    // ----------------------------------- the mode, without doing the work ----

    // Force-Happanion must not touch the bundled keys, so it needs the link's mode without
    // decrypting for it.
    @Test
    fun `happ link mode matches what a decryption would report`() {
        // A payload that parses far enough to carry a mode but decrypts to
        // nothing useful - the mode has to agree either way.
        for ((prefix, expected) in listOf(
            "happ://crypt/" to "crypt",
            "happ://crypt2/" to "crypt2",
            "happ://crypt3/" to "crypt3",
            "happ://crypt4/" to "crypt4",
            "happ://crypt5/" to "crypt5"
        )) {
            val link = prefix + "Zz".repeat(40)
            assertEquals("happLinkMode disagreed for $prefix", expected, HappCrypto.happLinkMode(link))

            val viaDecrypt = when (val r = HappCrypto.decryptHappLink(link)) {
                is HappCrypto.HappLinkResult.Decrypted -> r.mode
                is HappCrypto.HappLinkResult.Error -> r.mode
                HappCrypto.HappLinkResult.NotHappLink -> null
            }
            assertEquals(
                "the label would change for $prefix: $expected vs $viaDecrypt",
                expected, viaDecrypt
            )
        }
    }
    @Test
    fun `happ link mode ignores scheme case like everything else`() {
        assertEquals("crypt5", HappCrypto.happLinkMode("HAPP://CRYPT5/AAAA"))
        assertEquals("crypt2", HappCrypto.happLinkMode("Happ://Crypt2/AAAA"))
        // Leading and trailing space is trimmed, as decryptHappLink does.
        assertEquals("crypt", HappCrypto.happLinkMode("  happ://crypt/AAAA  "))
    }
    @Test
    fun `happ link mode is null for anything that is not a crypt link`() {
        for (s in listOf(
            null, "", "   ",
            "https://example.com",
            "happ://add/https://example.com",     // a happ link, but not a crypt one
            "happ://crypt5",                      // no payload separator
            "v2raytun://crypt/AAAA",
            "incy://crypt1/AAAA"
        )) {
            assertNull("expected null for ${s?.take(30)}", HappCrypto.happLinkMode(s))
        }
    }
}
