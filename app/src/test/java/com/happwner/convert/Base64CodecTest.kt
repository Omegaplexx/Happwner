package com.happwner.convert

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// The converter carries secrets through these codecs - REALITY keys, ML-KEM encapsulation keys,
// WireGuard keys, certificate pins - so "looks right" is not enough.
class Base64CodecTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    // ------------------------------------------------------- round trips ----

    @Test
    fun `encode matches java for every length up to a few blocks`() {
        val rnd = java.util.Random(20260802)
        for (len in 0..64) {
            val data = ByteArray(len).also { rnd.nextBytes(it) }
            assertEquals(
                "length $len",
                Base64.getEncoder().encodeToString(data),
                encodeBase64Std(data)
            )
        }
    }

    @Test
    fun `decode matches java across alphabets and padding`() {
        val rnd = java.util.Random(1234)
        for (len in 0..64) {
            val data = ByteArray(len).also { rnd.nextBytes(it) }

            val stdPadded = Base64.getEncoder().encodeToString(data)
            assertArrayEquals("std padded, len $len", data, decodeBase64(stdPadded, urlSafe = false, padded = true))

            val stdRaw = Base64.getEncoder().withoutPadding().encodeToString(data)
            assertArrayEquals("std raw, len $len", data, decodeBase64(stdRaw, urlSafe = false, padded = false))

            val urlPadded = Base64.getUrlEncoder().encodeToString(data)
            assertArrayEquals("url padded, len $len", data, decodeBase64(urlPadded, urlSafe = true, padded = true))

            val urlRaw = Base64.getUrlEncoder().withoutPadding().encodeToString(data)
            assertArrayEquals("url raw, len $len", data, decodeBase64(urlRaw, urlSafe = true, padded = false))

            // The permissive front door has to accept all four.
            for (form in listOf(stdPadded, stdRaw, urlPadded, urlRaw)) {
                assertArrayEquals("any, len $len, $form", data, decodeBase64Any(form))
            }
        }
    }

    // -------------------------------------------------- the distinctions ----

    @Test
    fun `padding is required or refused according to the flag`() {
        // "QQ==" is padded; "QQ" is raw.
        assertArrayEquals(bytes(0x41), decodeBase64("QQ==", urlSafe = false, padded = true))
        assertNull(decodeBase64("QQ==", urlSafe = false, padded = false))
        assertArrayEquals(bytes(0x41), decodeBase64("QQ", urlSafe = false, padded = false))
        assertNull(decodeBase64("QQ", urlSafe = false, padded = true))
    }

    @Test
    fun `the two alphabets do not accept each other's characters`() {
        // 0xFB 0xFF encodes as "+/8=" in standard and "-_8=" in URL-safe.
        val data = bytes(0xFB, 0xFF)
        assertEquals("+/8=", Base64.getEncoder().encodeToString(data))
        assertArrayEquals(data, decodeBase64("+/8=", urlSafe = false, padded = true))
        assertNull(decodeBase64("+/8=", urlSafe = true, padded = true))
        assertArrayEquals(data, decodeBase64("-_8=", urlSafe = true, padded = true))
        assertNull(decodeBase64("-_8=", urlSafe = false, padded = true))
    }

    @Test
    fun `malformed input is refused rather than truncated`() {
        for (bad in listOf("A", "QQ=", "====", "QQ===", "!!!!", "QQ Q=", "Q Q==")) {
            assertNull("padded should refuse $bad", decodeBase64(bad, urlSafe = false, padded = true))
        }
        // A single leftover character cannot carry a byte.
        assertNull(decodeBase64("QQQQQ", urlSafe = false, padded = false))
        // Non-zero bits past the end are data that would be silently lost.
        assertNull("stray low bits must not be dropped", decodeBase64("QR", urlSafe = false, padded = false))
    }

    // ------------------------------------------------------ real payloads ----

    @Test
    fun `a raw-URL REALITY key decodes to 32 bytes and nothing else does`() {
        val key = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
        assertEquals(43, key.length)
        val decoded = decodeBase64RawUrl(key)
        assertNotNull(decoded)
        assertEquals(32, decoded!!.size)
        // Not valid as any other combination: length 43 is not a multiple of
        // four, and the "-" is outside the standard alphabet.
        assertNull(decodeBase64(key, urlSafe = true, padded = true))
        assertNull(decodeBase64(key, urlSafe = false, padded = false))
    }

    @Test
    fun `a WireGuard key is standard base64 with padding`() {
        val key = "C2WjYAXsSBprVLiYYyVs7vW/mOhr21oYDkqkL8lkxQs="
        val decoded = decodeBase64(key, urlSafe = false, padded = true)
        assertNotNull(decoded)
        assertEquals(32, decoded!!.size)
        assertEquals(key, encodeBase64Std(decoded))
    }

    // ---------------------------------------------------------------- hex ----

    @Test
    fun `hex round-trips and refuses non-hex`() {
        val rnd = java.util.Random(99)
        for (len in 0..48) {
            val data = ByteArray(len).also { rnd.nextBytes(it) }
            val hex = toHex(data)
            assertEquals(len * 2, hex.length)
            assertTrue(hex.all { it in "0123456789abcdef" })
            assertArrayEquals(data, fromHex(hex))
            assertArrayEquals(data, fromHex(hex.uppercase()))
        }
        assertNull(fromHex("abc"))
        assertNull(fromHex("zz"))
        assertNull(fromHex("0x1f"))
    }

    // -------------------------------------------------------------- ports ----

    @Test
    fun `port parsing refuses everything outside 1-65535`() {
        assertEquals(443, parsePort(" 443 "))
        assertEquals(65535, parsePort("65535"))
        for (bad in listOf("0", "-1", "65536", "", "abc", "44 3", "443.0")) {
            assertNull("should refuse $bad", parsePort(bad))
        }
    }

    // ------------------------------------------------------------- ranges ----

    @Test
    fun `ranges keep negative bounds and reject junk`() {
        assertEquals("114", parseRangeString("114")!!.render())
        assertEquals("114-514", parseRangeString("114-514")!!.render())
        // A leading minus belongs to the first bound, not to the separator.
        assertEquals(-114, parseRangeString("-114-514")!!.from)
        assertEquals(514, parseRangeString("-114-514")!!.to)
        // Reversed bounds are normalised rather than refused.
        assertEquals("114-514", parseRangeString("514-114")!!.render())
        assertNull(parseRangeString("114-514-999"))
        assertNull(parseRangeString("a-b"))
        assertEquals("", XRange.UNSET.render())
        assertEquals("", XRange(0, 0, true).renderNonZero())
    }
}
