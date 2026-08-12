package com.happwner.crypto

import java.security.KeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.RSAPublicKeySpec
import javax.crypto.Cipher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// End-to-end cover for `v2raytun://crypt/` links, built with the real bundled keys rather than a
// fixture.
class V2RayTunCryptTest {

    private fun privateKey(ordinal: Int): RSAPrivateCrtKey {
        val m = V2RayTunCrypto::class.java
            .getDeclaredMethod("loadKey", Int::class.javaPrimitiveType)
            .apply { isAccessible = true }
        return m.invoke(V2RayTunCrypto, ordinal) as RSAPrivateCrtKey
    }

    private fun encrypt(ordinal: Int, plaintext: ByteArray): ByteArray {
        val priv = privateKey(ordinal)
        val pub = KeyFactory.getInstance("RSA")
            .generatePublic(RSAPublicKeySpec(priv.modulus, priv.publicExponent))
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, pub)
        val keySize = (priv.modulus.bitLength() + 7) / 8
        // PKCS#1 v1.5 spends 11 bytes on padding, which is what caps a block.
        val chunk = keySize - 11
        val out = java.io.ByteArrayOutputStream()
        var off = 0
        while (off < plaintext.size) {
            val n = minOf(chunk, plaintext.size - off)
            out.write(cipher.doFinal(plaintext, off, n))
            off += n
        }
        return out.toByteArray()
    }

    private fun link(ordinal: Int, plaintext: String): String =
        "v2raytun://crypt/" + java.util.Base64.getEncoder()
            .encodeToString(encrypt(ordinal, plaintext.toByteArray(Charsets.UTF_8)))

    private fun blockSize(ordinal: Int): Int = (privateKey(ordinal).modulus.bitLength() + 7) / 8

    // ------------------------------------------------------- the happy path ----

    @Test
    fun `a link made with any bundled key decrypts back to itself`() {
        val url = "https://example.com/sub?token=abcdef0123456789&name=node"
        for (ordinal in 0 until 3) {
            val r = V2RayTunCrypto.decryptCryptLink(link(ordinal, url))
            assertTrue("key #$ordinal returned $r", r is V2RayTunCrypto.Result.Decrypted)
            assertEquals("key #$ordinal", url, (r as V2RayTunCrypto.Result.Decrypted).plaintext)
        }
    }

    @Test
    fun `a plaintext spanning several RSA blocks is reassembled in order`() {
        // Long enough to need three blocks, and self-describing so a misordered
        // or dropped block cannot pass unnoticed.
        val chunk = blockSize(0) - 11
        val url = "https://example.com/?p=" + (0 until chunk * 3 / 8).joinToString("") { "%07d.".format(it) }
        val r = V2RayTunCrypto.decryptCryptLink(link(0, url.take(chunk * 2 + 50)))
        assertTrue("expected a decrypt, got $r", r is V2RayTunCrypto.Result.Decrypted)
        assertEquals(url.take(chunk * 2 + 50), (r as V2RayTunCrypto.Result.Decrypted).plaintext)
    }

    @Test
    fun `url-safe base64 and whitespace in the payload are accepted`() {
        val url = "https://example.com/sub?a=1&b=2"
        val raw = encrypt(0, url.toByteArray())
        val urlSafe = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
        val wrapped = urlSafe.chunked(64).joinToString("\n")
        for ((label, payload) in listOf("url-safe" to urlSafe, "url-safe wrapped" to wrapped)) {
            val r = V2RayTunCrypto.decryptCryptLink("v2raytun://crypt/$payload")
            assertTrue("$label returned $r", r is V2RayTunCrypto.Result.Decrypted)
            assertEquals(label, url, (r as V2RayTunCrypto.Result.Decrypted).plaintext)
        }
    }

    // ------------------------------------------------------------- refusals ----

    @Test
    fun `a link past the block cap is refused quickly instead of grinding`() {
        // Every block here is validly encrypted on purpose: zeroes fail PKCS#1 unpadding on block 0 and cost
        // nothing. Measured uncapped on a desktop: 300 blocks took 2.9 s, and the public key is derivable.
        val chunk = blockSize(0) - 11
        val oversized = ByteArray(chunk * 300) { 'a'.code.toByte() }
        val payload = java.util.Base64.getEncoder()
            .encodeToString(encrypt(0, oversized))

        val started = System.nanoTime()
        val r = V2RayTunCrypto.decryptCryptLink("v2raytun://crypt/$payload")
        val elapsedMs = (System.nanoTime() - started) / 1_000_000

        assertTrue("expected an error, got $r", r is V2RayTunCrypto.Result.Error)
        assertTrue(
            "the reason should name the cap, was ${(r as V2RayTunCrypto.Result.Error).reason}",
            r.reason.contains("RSA blocks")
        )
        // Uncapped this same input took seconds; the bound below is loose enough
        // for a slow machine and still nowhere near that.
        assertTrue("refusing took ${elapsedMs}ms, so it decrypted first", elapsedMs < 1_000)
    }

    @Test
    fun `a payload that is not a whole number of blocks is refused`() {
        val payload = java.util.Base64.getEncoder().encodeToString(ByteArray(blockSize(0) + 1))
        val r = V2RayTunCrypto.decryptCryptLink("v2raytun://crypt/$payload")
        assertTrue("expected an error, got $r", r is V2RayTunCrypto.Result.Error)
        assertTrue((r as V2RayTunCrypto.Result.Error).reason.contains("not a multiple"))
    }

    @Test
    fun `ciphertext no bundled key can open is refused`() {
        // One block of random bytes: PKCS#1 unpadding fails for every key.
        val payload = java.util.Base64.getEncoder()
            .encodeToString(ByteArray(blockSize(0)) { (it * 31 + 7).toByte() })
        val r = V2RayTunCrypto.decryptCryptLink("v2raytun://crypt/$payload")
        assertTrue("expected an error, got $r", r is V2RayTunCrypto.Result.Error)
    }

    @Test
    fun `plaintext that is not a scheme link is refused`() {
        // Decrypts cleanly with a real key, but is not a link - so it must not
        // be handed to the URL field as though it were one.
        val r = V2RayTunCrypto.decryptCryptLink(link(0, "just some text, not a link"))
        assertTrue("expected an error, got $r", r is V2RayTunCrypto.Result.Error)
    }

    @Test
    fun `non-crypt input is reported as such rather than as an error`() {
        for (s in listOf(null, "", "   ", "https://example.com", "v2raytun://import/abc")) {
            assertEquals(
                "input ${s?.take(24)}",
                V2RayTunCrypto.Result.NotCryptLink,
                V2RayTunCrypto.decryptCryptLink(s)
            )
        }
        assertTrue(
            V2RayTunCrypto.decryptCryptLink("v2raytun://crypt/") is V2RayTunCrypto.Result.Error
        )
    }

    @Test
    fun `the scheme match is case-insensitive`() {
        val url = "https://example.com/x"
        val l = link(0, url).replace("v2raytun://crypt/", "V2RayTun://CRYPT/")
        val r = V2RayTunCrypto.decryptCryptLink(l)
        assertTrue("expected a decrypt, got $r", r is V2RayTunCrypto.Result.Decrypted)
        assertEquals(url, (r as V2RayTunCrypto.Result.Decrypted).plaintext)
    }
}
