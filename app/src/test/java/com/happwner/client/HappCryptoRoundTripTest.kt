package com.happwner.client

import java.security.KeyFactory
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.RSAPublicKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// A link built the way Happ builds it comes back whole: crypt to crypt4 as RSA/PKCS1 blocks under
// that version's key, crypt5 as ChaCha20-Poly1305 under a key wrapped for its marker, both layouts.
class HappCryptoRoundTripTest {
	private val modes = listOf("crypt", "crypt2", "crypt3", "crypt4")

	private fun key(ordinal: Int): RSAPrivateCrtKey {
		val load = HappCrypto::class.java.getDeclaredMethod("loadCryptKey", Int::class.javaPrimitiveType)
		load.isAccessible = true
		return load.invoke(HappCrypto, ordinal) as RSAPrivateCrtKey
	}

	private fun encrypt(plain: String, key: RSAPrivateCrtKey): String = encryptBytes(plain.toByteArray(), key)

	private fun encryptBytes(bytes: ByteArray, key: RSAPrivateCrtKey): String {
		val spec = RSAPublicKeySpec(key.modulus, key.publicExponent)
		val public = KeyFactory.getInstance("RSA").generatePublic(spec)
		val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding").apply { init(Cipher.ENCRYPT_MODE, public) }
		val block = (key.modulus.bitLength() + 7) / 8 - 11
		val out = (bytes.indices step block).flatMap { start ->
			cipher.doFinal(bytes, start, minOf(block, bytes.size - start)).toList()
		}
		return Base64.getEncoder().encodeToString(out.toByteArray())
	}

	@Test
	fun `every rsa version decrypts a link encrypted under its key, over several blocks, and no other version's`() {
		val url = "https://sub.example.com/" + "p".repeat(400) + "?token=abc"
		for ((ordinal, mode) in modes.withIndex()) {
			val link = "happ://$mode/" + encrypt(url, key(ordinal))
			assertEquals(HappCrypto.HappLinkResult.Decrypted(url, mode), HappCrypto.decryptHappLink(link))
		}
		assertNotEquals(key(1).modulus, key(2).modulus)
		val link = "happ://crypt3/" + encrypt("https://sub.example.com/x", key(1))
		assertTrue(HappCrypto.decryptHappLink(link) is HappCrypto.HappLinkResult.Error)
	}

	private fun marker(name: String): RSAPrivateCrtKey {
		val load = HappCrypto::class.java.getDeclaredMethod("loadCrypt5Key", String::class.java)
		load.isAccessible = true
		return load.invoke(HappCrypto, name) as RSAPrivateCrtKey
	}

	@Suppress("UNCHECKED_CAST")
	private fun markers(): List<String> {
		val field = HappCrypto::class.java.getDeclaredField("CRYPT5_PKCS8_KEYS_B64")
		field.isAccessible = true
		return (field.get(null) as Map<String, String>).keys.toList()
	}

	// Adjacent characters swapped in pairs, and the halves of each 4-character block swapped: both
	// undo themselves, so building a link runs them the same way reading does.
	private fun swapPairs(s: String) = s.chunked(2).joinToString("") { it.reversed() }
	private fun blockPairSwap(s: String) =
		s.chunked(4).joinToString("") { if (it.length == 4) it.substring(2) + it.substring(0, 2) else it }

	private fun crypt5Link(
		url: String,
		marker: String,
		salted: Boolean,
		tag: String = "tg"
	): String {
		val random = SecureRandom()
		val wrapped = ByteArray(32).also { random.nextBytes(it) }
		val salt = "s4ltS4Lt"
		val key = if (salted) {
			ByteArray(32) { wrapped[it].toInt().xor(salt[it % 8].code).toByte() }
		} else {
			wrapped
		}
		val nonce = "n0nce-12char"
		val chacha = Cipher.getInstance("ChaCha20-Poly1305")
		chacha.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce.toByteArray()))
		val inner = swapPairs(Base64.getEncoder().encodeToString(url.toByteArray()))
		val sealed = chacha.doFinal(inner.toByteArray(Charsets.ISO_8859_1))
		val segment = Base64.getEncoder().encodeToString(sealed)
		val keyText = swapPairs(Base64.getEncoder().encodeToString(wrapped))
		val rsa = encryptBytes(keyText.toByteArray(Charsets.ISO_8859_1), marker(marker))
		val body = nonce + (if (salted) tag + salt else "") + segment.length + "x" + segment + rsa
		return "happ://crypt5/" + blockPairSwap(marker.substring(0, 4) + body + marker.substring(4))
	}

	@Test
	fun `crypt5 decrypts a link built for its marker in both layouts, and says why when neither reads the body`() {
		val url = "https://sub.example.com/" + "q".repeat(300) + "?id=5"
		val names = markers()
		assertTrue("expected crypt5 markers in the build, got $names", names.size >= 3)
		for (name in listOf(names.first(), names[names.size / 2], names.last())) {
			for (salted in listOf(false, true)) {
				val result = HappCrypto.decryptHappLink(crypt5Link(url, name, salted))
				val expected = HappCrypto.HappLinkResult.Decrypted(url, "crypt5")
				assertEquals("marker $name, salted $salted", expected, result)
			}
		}
		// body[12] picks the layout tried first; a digit there sends a salted link down the legacy one
		// first, which has to give way to the salted reading.
		val digit = "https://sub.example.com/?id=7"
		val link = crypt5Link(digit, names.first(), salted = true, tag = "7g")
		assertEquals(HappCrypto.HappLinkResult.Decrypted(digit, "crypt5"), HappCrypto.decryptHappLink(link))
		// When neither layout reads the body, the second one's reason is the one given.
		val body = "n0nce-12char7gs4ltS4Ltzzzz"
		val unreadable = "happ://crypt5/" + blockPairSwap(names.first().substring(0, 4) + body + names.first().substring(4))
		assertEquals(
			HappCrypto.HappLinkResult.Error("crypt5", "crypt5 segment length missing"),
			HappCrypto.decryptHappLink(unreadable)
		)
	}
}
