package com.happwner.client

import com.happwner.text.toHex
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertEquals
import org.junit.Test

// An INCY crypt1 link end to end, sealed here with the very key the decryptor derives, so each
// refusal is reached with the reason the person is shown.
class IncyCryptoTest {

	private val key: SecretKeySpec by lazy {
		val method = IncyCrypto::class.java.getDeclaredMethod("deriveKey")
		method.isAccessible = true
		checkNotNull(method.invoke(IncyCrypto)) as SecretKeySpec
	}

	private fun payloadOf(plain: ByteArray): ByteArray {
		val iv = ByteArray(12) { it.toByte() }
		val cipher = Cipher.getInstance("AES/GCM/NoPadding")
		cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
		return iv + cipher.doFinal(plain)
	}

	private fun linkOf(payload: ByteArray) =
		"incy://crypt1/" + Base64.getUrlEncoder().withoutPadding().encodeToString(payload)

	private fun sealed(json: String) = linkOf(payloadOf(json.toByteArray()))

	private fun reason(link: String?) =
		(IncyCrypto.decryptCryptLink(link) as CryptLinkResult.Error).reason

	// The bundled keymat yields the key the published INCY clients use: a slip in either blob would
	// otherwise show only as every link failing to open.
	@Test
	fun `the derived key is the one the INCY clients use`() {
		assertEquals(32, key.encoded.size)
		assertEquals("AES", key.algorithm)
		val published = "b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c"
		assertEquals(published, toHex(MessageDigest.getInstance("SHA-256").digest(key.encoded)))
	}

	@Test
	fun `a sealed link opens to its url, however its prefix is written, and what is no crypt link is left alone`() {
		val link = sealed("""{"url":" https://sub.example/s ","n":"Mine"}""")
		val opened = CryptLinkResult.Decrypted("https://sub.example/s")
		assertEquals(opened, IncyCrypto.decryptCryptLink(link))
		val upper = "INCY://CRYPT1/" + link.substringAfter("crypt1/")
		assertEquals(opened, IncyCrypto.decryptCryptLink(upper))
		assertEquals(opened, IncyCrypto.decryptCryptLink(" $link/ "))
		for (other in listOf(null, "", "https://sub.example/s", "incy://add/https://sub.example/s")) {
			assertEquals(CryptLinkResult.NotCryptLink, IncyCrypto.decryptCryptLink(other))
		}
	}

	@Test
	fun `a later version, a broken payload and a plaintext that is no subscription are each refused with their reason`() {
		assertEquals(
			"unsupported INCY scheme version (only crypt1 is implemented)",
			reason("incy://crypt2/AAAA")
		)
		assertEquals("empty payload", reason("incy://crypt1/"))
		assertEquals("empty payload", reason("incy://crypt1///"))
		assertEquals("payload is not valid base64url", reason("incy://crypt1/A"))
		assertEquals("payload too short: 20B, need more than 28B", reason(linkOf(ByteArray(20))))
		val tampered = payloadOf("""{"url":"https://sub.example/s"}""".toByteArray())
		tampered[tampered.size - 1] = (tampered.last().toInt() xor 1).toByte()
		assertEquals("authentication failed (wrong key or tampered payload)", reason(linkOf(tampered)))

		val notUtf8 = byteArrayOf(0xC3.toByte(), 0x28)
		assertEquals("plaintext is not valid UTF-8", reason(linkOf(payloadOf(notUtf8))))
		assertEquals("malformed plaintext", reason(sealed("not json")))
		assertEquals("malformed plaintext", reason(sealed("[".repeat(300) + "]".repeat(300))))
		assertEquals("missing url field", reason(sealed("""{"n":"Mine"}""")))
		assertEquals("missing url field", reason(sealed("""{"url":"   "}""")))
	}
}
