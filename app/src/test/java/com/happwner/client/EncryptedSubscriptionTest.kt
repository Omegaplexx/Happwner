package com.happwner.client

import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertEquals
import org.junit.Test

// A subscription body a server sealed with a bundled key - the key named in the address, the tag in
// the Encrypt-Tag header - through every way a response can pass as it came, open or fail.
class EncryptedSubscriptionTest {

	private val keys: Map<String, ByteArray> by lazy {
		val field = HappCrypto::class.java.getDeclaredField("KEYS")
		field.isAccessible = true
		(field.get(HappCrypto) as Map<*, *>).entries.associate { (name, key) ->
			name as String to key as ByteArray
		}
	}

	private val url = "https://sub.example/s?key=key01"

	// Sealed as the server seals it: AES-GCM under the fixed IV, the tag sent apart from the body.
	private fun sealed(keyName: String, text: String): Pair<String, String> {
		val cipher = Cipher.getInstance("AES/GCM/NoPadding")
		val iv = GCMParameterSpec(128, ByteArray(12) { 0x6b })
		cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keys.getValue(keyName), "AES"), iv)
		val out = cipher.doFinal(text.toByteArray())
		val body = out.copyOfRange(0, out.size - 16)
		val tag = out.copyOfRange(out.size - 16, out.size)
		return Base64.getEncoder().encodeToString(body) to Base64.getEncoder().encodeToString(tag)
	}

	private fun headers(tag: String) = mapOf("encrypt-tag" to listOf(tag))

	@Test
	fun `every bundled key is an AES-128 key that opens what it sealed`() {
		for (name in keys.keys) {
			assertEquals(name, 16, keys.getValue(name).size)
			val text = "vless://$name@h.example:443"
			val (body, tag) = sealed(name, text)
			val result = HappCrypto.process("https://sub.example/s?key=$name", body, headers(tag))
			assertEquals(HappCrypto.Result.Success(text), result)
			assertEquals(text, HappCrypto.plaintextOf(result, body))
		}
	}

	@Test
	fun `a response without a known key or a tag passes as it came`() {
		val (body, tag) = sealed("key01", "vless://a@h.example:443")
		val passed = HappCrypto.Result.NotEncrypted
		assertEquals(passed, HappCrypto.process("https://sub.example/s", body, headers(tag)))
		val unknown = "https://sub.example/s?key=key99"
		assertEquals(passed, HappCrypto.process(unknown, body, headers(tag)))
		assertEquals(passed, HappCrypto.process(null, body, headers(tag)))
		assertEquals(passed, HappCrypto.process(url, body, null))
		assertEquals(passed, HappCrypto.process(url, body, mapOf("Encrypt-Tag" to listOf(""))))
		assertEquals("raw", HappCrypto.plaintextOf(passed, "raw"))
	}

	@Test
	fun `an empty or undecodable response fails with its reason and keeps its body`() {
		val (body, tag) = sealed("key01", "vless://a@h.example:443")
		fun failed(reason: String, kept: String) = HappCrypto.Result.Failed("key01", reason, kept)
		assertEquals(failed("empty body", ""), HappCrypto.process(url, "", headers(tag)))
		assertEquals(failed("empty body", ""), HappCrypto.process(url, null, headers(tag)))
		assertEquals(failed("ciphertext is empty after base64 decode", "   "),
			HappCrypto.process(url, "   ", headers(tag)))
		val broken = HappCrypto.process(url, "A", headers(tag))
		assertEquals(failed("body is not valid base64", "A"), broken)
		assertEquals(failed("Encrypt-Tag is not valid base64", body),
			HappCrypto.process(url, body, headers("A")))
		val shortTag = Base64.getEncoder().encodeToString(ByteArray(8))
		val result = HappCrypto.process(url, body, headers(shortTag))
		assertEquals(failed("Encrypt-Tag must be 16 bytes, got 8", body), result)
		assertEquals(body, HappCrypto.plaintextOf(result, "raw"))
	}

	@Test
	fun `a tampered response or the wrong key fails authentication`() {
		val (body, tag) = sealed("key01", "vless://a@h.example:443")
		val bytes = Base64.getDecoder().decode(body)
		bytes[0] = (bytes[0].toInt() xor 1).toByte()
		val tampered = Base64.getEncoder().encodeToString(bytes)
		assertEquals(HappCrypto.Result.Failed("key01", "AEADBadTagException", tampered),
			HappCrypto.process(url, tampered, headers(tag)))
		assertEquals(HappCrypto.Result.Failed("key02", "AEADBadTagException", body),
			HappCrypto.process("https://sub.example/s?key=key02", body, headers(tag)))
	}
}
