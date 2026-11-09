package com.happwner.client

import com.happwner.text.toHex
import java.security.MessageDigest
import java.security.interfaces.RSAPrivateCrtKey
import org.junit.Assert.assertEquals
import org.junit.Test

// The bundled RSA keys pinned by their numbers. The round trips seal with the very key they open
// with, so only this catches a key whose text changed - by a slip or a careless re-encoding.
class HappKeysTest {

	private fun cryptKey(ordinal: Int): RSAPrivateCrtKey {
		val load = HappCrypto::class.java
			.getDeclaredMethod("loadCryptKey", Int::class.javaPrimitiveType)
		load.isAccessible = true
		return load.invoke(HappCrypto, ordinal) as RSAPrivateCrtKey
	}

	private fun crypt5Key(marker: String): RSAPrivateCrtKey {
		val load = HappCrypto::class.java.getDeclaredMethod("loadCrypt5Key", String::class.java)
		load.isAccessible = true
		return load.invoke(HappCrypto, marker) as RSAPrivateCrtKey
	}

	// A key's eight numbers as one hash: any change to them changes it, re-encoding them does not.
	private fun fingerprint(key: RSAPrivateCrtKey): String {
		val numbers = listOf(key.modulus, key.publicExponent, key.privateExponent, key.primeP,
			key.primeQ, key.primeExponentP, key.primeExponentQ, key.crtCoefficient)
		val text = numbers.joinToString(":") { it.toString(16) }
		return toHex(MessageDigest.getInstance("SHA-256").digest(text.toByteArray()))
	}

	@Test
	fun `each crypt to crypt4 key is the one its version was issued with`() {
		val issued = listOf(
			"5bbe3b1f2878cfb7c844e931f723cf4991ae506e80d2144774b9b03f957484ea",
			"1045ef31849ec35464d24a907cb5e7ab9fa5a4d5941a2a47e1d4878521c8811a",
			"0180d809cf23e3930fc3a274740b05e35a3befe67f30250b1e8358ad36529f82",
			"38153c418cf8cedf4de47134a7d6ec21100549eb9a88a5d7ccff05f4b516487b"
		)
		for (ordinal in 0..3) {
			assertEquals("crypt key $ordinal", issued[ordinal], fingerprint(cryptKey(ordinal)))
		}
	}

	@Test
	fun `the crypt5 keys are the ones their markers were issued with`() {
		val field = HappCrypto::class.java.getDeclaredField("CRYPT5_PKCS8_KEYS_B64")
		field.isAccessible = true
		val markers = (field.get(HappCrypto) as Map<*, *>).keys.map { it as String }.sorted()
		val all = markers.joinToString(",") { "$it=${fingerprint(crypt5Key(it))}" }
		val digest = toHex(MessageDigest.getInstance("SHA-256").digest(all.toByteArray()))
		assertEquals("8687d40fdef36042d1efab52cdac724402cbb6f18b278eb869d77d0a809c04b2", digest)
	}
}
