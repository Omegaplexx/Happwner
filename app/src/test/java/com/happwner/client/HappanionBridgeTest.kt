package com.happwner.client

import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class HappanionBridgeTest {
	private fun assets(vararg names: String) =
		JSONArray(names.map { JSONObject().put("name", it).put("browser_download_url", "https://d/$it") })

	private fun pick(abis: List<String>, vararg names: String) =
		HappanionBridge.apkAssetUrl(assets(*names), abis)

	@Test
	fun `the build is picked by the device's ABI in its order of preference, an ABI counts only at the end of the name, and only APKs count`() {
		val names = arrayOf("happanion-armeabi-v7a.apk", "happanion-arm64-v8a.apk")
		assertEquals("https://d/happanion-arm64-v8a.apk", pick(listOf("arm64-v8a", "armeabi-v7a"), *names))
		assertEquals("https://d/happanion-armeabi-v7a.apk", pick(listOf("armeabi-v7a"), *names))
		// A device no build names takes the universal one, then whatever there is.
		assertEquals("https://d/happanion.apk", pick(listOf("x86_64"), "happanion-arm64-v8a.apk", "happanion.apk"))
		// Many x86 devices run ARM code through a translator, so an ARM build still beats nothing.
		assertEquals("https://d/happanion-arm64-v8a.apk", pick(listOf("x86_64"), "happanion-arm64-v8a.apk"))

		val upper = pick(listOf("arm64-v8a"), "notes.txt", "HAPPANION-ARM64-V8A.APK")
		assertEquals("https://d/HAPPANION-ARM64-V8A.APK", upper)
		val mixed = pick(listOf("armeabi-v7a"), "happanion-arm64-v8a.Apk", "happanion-armeabi-v7a.Apk")
		assertEquals("https://d/happanion-armeabi-v7a.Apk", mixed)
		// Named mid-way, the ABI makes it a universal build, taken only when none names the device.
		assertEquals("https://d/happanion-armeabi-v7a.apk",
			pick(listOf("armeabi-v7a"), "happanion-arm64-v8a-debug.apk", "happanion-armeabi-v7a.apk"))
		assertNull(pick(listOf("arm64-v8a"), "notes.txt", "source.zip"))
		val noUrl = JSONArray().put(JSONObject().put("name", "happanion.apk"))
		assertNull(HappanionBridge.apkAssetUrl(noUrl, listOf("arm64-v8a")))
	}

	@Test
	fun `the built-in keys come first, and Happanion only when they fail`() = runBlocking {
		val fromKeys = HappCrypto.HappLinkResult.Decrypted("https://sub.example/keys", "crypt4")
		var asked = 0
		val happanion: suspend (String) -> String? = { asked++; "https://sub.example/happanion" }
		assertEquals(fromKeys, HappanionBridge.decryptWithFallback("l", { fromKeys }, happanion))
		assertEquals(0, asked)
		// Whatever the keys failed on: Happ's own library may still open it.
		for (error in listOf(
			HappCrypto.HappLinkResult.Error("crypt5", "unknown crypt5 marker: x"),
			HappCrypto.HappLinkResult.Error("crypt6", "unknown version"),
			HappCrypto.HappLinkResult.Error("crypt4", "BadPaddingException: ")
		)) {
			val result = HappanionBridge.decryptWithFallback("l", { error }, happanion)
			val expected = HappCrypto.HappLinkResult.Decrypted("https://sub.example/happanion", error.mode)
			assertEquals(expected, result)
		}
		assertEquals(3, asked)
	}

	@Test
	fun `Happanion failing too keeps the built-in reason, and a non-link never reaches it`() = runBlocking {
		val error = HappCrypto.HappLinkResult.Error("crypt3", "bad input")
		assertEquals(error, HappanionBridge.decryptWithFallback("l", { error }, { null }))
		var asked = false
		HappanionBridge.decryptWithFallback(
			"l", { HappCrypto.HappLinkResult.NotHappLink }, { asked = true; "x" }
		)
		assertFalse(asked)
	}
}
