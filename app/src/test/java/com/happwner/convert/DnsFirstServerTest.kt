package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// With disableFallback, or every server out of Xray's order, Xray asks its first server alone about a
// name no domains match - whatever that server is narrowed to. Both passes make it the default.
class DnsFirstServerTest {
	private val proxy = """{"protocol":"vless","tag":"p","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"u","encryption":"none"}]}]}}"""

	private fun singBox(dns: String) = SubscriptionConverter.convertWithStats(
		"""{"outbounds":[$proxy],"dns":$dns}""", jsonToUri = false, xrayToSingBox = true
	)

	private fun mihomo(dns: String) =
		MihomoConverter.convert("""{"outbounds":[$proxy],"dns":$dns}""") as MihomoConverter.Result.Ok

	private fun tagOf(text: String, server: String): String {
		val servers = JSONObject(text).getJSONObject("dns").getJSONArray("servers")
		return (0 until servers.length()).map { servers.getJSONObject(it) }
			.first { it.optString("server") == server }.getString("tag")
	}

	@Test
	fun `with disableFallback the first server is the default, narrowed or not`() {
		val dns = """{"disableFallback":true,"servers":[
			{"address":"https://dns.adguard.com/dns-query","domains":["domain:example.cn"]},"8.8.8.8"]}"""
		val out = singBox(dns)
		val final = JSONObject(out.text).getJSONObject("dns").getString("final")
		assertEquals(tagOf(out.text, "dns.adguard.com"), final)
		assertFalse("${out.notes}", out.notes.any { "would have asked next" in it })
		assertTrue(mihomo(dns).yaml, "nameserver: [https://dns.adguard.com/dns-query]" in mihomo(dns).yaml)
	}

	@Test
	fun `every server out of the order leaves the first alone`() {
		val dns = """{"servers":[{"address":"1.1.1.1","skipFallback":true,"domains":["domain:a.test"]},
			{"address":"8.8.8.8","skipFallback":true}]}"""
		val out = singBox(dns)
		assertEquals(tagOf(out.text, "1.1.1.1"), JSONObject(out.text).getJSONObject("dns").getString("final"))
		assertTrue(mihomo(dns).yaml, "nameserver: [1.1.1.1]" in mihomo(dns).yaml)
	}

	@Test
	fun `a first server that cannot be the default is named`() {
		val dns = """{"disableFallback":true,"servers":["fakedns","8.8.8.8"]}"""
		val said = "is the only one Xray asks about a name no domains match"
		assertTrue("${singBox(dns).notes}", singBox(dns).notes.any { said in it })
		assertTrue("${mihomo(dns).notes}", mihomo(dns).notes.any { said in it })
	}
}
