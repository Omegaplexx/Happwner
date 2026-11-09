package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Xray passes over a DNS server whose answer holds none of its expectIPs and asks the next one; the
// sing-box document does the same with a rule skipped on such an answer, the next server the default.
class DnsAnswerFilterTest {
	private val node = """{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"p.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
		"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"p.example.com"}}}"""

	private fun convert(servers: String, fakedns: String = ""): SingBoxConverter.Result.Ok {
		val body = """{"outbounds":[$node],$fakedns"dns":{"servers":$servers}}"""
		return SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
	}

	private fun dnsOf(result: SingBoxConverter.Result.Ok): JSONObject = result.config.getJSONObject("dns")

	@Test
	fun `a filtered first server is asked first and passed over, the next one the default`() {
		val result = convert("""[{"address":"94.140.14.14","expectIPs":["geoip:cn"]},"8.8.8.8"]""")
		val dns = dnsOf(result)
		val servers = dns.getJSONArray("servers")
		val tagOf = { address: String ->
			(0 until servers.length()).map { servers.getJSONObject(it) }
				.first { it.optString("server") == address }.getString("tag")
		}
		val rules = dns.getJSONArray("rules")
		val filtered = (0 until rules.length()).map { rules.getJSONObject(it) }
			.single { it.optString("server") == tagOf("94.140.14.14") }
		assertEquals("geoip-cn", filtered.getJSONArray("rule_set").getString(0))
		assertEquals(tagOf("8.8.8.8"), dns.getString("final"))
		val sets = result.config.getJSONObject("route").getJSONArray("rule_set")
		assertTrue((0 until sets.length()).any { sets.getJSONObject(it).getString("tag") == "geoip-cn" })
		assertTrue("${result.notes}", result.notes.none { "answer filter" in it })
	}

	@Test
	fun `beside a fakeip server the filter is left out, and the reason named`() {
		val servers = """[{"address":"94.140.14.14","expectIPs":["geoip:cn"]},"8.8.8.8","fakedns"]"""
		val result = convert(servers, fakedns = """"fakedns":[{"ipPool":"198.18.0.0/15"}],""")
		val rules = dnsOf(result).getJSONArray("rules")
		assertTrue((0 until rules.length()).none { rules.getJSONObject(it).has("rule_set") &&
			rules.getJSONObject(it).getJSONArray("rule_set").toString().contains("geoip") })
		assertTrue("${result.notes}", result.notes.any { "1.14 core refuses it" in it })
	}

	@Test
	fun `mihomo asks the filtered server first and falls back on another country's answer`() {
		val body = """{"outbounds":[$node],"dns":{"servers":[
			{"address":"94.140.14.14","expectIPs":["geoip:cn"]},"8.8.8.8"]}}"""
		val yaml = (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).yaml
		val dns = yaml.substringAfter("dns:").substringBefore("proxies:")
		val nameserver = dns.substringAfter("nameserver:").substringBefore("\n")
		assertTrue(dns, "94.140.14.14" in nameserver && "8.8.8.8" !in nameserver)
		assertTrue(dns, "8.8.8.8" in dns.substringAfter("fallback:").substringBefore("\n"))
		assertTrue(dns, "geoip-code: CN" in dns)
	}

	@Test
	fun `a second country's filter behind the leading one is named for what it is`() {
		val body = """{"outbounds":[$node],"dns":{"servers":[
			{"address":"94.140.14.14","expectIPs":["geoip:cn"]},
			{"address":"9.9.9.9","expectIPs":["geoip:us"]},"8.8.8.8"]}}"""
		val result = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
		assertTrue(result.yaml, "geoip-code: CN" in result.yaml)
		val note = result.notes.single { "9.9.9.9" in it }
		assertTrue(note, "takes only the country leading Xray's order" in note)
		assertFalse(note, "answers every name" in note)
	}

	// With disableFallback Xray moves on from no server to another: a name no domains match goes to
	// its first server alone, so no pass may hand a failed answer to the next one.
	@Test
	fun `no answer filter moves on under disableFallback, in either pass`() {
		val body = """{"outbounds":[$node],"dns":{"disableFallback":true,"servers":[
			{"address":"94.140.14.14","expectIPs":["geoip:cn"]},"8.8.8.8"]}}"""
		val singBox = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true)
		assertFalse(singBox.text, "geoip-cn" in singBox.text)
		val firstServer = "returns nothing for an answer that fails it"
		assertTrue("${singBox.notes}", singBox.notes.any { firstServer in it })
		val mihomo = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
		assertFalse(mihomo.yaml, "fallback-filter" in mihomo.yaml)
		assertTrue("${mihomo.notes}", mihomo.notes.any { firstServer in it })
	}

	// Xray now reads expectedIPs first and still takes expectIPs, each as a StringList: an array or
	// one comma-separated string. Both passes read them through one reader.
	@Test
	fun `expectedIPs as a bare string carries in both passes`() {
		val body = """{"outbounds":[$node],"dns":{"servers":[
			{"address":"94.140.14.14","expectedIPs":"geoip:cn"},"8.8.8.8"]}}"""
		val singBox = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true)
		assertTrue(singBox.text, "geoip-cn" in singBox.text)
		val mihomo = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
		assertTrue(mihomo.yaml, "geoip-code: CN" in mihomo.yaml)
	}

	// finalQuery ends Xray's list at its server: a failed answer there is nothing, and none past it
	// is ever asked.
	@Test
	fun `finalQuery stops the filter and ends the fallback`() {
		val stopping = """{"outbounds":[$node],"dns":{"servers":[
			{"address":"94.140.14.14","expectIPs":["geoip:cn"],"finalQuery":true},"8.8.8.8"]}}"""
		val singBox =
			SubscriptionConverter.convertWithStats(stopping, jsonToUri = false, xrayToSingBox = true)
		assertFalse(singBox.text, "geoip-cn" in singBox.text)
		assertTrue("${singBox.notes}", singBox.notes.any { "with finalQuery" in it })
		val ending = """{"outbounds":[$node],"dns":{"servers":[
			{"address":"94.140.14.14","expectIPs":["geoip:cn"]},{"address":"1.1.1.1","finalQuery":true},
			"8.8.8.8"]}}"""
		val yaml = (MihomoConverter.convert(ending) as MihomoConverter.Result.Ok).yaml
		assertTrue(yaml, "fallback: [1.1.1.1]" in yaml)
	}

	@Test
	fun `a filter that could never decide is dropped, the reason given`() {
		// Alone it has no server to pass names on to; behind one answering every name it is never asked.
		val alone = convert("""[{"address":"8.8.8.8","expectIPs":["10.0.0.0/8"]}]""")
		assertTrue(alone.notes.toString(), alone.notes.any { it.contains("no server comes after it") })
		val behind = convert("""["1.1.1.1",{"address":"8.8.8.8","expectIPs":["10.0.0.0/8"]}]""")
		assertTrue(behind.notes.toString(), behind.notes.any { it.contains("answers every name") })
		for (result in listOf(alone, behind)) assertEquals(0, dnsOf(result).getJSONArray("rules").length())
	}

	@Test
	fun `a fakedns holding no pool leaves every name to the servers`() {
		val servers = dnsOf(convert("""["8.8.8.8"]""", fakedns = "\"fakedns\":true,")).getJSONArray("servers")
		val types = (0 until servers.length()).map { servers.getJSONObject(it).optString("type") }
		assertTrue(types.toString(), "fakeip" !in types)
	}

	@Test
	fun `a fakedns written as one pool is read as the list of one, either family`() {
		// Xray takes the pool alone or in a list; an IPv6 pool lands in the IPv6 range.
		for ((pool, field) in listOf("198.18.0.0/15" to "inet4_range", "fc00::/18" to "inet6_range")) {
			val fakedns = """"fakedns":{"ipPool":"$pool","poolSize":65535},"""
			val servers = dnsOf(convert("""["fakedns","8.8.8.8"]""", fakedns)).getJSONArray("servers")
			val fake = (0 until servers.length()).map { servers.getJSONObject(it) }
				.single { it.optString("type") == "fakeip" }
			assertEquals(fake.toString(), pool, fake.getString(field))
		}
	}
}
