package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// Xray reads a DNS server address as a URL: a fragment names nothing, and a plain transport is only
// its host and port. A bare address carrying URL syntax is a name Xray can never resolve.
class DnsAddressTest {
	private val proxy = """{"protocol":"vless","tag":"p","settings":{"vnext":[{"address":"a.example.com",
		"port":443,"users":[{"id":"u","encryption":"none"}]}]}}"""

	private fun body(server: String) =
		"""{"outbounds":[$proxy],"dns":{"servers":["$server","8.8.8.8"]}}"""

	private fun singBoxFirst(server: String): Pair<JSONObject, List<String>> {
		val out =
			SubscriptionConverter.convertWithStats(body(server), jsonToUri = false, xrayToSingBox = true)
		val servers = JSONObject(out.text).getJSONObject("dns").getJSONArray("servers")
		val first = (0 until servers.length()).map { servers.getJSONObject(it) }
			.first { it.optString("tag").startsWith("dns-") }
		return first to out.notes
	}

	private fun mihomo(server: String) = MihomoConverter.convert(body(server)) as MihomoConverter.Result.Ok

	@Test
	fun `a fragment is no part of the resolver`() {
		assertEquals("/dns-query", singBoxFirst("https://dns.example/dns-query#frag").first.getString("path"))
		assertEquals("1.1.1.1", singBoxFirst("tls://1.1.1.1#frag").first.getString("server"))
		val yaml = mihomo("https://dns.example/dns-query#frag").yaml
		assertTrue(yaml, "nameserver: [https://dns.example/dns-query, 8.8.8.8]" in yaml)
	}

	@Test
	fun `a plain transport is its host and port alone`() {
		val (server, _) = singBoxFirst("tcp://1.1.1.1:53/x?y=1")
		assertEquals("1.1.1.1", server.getString("server"))
		assertEquals(53, server.getInt("server_port"))
		assertTrue("nameserver: [tcp://1.1.1.1:53, 8.8.8.8]" in mihomo("tcp://1.1.1.1:53/x?y=1").yaml)
	}

	@Test
	fun `a bare address with URL syntax is left out, and said`() {
		val (server, notes) = singBoxFirst("1.1.1.1#frag")
		assertEquals("8.8.8.8", server.getString("server"))
		assertTrue("$notes", notes.any { "names no resolver Xray can use" in it })
		val result = mihomo("1.1.1.1#frag")
		assertTrue(result.yaml, "nameserver: [8.8.8.8]" in result.yaml)
		assertTrue("${result.notes}", result.notes.any { "names no resolver Xray can use" in it })
	}

	@Test
	fun `Xray's cleartext h2c resolver is named as one neither core has`() {
		val (_, notes) = singBoxFirst("h2c://dns.example/dns-query")
		assertTrue("$notes", notes.any { "cleartext HTTP/2, which this core has no resolver for" in it })
		val mihomoNotes = mihomo("h2c://dns.example/dns-query").notes
		assertTrue(
			"$mihomoNotes",
			mihomoNotes.any { "cleartext HTTP/2, which this core has no resolver for" in it }
		)
	}
}
