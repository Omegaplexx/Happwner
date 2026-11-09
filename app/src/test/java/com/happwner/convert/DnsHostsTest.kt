package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// A "domain:" hosts key is its name and every name under it; sing-box's hosts server matches whole
// names, so the name itself is carried - behind an exact key for it - and the rest is said.
class DnsHostsTest {
	private val node = """{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"p.example.com",
		"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
		"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"p.example.com"}}}"""

	private fun convert(hosts: String): SingBoxConverter.Result.Ok {
		val body = """{"outbounds":[$node],"dns":{"hosts":$hosts,"servers":["8.8.8.8"]}}"""
		return SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
	}

	private fun predefinedOf(result: SingBoxConverter.Result.Ok): JSONObject {
		val servers = result.config.getJSONObject("dns").getJSONArray("servers")
		return (0 until servers.length()).map { servers.getJSONObject(it) }
			.single { it.optString("type") == "hosts" }.getJSONObject("predefined")
	}

	@Test
	fun `a domain key carries its own name, the names under it said`() {
		val result = convert("""{"domain:example.test":"1.2.3.4"}""")
		assertEquals("1.2.3.4", predefinedOf(result).getJSONArray("example.test").getString(0))
		assertTrue("${result.notes}", result.notes.any { "is carried and the names under it" in it })
	}

	@Test
	fun `an exact key for the same name outranks the domain key`() {
		val result = convert("""{"domain:example.test":"1.2.3.4","full:example.test":"5.6.7.8"}""")
		assertEquals("5.6.7.8", predefinedOf(result).getJSONArray("example.test").getString(0))
		assertTrue("${result.notes}", result.notes.any { "keeps its own entry" in it })
	}
}
