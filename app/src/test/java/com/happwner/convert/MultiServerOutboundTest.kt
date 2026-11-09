package com.happwner.convert

import java.net.URLDecoder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// An outbound may name several servers, and every one of them is a node somebody paid for. A pass
// that renders one link per outbound hands back a shorter list than the subscription was given.
class MultiServerOutboundTest {

	private fun links(body: String): List<String> =
		SubscriptionConverter.convert(body.trimIndent().replace("\n", " "), jsonToUri = true).trim().lines()

	private fun name(link: String) = URLDecoder.decode(link.substringAfter('#', ""), "UTF-8")

	@Test
	fun `every server of a hysteria2 outbound becomes its own link, with its own credentials`() {
		val out = links(
			"""{"remarks":"DE","outbounds":[{"protocol":"hysteria2","tag":"proxy","settings":{"servers":[
               {"address":"a.example.com","port":443,"password":"pw1","ports":"1000-2000"},
               {"address":"b.example.com","port":8443,"password":"pw2"}]}}]}"""
		)
		assertEquals(2, out.size)
		assertTrue(out[0], out[0].startsWith("hysteria2://pw1@a.example.com:443"))
		assertTrue("the first server keeps its own port range: ${out[0]}", out[0].contains("mport=1000-2000"))
		assertTrue(out[1], out[1].startsWith("hysteria2://pw2@b.example.com:8443"))
		assertTrue("the second server has no range of its own: ${out[1]}", !out[1].contains("mport="))
		for (link in out) assertEquals("DE", name(link))
	}

	@Test
	fun `every vnext entry and every user of one becomes its own link`() {
		val twoServers = links(
			"""{"remarks":"DE","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
               {"address":"a.example.com","port":443,"users":[{"id":"u1","encryption":"none"}]},
               {"address":"b.example.com","port":443,"users":[{"id":"u2","encryption":"none"}]}]},
               "streamSettings":{"network":"tcp"}}]}"""
		)
		assertEquals(2, twoServers.size)
		assertTrue(twoServers[0], twoServers[0].startsWith("vless://u1@a.example.com:443"))
		assertTrue(twoServers[1], twoServers[1].startsWith("vless://u2@b.example.com:443"))

		// Two credentials for one server are two nodes as well, and each keeps its own flow.
		val twoUsers = links(
			"""{"remarks":"DE","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
               {"address":"a.example.com","port":443,"users":[{"id":"u1","encryption":"none"},
               {"id":"u2","encryption":"none","flow":"xtls-rprx-vision"}]}]},
               "streamSettings":{"network":"tcp","security":"tls",
                 "tlsSettings":{"serverName":"a.example.com"}}}]}"""
		)
		assertEquals(2, twoUsers.size)
		assertTrue(twoUsers[0], twoUsers[0].startsWith("vless://u1@") && !twoUsers[0].contains("flow="))
		assertTrue(twoUsers[1],
			twoUsers[1].startsWith("vless://u2@") && twoUsers[1].contains("flow=xtls-rprx-vision"))
	}

	@Test
	fun `an outbound naming one server is left exactly as it was`() {
		val out = links(
			"""{"remarks":"DE","outbounds":[{"protocol":"trojan","tag":"proxy","settings":{"servers":[
               {"address":"a.example.com","port":443,"password":"pw"}]}}]}"""
		)
		assertEquals(1, out.size)
		assertEquals("trojan://pw@a.example.com:443?security=none&type=tcp#DE", out[0])
	}

	// The sing-box pass hands back every server as well: one outbound each, and a urltest group
	// under the original tag standing for the whole.
	@Test
	fun `the sing-box pass carries every server`() {
		val body = """
			{"remarks":"DE","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"u1","encryption":"none"}]},
			{"address":"b.example.com","port":443,"users":[{"id":"u2","encryption":"none"}]}]},
			"streamSettings":{"network":"tcp"}}]}
		""".trimIndent().replace("\n", " ")
		val result = SingBoxConverter.convertToOutbounds(body, "DE")
		assertTrue("$result", result is SingBoxConverter.OutboundsResult.Ok)
		val servers = (result as SingBoxConverter.OutboundsResult.Ok).outbounds
			.filter { it.has("server") }.map { it.optString("server") }
		assertEquals(listOf("a.example.com", "b.example.com"), servers)
		// The group standing for the whole is a document's to hold, so it appears on that path.
		val doc = JSONObject(SubscriptionConverter.convert(body, jsonToUri = false, xrayToSingBox = true))
		val outs = doc.getJSONArray("outbounds")
		assertTrue((0 until outs.length()).map { outs.getJSONObject(it) }
			.any { it.optString("type") == "urltest" && it.optString("tag") == "DE" })
	}
}
