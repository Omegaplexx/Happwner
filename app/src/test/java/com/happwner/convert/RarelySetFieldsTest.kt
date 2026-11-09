package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// Fields a real configuration sets rarely, which neither the other tests nor the corpus reached:
// each is a place a person would otherwise learn about from a broken or silently changed file.
class RarelySetFieldsTest {

	private val node = """{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":""" +
		""""a.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811",""" +
		""""encryption":"none"}]}]}}"""

	private fun singBox(body: String) =
		SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok

	private fun mihomo(body: String) = MihomoConverter.convert(body) as MihomoConverter.Result.Ok

	// Every list under key anywhere in the document, logical rules included.
	private fun listsUnder(value: Any?, key: String): List<List<String>> = when (value) {
		is JSONObject -> value.keys().asSequence().flatMap { name ->
			val child = value.opt(name)
			val own = if (name == key && child is JSONArray) listOf(stringsOf(child))
			else emptyList()
			own + listsUnder(child, key)
		}.toList()
		is JSONArray -> (0 until value.length()).flatMap { listsUnder(value.opt(it), key) }
		else -> emptyList()
	}

	private fun stringsOf(array: JSONArray) = (0 until array.length()).map { array.getString(it) }

	@Test
	fun `an unreadable client subnet is dropped with its reason, globally and per server`() {
		val body = """{"dns":{"clientIp":"not-an-ip","servers":[{"address":"1.1.1.1",""" +
			""""domains":["domain:example.com"],"clientIP":"nope"},"8.8.8.8"]},""" +
			""""outbounds":[$node]}"""
		val global = unreadableClientIp("dns.clientIp", "not-an-ip")
		val own = unreadableClientIp("dns.servers[0].clientIP", "nope")
		for (notes in listOf(singBox(body).notes, mihomo(body).notes)) {
			assertTrue(notes.toString(), notes.any { global in it })
			assertTrue(notes.toString(), notes.any { own in it })
		}
	}

	@Test
	fun `a routing rule on inbounds, protocols, networks, users or processes keeps its lists`() {
		val rules = listOf(
			""""inboundTag":["socks-in","http-in"]""", """"protocol":["bittorrent"]""",
			""""network":["tcp"]""", """"user":["alice@example.com"]""", """"process":["curl"]"""
		).joinToString(",") { """{"type":"field",$it,"outboundTag":"direct"}""" }
		val body = """{"outbounds":[$node,{"tag":"direct","protocol":"freedom"}],""" +
			""""routing":{"rules":[$rules]}}"""
		val route = singBox(body).config.getJSONObject("route")
		assertTrue(listsUnder(route, "inbound").contains(listOf("socks-in", "http-in")))
		assertTrue(listsUnder(route, "protocol").contains(listOf("bittorrent")))
		assertTrue(listsUnder(route, "network").contains(listOf("tcp")))
		assertTrue(listsUnder(route, "auth_user").contains(listOf("alice@example.com")))
		assertTrue(listsUnder(route, "process_name").contains(listOf("curl")))
	}

	@Test
	fun `a hysteria port range with no base port dials the low end of the range`() {
		val body = """{"outbounds":[{"tag":"hy","protocol":"hysteria","settings":{"version":2,""" +
			""""address":"hy.example.com","port":0},"streamSettings":{"network":"hysteria",""" +
			""""security":"tls","tlsSettings":{"serverName":"hy.example.com"},""" +
			""""hysteriaSettings":{"version":2,"auth":"secret","udpHop":{"ports":"20000-30000",""" +
			""""interval":"30s"}}}}]}"""
		val outbounds = singBox(body).config.getJSONArray("outbounds")
		val hysteria = (0 until outbounds.length()).map { outbounds.getJSONObject(it) }
			.single { it.optString("type") == "hysteria2" }
		assertEquals(20000, hysteria.getInt("server_port"))
		val yaml = mihomo(body).yaml
		assertTrue(yaml, yaml.contains("port: 20000"))
	}

	@Test
	fun `a sniffed protocol mihomo cannot sniff is dropped with its reason`() {
		val body = """{"inbounds":[{"tag":"socks","protocol":"socks","port":1080,"sniffing":""" +
			"""{"enabled":true,"destOverride":["http","tls","fakedns+others"]}}],""" +
			""""outbounds":[$node]}"""
		val expected = "sniffing.destOverride \"fakedns+others\" is not a protocol mihomo " +
			"sniffs, so it was dropped"
		val notes = mihomo(body).notes
		assertTrue(notes.toString(), notes.any { expected in it })
	}

	@Test
	fun `a host header written as a list gives the link its first host`() {
		val body = """{"outbounds":[{"tag":"ws","protocol":"vless","settings":{"vnext":[""" +
			"""{"address":"a.example.com","port":443,"users":[{"id":""" +
			""""b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},""" +
			""""streamSettings":{"network":"ws","wsSettings":{"path":"/ws",""" +
			""""headers":{"Host":["","h1.example.com"]}}}}]}"""
		val link = SubscriptionConverter.convert(body, jsonToUri = true)
		assertTrue(link, "host=h1.example.com" in link)
	}
}
