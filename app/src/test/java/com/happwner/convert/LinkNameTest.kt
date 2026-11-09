package com.happwner.convert

import android.util.Base64
import java.net.URLDecoder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// The name a link carries, read from every field a configuration may spell it in.
class LinkNameTest {

	private val nodes = mapOf(
		"vless" to """"protocol":"vless","settings":{"vnext":[{"address":"a.example.com","port":443,
          "users":[{"id":"u","encryption":"none"}]}]}""",
		"vmess" to """"protocol":"vmess","settings":{"vnext":[{"address":"a.example.com","port":443,
          "users":[{"id":"u"}]}]}""",
		"trojan" to """"protocol":"trojan","settings":{"servers":[{"address":"a.example.com",
          "port":443,"password":"pw"}]}""",
		"shadowsocks" to """"protocol":"shadowsocks",
          "settings":{"servers":[{"address":"a.example.com","port":8388,"password":"pw",
            "method":"aes-256-gcm"}]}""",
		"hysteria2" to """"protocol":"hysteria2","settings":{"servers":[{"address":"a.example.com",
          "port":443,"password":"pw"}]}""",
		"hysteria" to """"protocol":"hysteria","settings":{"servers":[{"address":"a.example.com",
          "port":443,"auth_str":"pw","up_mbps":50,"down_mbps":100}]}""",
		"tuic" to """"protocol":"tuic","settings":{"servers":[{"address":"a.example.com","port":443,
          "uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"}]}""",
		"socks" to """"protocol":"socks","settings":{"servers":[{"address":"a.example.com","port":1080}]}""",
		"http" to """"protocol":"http","settings":{"servers":[{"address":"a.example.com","port":8080}]}"""
	)

	private fun config(node: String, tag: String? = null, own: String? = null,
		remarks: String? = null): String {
		val head = if (remarks == null) "" else """"remarks":${JSONObject.quote(remarks)},"""
		val parts = listOfNotNull(
			node,
			tag?.let { """"tag":${JSONObject.quote(it)}""" },
			own?.let { """"remarks":${JSONObject.quote(it)}""" }
		)
		return """{$head"outbounds":[{${parts.joinToString(",")}}]}"""
	}

	// The name a link ended up with, whichever way the protocol carries it.
	private fun nameOf(body: String): String {
		val link = SubscriptionConverter.convert(body, jsonToUri = true).trim()
		if (link.startsWith("vmess://")) {
			val blob = String(Base64.decode(link.removePrefix("vmess://"),
				Base64.DEFAULT))
			return JSONObject(blob).optString("ps")
		}
		return URLDecoder.decode(link.substringAfter('#', ""), "UTF-8")
	}

	@Test
	fun `the config's own remarks names every protocol's link`() {
		for ((proto, node) in nodes) {
			assertEquals(proto, "Frankfurt", nameOf(config(node, remarks = "Frankfurt")))
		}
	}

	@Test
	fun `an outbound's own remarks wins over the config's`() {
		for ((proto, node) in nodes) {
			assertEquals(proto, "Own", nameOf(config(node, own = "Own", remarks = "Config")))
		}
	}

	// A Hysteria2 node is named from either of them, not left unnamed.
	@Test
	fun `hysteria2 is named like everything else`() {
		val node = nodes.getValue("hysteria2")
		assertEquals("Config", nameOf(config(node, tag = "proxy", remarks = "Config")))
		assertEquals("Own", nameOf(config(node, tag = "proxy", own = "Own", remarks = "Config")))
		assertEquals("h", nameOf(config(node, tag = "h")))
	}

	// The shape Xray 26 panels write Hysteria2 in - "hysteria" with version 2, the password in
	// hysteriaSettings, a freedom beside it - alone and in a JSON list of configurations.
	@Test
	fun `a hysteria2 node in the shape Xray 26 panels write is named by its configuration in every pass`() {
		fun config(name: String) = """{"remarks":${JSONObject.quote(name)},"outbounds":[{"tag":"proxy",
			"protocol":"hysteria","settings":{"address":"us.example.com","port":443,"version":2},
			"streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"pw"},
			"security":"tls","tlsSettings":{"serverName":"us.example.com","fingerprint":"chrome",
			"alpn":["h3"]}}},{"tag":"direct","protocol":"freedom"}]}"""
		val usa = config("🇺🇸 USA Hy2")
		assertEquals("🇺🇸 USA Hy2", nameOf(usa))
		val list = "[$usa,${config("Germany Hy2")}]"
		val names = SubscriptionConverter.convert(list, jsonToUri = true).trim().lines()
			.map { URLDecoder.decode(it.substringAfter('#'), "UTF-8") }
		assertEquals(listOf("🇺🇸 USA Hy2", "Germany Hy2"), names)
		val mihomo = SubscriptionConverter.convert(list, jsonToUri = false, xrayToMihomo = true)
		assertTrue(mihomo, mihomo.contains("name: Germany Hy2"))
		val singBox = JSONObject(SubscriptionConverter.convert(list, jsonToUri = false, xrayToSingBox = true))
		val outbounds = singBox.getJSONArray("outbounds")
		val tags = (0 until outbounds.length()).map { outbounds.getJSONObject(it) }
			.filter { it.optString("type") == "hysteria2" }.map { it.optString("tag") }
		assertEquals(listOf("\uD83C\uDDFA\uD83C\uDDF8 USA Hy2", "Germany Hy2"), tags)
	}

	@Test
	fun `a routing tag never masks the name the config gave`() {
		for ((proto, node) in nodes) {
			assertEquals(proto, "Frankfurt", nameOf(config(node, tag = "proxy", remarks = "Frankfurt")))
		}
	}

	@Test
	fun `a tag names a link only when nothing else did, and not a routing one`() {
		for ((proto, node) in nodes) {
			assertEquals(proto, "Amsterdam", nameOf(config(node, tag = "Amsterdam")))
			// A role tag is no name, so the node falls back to what it is - never to nothing, which
			// reaches the client as an unnamed row showing the address.
			// ss is what the link calls shadowsocks; hysteria2 arrives under either spelling.
			val prefix = when (proto) {
				"shadowsocks" -> "ss"
				else -> proto
			}
			assertTrue(proto, nameOf(config(node, tag = "proxy")).startsWith("$prefix-a.example.com:"))
			assertTrue(proto, nameOf(config(node, tag = "DIRECT")).startsWith("$prefix-a.example.com:"))
		}
	}

	// A node no one named still arrives as something a person can tell from the next one, and all
	// three passes say the same thing about it.
	@Test
	fun `a node the configuration never named is named by what it is`() {
		val body = """
			{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"de.example.com",
			 "port":443,"users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}]}
		""".trimIndent().replace("\n", " ")
		assertEquals("vless-de.example.com:443", nameOf(body))
		val mihomo = SubscriptionConverter.convert(body, jsonToUri = false, xrayToMihomo = true)
		assertTrue(mihomo, mihomo.contains("name: vless-de.example.com:443"))
		val singBox = SubscriptionConverter.convert(body, jsonToUri = false, xrayToSingBox = true)
		assertTrue(singBox, singBox.contains("\"tag\":\"proxy\""))
	}

	// Even a generic tag tells two nodes of one configuration apart, which nothing else here does.
	@Test
	fun `several proxies are told apart even by a generic tag`() {
		val body = """
            {"remarks":"Sub","outbounds":[
              {${nodes.getValue("vless")},"tag":"proxy"},
              {${nodes.getValue("trojan")},"tag":"out"}
            ]}
		""".trimIndent()
		val names = SubscriptionConverter.convert(body, jsonToUri = true).trim().lines()
			.map { URLDecoder.decode(it.substringAfter('#'), "UTF-8") }
		assertEquals(listOf("Sub #proxy", "Sub #out"), names)
	}

	// Every node of a configuration is named by it. With several in one file the label alone would
	// name them all the same, so the tag comes along to say which is which - the same shape the
	// sing-box pass writes. An outbound's own label still wins over both.
	@Test
	fun `every outbound of a config is named, not just the first`() {
		val body = """
            {"remarks":"Sub","outbounds":[
              {${nodes.getValue("vless")},"tag":"proxy-de-1"},
              {${nodes.getValue("hysteria2")},"tag":"b","remarks":"Second"}
            ]}
		""".trimIndent()
		val links = SubscriptionConverter.convert(body, jsonToUri = true).trim().lines()
		assertEquals(2, links.size)
		// Not "proxy-de-1" on its own: a tag names a role, and it does not get to replace a name
		// written to be read - it stands beside it.
		assertEquals("Sub #proxy-de-1", URLDecoder.decode(links[0].substringAfter('#'), "UTF-8"))
		assertEquals("Second", URLDecoder.decode(links[1].substringAfter('#'), "UTF-8"))
	}

	// A configuration may spell its name any of five ways, and the link reads all of them, as the
	// mihomo pass does.
	@Test
	fun `a name is read in every spelling a generator writes it`() {
		for (key in listOf("remarks", "remark", "name", "ps", "tag")) {
			val body = """{"$key":"Frankfurt","outbounds":[{${nodes.getValue("hysteria2")},"tag":"proxy"}]}"""
			assertEquals("config label as \"$key\"", "Frankfurt", nameOf(body))
		}
		for (key in listOf("remarks", "remark", "name", "ps")) {
			val body = """{"remarks":"Config","outbounds":[{${nodes.getValue("hysteria2")},"$key":"Own"}]}"""
			assertEquals("outbound label as \"$key\"", "Own", nameOf(body))
		}
	}

	@Test
	fun `a node that arrives on its own keeps its tag`() {
		val vmess =
			"""{"protocol":"vmess","tag":"Solo","settings":{"vnext":[{"address":"a.example.com",
                 "port":443,"users":[{"id":"u"}]}]}}"""
		assertEquals("Solo", nameOf(vmess))
		val tuic =
			"""{"protocol":"tuic","tag":"Solo","settings":{"servers":[{"address":"a.example.com",
                 "port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"}]}}"""
		assertEquals("Solo", nameOf(tuic))
	}
}
