package com.happwner.convert

import java.net.URI
import java.net.URLDecoder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// A link that imports but does not connect is worse than no link at all. These walk a matrix of
// nodes through all three passes and check that each one describes the same server, over the same
// transport, behind the same security layer - and that the link itself is a URI a parser accepts.
class ConverterAgreementTest {

	private val uuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"

	private val transports = mapOf(
		"tcp" to """"network":"tcp"""",
		"ws" to """"network":"ws","wsSettings":{"path":"/p","host":"cdn.example.com"}""",
		"grpc" to """"network":"grpc","grpcSettings":{"serviceName":"gun"}""",
		"httpupgrade" to """"network":"httpupgrade","httpupgradeSettings":{"path":"/u",
          "host":"cdn.example.com"}""",
		"http" to """"network":"http","httpSettings":{"path":"/h","host":"cdn.example.com"}"""
	)

	private val securities = mapOf(
		"none" to """"security":"none"""",
		"tls" to """"security":"tls","tlsSettings":{"serverName":"sni.example.com","fingerprint":"chrome"}""",
		"reality" to """"security":"reality","realitySettings":{"serverName":"front.example.com",
          "password":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw","shortId":"aa","fingerprint":"chrome"}"""
	)

	private fun vless(transport: String, security: String): String = """
        {"remarks":"Node","outbounds":[{"protocol":"vless","tag":"proxy",
          "settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"$uuid","encryption":"none","flow":""}]}]},
          "streamSettings":{$transport,$security}}]}
	""".trimIndent()

	private fun singBox(body: String): JSONObject {
		val result = SingBoxConverter.convertToOutbounds(body, "Node")
		assertTrue("sing-box refused: $result", result is SingBoxConverter.OutboundsResult.Ok)
		return (result as SingBoxConverter.OutboundsResult.Ok).outbounds.first()
	}

	private fun mihomo(body: String): String {
		val result = MihomoConverter.convert(body)
		assertTrue("mihomo refused: $result", result is MihomoConverter.Result.Ok)
		return (result as MihomoConverter.Result.Ok).yaml
	}

	@Test
	fun `every pass points at the same server over the same transport`() {
		for ((netName, transport) in transports) {
			for ((secName, security) in securities) {
				// REALITY only rides RAW, XHTTP and gRPC, so the rest of the matrix is not a node.
				if (secName == "reality" && netName !in setOf("tcp", "grpc")) continue
				val label = "$netName/$secName"
				val body = vless(transport, security)

				val uri = SubscriptionConverter.convert(body, jsonToUri = true).trim()
				val parsed = URI(uri)
				assertEquals("$label scheme", "vless", parsed.scheme)
				assertEquals("$label host", "a.example.com", parsed.host)
				assertEquals("$label port", 443, parsed.port)
				assertEquals("$label uuid", uuid, parsed.userInfo)

				val query = queryOf(uri)
				assertEquals("$label type", if (netName == "http") "http" else netName, query["type"])
				assertEquals("$label security", if (secName == "none") "none" else secName, query["security"])

				val singBoxOutbound = singBox(body)
				assertEquals("$label sing-box server", "a.example.com", singBoxOutbound.optString("server"))
				assertEquals("$label sing-box port", 443, singBoxOutbound.optInt("server_port"))
				assertEquals("$label sing-box uuid", uuid, singBoxOutbound.optString("uuid"))
				val tlsOn = singBoxOutbound.optJSONObject("tls")?.optBoolean("enabled") == true
				assertEquals("$label sing-box tls", secName != "none", tlsOn)
				if (secName == "reality") {
					assertTrue("$label sing-box reality",
						singBoxOutbound.optJSONObject("tls")?.has("reality") == true)
				}

				val yaml = mihomo(body)
				assertTrue("$label mihomo server:\n$yaml", yaml.contains("server: a.example.com"))
				assertTrue("$label mihomo port:\n$yaml", yaml.contains("port: 443"))
				assertTrue("$label mihomo uuid:\n$yaml", yaml.contains("uuid: $uuid"))
				assertEquals("$label mihomo tls:\n$yaml", secName != "none", yaml.contains("tls: true"))
				if (secName == "reality") {
					assertTrue("$label mihomo reality:\n$yaml", yaml.contains("reality-opts:"))
				}
			}
		}
	}

	// Xray sends the TLS server name as the Host where a transport names none: every pass writes it out where
	// its clients would send the address, and leaves it unwritten where the two are one.
	@Test
	fun `every pass sends the Host Xray sends where the transport names none`() {
		val ws = """"network":"ws","wsSettings":{"path":"/p"}"""
		val named = vless(ws, """"security":"tls","tlsSettings":{"serverName":"sni.example.com"}""")
		val headers = singBox(named).getJSONObject("transport").getJSONObject("headers")
		assertEquals("sni.example.com", headers.getString("Host"))
		assertTrue(mihomo(named), "Host: sni.example.com" in mihomo(named))
		val link = SubscriptionConverter.convert(named, jsonToUri = true, base64Result = false)
		assertEquals(link, "sni.example.com", queryOf(link)["host"])
		val addressed = vless(ws, """"security":"tls","tlsSettings":{"serverName":"a.example.com"}""")
		assertFalse(singBox(addressed).getJSONObject("transport").has("headers"))
		assertFalse(mihomo(addressed), "Host:" in mihomo(addressed))
		val plain = SubscriptionConverter.convert(addressed, jsonToUri = true, base64Result = false)
		assertFalse(plain, "host" in queryOf(plain))
		// Without TLS Xray sends the address, which mihomo would replace with a name of its own for VLESS -
		// over httpupgrade too, and an IPv6 one in brackets.
		val bare = vless(ws, """"security":"none"""")
		assertTrue(mihomo(bare), "Host: a.example.com" in mihomo(bare))
		assertFalse(singBox(bare).getJSONObject("transport").has("headers"))
		val vmess = bare.replace(""""protocol":"vless"""", """"protocol":"vmess"""")
		assertFalse(mihomo(vmess), "Host:" in mihomo(vmess))
		val upgrade = vless(""""network":"httpupgrade","httpupgradeSettings":{"path":"/u"}""",
			""""security":"none"""")
		assertTrue(mihomo(upgrade), "Host: a.example.com" in mihomo(upgrade))
		val v6 = bare.replace("a.example.com", "2001:db8::1")
		assertTrue(mihomo(v6), "Host: '[2001:db8::1]'" in mihomo(v6))
	}

	// Xray sends the address as the TLS server name where none is written; a client that would take a Host
	// for it - husi from any link, mihomo over ws - is given the address.
	@Test
	fun `every pass sends the server name Xray sends where a Host is named and the server name is not`() {
		fun link(body: String) = SubscriptionConverter.convert(body, jsonToUri = true, base64Result = false)
		val ws = """"network":"ws","wsSettings":{"path":"/p","host":"cdn.example.com"}"""
		val unnamed = vless(ws, """"security":"tls","tlsSettings":{}""")
		assertEquals(link(unnamed), "a.example.com", queryOf(link(unnamed))["sni"])
		assertTrue(mihomo(unnamed), "servername: a.example.com" in mihomo(unnamed))
		assertFalse(singBox(unnamed).getJSONObject("tls").has("server_name"))
		val named = vless(ws, """"security":"tls","tlsSettings":{"serverName":"sni.example.com"}""")
		assertTrue(mihomo(named), "servername: sni.example.com" in mihomo(named))
		assertFalse(mihomo(named), "servername: a.example.com" in mihomo(named))
		val vmess = unnamed.replace(""""protocol":"vless"""", """"protocol":"vmess"""")
		assertTrue(mihomo(vmess), "servername: a.example.com" in mihomo(vmess))
		// mihomo takes a Trojan node's server name from its address, not its Host.
		val trojan = """{"remarks":"Node","outbounds":[{"protocol":"trojan","tag":"proxy","settings":""" +
			"""{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]},""" +
			""""streamSettings":{$ws,"security":"tls","tlsSettings":{}}}]}"""
		assertFalse(mihomo(trojan), "servername:" in mihomo(trojan) || "sni:" in mihomo(trojan))
		assertEquals(link(trojan), "a.example.com", queryOf(link(trojan))["sni"])
		// The same name as the address, however written, leaves the server name unwritten.
		val alike = unnamed.replace("cdn.example.com", "A.Example.com")
		assertFalse(link(alike), "sni" in queryOf(link(alike)))
		assertFalse(mihomo(alike), "servername:" in mihomo(alike))
		// An HTTP/2 link carries every host, and husi would send them all as one name - the address among
		// them too.
		for (first in listOf("b.example.com", "a.example.com")) {
			val hosts = """"network":"http","httpSettings":""" +
				"""{"path":"/h","host":["$first","c.example.com"]}"""
			val h2 = vless(hosts, """"security":"tls","tlsSettings":{}""")
			assertEquals(link(h2), "a.example.com", queryOf(link(h2))["sni"])
		}
	}

	// The parameters a peer has to agree on: getting one of them wrong is a node that imports and
	// then fails to connect.
	@Test
	fun `the parameters both ends must agree on survive into the link`() {
		val query = queryOf(SubscriptionConverter.convert(vless(transports.getValue("ws"),
			securities.getValue("tls")), jsonToUri = true))
		assertEquals("/p", query["path"])
		assertEquals("cdn.example.com", query["host"])
		assertEquals("sni.example.com", query["sni"])
		assertEquals("chrome", query["fp"])
		assertEquals("none", query["encryption"])

		val grpc = queryOf(SubscriptionConverter.convert(vless(transports.getValue("grpc"),
			securities.getValue("reality")), jsonToUri = true))
		assertEquals("gun", grpc["serviceName"])
		assertEquals("HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw", grpc["pbk"])
		assertEquals("aa", grpc["sid"])
		assertEquals("chrome", grpc["fp"])
	}

	// No parameter may be present with an empty value: the share-link standard forbids it, and a
	// client reading sni= or path= as a real value connects to nothing.
	@Test
	fun `no link carries an empty parameter or an unencoded space`() {
		val nodes = mutableListOf<String>()
		for ((_, transport) in transports) for ((_, security) in securities) {
			nodes.add(vless(transport, security))
		}
		nodes.add(
			"""{"remarks":"T","outbounds":[{"protocol":"trojan","tag":"proxy","settings":{"servers":[
                {"address":"a.example.com","port":443,"password":"pw"}]},
                "streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/p"},
                "tlsSettings":{"serverName":"sni.example.com"}}}]}"""
		)
		nodes.add(
			"""{"remarks":"H","outbounds":[{"protocol":"hysteria2","tag":"proxy","settings":{"servers":[
                {"address":"a.example.com","port":443,"password":"pw"}]},
                "streamSettings":{"security":"tls","tlsSettings":{"serverName":"sni.example.com"}}}]}"""
		)
		for (node in nodes) {
			val uri = SubscriptionConverter.convert(node, jsonToUri = true).trim()
			assertFalse("empty parameter in $uri", Regex("[?&][^=&#]+=(&|#|$)").containsMatchIn(uri))
			assertFalse("raw space in $uri", uri.contains(' '))
			// Parses as a URI, which is what every client hands the link to first.
			URI(uri)
		}
	}

	// A node that cannot authenticate is not a link. Handing one over means a client that imports
	// it, shows it in the list and never connects - the failure these conversions exist to avoid.
	@Test
	fun `a node with nothing to authenticate with has no link`() {
		val unlinkable = listOf(
			// TUIC v4: a token instead of the uuid the tuic:// scheme carries.
			"""{"protocol":"tuic","tag":"n","settings":{"servers":[
                {"address":"a.example.com","port":443,"token":"tok"}]}}""",
			// Trojan authenticates by password alone.
			"""{"protocol":"trojan","tag":"n","settings":{"servers":[
                {"address":"a.example.com","port":443,"password":""}]}}""",
			// Shadowsocks needs both halves of its userinfo.
			"""{"protocol":"shadowsocks","tag":"n","settings":{"servers":[
                {"address":"a.example.com","port":8388,"method":"","password":"pw"}]}}""",
			"""{"protocol":"shadowsocks","tag":"n","settings":{"servers":[
                {"address":"a.example.com","port":8388,"method":"aes-256-gcm","password":""}]}}"""
		)
		for (node in unlinkable) {
			val body = """{"remarks":"R","outbounds":[${node.trimIndent().replace("\n", " ")}]}"""
			val stats = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
			assertFalse("a dead link was handed over: ${stats.text}", stats.text.contains("://"))
			// TUIC v4 works and only has no link form, so it stays as it was written; a node with
			// nothing to authenticate with works nowhere, so it is left out with its reason.
			if ("\"token\"" in node) {
				assertTrue(
					"the node must say why it stayed as it was: ${stats.notes}",
					stats.notes.any { it.contains("no link form") }
				)
			} else {
				assertEquals(stats.text, "", stats.text)
				assertEquals(1, stats.xraySkipped)
				assertTrue("${stats.notes}", stats.notes.any { it.startsWith("skipped: outbounds[0] ") })
			}
		}
	}

	// One node on its own is the same node as one inside a configuration, and all three passes
	// read it as one.
	@Test
	fun `a node that arrived on its own reaches every pass`() {
		val lone = """{"protocol":"vless","tag":"Solo","settings":{"vnext":[{"address":"a.example.com",
            "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
            "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example.com"},
            "wsSettings":{"path":"/p"}}}""".trimIndent().replace("\n", " ")

		val uri = SubscriptionConverter.convert(lone, jsonToUri = true).trim()
		assertTrue(uri, uri.startsWith("vless://$uuid@a.example.com:443"))

		val singBoxOutbound = singBox(lone)
		assertEquals("a.example.com", singBoxOutbound.optString("server"))
		assertEquals(uuid, singBoxOutbound.optString("uuid"))
		assertEquals("ws", singBoxOutbound.optJSONObject("transport")?.optString("type"))

		val yaml = mihomo(lone)
		assertTrue(yaml, yaml.contains("server: a.example.com"))
		assertTrue(yaml, yaml.contains("network: ws"))
	}

	// But a lone outbound that is not a server is left exactly as it was: reading it as a
	// configuration of nothing would throw the line away.
	@Test
	fun `a lone outbound that is not a server is left alone`() {
		for (aux in listOf("""{"protocol":"freedom","tag":"direct"}""",
			"""{"protocol":"blackhole","tag":"block"}""")) {
			assertTrue(aux, SingBoxConverter.convert(aux) is SingBoxConverter.Result.NotXray)
			assertEquals(aux, SubscriptionConverter.convert(aux, jsonToUri = true).trim())
		}
	}

	// The name too, not only the server, transport and security layer: the passes must agree on
	// what a node is called, in every spelling of it.
	@Test
	fun `every pass calls the node the same thing`() {
		for (key in listOf("remarks", "remark", "name", "ps")) {
			for (proto in listOf("vless", "hysteria2", "trojan")) {
				val node = when (proto) {
					"vless" -> """"protocol":"vless",
                      "settings":{"vnext":[{"address":"a.example.com","port":443,
                        "users":[{"id":"$uuid","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}"""
					"hysteria2" -> """"protocol":"hysteria2","settings":{"servers":[
                        {"address":"a.example.com","port":443,"password":"pw"}]}"""
					else -> """"protocol":"trojan","settings":{"servers":[
                        {"address":"a.example.com","port":443,"password":"pw"}]},
                        "streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}"""
				}
				val body = """{"$key":"Frankfurt","outbounds":[{$node,"tag":"proxy"}]}"""
					.trimIndent().replace("\n", " ")
				val label = "$proto named by \"$key\""

				val uri = SubscriptionConverter.convert(body, jsonToUri = true).trim()
				assertEquals("$label (uri)", "Frankfurt", URLDecoder.decode(uri.substringAfter('#'), "UTF-8"))
				assertEquals("$label (sing-box)", "Frankfurt", singBox(body).optString("tag"))
				assertTrue("$label (mihomo):\n" + mihomo(body), mihomo(body).contains("name: Frankfurt"))
			}
		}
	}
}
