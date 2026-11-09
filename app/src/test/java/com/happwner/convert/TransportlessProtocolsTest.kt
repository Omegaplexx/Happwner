package com.happwner.convert

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// shadowsocks, socks and http carry no transport of their own. "raw" is the spelling Xray writes
// for tcp now, and a plain node under it is a plain node; an HTTP masquerade on the raw stream is
// something the server waits for, and a node handed over without it connects to nothing.
class TransportlessProtocolsTest {

	private fun config(protocol: String, stream: String): String {
		val settings = when (protocol) {
			"shadowsocks" -> """{"servers":[{"address":"s.example.com","port":8388,
              "method":"aes-256-gcm","password":"pw"}]}"""
			else -> """{"servers":[{"address":"s.example.com","port":1080}]}"""
		}
		return """{"remarks":"T","outbounds":[{"protocol":"$protocol","tag":"p","settings":$settings,
            "streamSettings":$stream}]}""".replace("\n", " ")
	}

	private fun passes(body: String): Triple<SubscriptionConverter.ConversionResult,
		SubscriptionConverter.ConversionResult, SubscriptionConverter.ConversionResult> =
		Triple(
			SubscriptionConverter.convertWithStats(body, jsonToUri = true),
			SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true),
			SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true)
		)

	@Test
	fun `a plain node spelled raw is written by every pass`() {
		for (protocol in listOf("shadowsocks", "socks", "http")) {
			val (link, singBox, mihomo) = passes(config(protocol, """{"network":"raw"}"""))
			val scheme = if (protocol == "shadowsocks") "ss://" else "$protocol://"
			assertTrue("$protocol link: ${link.text}", link.text.startsWith(scheme))
			assertTrue("$protocol sing-box: ${singBox.notes}",
				singBox.text.contains("\"server\":\"s.example.com\""))
			assertTrue("$protocol mihomo: ${mihomo.notes}", mihomo.text.contains("server: s.example.com"))
			for (pass in listOf(link, singBox, mihomo)) assertFalse(pass.notes.toString(),
				pass.notes.any { "has no form" in it })
		}
	}

	// mihomo's trojan always speaks TLS; a server that takes plaintext would be handed a handshake it
	// does not answer, so the mihomo pass refuses the node instead of writing it with TLS on.
	@Test
	fun `a plaintext trojan node is refused by the mihomo pass and written plain by the others`() {
		val body = """{"remarks":"T","outbounds":[{"protocol":"trojan","tag":"p","settings":{"servers":[
            {"address":"s.example.com","port":443,"password":"pw"}]},"streamSettings":{"network":"tcp",
            "security":"none"}}]}""".replace("\n", " ")
		val (link, singBox, mihomo) = passes(body)
		assertTrue(link.text, link.text.startsWith("trojan://") && link.text.contains("security=none"))
		assertTrue(singBox.text,
			singBox.text.contains("\"type\":\"trojan\"") && !singBox.text.contains("\"tls\""))
		assertFalse(mihomo.text, mihomo.text.contains("type: trojan"))
		assertTrue(mihomo.notes.toString(), mihomo.notes.any { "mihomo always uses TLS" in it })
	}

	// One reader for the security layer in every pass: xtls is the tls it became, a REALITY block
	// with no security named is REALITY, and a name Xray does not take is refused everywhere.
	@Test
	fun `every pass reads the security layer the same way`() {
		fun vless(stream: String) = """{"remarks":"S","outbounds":[{"protocol":"vless","tag":"p",
          "settings":{"vnext":[
            {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
            "streamSettings":{"network":"tcp",$stream}}]}""".replace("\n", " ")
		val xtls = passes(vless(""""security":"xtls","xtlsSettings":{"serverName":"a.example.com"}"""))
		assertTrue(xtls.first.text, xtls.first.text.contains("security=tls"))
		assertTrue(xtls.second.text, xtls.second.text.contains("\"server_name\":\"a.example.com\""))
		assertTrue(xtls.third.text, xtls.third.text.contains("tls: true"))

		val reality = passes(vless(
			""""realitySettings":{"serverName":"r.example.com","publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw","shortId":"ab12"}"""))
		assertTrue(reality.first.text, reality.first.text.contains("security=reality"))
		assertTrue(reality.second.text, reality.second.text.contains("\"reality\":{"))
		assertTrue(reality.third.text, reality.third.text.contains("reality-opts:"))

		val odd = passes(vless(""""security":"quantum""""))
		for (pass in listOf(odd.first, odd.second, odd.third)) {
			assertFalse(pass.text,
				pass.text.contains("vless://") || pass.text.contains("\"type\":\"vless\"") ||
					pass.text.contains("type: vless"))
			assertTrue(pass.notes.toString(),
				pass.notes.any { "security \"quantum\" is not one Xray accepts" in it })
		}
	}

	// The v2ray-plugin options of a link and of sing-box have no switch for allowInsecure, so the
	// plugin verifies the certificate and the loss is named; mihomo's options carry it.
	@Test
	fun `allowInsecure under the websocket plugin is carried by mihomo and named elsewhere`() {
		val body = config("shadowsocks", """{"network":"ws","wsSettings":{"path":"/ws"},"security":"tls",
            "tlsSettings":{"serverName":"s.example.com","allowInsecure":true}}""")
		val (link, singBox, mihomo) = passes(body)
		assertTrue(link.text, link.text.contains("plugin=v2ray-plugin"))
		assertTrue(link.notes.toString(),
			link.notes.any { "allowInsecure has no place in the v2ray-plugin" in it })
		assertTrue(singBox.text, singBox.text.contains("\"plugin\":\"v2ray-plugin\""))
		assertTrue(singBox.notes.toString(),
			singBox.notes.any { "allowInsecure has no place in the v2ray-plugin" in it })
		assertTrue(mihomo.text, mihomo.text.contains("skip-cert-verify: true"))
		assertFalse(mihomo.notes.toString(), mihomo.notes.any { "allowInsecure" in it && "Xray 26" !in it })
	}

	@Test
	fun `an HTTP masquerade on the raw stream is refused with the reason by every pass`() {
		val stream = """{"network":"tcp","tcpSettings":{"header":{"type":"http",
            "request":{"path":["/"],"headers":{"Host":["cdn.example.com"]}}}}}"""
		for (protocol in listOf("shadowsocks", "socks", "http")) {
			val (link, singBox, mihomo) = passes(config(protocol, stream))
			assertFalse("$protocol link: ${link.text}", link.text.contains("://"))
			assertFalse("$protocol sing-box: ${singBox.text}",
				singBox.text.contains("\"server\":\"s.example.com\""))
			assertFalse("$protocol mihomo: ${mihomo.text}", mihomo.text.contains("server: s.example.com"))
			for (pass in listOf(link, singBox, mihomo)) {
				assertTrue("$protocol: ${pass.notes}", pass.notes.any { "HTTP masquerade has no form" in it })
			}
		}
	}
}
