package com.happwner.convert

import android.util.Base64
import java.net.URLDecoder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// What a share link cannot carry is said out loud. A node that reaches the other side missing a
// setting nobody mentioned is the failure these notes exist for.
class LinkDropNoteTest {

	private val pin = "10a4e6deb9672d8472d83f9ca6beaace16d1d96c7850e8a0c74fecf6cf9d6fca"

	private fun convert(body: String): SubscriptionConverter.ConversionResult =
		SubscriptionConverter.convertWithStats(body, jsonToUri = true)

	private fun notes(body: String): String = convert(body).notes.joinToString("\n")

	private fun vless(stream: String, extra: String = ""): String = """
        {"remarks":"R","outbounds":[{"protocol":"vless"$extra,
          "settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"u","encryption":"none"}]}]},
          "streamSettings":$stream}]}
	""".trimIndent()

	private fun tls(fields: String): String =
		"""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com",$fields}}"""

	@Test
	fun `the certificate pin a link can carry is carried, and says nothing`() {
		val stats = convert(vless(tls(""""pinnedPeerCertSha256":"$pin"""")))
		assertTrue("pin missing from ${stats.text}", stats.text.contains("pcs=$pin"))
		assertTrue("unexpected notes: ${stats.notes}", stats.notes.isEmpty())
	}

	@Test
	fun `several pinned hashes travel as the one value the field spells`() {
		val stats = convert(vless(tls(""""pinnedPeerCertSha256":["$pin","aa"]""")))
		assertTrue("joined pin missing from ${stats.text}", stats.text.contains("pcs=$pin%2Caa"))
	}

	// The removed fields hash the chain and the public key. Same shape, different value.
	@Test
	fun `a chain pin is reported rather than passed off as a certificate pin`() {
		val stats = convert(vless(tls(""""pinnedPeerCertificateChainSha256":["$pin"]""")))
		assertFalse("a chain hash was written as pcs: ${stats.text}", stats.text.contains("pcs="))
		assertTrue(notes(vless(tls(""""pinnedPeerCertificateChainSha256":["$pin"]"""))).contains(
			"pinnedPeerCertificateChainSha256"))
		assertTrue(
			notes(vless(tls(""""pinnedPeerCertificatePublicKeySha256":["$pin"]""")))
				.contains("pinnedPeerCertificatePublicKeySha256")
		)
	}

	// The core splits the commas in pcs and vcn itself, so a list of either is one value here.
	@Test
	fun `a list of names to verify travels comma-joined`() {
		val stats = convert(vless(tls(""""verifyPeerCertByName":["a.example.com","b.example.com"]""")))
		assertTrue("names missing from ${stats.text}",
			stats.text.contains("vcn=a.example.com%2Cb.example.com"))
		assertTrue("unexpected notes: ${stats.notes}", stats.notes.isEmpty())
	}

	@Test
	fun `an ECH list is reported rather than half carried`() {
		val stats = convert(vless(tls(""""echConfigList":["one","two"]""")))
		assertFalse("a list was written as one config: ${stats.text}", stats.text.contains("ech="))
		assertTrue(stats.notes.toString(), stats.notes.any { it.contains("echConfigList") })
	}

	@Test
	fun `TLS settings with no link form are reported`() {
		val notes = notes(vless(tls(""""minVersion":"1.3","cipherSuites":"X","disableSystemRoot":true""")))
		assertTrue(notes, notes.contains("minVersion"))
		assertTrue(notes, notes.contains("cipherSuites"))
		assertTrue(notes, notes.contains("disableSystemRoot"))
	}

	@Test
	fun `settings that belong to the dialer rather than the server are reported`() {
		assertTrue(notes(vless("""{"network":"tcp","sockopt":{"mark":255}}""")).contains("sockopt"))
		assertTrue(
			notes(vless("""{"network":"xhttp","downloadSettings":{"address":"b.example.com"}}"""))
				.contains("downloadSettings")
		)
		assertTrue(
			notes(vless("""{"network":"tcp"}""", ""","mux":{"enabled":true}"""))
				.contains("mux")
		)
		assertTrue(
			notes(vless("""{"network":"tcp"}""", ""","sendThrough":"10.0.0.2""""))
				.contains("sendThrough")
		)
		assertTrue(
			notes(vless("""{"network":"tcp"}""", ""","proxySettings":{"tag":"first-hop"}"""))
				.contains("first-hop")
		)
	}

	@Test
	fun `an ordinary node says nothing`() {
		val stats = convert(vless(
			"""{"network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com"},
                 "wsSettings":{"path":"/p"}}"""))
		assertTrue("unexpected notes: ${stats.notes}", stats.notes.isEmpty())
	}

	@Test
	fun `hysteria v1 reports the pin its scheme has no room for`() {
		val body = """
            {"remarks":"R","outbounds":[{"protocol":"hysteria",
              "settings":{"servers":[{"address":"a.example.com","port":443,"auth_str":"pw",
                "up_mbps":50,"down_mbps":100}]},
              "streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com",
                "pinnedPeerCertSha256":"$pin"}}}]}
		""".trimIndent()
		val stats = convert(body)
		assertTrue("expected a v1 link, got ${stats.text}", stats.text.startsWith("hysteria://"))
		assertFalse("v1 has no such parameter: ${stats.text}", stats.text.contains("pinSHA256"))
		assertTrue(stats.notes.toString(), stats.notes.any { it.contains("hysteria v1") })
	}

	// Hysteria2's own URI scheme does define pinSHA256, so there it travels.
	@Test
	fun `hysteria2 carries the same pin instead of reporting it`() {
		val body = """
            {"remarks":"R","outbounds":[{"protocol":"hysteria2",
              "settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]},
              "streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com",
                "pinnedPeerCertSha256":"$pin"}}}]}
		""".trimIndent()
		val stats = convert(body)
		assertTrue("pin missing from ${stats.text}", stats.text.contains("pinSHA256=$pin"))
		assertTrue("unexpected notes: ${stats.notes}", stats.notes.isEmpty())
	}

	// Shadowsocks over WebSocket is the v2ray-plugin in websocket mode, the same wire format, and
	// the link carries it as SIP002 carries a plugin; a transport no core can express under the
	// proxy type is not handed over as a bare link, since that link would connect to nothing.
	@Test
	fun `a transport under shadowsocks, socks or http is carried as a plugin or refused`() {
		fun node(protocol: String, settings: String, stream: String) = """
            {"remarks":"R","outbounds":[{"protocol":"$protocol","settings":$settings,
              "streamSettings":{$stream}}]}
		""".trimIndent()
		val shadowsocks = node("shadowsocks",
			"""{"servers":[{"address":"a.example.com","port":8388,"password":"pw",
                 "method":"aes-256-gcm"}]}""",
			""""network":"ws","wsSettings":{"path":"/w","host":"cdn.example.com"},"security":"tls",
                 "tlsSettings":{"serverName":"cdn.example.com"}""")
		val link = SubscriptionConverter.convert(shadowsocks, jsonToUri = true).trim()
		assertTrue(link, link.startsWith("ss://"))
		val plugin = URLDecoder.decode(link.substringAfter("plugin=").substringBefore("#"), "UTF-8")
		assertEquals("v2ray-plugin;mode=websocket;host=cdn.example.com;path=/w;tls", plugin)

		val ssGrpc = node("shadowsocks",
			"""{"servers":[{"address":"a.example.com","port":8388,"password":"pw",
                 "method":"aes-256-gcm"}]}""",
			""""network":"grpc","grpcSettings":{"serviceName":"svc"}""")
		assertFalse(SubscriptionConverter.convert(ssGrpc, jsonToUri = true).contains("ss://"))
		assertTrue(notes(ssGrpc), notes(ssGrpc).contains("shadowsocks over grpc has no form"))

		// An https link names the TLS layer itself; a transport under http has no form.
		val http = node("http", """{"servers":[{"address":"a.example.com","port":8080}]}""",
			""""network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com"}""")
		assertFalse(SubscriptionConverter.convert(http, jsonToUri = true).contains("https://"))
		assertTrue(notes(http), notes(http).contains("http over ws over tls has no form"))
	}

	@Test
	fun `the QUIC schemes report the TLS details they have no field for`() {
		val hy2 = """
			{"remarks":"R","outbounds":[{"protocol":"hysteria2",
			  "settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]},
			  "streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com",
			    "fingerprint":"chrome"}}}]}
		""".trimIndent()
		assertTrue(notes(hy2),
			notes(hy2).contains("the hysteria2 link form has no field for tlsSettings.fingerprint"))

		val tuic = """
            {"remarks":"R","outbounds":[{"protocol":"tuic",
              "settings":{"servers":[{"address":"a.example.com","port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"}]},
              "streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com",
                "pinnedPeerCertSha256":"$pin"}}}]}
		""".trimIndent()
		assertTrue(notes(tuic),
			notes(tuic).contains("the tuic link form has no field for tlsSettings.pinnedPeerCertSha256"))
	}

	@Test
	fun `the vmess blob reports the parameters it has no field for`() {
		val body = """
			{"remarks":"R","outbounds":[{"protocol":"vmess",
			  "settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"u"}]}]},
			  "streamSettings":{"network":"grpc","security":"tls",
			    "tlsSettings":{"serverName":"a.example.com","allowInsecure":true},
			    "grpcSettings":{"serviceName":"gun","multiMode":true}}}]}
		""".trimIndent()
		val stats = convert(body)
		assertTrue("expected a vmess link, got ${stats.text}", stats.text.startsWith("vmess://"))
		// The gRPC mode travels in the blob's "type" as v2rayNG reads it, and allowInsecure in its
		// own field; neither is reported as dropped.
		val notes = stats.notes.joinToString("\n")
		assertFalse(notes, notes.contains("mode"))
		// Carried as "insecure", so never named lost; only Xray's refusal of it is said.
		assertFalse(notes, notes.lines().any { "allowInsecure" in it && "Xray 26" !in it })
		val blob = JSONObject(
			String(Base64.decode(stats.text.removePrefix("vmess://"),
				Base64.DEFAULT))
		)
		assertEquals("1", blob.optString("insecure"))
		assertEquals("gun", blob.optString("path"))
		assertEquals("multi", blob.optString("type"))
	}
}
