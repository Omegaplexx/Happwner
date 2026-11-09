package com.happwner.convert

import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Xray's QUIC transport runs TLS whether security names tls or nothing: tlsSettings for tls, its
// own unverified name otherwise, h2/http/1.1 when no ALPN is set, never uTLS. Every output has to
// say exactly that, or a client other than Xray loads the node and then cannot connect.
class QuicTransportTest {

	private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
	private val realityKey = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
	private val chromeDropped = requireNotNull(quicFingerprintDropped("chrome"))

	private fun config(protocol: String, stream: String): String {
		val user = if (protocol == "vless") """{"id":"$uuid","encryption":"none"}""" else """{"id":"$uuid"}"""
		return """{"remarks":"Q","outbounds":[{"protocol":"$protocol","tag":"n","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[$user]}]},"streamSettings":$stream}]}"""
	}

	private fun singBox(stream: String): Pair<JSONObject, List<String>> {
		val result = SingBoxConverter.convertToOutbounds(config("vless", stream))
		assertTrue("expected a node for $stream, got $result", result is SingBoxConverter.OutboundsResult.Ok)
		val ok = result as SingBoxConverter.OutboundsResult.Ok
		return ok.outbounds.first { it.optString("type") == "vless" } to ok.notes
	}

	private fun link(protocol: String, stream: String): Pair<String, List<String>> {
		val stats = SubscriptionConverter.convertWithStats(config(protocol, stream))
		return stats.text.trim() to stats.notes
	}

	private fun assertOwnTls(tls: JSONObject) {
		assertTrue(tls.getBoolean("enabled"))
		assertEquals(XRAY_QUIC_OWN_SNI, tls.getString("server_name"))
		assertTrue(tls.getBoolean("insecure"))
		assertEquals("[\"h2\",\"http/1.1\"]", jsonText(tls.getJSONArray("alpn")))
		assertFalse("QUIC takes no uTLS", tls.has("utls"))
		assertFalse(tls.has("reality"))
	}

	@Test
	fun `quic without a tls block runs Xray's own tls in sing-box`() {
		for (stream in listOf("""{"network":"quic","security":"none"}""", """{"network":"quic"}""")) {
			val (outbound, notes) = singBox(stream)
			assertEquals("quic", outbound.getJSONObject("transport").getString("type"))
			assertOwnTls(outbound.getJSONObject("tls"))
			assertTrue("nothing is lost, so nothing is reported: $notes", notes.isEmpty())
		}
	}

	@Test
	fun `reality over quic never ran, so every pass leaves it out`() {
		// Xray has never run REALITY over QUIC and refuses the configuration; no pass hands one on.
		val body = """{"remarks":"R","outbounds":[{"protocol":"vless","tag":"p","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
			"streamSettings":{"network":"quic","security":"reality","realitySettings":
			{"serverName":"a.example.com","publicKey":"$realityKey","shortId":"aa"}}}]}""".replace("\n", "")
		for (pass in listOf("links", "sing-box", "mihomo")) {
			val result = SubscriptionConverter.convertWithStats(
				body, jsonToUri = pass == "links", xrayToSingBox = pass == "sing-box",
				xrayToMihomo = pass == "mihomo"
			)
			assertTrue("$pass: ${result.notes}", result.notes.any { "refuses it over \"quic\"" in it })
		}
	}

	@Test
	fun `quic tls keeps its settings, gains Xray's alpn and loses utls`() {
		val (outbound, notes) = singBox("""{"network":"quic","security":"tls",
			"tlsSettings":{"serverName":"q.example.com","fingerprint":"chrome"}}""")
		val tls = outbound.getJSONObject("tls")
		assertEquals("q.example.com", tls.getString("server_name"))
		assertFalse(tls.has("insecure"))
		assertEquals("[\"h2\",\"http/1.1\"]", jsonText(tls.getJSONArray("alpn")))
		assertFalse(tls.has("utls"))
		assertTrue(notes.toString(), notes.any { it.contains(chromeDropped) })

		val (named, _) = singBox("""{"network":"quic","security":"tls",
			"tlsSettings":{"serverName":"q.example.com","alpn":["h3"]}}""")
		assertEquals("[\"h3\"]", jsonText(named.getJSONObject("tls").getJSONArray("alpn")))
	}

	@Test
	fun `unsafe asks for the plain tls QUIC runs anyway, so nothing is reported`() {
		val stream = """{"network":"quic","security":"tls",
			"tlsSettings":{"serverName":"q.example.com","fingerprint":"unsafe"}}"""
		val (outbound, notes) = singBox(stream)
		assertFalse(outbound.getJSONObject("tls").has("utls"))
		assertTrue(notes.toString(), notes.none { it.contains("unsafe") })
		val (uri, linkNotes) = link("vless", stream)
		assertFalse(queryOf(uri).containsKey("fp"))
		assertTrue(linkNotes.toString(), linkNotes.none { it.contains("unsafe") })
	}

	@Test
	fun `quic's own encryption and headers still have no sing-box form`() {
		for (quic in listOf("""{"security":"aes-128-gcm","key":"k"}""", """{"header":{"type":"srtp"}}""")) {
			val stream = """{"network":"quic","quicSettings":$quic}"""
			val result = SingBoxConverter.convertToOutbounds(config("vless", stream))
			assertTrue("$quic, got $result", result is SingBoxConverter.OutboundsResult.Unsupported)
		}
	}

	@Test
	fun `a quic link spells out the tls Xray runs`() {
		val (uri, notes) = link("vless", """{"network":"quic","security":"none"}""")
		val query = queryOf(uri)
		assertEquals("quic", query["type"])
		assertEquals("tls", query["security"])
		assertEquals(XRAY_QUIC_OWN_SNI, query["sni"])
		assertEquals("1", query["allowInsecure"])
		assertEquals("h2,http/1.1", query["alpn"])
		assertTrue(notes.toString(), notes.isEmpty())
	}

	@Test
	fun `a quic tls link keeps its name, gains Xray's alpn and loses the fingerprint`() {
		val (uri, notes) = link("vless", """{"network":"quic","security":"tls",
			"tlsSettings":{"serverName":"q.example.com","fingerprint":"chrome"}}""")
		val query = queryOf(uri)
		assertEquals("q.example.com", query["sni"])
		assertEquals("h2,http/1.1", query["alpn"])
		assertFalse(query.containsKey("fp"))
		assertFalse(query.containsKey("allowInsecure"))
		assertTrue(notes.toString(), notes.any { it.contains(chromeDropped) })
	}

	@Test
	fun `a vmess quic link carries the same tls in its blob`() {
		val (uri, _) = link("vmess", """{"network":"quic"}""")
		val blob = JSONObject(String(Base64.getDecoder().decode(uri.removePrefix("vmess://"))))
		assertEquals("quic", blob.getString("net"))
		assertEquals("tls", blob.getString("tls"))
		assertEquals(XRAY_QUIC_OWN_SNI, blob.getString("sni"))
		assertEquals("1", blob.getString("insecure"))
		assertEquals("h2,http/1.1", blob.getString("alpn"))
	}
}
