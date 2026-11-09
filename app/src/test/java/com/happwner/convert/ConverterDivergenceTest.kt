package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Seam tests: the exact edges where SingBoxConverter and the mihomo converter look like they do the
// same thing but do not. Every case here is current, verified behaviour.
class ConverterDivergenceTest {

	private fun result(xray: String) = SingBoxConverter.convertToOutbounds(xray)

	private fun single(xray: String): JSONObject {
		val converted = result(xray)
		assertTrue("expected Ok, got $converted", converted is SingBoxConverter.OutboundsResult.Ok)
		val list = (converted as SingBoxConverter.OutboundsResult.Ok).outbounds
		assertEquals(1, list.size)
		return list[0]
	}

	private fun vlessFlow(flowJson: String) = """
        {"remarks":"F","outbounds":[{"tag":"t","protocol":"vless",
         "settings":{"vnext":[{"address":"a.com","port":443,
           "users":[{"id":"u","flow":$flowJson,"encryption":"none"}]}]},
         "streamSettings":{"network":"tcp","security":"tls"}}]}
	""".trimIndent()

	private fun reality(fingerprintJson: String) = """
        {"remarks":"R","outbounds":[{"tag":"t","protocol":"vless",
         "settings":{"vnext":[{"address":"a.com","port":443,
           "users":[{"id":"u","encryption":"none"}]}]},
         "streamSettings":{"network":"tcp","security":"reality",
           "realitySettings":{"serverName":"s","publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw","shortId":"ab12",
                              "fingerprint":$fingerprintJson}}}]}
	""".trimIndent()

	private fun wireguard(endpointJson: String) = """
        {"remarks":"W","outbounds":[{"tag":"w","protocol":"wireguard",
         "settings":{"secretKey":"cKX1G0yg4Uyq6M6l7xX6h4L3s8m3Jo2eZk1v7d9n2ZA=","address":["10.0.0.2/32"],
                     "peers":[{"endpoint":$endpointJson,"publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="}]}}]}
	""".trimIndent()

	// Flow: one normaliser for every pass; it describes the input, and the passes apply their own rules.
	@Test
	fun `normalizeFlow trims and reads none as no flow`() {
		assertEquals("xtls-rprx-vision", normalizeFlow(" xtls-rprx-vision "))
		assertEquals("", normalizeFlow("none"))
		assertEquals("", normalizeFlow("  none  "))
	}

	@Test
	fun `normalizeFlow drops the udp443 variant of any flow`() {
		// The variant is the same flow letting UDP 443 through, which neither core distinguishes;
		// whether the flow itself is accepted is each pass's own question.
		assertEquals("xtls-rprx-vision", normalizeFlow("xtls-rprx-vision-udp443"))
		assertEquals("xtls-rprx-direct", normalizeFlow("xtls-rprx-direct-udp443"))
	}

	@Test
	fun `normalizeFlow is case sensitive`() {
		assertEquals("XTLS-RPRX-VISION", normalizeFlow("XTLS-RPRX-VISION"))
	}

	@Test
	fun `none and stray whitespace do not reject the outbound`() {
		assertFalse(single(vlessFlow("\"none\"")).has("flow"))
		assertEquals(
			"xtls-rprx-vision",
			single(vlessFlow("\" xtls-rprx-vision \"")).optString("flow")
		)
	}

	@Test
	fun `a flow Xray itself dropped still rejects the outbound`() {
		// Normalisation strips only the -udp443, and xtls-rprx-direct is gone from Xray since 1.8.
		assertTrue(
			"expected Unsupported",
			result(vlessFlow("\"xtls-rprx-direct-udp443\"")) is SingBoxConverter.OutboundsResult.Unsupported
		)
	}

	@Test
	fun `a json null flow is treated as absent`() {
		val outbound = single(vlessFlow("null"))
		assertFalse(outbound.has("flow"))
	}

	// uTLS: utlsFingerprint() falls back to "chrome" under REALITY for anything it does not
	// recognise, and the two accepted sets are target vocabularies rather than a shared Xray
	// concern - do not merge them.
	@Test
	fun `an unknown fingerprint falls back to chrome`() {
		for (fingerprint in listOf("\"bogus\"", "123", "null", "true")) {
			val utls = single(reality(fingerprint)).optJSONObject("tls")?.optJSONObject("utls")
			assertEquals("fingerprint $fingerprint", "chrome", utls?.optString("fingerprint"))
		}
	}

	@Test
	fun `fingerprint matching is case sensitive so Chrome becomes chrome by fallback`() {
		val utls = single(reality("\"Chrome\"")).optJSONObject("tls")?.optJSONObject("utls")
		assertEquals("chrome", utls?.optString("fingerprint"))
	}

	@Test
	fun `versioned fingerprints mihomo knows are downgraded here`() {
		// mihomo accepts chrome120; sing-box's set does not, so it lands on
		// the fallback. A shared fingerprint set would break one of the two.
		val utls = single(reality("\"chrome120\"")).optJSONObject("tls")?.optJSONObject("utls")
		assertEquals("chrome", utls?.optString("fingerprint"))
	}

	@Test
	fun `a bracketed ipv6 endpoint splits into address and port`() {
		val peer = single(wireguard("\"[2001:db8::1]:51820\"")).optJSONArray("peers")?.optJSONObject(0)!!
		assertEquals("2001:db8::1", peer.optString("address"))
		assertEquals(51820, peer.optInt("port"))
	}

	// The real Xray answers both with "IPC error -22: failed to set endpoint" and has no tunnel.
	@Test
	fun `an endpoint without a port fails the tunnel, so the node never worked`() {
		val result = SingBoxConverter.convertToOutbounds(wireguard("\"w.com\""))
		assertTrue(result.toString(), result.toString().contains("is not host:port"))
	}

	@Test
	fun `an unbracketed ipv6 endpoint has no port either, so the node never worked`() {
		val result = SingBoxConverter.convertToOutbounds(wireguard("\"2001:db8::1\""))
		assertTrue(result.toString(), result.toString().contains("is not host:port"))
	}

	// A port past 65535 fails the tunnel the same way; written out, sing-box would refuse the
	// whole document over it ("cannot unmarshal number 70000") and mihomo the node.
	@Test
	fun `an endpoint with a port out of range fails the tunnel, so the node never worked`() {
		val body = wireguard("\"1.2.3.4:70000\"")
		val singBox = SingBoxConverter.convertToOutbounds(body)
		assertTrue(singBox.toString(), singBox.toString().contains("is not host:port"))
		assertFalse(singBox.toString(), singBox.toString().contains("\"port\":70000"))
		val mihomo = MihomoConverter.convert(body)
		assertTrue(mihomo.toString(), mihomo.toString().contains("is not host:port"))
		assertFalse(mihomo.toString(), mihomo.toString().contains("port: 70000"))
	}

	// Scalar coercion: what happens with the loosely typed values the mihomo accessors absorb.
	@Test
	fun `a quoted port is coerced to a number`() {
		val xray = """
			{"remarks":"P","outbounds":[{"tag":"t","protocol":"vless",
			 "settings":{"vnext":[{"address":"a.com","port":"443",
			   "users":[{"id":"u","encryption":"none"}]}]},
			 "streamSettings":{"network":"tcp","security":"tls"}}]}
		""".trimIndent()
		// sing-box wants a number here; a quoted one makes the whole generated config unloadable.
		val port = single(xray).opt("server_port")
		assertTrue("expected a number, got ${'$'}{port?.javaClass?.simpleName}", port is Int)
		assertEquals(443, port)
	}

	@Test
	fun `a quoted alterId is coerced to a number`() {
		val xray = """
			{"remarks":"P","outbounds":[{"tag":"t","protocol":"vmess",
			 "settings":{"vnext":[{"address":"a.com","port":80,
			   "users":[{"id":"u","alterId":"0"}]}]},
			 "streamSettings":{"network":"tcp"}}]}
		""".trimIndent()
		val aid = single(xray).opt("alter_id")
		assertTrue("expected a number, got ${'$'}{aid?.javaClass?.simpleName}", aid is Int)
		assertEquals(0, aid)
	}

	@Test
	fun `a whitespace padded address and uuid are trimmed`() {
		val xray = """
			{"remarks":"P","outbounds":[{"tag":"t","protocol":"vless",
			 "settings":{"vnext":[{"address":"  a.com  ","port":443,
			   "users":[{"id":"  u  ","encryption":"none"}]}]},
			 "streamSettings":{"network":"tcp","security":"tls"}}]}
		""".trimIndent()
		val outbound = single(xray)
		assertEquals("a.com", outbound.optString("server"))
		assertEquals("u", outbound.optString("uuid"))
	}

	@Test
	fun `whitespace around protocol and network does not reject the outbound`() {
		val xray = """
			{"remarks":"P","outbounds":[{"tag":"t","protocol":" vless ",
			 "settings":{"vnext":[{"address":"a.com","port":443,
			   "users":[{"id":"u","encryption":" none "}]}]},
			 "streamSettings":{"network":" ws ","security":" tls ",
			   "wsSettings":{"path":"/p"}}}]}
		""".trimIndent()
		val outbound = single(xray)
		assertEquals("vless", outbound.optString("type"))
		assertEquals("ws", outbound.optJSONObject("transport")?.optString("type"))
		assertTrue(outbound.optJSONObject("tls")?.optBoolean("enabled") == true)
	}

	@Test
	fun `a padded plugin name is trimmed on the way out, not just on the way in`() {
		// The supported-check and the emit path read this field separately.
		val xray = """
			{"remarks":"SS","outbounds":[{"tag":"s","protocol":"shadowsocks",
			 "settings":{"servers":[{"address":"s.com","port":8388,
			   "method":"aes-256-gcm","password":"pw","plugin":"  obfs-local  "}]}}]}
		""".trimIndent()
		assertEquals("obfs-local", single(xray).optString("plugin"))
	}

	@Test
	fun `a boolean written as one is honoured`() {
		val xray = """
			{"remarks":"P","outbounds":[{"tag":"t","protocol":"vless",
			 "settings":{"vnext":[{"address":"a.com","port":443,
			   "users":[{"id":"u","encryption":"none"}]}]},
			 "streamSettings":{"network":"tcp","security":"tls",
			   "tlsSettings":{"allowInsecure":1}}}]}
		""".trimIndent()
		assertTrue(single(xray).optJSONObject("tls")?.optBoolean("insecure") == true)
	}

	@Test
	fun `a json null security drops the tls block entirely`() {
		val xray = """
			{"remarks":"P","outbounds":[{"tag":"t","protocol":"vless",
			 "settings":{"vnext":[{"address":"a.com","port":443,
			   "users":[{"id":"u","encryption":"none"}]}]},
			 "streamSettings":{"network":"tcp","security":null}}]}
		""".trimIndent()
		assertNull(single(xray).optJSONObject("tls"))
	}

	@Test
	fun `plugin options written as an object reach sing-box as the plugin's own string`() {
		val xray = """
			{"remarks":"SS","outbounds":[{"tag":"s","protocol":"shadowsocks",
			 "settings":{"servers":[{"address":"s.com","port":8388,"method":"aes-256-gcm","password":"pw",
			   "plugin":"obfs-local","pluginOpts":{"obfs":"http","obfs-host":"a.example.com"}}]}}]}
		""".trimIndent()
		assertEquals("obfs=http;obfs-host=a.example.com", single(xray).optString("plugin_opts"))
	}

	@Test
	fun `wireguard workers and keepAlive reach the endpoint`() {
		val xray = wireguard("\"w.example.com:51820\"")
			.replace("\"address\":[\"10.0.0.2/32\"],", "\"address\":[\"10.0.0.2/32\"],\"workers\":2,")
			.replace("\"publicKey\"", "\"keepAlive\":25,\"publicKey\"")
		val endpoint = single(xray)
		assertEquals(2, endpoint.optInt("workers"))
		val peer = endpoint.getJSONArray("peers").getJSONObject(0)
		assertEquals(25, peer.optInt("persistent_keepalive_interval"))
	}
}
