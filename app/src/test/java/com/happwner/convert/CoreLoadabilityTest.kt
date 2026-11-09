package com.happwner.convert

import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Values each real core refuses a whole document over, found by loading every converted document
// into sing-box 1.12, 1.13 and 1.14 and mihomo: none of them may reach the output.
class CoreLoadabilityTest {

	private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

	private fun vless(stream: String) = """{"outbounds":[{"protocol":"vless","tag":"n","settings":{"vnext":[
		{"address":"a.example.com","port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
		"streamSettings":$stream}]}""".replace("\n", "")

	private fun singBox(body: String): SingBoxConverter.Result = SingBoxConverter.convert(body, "N")

	private fun tlsOf(body: String): JSONObject {
		val result = singBox(body)
		assertTrue("$result", result is SingBoxConverter.Result.Ok)
		return (result as SingBoxConverter.Result.Ok).config.getJSONArray("outbounds")
			.getJSONObject(0).getJSONObject("tls")
	}

	@Test
	fun `a padded REALITY key is one Xray refuses, so no pass writes the node`() {
		val body = vless("""{"network":"tcp","security":"reality","realitySettings":{"serverName":"s",
			"publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","fingerprint":"chrome"}}""")
		assertTrue(singBox(body) is SingBoxConverter.Result.Unsupported)
		assertFalse(SubscriptionConverter.convert(body, jsonToUri = false, xrayToMihomo = true)
			.contains("public-key"))
		assertFalse(SubscriptionConverter.convertWithStats(body, jsonToUri = true).text.contains("pbk="))
	}

	@Test
	fun `a body whose every configuration sing-box refuses comes back empty, each reason under its place`() {
		val refused = vless("""{"network":"tcp","security":"reality","realitySettings":{"serverName":"s",
			"publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","fingerprint":"chrome"}}""")
		val flags = ConversionFlags(
			jsonToUri = false, xrayToSingBox = true, xrayToMihomo = false, base64Result = false
		)
		for (body in listOf("[$refused,$refused]", "$refused\n$refused")) {
			val result = SubscriptionConverter.convertWithStats(body, flags)
			assertEquals(body, "", result.text)
			assertEquals(body, 2, result.xraySkipped)
			for (place in listOf("config[0]", "config[1]")) {
				assertTrue("${result.notes}", result.notes.any { it.contains(place) })
			}
		}
	}

	@Test
	// Xray logs "failed to append cert" and verifies against the system store; sing-box would refuse the
	// whole document over such a certificate, so it is left out and said while the node stays.
	fun `a certificate to verify against that does not read is dropped and the node kept`() {
		val stream = { pem: String ->
			"""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com",
			"certificates":[{"usage":"verify","certificate":["$pem"]}]}}"""
		}
		val broken = vless(stream("-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----"))
		val result = singBox(broken)
		assertTrue("$result", result is SingBoxConverter.Result.Ok)
		val kept = result as SingBoxConverter.Result.Ok
		assertFalse(kept.config.toString(), kept.config.toString().contains("BEGIN CERTIFICATE"))
		assertTrue("${kept.notes}", kept.notes.any { it.contains("certificates[0]") })
		assertTrue(tlsOf(vless(stream(TEST_CERTIFICATE_JSON))).optString("certificate").contains("BEGIN"))
	}

	@Test
	fun `only the cipher suites sing-box takes go out, the rest are named`() {
		val body = vless("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com",
			"cipherSuites":"TLS_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA:X"}}""")
		assertEquals("[\"TLS_AES_128_GCM_SHA256\"]", tlsOf(body).getJSONArray("cipher_suites").toString())
		val notes = (singBox(body) as SingBoxConverter.Result.Ok).notes
		assertTrue("$notes", notes.any { it.contains("TLS_RSA_WITH_AES_128_CBC_SHA, X") })
	}

	@Test
	fun `an ECH list that does not read as one is not wrapped for the core`() {
		for (list in listOf("\"not base64 at all\"", "[\"one\",\"two\"]", "\"AAAA\"")) {
			val body = vless("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com",
				"echConfigList":$list}}""")
			val ech = tlsOf(body).getJSONObject("ech")
			assertFalse("$list", ech.has("config"))
		}
		// A two-byte length, then one config of a version and a length: that shape is written.
		val good = "AAj+DQAEAQIDBA=="
		val body = vless("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com",
			"echConfigList":"$good"}}""")
		assertEquals(good, tlsOf(body).getJSONObject("ech").getJSONArray("config").getString(1))
	}

	@Test
	fun `mihomo reads a pattern in its own engine's spelling`() {
		val proxy = """{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com",
			"port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},"streamSettings":{"security":"tls"}}"""
		val body = """{"outbounds":[$proxy,{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[
			{"type":"field","domain":["regexp:(?P<h>ab)+\\.example$","regexp:\\Qa.b\\E$","regexp:x\\Cy"],
			"outboundTag":"direct"}]}}""".replace("\n", "")
		val yaml = SubscriptionConverter.convert(body, jsonToUri = false, xrayToMihomo = true)
		assertTrue(yaml, yaml.contains("DOMAIN-REGEX,(?<h>ab)+\\.example$"))
		assertTrue(yaml, yaml.contains("DOMAIN-REGEX,a\\.b$"))
		assertFalse(yaml, yaml.contains("x\\Cy"))
	}

	@Test
	fun `mihomo leaves out a client certificate that does not read`() {
		val body = vless("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com",
			"certificates":[{"certificate":["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
			"key":["k"]}]}}""")
		val result = MihomoConverter.convert(body)
		assertFalse("$result", result.toString().contains("private-key"))
		assertTrue("$result", result.toString().contains("client certificate that does not read"))
	}

	@Test
	fun `a link Xray would refuse is not written, and is counted and named as skipped`() {
		// One such line costs a Clash client the whole subscription: its parser refuses it all.
		val key = "RvI5xPRmxvhVMSxOsCUDIF1uu4sN0-1Z9RXTVIrGYFk"
		val refused = listOf(
			"\"encryption\":\"mlkem768x25519plus.sideways.1rtt.$key\"",
			"\"encryption\":\"mlkem768x25519plus.native.1rtt.k\"",
			"\"encryption\":\"none\",\"flow\":\"xtls-rprx-direct\""
		)
		for (user in refused) {
			val body = """{"outbounds":[{"protocol":"vless","tag":"n","settings":{"vnext":[
				{"address":"a.example.com","port":443,"users":[{"id":"$uuid",$user}]}]},
				"streamSettings":{"security":"tls"}}]}""".replace("\n", "")
			val result = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
			assertFalse(result.text, result.text.contains("a.example.com"))
			assertEquals(user, 1, result.xraySkipped)
			val notes = result.notes
			assertTrue("$notes", notes.any { it.startsWith("skipped: outbounds[0] (vless): ") })
		}
	}

	@Test
	fun `a Shadowsocks link spells the method the way every client reads it`() {
		val body = """{"outbounds":[{"protocol":"shadowsocks","settings":{"servers":[
			{"address":"a.example.com","port":8388,"method":"chacha20-poly1305","password":"pw"}]}}]}"""
			.replace("\n", "")
		val link = SubscriptionConverter.convertWithStats(body, jsonToUri = true).text
		val userInfo = link.substringAfter("ss://").substringBefore("@")
		assertEquals("chacha20-ietf-poly1305:pw", String(Base64.getUrlDecoder().decode(userInfo)))
	}

	@Test
	fun `a refused node is said once and counted once, however its configuration is laid out`() {
		val body = """{"remarks":"R","outbounds":[{"protocol":"vless","tag":"p","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"$uuid","encryption":"none",
			"flow":"xtls-rprx-direct"}]}]},"streamSettings":{"security":"tls"}}]}"""
		for (layout in listOf(body.replace("\n", ""), body)) {
			val links = SubscriptionConverter.convertWithStats(layout, jsonToUri = true)
			assertEquals(links.text, "", links.text)
			assertEquals(1, links.xraySkipped)
			assertEquals("${links.notes}", 1, links.notes.count { it.startsWith("skipped: ") })
			// mihomo has no document to write, so the body comes back as it came - with mihomo's count.
			val mihomo =
				SubscriptionConverter.convertWithStats(layout, jsonToUri = false, xrayToMihomo = true)
			assertEquals(1, mihomo.xraySkipped)
			assertTrue(mihomo.mihomo)
		}
	}

	@Test
	fun `a node both the filter and the link pass refuse is named once`() {
		val good = """{"protocol":"vless","tag":"good","settings":{"vnext":[
			{"address":"g.example.com","port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
			"streamSettings":{"network":"ws","security":"tls"}}"""
		val bad = """{"protocol":"vless","tag":"bad","settings":{"vnext":[
			{"address":"b.example.com","port":443,
			"users":[{"id":"$uuid","encryption":"none","flow":"xtls-rprx-direct"}]}]},
			"streamSettings":{"security":"tls"}}"""
		val body = """{"remarks":"M","outbounds":[$good,$bad]}""".replace("\n", "")
		for ((sb, mh) in listOf(true to false, false to true, true to true)) {
			val result = SubscriptionConverter.convertWithStats(
				body, jsonToUri = true, xrayToSingBox = sb, dropIncompatibleMihomo = mh
			)
			assertEquals(1, result.xraySkipped)
			assertEquals("${result.notes}", 1, result.notes.count { it.contains("xtls-rprx-direct") })
		}
	}

	@Test
	fun `a count the link pass alone made is worded for the URI conversion`() {
		val body = """{"remarks":"R","outbounds":[{"protocol":"vless","tag":"p","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"$uuid","encryption":"none",
			"flow":"xtls-rprx-direct"}]}]},"streamSettings":{"security":"tls"}}]}""".replace("\n", "")
		val plain = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
		assertEquals(1, plain.xraySkipped)
		assertTrue(plain.uri)
		assertFalse(plain.mihomo)
		// With a core judging, the label names the core.
		val judged = SubscriptionConverter.convertWithStats(body, jsonToUri = true, xrayToSingBox = true)
		assertFalse(judged.uri)
	}

	@Test
	fun `a node dropped for its chain is named as a skipped node in both cores`() {
		fun node(tag: String, extra: String) = """{"protocol":"vless","tag":"$tag","settings":{"vnext":[
			{"address":"$tag.example.com","port":443,"users":[{"id":"$uuid","encryption":"none"$extra}]}]},
			"streamSettings":{"security":"tls"}}""".replace("\n", "")
		val a = node("a", "").dropLast(1) + ""","proxySettings":{"tag":"b"}}"""
		val body = """{"remarks":"C","outbounds":[$a,${node("b", ""","flow":"xtls-rprx-direct"""")}]}"""
		for (mihomo in listOf(false, true)) {
			val result = SubscriptionConverter.convertWithStats(
				body, jsonToUri = false, xrayToSingBox = !mihomo, xrayToMihomo = mihomo
			)
			val chain = result.notes.single { "dials through" in it }
			assertTrue(chain, chain.startsWith("skipped: outbounds[0] (vless): dials through \"b\""))
		}
		val mihomo = MihomoConverter.convert(body)
		assertTrue(mihomo is MihomoConverter.Result.Unsupported)
		assertEquals(2, (mihomo as MihomoConverter.Result.Unsupported).skipped)
	}

	@Test
	fun `a node no client can use is left out by every pass with the same words`() {
		val dead = listOf(
			"""{"protocol":"trojan","tag":"n","settings":{"servers":[
				{"address":"a.example.com","port":443,"password":""}]}}""" to
				missingCredentialRefusal("trojan", "password"),
			"""{"protocol":"shadowsocks","tag":"n","settings":{"servers":[
				{"address":"a.example.com","port":8388,"method":"","password":"pw"}]}}""" to
				MISSING_SS_METHOD_REFUSAL,
			"""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":0,
				"users":[{"id":"$uuid","encryption":"none"}]}]}}""" to
				unusableServerRefusal("vless", "a.example.com", 0),
			"""{"protocol":"hysteria2","tag":"n","settings":{"servers":[
				{"address":"a.example.com","port":443}]},
				"streamSettings":{"security":"tls"}}""" to
				MISSING_HYSTERIA2_PASSWORD_REFUSAL,
			"""{"protocol":"wireguard","tag":"n","settings":{"peers":[
				{"publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
				"endpoint":"d.example.com:51820"}]}}""" to
				"the wireguard outbound has no secretKey, which Xray refuses, so the node never worked",
			"""{"protocol":"wireguard","tag":"n","settings":{
				"secretKey":"cKX1G0yg4Uyq6M6l7xX6h4L3s8m3Jo2eZk1v7d9n2ZA=",
				"peers":[{"endpoint":"d.example.com:51820"}]}}""" to
				"a WireGuard peer has no publicKey, so the tunnel has no one to reach",
			"""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,
				"users":[{"id":"$uuid","encryption":"none"}]}]},"streamSettings":{"network":"ws",
				"security":"reality","realitySettings":{"serverName":"a.example.com",
				"publicKey":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"}}}""" to
				"REALITY runs only over raw, xhttp, grpc or h2, and Xray refuses it over \"ws\", " +
				"so the node never worked",
			"""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,
				"users":[{"id":"$uuid","encryption":"none"}]}]},"streamSettings":{"security":"reality",
				"realitySettings":{"serverName":"a.example.com"}}}""" to
				"realitySettings has no public key, which Xray refuses, so the node never worked"
		)
		for ((node, reason) in dead) {
			val outbound = node.replace("\n", "").replace("\t", "")
			val body = """{"remarks":"R","outbounds":[$outbound]}"""
			val said = "skipped: outbounds[0] (${JSONObject(outbound).getString("protocol")}): $reason"
			for (pass in listOf("links", "sing-box", "mihomo")) {
				val result = SubscriptionConverter.convertWithStats(
					body, jsonToUri = pass == "links", xrayToSingBox = pass == "sing-box",
					xrayToMihomo = pass == "mihomo"
				)
				assertTrue("$pass: ${result.notes}", said in result.notes)
			}
		}
	}

	@Test
	fun `a shadowsocks node that keeps its server on the outbound is carried by every pass`() {
		val body = """{"remarks":"N","outbounds":[{"protocol":"shadowsocks","tag":"n",
			"server":"a.example.com",
			"server_port":8388,"method":"AES-256-GCM","password":"p"}]}""".replace("\n", "").replace("\t", "")
		val sb = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true)
		assertEquals(sb.notes.toString(), 0, sb.xraySkipped)
		val node = JSONObject(sb.text).getJSONArray("outbounds").getJSONObject(0)
		assertEquals("a.example.com", node.getString("server"))
		assertEquals(8388, node.getInt("server_port"))
		assertEquals("aes-256-gcm", node.getString("method"))
		val links = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
		assertTrue(links.text, links.text.startsWith("ss://"))
		val mihomo = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true)
		assertTrue(mihomo.text, mihomo.text.contains("cipher: aes-256-gcm"))
	}

	@Test
	fun `a node is named by what its file holds, whichever neighbour a pass drops`() {
		fun node(tag: String, extra: String) = """{"protocol":"vless","tag":"$tag","settings":{"vnext":[
			{"address":"$tag.example.com","port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
			"streamSettings":{"security":"tls"$extra}}""".replace("\n", "").replace("\t", "")
		// A neighbour every pass drops, and one only sing-box drops (it has no xhttp).
		for (neighbour in listOf(node("dead", "").replace("\"port\":443", "\"port\":0"),
			node("xh", ",\"network\":\"xhttp\""))) {
			val body = """{"remarks":"N","outbounds":[${node("good", "")},$neighbour]}"""
			val sb = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true)
			val tags = JSONObject(sb.text).getJSONArray("outbounds").let { a -> (0 until a.length()).map {
				a.getJSONObject(it).optString("tag") } }
			assertTrue("$tags", "N #good" in tags)
			val links = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
			assertTrue(links.text, links.text.lines().first().endsWith("#N%20%23good"))
			val mihomo = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true)
			// Quoted, since " #" would open a YAML comment.
			assertTrue(mihomo.text, mihomo.text.contains("name: 'N #good'"))
		}
	}

	@Test
	fun `every wireguard key reaches mihomo in the form it decodes, the further peers' too`() {
		val std = "++++++++++++++++++++++++++++++++++++++++//4="
		val url = std.replace('+', '-').replace('/', '_').trimEnd('=')
		val body = """{"remarks":"W","outbounds":[{"protocol":"wireguard","tag":"w","settings":{
			"secretKey":"cKX1G0yg4Uyq6M6l7xX6h4L3s8m3Jo2eZk1v7d9n2ZA=","address":["10.0.0.2/32"],"peers":[
			{"publicKey":"$std","endpoint":"a.example.com:51820"},
			{"publicKey":"$url","endpoint":"b.example.com:51820"}]}}]}""".replace("\n", "").replace("\t", "")
		val yaml = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true).text
		assertFalse(yaml, url in yaml)
		assertTrue(yaml, "public-key: $std" in yaml.substringAfter("server: b.example.com"))
	}

	@Test
	fun `a listed wireguard peer without allowedIPs gets the Xray default, not a refused file`() {
		val body = """{"remarks":"W","outbounds":[{"protocol":"wireguard","tag":"w","settings":{
			"secretKey":"cKX1G0yg4Uyq6M6l7xX6h4L3s8m3Jo2eZk1v7d9n2ZA=","address":["10.0.0.2/32"],"peers":[
			{"publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","endpoint":"a.example.com:51820"},
			{"publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
			"endpoint":"b.example.com:51820"}]}}]}"""
			.replace("\n", "").replace("\t", "")
		val yaml = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true).text
		val peers = yaml.substringAfter("    peers:").substringBefore("proxy-groups:")
		assertEquals(yaml, 2, Regex("allowed-ips: \\[0\\.0\\.0\\.0/0, '?::/0'?]").findAll(peers).count())
	}
}
