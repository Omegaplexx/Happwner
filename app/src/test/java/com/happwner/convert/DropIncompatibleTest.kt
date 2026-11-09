package com.happwner.convert

import android.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// The URI mode's two "drop what this core could not carry" boxes. They are separate switches
// because the cores refuse different things: sing-box has no XHTTP transport, mihomo has no QUIC
// one, and a person converting for one of them should not lose what the other could not take.
class DropIncompatibleTest {

	private fun node(stream: String) = """
        {"remarks":"Node","outbounds":[{"protocol":"vless","tag":"proxy",
          "settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"u","encryption":"none"}]}]},
          "streamSettings":$stream}]}
	""".trimIndent().replace("\n", " ")

	private val xhttp = node(
		"""{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"a.example.com"},
           "xhttpSettings":{"path":"/x"}}"""
	)
	private val quic = node(
		"""{"network":"quic","security":"tls","tlsSettings":{"serverName":"a.example.com"},
           "quicSettings":{}}"""
	)

	private fun uri(body: String, dropSb: Boolean = false, dropMihomo: Boolean = false) =
		SubscriptionConverter.convertWithStats(
			body,
			jsonToUri = true,
			xrayToSingBox = dropSb,
			dropIncompatibleMihomo = dropMihomo
		)

	@Test
	fun `with neither box ticked both nodes become links`() {
		assertTrue(uri(xhttp).text.startsWith("vless://"))
		assertTrue(uri(quic).text.startsWith("vless://"))
	}

	@Test
	fun `the sing-box box drops what sing-box cannot carry, and nothing else`() {
		val dropped = uri(xhttp, dropSb = true)
		assertEquals("", dropped.text)
		assertEquals(1, dropped.xraySkipped)
		assertTrue(dropped.notes.toString(), dropped.notes.any { it.contains("xhttp") })

		assertTrue(uri(quic, dropSb = true).text.startsWith("vless://"))
	}

	@Test
	fun `the mihomo box drops what mihomo cannot carry, and nothing else`() {
		val dropped = uri(quic, dropMihomo = true)
		assertEquals("", dropped.text)
		assertEquals(1, dropped.xraySkipped)
		assertTrue(dropped.notes.toString(), dropped.notes.any { it.contains("QUIC", ignoreCase = true) })

		assertTrue(uri(xhttp, dropMihomo = true).text.startsWith("vless://"))
	}

	@Test
	fun `both ticked keeps only what both cores can carry`() {
		assertEquals("", uri(xhttp, dropSb = true, dropMihomo = true).text)
		assertEquals("", uri(quic, dropSb = true, dropMihomo = true).text)

		val plain = node(
			"""{"network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com"},
                 "wsSettings":{"path":"/p"}}""")
		val kept = uri(plain, dropSb = true, dropMihomo = true)
		assertTrue(kept.text, kept.text.startsWith("vless://"))
		assertEquals(0, kept.xraySkipped)
	}

	// Asking for a mihomo document is not the same as asking to drop what mihomo cannot carry, and
	// the flag that means the first must keep meaning it beside the URI pass.
	@Test
	fun `asking for a mihomo document still produces one`() {
		val out = SubscriptionConverter.convertWithStats(
			node("""{"network":"ws","wsSettings":{"path":"/p"}}"""),
			jsonToUri = true, xrayToSingBox = true, xrayToMihomo = true
		)
		assertTrue(out.text, out.text.contains("proxy-groups:"))
		assertFalse(out.text, out.text.contains("vless://"))
	}

	// A lone outbound is never judged. The two readers do not agree about which of those shapes
	// they can parse at all, and a node one of them could not read is not a node the person asked
	// to throw away, so neither box touches one.
	@Test
	fun `neither box touches a node that arrived on its own`() {
		val lone = listOf(
			"""{"protocol":"shadowsocks","tag":"n","server":"a.example.com","server_port":8388,
               "method":"chacha20-ietf-poly1305","password":"pw"}""",
			"""{"protocol":"vmess","tag":"n","server":"a.example.com","server_port":443,
               "uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"}""",
			"""{"protocol":"tuic","tag":"n","server":"a.example.com","server_port":443,
               "uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"}""",
			"""{"protocol":"freedom","tag":"direct"}"""
		).map { it.trimIndent().replace("\n", " ") }

		for (body in lone) {
			val plain = SubscriptionConverter.convertWithStats(body, jsonToUri = true).text
			for (stats in listOf(
				uri(body, dropSb = true),
				uri(body, dropMihomo = true),
				uri(body, dropSb = true, dropMihomo = true)
			)) {
				assertEquals(body, plain, stats.text)
				assertEquals(body, 0, stats.xraySkipped)
			}
		}
	}

	// The same nodes read by mihomo itself: a server written the way sing-box writes it is the same
	// server, and refusing to read it would leave a working node behind.
	@Test
	fun `mihomo reads a node written the way sing-box writes it`() {
		val nodes = listOf(
			"""{"protocol":"shadowsocks","tag":"n","server":"a.example.com","server_port":8388,
               "method":"chacha20-ietf-poly1305","password":"pw"}""" to "cipher: chacha20-ietf-poly1305",
			"""{"protocol":"vmess","tag":"n","server":"a.example.com","server_port":443,
               "uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}""" to
				"uuid: b831381d-6324-4d53-ad4f-8cda48b30811",
			"""{"protocol":"tuic","tag":"n","server":"a.example.com","server_port":443,
               "uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"}""" to
				"uuid: 9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"
		)
		for ((body, expected) in nodes) {
			val result = MihomoConverter.convert(body.trimIndent().replace("\n", " "))
			assertTrue("mihomo refused $body: $result", result is MihomoConverter.Result.Ok)
			val yaml = (result as MihomoConverter.Result.Ok).yaml
			assertTrue(yaml, yaml.contains("server: a.example.com"))
			assertTrue(yaml, yaml.contains(expected))
		}
	}

	// Among a configuration's outbounds sing-box reads them as well, so such a node is the same node in
	// every pass.
	@Test
	fun `sing-box reads a node written the way sing-box writes it`() {
		val vmess = """{"protocol":"vmess","tag":"n","server":"a.example.com","server_port":443,""" +
			""""uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"auto","alter_id":0}"""
		val tuic = """{"protocol":"tuic","tag":"n","server":"a.example.com","server_port":443,""" +
			""""uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"}"""
		for ((body, uuid) in listOf(
			vmess to "b831381d-6324-4d53-ad4f-8cda48b30811", tuic to "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"
		)) {
			val result = SingBoxConverter.convert("""{"outbounds":[$body]}""", "N")
			assertTrue("sing-box refused $body: $result", result is SingBoxConverter.Result.Ok)
			val outbounds = (result as SingBoxConverter.Result.Ok).config.getJSONArray("outbounds")
			val node = (0 until outbounds.length()).map { outbounds.getJSONObject(it) }
				.first { it.optString("uuid") == uuid }
			assertEquals("a.example.com", node.getString("server"))
			assertEquals(443, node.getInt("server_port"))
		}
	}

	// Alone as among a configuration's outbounds: sing-box mode reads such a node, and one it does not read
	// or convert goes back as it came, as it went before - nothing of it lost.
	@Test
	fun `sing-box mode reads a lone node written the way sing-box writes it, and hands back the rest`() {
		val flags = ConversionFlags(false, true, false, false)
		val vmess = """{"protocol":"vmess","tag":"n","server":"a.example.com","server_port":443,""" +
			""""uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}"""
		val shadowsocks = """{"protocol":"shadowsocks","tag":"s","server":"a.example.com",""" +
			""""server_port":8388,"method":"chacha20-ietf-poly1305","password":"pw"}"""
		val tuic = """{"protocol":"tuic","tag":"t","server":"a.example.com","server_port":443,""" +
			""""uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"}"""
		for ((body, type) in listOf(vmess to "vmess", shadowsocks to "shadowsocks", tuic to "tuic")) {
			val document = JSONObject(SubscriptionConverter.convertWithStats(body, flags).text)
			val node = document.getJSONArray("outbounds").getJSONObject(0)
			assertEquals(type, node.getString("type"))
			assertEquals("a.example.com", node.getString("server"))
		}
		val vless = """{"protocol":"vless","tag":"v","server":"b.example.com","server_port":443,""" +
			""""uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","tls":{"enabled":true}}"""
		val back = SubscriptionConverter.convertWithStats(vless, flags)
		assertEquals(vless, back.text)
		assertTrue("${back.notes}", back.notes.any { "tls block" in it })
		// Among others, the one not read goes back beside the document rather than nowhere.
		val lines = SubscriptionConverter.convertWithStats("[$vmess,$vless]", flags).text.lines()
		val first = JSONObject(lines[0]).getJSONArray("outbounds").getJSONObject(0)
		assertEquals("vmess", first.getString("type"))
		assertEquals(JSONObject(vless).toString(), JSONObject(lines[1]).toString())
		// An entry that is no object at all goes back as written too: a link, a number, a list.
		val mixed = SubscriptionConverter.convertWithStats("[$vmess,\"vless://a@b:1#k\",42,[1]]", flags)
		assertEquals(listOf("vless://a@b:1#k", "42", "[1]"), mixed.text.lines().drop(1))
	}

	// A TUIC node written the way sing-box writes it keeps its TLS in a block of its own, read by every pass.
	@Test
	fun `every pass reads the tls block of a node written the way sing-box writes it`() {
		val tuic = """{"protocol":"tuic","tag":"t","server":"a.example.com","server_port":443,""" +
			""""uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw",""" +
			""""tls":{"enabled":true,"server_name":"t.example.com","insecure":true}}"""
		val body = """{"outbounds":[$tuic]}"""
		val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		val tls = singBox.config.getJSONArray("outbounds").getJSONObject(0).getJSONObject("tls")
		assertEquals("t.example.com", tls.getString("server_name"))
		assertTrue("$tls", tls.getBoolean("insecure"))
		val yaml = (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).yaml
		assertTrue(yaml, "sni: t.example.com" in yaml && "skip-cert-verify: true" in yaml)
		val link = SubscriptionConverter.convertWithStats(body, jsonToUri = true).text
		assertTrue(link, "sni=t.example.com" in link && "allow_insecure=1" in link)
		// Beside settings as well, filling in what they leave out.
		val hybrid = """{"outbounds":[{"protocol":"tuic","tag":"t","settings":{"address":"a.example.com",""" +
			""""port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"},""" +
			""""tls":{"enabled":true,"server_name":"t.example.com","insecure":true}}]}"""
		val both = SubscriptionConverter.convertWithStats(hybrid, jsonToUri = true).text
		assertTrue(both, "sni=t.example.com" in both && "allow_insecure=1" in both)
		val hybridYaml = (MihomoConverter.convert(hybrid) as MihomoConverter.Result.Ok).yaml
		assertTrue(hybridYaml, "sni: t.example.com" in hybridYaml)
		val hybridBox = SingBoxConverter.convert(hybrid, "N") as SingBoxConverter.Result.Ok
		val hybridTls = hybridBox.config.getJSONArray("outbounds").getJSONObject(0).getJSONObject("tls")
		assertEquals("t.example.com", hybridTls.getString("server_name"))
	}

	// A node with no link form comes back as a configuration of one outbound. That leftover is the
	// same kind of thing the box was ticked to remove, so it is judged too - and only then does
	// pressing the button twice give the same answer as pressing it once.
	@Test
	fun `a leftover the core cannot carry is dropped with the rest`() {
		val vless = """{"protocol":"vless","tag":"a",
          "settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}"""
		val ssr = """{"protocol":"shadowsocksr","tag":"b","settings":{"servers":[
            {"address":"b.example.com","port":443,"password":"pw"}]}}"""
		val body = """{"remarks":"M","outbounds":[$vless,$ssr]}""".trimIndent().replace("\n", " ")

		// Untouched, the node with no link form is kept as a configuration of its own.
		val plain = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
		assertTrue(plain.text, plain.text.contains("vless://"))
		assertTrue(plain.text, plain.text.contains("shadowsocksr"))

		val dropped = uri(body, dropSb = true)
		assertTrue(dropped.text, dropped.text.startsWith("vless://"))
		assertFalse("the leftover was left behind: ${dropped.text}", dropped.text.contains("shadowsocksr"))
		assertEquals(1, dropped.xraySkipped)

		// Idempotent: the answer does not depend on how many times it is asked for.
		assertEquals(dropped.text, uri(dropped.text, dropSb = true).text)
	}

	// Precise rather than blanket: a node with no link form that the core does carry stays.
	@Test
	fun `a leftover the core can carry is kept`() {
		val vless = """{"protocol":"vless","tag":"a",
          "settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}"""
		val wireguard = """{"protocol":"wireguard","tag":"w","settings":{
            "secretKey":"cKX1G0yg4Uyq6M6l7xX6h4L3s8m3Jo2eZk1v7d9n2ZA=","address":["10.0.0.2/32"],
            "peers":[{"publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
            "endpoint":"d.example.com:51820"}]}}"""
		val body = """{"remarks":"M","outbounds":[$vless,$wireguard]}""".trimIndent().replace("\n", " ")

		val dropped = uri(body, dropSb = true)
		assertTrue(dropped.text, dropped.text.contains("vless://"))
		assertTrue("sing-box carries wireguard, so it must stay: ${dropped.text}",
			dropped.text.contains("wireguard"))
		assertEquals(0, dropped.xraySkipped)
	}

	// The leftover is judged by the cores where its place is known, so its reason is said once, and
	// a wrapped body still comes back wrapped.
	@Test
	fun `judging the leftover costs neither a repeated reason nor the wrapping`() {
		val vless = """{"protocol":"vless","tag":"a",
          "settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}"""
		val ssr = """{"protocol":"shadowsocksr","tag":"b","settings":{"servers":[
            {"address":"b.example.com","port":443,"password":"pw"}]}}"""
		val body = """{"remarks":"M","outbounds":[$vless,$ssr]}""".trimIndent().replace("\n", " ")

		val stats = uri(body, dropSb = true)
		val repeated = stats.notes.groupBy { it }.filterValues { it.size > 1 }.keys
		assertTrue("a reason was given twice: $repeated", repeated.isEmpty())

		val encoded = Base64.encodeToString(body.toByteArray(), Base64.NO_WRAP)
		val wrapped = SubscriptionConverter.convertWithStats(
			encoded, jsonToUri = true, base64Result = true, xrayToSingBox = true
		)
		val decoded = String(Base64.decode(wrapped.text.trim(), Base64.DEFAULT))
		assertTrue(decoded, decoded.startsWith("vless://"))
		assertFalse(decoded, decoded.contains("shadowsocksr"))
	}
}
