package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// VLESS, Trojan and Hysteria2 written the way sing-box writes them - server, port and credential beside
// the protocol - read by every pass as Shadowsocks, VMess and TUIC are; and a stream kept in sing-box's own
// tls or transport block, which no pass translates, left out rather than dialled without it.
class SingBoxShapedNodeTest {
	private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
	private val vless = """{"protocol":"vless","tag":"v","server":"b.example.com","server_port":443,""" +
		""""uuid":"$uuid","flow":"xtls-rprx-vision","streamSettings":{"network":"tcp","security":"tls",""" +
		""""tlsSettings":{"serverName":"b.example.com"}}}"""
	private val trojan = """{"protocol":"trojan","tag":"t","server":"c.example.com","server_port":443,""" +
		""""password":"pw","streamSettings":{"network":"ws","security":"tls",""" +
		""""tlsSettings":{"serverName":"c.example.com"},"wsSettings":{"path":"/t"}}}"""
	private val hysteria2 = """{"protocol":"hysteria2","tag":"h","server":"d.example.com",""" +
		""""server_port":443,"password":"pw","up_mbps":50,"down_mbps":100,""" +
		""""obfs":{"type":"salamander","password":"ob"},""" +
		""""server_ports":["20000:30000"],"hop_interval":"30s",""" +
		""""tls":{"enabled":true,"server_name":"d.example.com","insecure":true}}"""

	private fun links(body: String, singBox: Boolean = false, mihomo: Boolean = false) =
		SubscriptionConverter.convertWithStats(body, ConversionFlags(true, singBox, false, false, mihomo))

	private val singBoxMode = ConversionFlags(false, true, false, false)

	private fun singBox(node: String) =
		(SingBoxConverter.convert("""{"outbounds":[$node]}""", "N") as SingBoxConverter.Result.Ok)
			.config.getJSONArray("outbounds").getJSONObject(0)

	private fun mihomo(node: String) =
		(MihomoConverter.convert("""{"outbounds":[$node]}""") as MihomoConverter.Result.Ok).yaml

	@Test
	fun `every pass reads VLESS, Trojan and Hysteria2 written the way sing-box writes them`() {
		val vlessLink = links(vless).text
		assertTrue(vlessLink, vlessLink.startsWith("vless://$uuid@b.example.com:443?"))
		assertTrue(vlessLink, "flow=xtls-rprx-vision" in vlessLink && "sni=b.example.com" in vlessLink)
		val trojanLink = links(trojan).text
		assertTrue(trojanLink, trojanLink.startsWith("trojan://pw@c.example.com:443?"))
		assertTrue(trojanLink, "path=%2Ft" in trojanLink)
		val hysteriaLink = links(hysteria2).text
		assertTrue(hysteriaLink, hysteriaLink.startsWith("hysteria2://pw@d.example.com:443/?"))
		for (part in listOf("obfs-password=ob", "insecure=1", "mport=20000-30000", "mportHopInt=30")) {
			assertTrue(hysteriaLink, part in hysteriaLink)
		}

		val vlessNode = singBox(vless)
		assertEquals("b.example.com", vlessNode.getString("server"))
		assertEquals("xtls-rprx-vision", vlessNode.getString("flow"))
		assertEquals("ws", singBox(trojan).getJSONObject("transport").getString("type"))
		val hysteriaNode = singBox(hysteria2)
		assertEquals("20000:30000", hysteriaNode.getJSONArray("server_ports").getString(0))
		assertEquals("ob", hysteriaNode.getJSONObject("obfs").getString("password"))
		assertTrue("$hysteriaNode", hysteriaNode.getJSONObject("tls").getBoolean("insecure"))

		val vlessYaml = mihomo(vless)
		assertTrue(vlessYaml, "uuid: $uuid" in vlessYaml && "flow: xtls-rprx-vision" in vlessYaml)
		assertTrue(mihomo(trojan), "password: pw" in mihomo(trojan))
		val hysteriaYaml = mihomo(hysteria2)
		val parts = listOf("ports: 20000-30000", "obfs-password: ob", "up: 50 Mbps", "skip-cert-verify: true")
		for (part in parts) {
			assertTrue(hysteriaYaml, part in hysteriaYaml)
		}

		// Alone on a line too, in sing-box mode as in the others.
		val alone = SubscriptionConverter.convertWithStats(trojan, singBoxMode)
		assertTrue(alone.text, alone.text.startsWith("{\"log\""))
		// A settings left null is none, as the VMess reader takes it.
		val nulled = links(trojan.replace(""""tag":"t",""", """"tag":"t","settings":null,""")).text
		assertTrue(nulled, nulled.startsWith("trojan://pw@c.example.com:443?"))
	}

	@Test
	fun `a stream in sing-box's own block is left out of the documents and kept as written by a link`() {
		val tls = """{"protocol":"vmess","tag":"m","server":"e.example.com","server_port":443,""" +
			""""uuid":"$uuid","tls":{"enabled":true,"server_name":"e.example.com"}}"""
		val transport = """{"protocol":"trojan","tag":"t","server":"c.example.com","server_port":443,""" +
			""""password":"pw","streamSettings":{"security":"tls",""" +
			""""tlsSettings":{"serverName":"c.example.com"}},""" +
			""""transport":{"type":"grpc","service_name":"s"}}"""
		for ((node, reason) in listOf(tls to "without TLS", transport to "over raw TCP rather than grpc")) {
			val sing = SingBoxConverter.convert("""{"outbounds":[$node]}""", "N")
			assertTrue("$sing", sing is SingBoxConverter.Result.Unsupported && "$sing".contains(reason))
			val yaml = MihomoConverter.convert("""{"outbounds":[$node]}""")
			assertTrue("$yaml", yaml is MihomoConverter.Result.Unsupported && "$yaml".contains(reason))
			val kept = links(node)
			assertTrue(kept.text, kept.text.startsWith("{"))
			assertTrue("${kept.notes}", kept.notes.any { reason in it })
			// Alone in sing-box mode it goes back as it came, saying why.
			val back = SubscriptionConverter.convertWithStats(node, singBoxMode)
			assertEquals(node, back.text)
			assertTrue("${back.notes}", back.notes.any { reason in it && !it.startsWith("skipped: ") })
		}
		// What streamSettings secures decides, and a block switched off is none.
		val named = tls.replace(""""tls":""", """"streamSettings":{"security":"tls"},"tls":""")
		assertTrue(links(named).text.startsWith("vmess://"))
		val off = tls.replace(""""enabled":true""", """"enabled":false""")
		assertTrue(links(off).text.startsWith("vmess://"))
		// Naming no TLS, or raw TCP, streamSettings leaves it to the block.
		val unsecured = """"streamSettings":{"security":"NONE","network":"raw"},"tls":"""
		val plain = tls.replace(""""tls":""", unsecured)
		val overTcp = tls.replace(""""tls":{"enabled":true,"server_name":"e.example.com"}""",
			""""streamSettings":{"network":"tcp"},"transport":{"type":"ws","path":"/w"}""")
		for (node in listOf(plain, overTcp)) {
			assertTrue(links(node).text, links(node).text.startsWith("{"))
		}
		// Written with settings, a node is read as Xray reads it, past a block Xray does not know.
		val servers = """"settings":{"servers":[{"address":"c.example.com","port":443,"password":"pw"}]}"""
		val stray = """{"protocol":"trojan","tag":"t",$servers,"streamSettings":{"network":"tcp"},""" +
			""""tls":{"enabled":true,"server_name":"c.example.com"},"transport":{"type":"grpc"}}"""
		assertTrue(links(stray).text, links(stray).text.startsWith("trojan://pw@c.example.com:443?"))
		assertTrue("security=none" in links(stray).text && "type=tcp" in links(stray).text)
		val strayNode = singBox(stray)
		assertFalse("$strayNode", strayNode.has("tls") || strayNode.has("transport"))
		val strayYaml = MihomoConverter.convert("""{"outbounds":[$stray]}""")
		assertTrue("$strayYaml", MIHOMO_PLAINTEXT_REFUSAL in "$strayYaml")
		val vnext = """{"vnext":[{"address":"e.example.com","port":443,"users":[{"id":"$uuid"}]}]}"""
		val written = tls.replace(""""tag":"m",""", """"tag":"m","settings":$vnext,""")
		assertTrue(links(written).text, links(written).text.startsWith("vmess://"))
		// VMess settings that name no server leave it read from beside the protocol, its block with it.
		val noTls = "without TLS"
		for (hollow in listOf("{}", """{"vnext":[]}""", """{"vnext":[{"port":443}]}""")) {
			val node = tls.replace(""""tag":"m",""", """"tag":"m","settings":$hollow,""")
			val sing = SingBoxConverter.convert("""{"outbounds":[$node]}""", "N")
			assertTrue("$sing", sing is SingBoxConverter.Result.Unsupported && "$sing".contains(noTls))
			val yaml = MihomoConverter.convert("""{"outbounds":[$node]}""")
			assertTrue("$yaml", yaml is MihomoConverter.Result.Unsupported && "$yaml".contains(noTls))
			assertTrue(links(node).text, links(node).text.startsWith("{"))
		}
		// So does any node Xray has not whole in its settings, whatever a reader fills in from elsewhere:
		// a server or port beside the protocol, an id past a blank one, names only mihomo reads, a bad port.
		val settings = listOf(
			"""{"vnext":[{"address":"f.example.com","users":[{"id":"$uuid"}]}]}""",
			"""{"vnext":[{"port":443,"users":[{"id":"$uuid"}]}]}""",
			"""{"vnext":[{"address":"f.example.com","port":443,"users":[{"id":"  "}]}]}""",
			"""{"server":"e.example.com","server_port":443,"uuid":"$uuid"}""",
			"""{"address":"","vnext":[{"address":"f.example.com","port":443,"users":[{"id":"$uuid"}]}]}"""
		)
		val partial = settings.map { tls.replace(""""tag":"m",""", """"tag":"m","settings":$it,""") } +
			tls.replace(""""server_port":443""", """"server_port":443.5""")
		for (node in partial) {
			val kept = links(node)
			assertTrue(kept.text, kept.text.startsWith("{"))
			assertTrue("${kept.notes}", kept.notes.any { noTls in it })
			val yaml = MihomoConverter.convert("""{"outbounds":[$node]}""")
			assertTrue("$yaml", yaml is MihomoConverter.Result.Unsupported && "$yaml".contains(noTls))
		}
		// And a node keyed by type, as sing-box keys it: Xray reads none, the links would read it anyway.
		val typedVmess = tls.replace(""""protocol":"vmess"""", """"type":"vmess"""")
		val user = """{"id":"$uuid","encryption":"none"}"""
		val vlessNext = """{"vnext":[{"address":"b.example.com","port":443,"users":[$user]}]}"""
		val typedVless = """{"type":"vless","tag":"v","settings":$vlessNext,"tls":{"enabled":true}}"""
		for (node in listOf(typedVmess, typedVless)) {
			val kept = links(node)
			assertTrue(kept.text, kept.text.startsWith("{"))
			assertTrue("${kept.notes}", kept.notes.any { noTls in it })
		}
	}

	@Test
	fun `a trojan link without TLS is left out under the mihomo box`() {
		val flat = """{"protocol":"trojan","tag":"t","server":"c.example.com","server_port":443,""" +
			""""password":"pw"}"""
		val servers = """"settings":{"servers":[{"address":"c.example.com","port":443,"password":"pw"}]}"""
		val written = """{"protocol":"trojan","tag":"t",$servers,"streamSettings":{"network":"tcp"}}"""
		for (plain in listOf(flat, written)) {
			assertTrue(links(plain).text.startsWith("trojan://"))
			assertTrue(links(plain, singBox = true).text.startsWith("trojan://"))
			val dropped = links(plain, mihomo = true)
			assertEquals("", dropped.text)
			assertTrue("${dropped.notes}", dropped.notes.single().contains(MIHOMO_PLAINTEXT_REFUSAL))
		}
		assertFalse(links(trojan, mihomo = true).text.isEmpty())
		// QUIC is never plaintext: what mihomo lacks there is the transport, in its links and its document.
		val quic = written.replace(""""network":"tcp"""", """"network":"quic"""")
		val quicLinks = links(quic, mihomo = true)
		assertEquals("", quicLinks.text)
		assertTrue("${quicLinks.notes}", quicLinks.notes.single().contains("runs no QUIC transport"))
		val document = MihomoConverter.convert(quic)
		assertTrue("$document", document is MihomoConverter.Result.Unsupported)
		assertTrue("$document", "no QUIC transport" in "$document")
		assertFalse("$document", MIHOMO_PLAINTEXT_REFUSAL in "$document")
	}

	@Test
	fun `the sing-box document names and balances nodes written the way sing-box writes them`() {
		val single = SingBoxConverter.convert("""{"remarks":"MyNode","outbounds":[$vless]}""", "N")
		val node = (single as SingBoxConverter.Result.Ok).config.getJSONArray("outbounds").getJSONObject(0)
		assertEquals("MyNode", node.getString("tag"))
		val balancer = """"routing":{"balancers":[{"tag":"bal","selector":["p-"]}],""" +
			""""rules":[{"type":"field","network":"tcp,udp","balancerTag":"bal"}]}"""
		val members = vless.replace(""""tag":"v"""", """"tag":"p-1"""") + "," +
			trojan.replace(""""tag":"t"""", """"tag":"p-2"""")
		val balanced = SingBoxConverter.convert("""{"remarks":"Bal","outbounds":[$members],$balancer}""", "N")
		val outbounds = (balanced as SingBoxConverter.Result.Ok).config.getJSONArray("outbounds")
		val tags = (0 until outbounds.length()).map { outbounds.getJSONObject(it).getString("tag") }
		assertTrue("$tags", "Bal #p-1" in tags && "Bal #p-2" in tags && "bal" in tags)
		assertFalse("${balanced.notes}", balanced.notes.any { "selects no outbound" in it })
	}

	@Test
	fun `what such a node says beside its server is read, or keeps it out`() {
		// A VLESS encryption beside the protocol is the node's own, not none.
		val encrypted = vless.replace(""""flow":"xtls-rprx-vision",""", """"encryption":"foo",""")
		assertEquals("", links(encrypted).text)
		assertTrue("${links(encrypted).notes}", links(encrypted).notes.any { "encryption \"foo\"" in it })
		// Hops as sing-box 1.14 writes them, up to hop_interval_max, and a hop list left null.
		val ranged = hysteria2.replace(""""hop_interval":"30s"""", """"hop_interval":"10s",""" +
			""""hop_interval_max":"30s"""")
		assertTrue(mihomo(ranged), "hop-interval: 10-30" in mihomo(ranged))
		val portless = hysteria2.replace(""""server_ports":["20000:30000"],""", """"server_ports":null,""")
		assertFalse("${links(portless).notes}", links(portless).notes.any { "port hopping" in it })
		// A raw TCP transport block, by either of Xray's names, is no transport to translate.
		for (type in listOf("tcp", "raw")) {
			for (network in listOf("", """"network":"raw",""")) {
				val raw = trojan.replace(""""network":"ws",""", network)
					.replace(""""streamSettings":""", """"transport":{"type":"$type"},"streamSettings":""")
				assertTrue(links(raw).text, links(raw).text.startsWith("trojan://"))
			}
		}
	}

	@Test
	fun `a Hysteria2 tls block's own CA or pin keeps the node out of documents, as written in a link`() {
		val why = "its tls block names a CA or pin of its own"
		for (own in listOf(""""certificate":["c"]""", """"certificate_public_key_sha256":["cGlu"]""",
			""""certificate_sha256":"cGlu"""")) {
			val trusting = """{"outbounds":[${hysteria2.replace(""""insecure":true""", own)}]}"""
			val yaml = MihomoConverter.convert(trusting)
			assertTrue("$yaml", yaml is MihomoConverter.Result.Unsupported && "$yaml".contains(why))
			val sing = SingBoxConverter.convert(trusting, "N")
			assertTrue("$sing", sing is SingBoxConverter.Result.Unsupported && "$sing".contains(why))
			val kept = links(trusting)
			assertTrue(kept.text, kept.text.startsWith("{") && own.substringBefore(':') in kept.text)
		}
		// With the check skipped the CA decides nothing.
		val skipped = hysteria2.replace(""""insecure":true""", """"insecure":true,"certificate":["c"]""")
		assertTrue(links(skipped).text, links(skipped).text.startsWith("hysteria2://"))
		// Keyed by type, with its server in settings, the links read it all the same.
		val settings = """"settings":{"address":"d.example.com","port":443,"password":"pw",""" +
			""""tls":{"enabled":true,"server_name":"d.example.com","certificate_sha256":["aa"]}}"""
		val typed = links("""{"type":"hysteria2","tag":"h",$settings}""")
		assertTrue(typed.text, typed.text.startsWith("{"))
		assertTrue("${typed.notes}", typed.notes.any { why in it })
	}

	@Test
	fun `a node written the way sing-box writes it goes back in the form it came in`() {
		val blocked = """{"protocol":"vless","tag":"v","server":"b.example.com","server_port":443,""" +
			""""uuid":"$uuid","tls":{"enabled":true,"server_name":"b.example.com"}}"""
		val kept = links("""{"outbounds":[$blocked]}""")
		val line = JSONObject(kept.text).getJSONArray("outbounds").getJSONObject(0)
		assertEquals(JSONObject(blocked).toString(), line.toString())
	}
}
