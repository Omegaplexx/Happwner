package com.happwner.convert

import android.util.Base64
import java.net.URI
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// A link as the clients it is made for take it: a CA pinned where it is the server's own certificate and
// carried whole where husi reads one, a name to verify sent where a client checks the one sent, REALITY as
// mihomo dials it - and under a drop box, what that box's client could not connect from left out.
class LinkClientsTest {
	private val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""

	// One node of the protocol at h.example.com:443 over TLS with these settings.
	private fun node(protocol: String, tls: String): String {
		val stream = """{"network":"tcp","security":"tls","tlsSettings":$tls}"""
		val outbound = when (protocol) {
			"vless", "vmess" -> """{"protocol":"$protocol","tag":"n","settings":{"vnext":[""" +
				"""{"address":"h.example.com","port":443,"users":[$user]}]},"streamSettings":$stream}"""
			"trojan" -> """{"protocol":"trojan","tag":"n","settings":{"servers":[""" +
				"""{"address":"h.example.com","port":443,"password":"pw"}]},"streamSettings":$stream}"""
			"hysteria2" -> """{"protocol":"hysteria","tag":"n","settings":{"version":2,""" +
				""""address":"h.example.com","port":443},"streamSettings":{"network":"hysteria",""" +
				""""hysteriaSettings":{"version":2,"auth":"pw"},"security":"tls","tlsSettings":$tls}}"""
			"hysteria" -> """{"protocol":"hysteria","tag":"n","settings":{"servers":[""" +
				"""{"address":"h.example.com","port":443,"auth_str":"pw","up_mbps":50,"down_mbps":100}]},""" +
				""""streamSettings":{"security":"tls","tlsSettings":$tls}}"""
			"tuic" -> """{"protocol":"tuic","tag":"n","server":"h.example.com","server_port":443,""" +
				""""uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw",""" +
				""""streamSettings":{"security":"tls","tlsSettings":$tls}}"""
			"http" -> """{"protocol":"http","tag":"n","settings":{"servers":[""" +
				"""{"address":"h.example.com","port":443}]},"streamSettings":$stream}"""
			"shadowsocks" -> """{"protocol":"shadowsocks","tag":"n","settings":{"servers":[""" +
				"""{"address":"h.example.com","port":443,"method":"aes-128-gcm","password":"pw"}]},""" +
				""""streamSettings":{"network":"ws","security":"tls","tlsSettings":$tls,""" +
				""""wsSettings":{"path":"/p"}}}"""
			else -> error(protocol)
		}
		return """{"remarks":"N","outbounds":[$outbound]}"""
	}

	private fun links(body: String, singBox: Boolean = false, mihomo: Boolean = false) =
		SubscriptionConverter.convertWithStats(body, ConversionFlags(true, singBox, false, false, mihomo))

	// A parameter of a link, decoded; a vmess link's from its blob.
	private fun param(link: String, name: String): String? {
		if (!link.startsWith("vmess://")) return queryOf(link)[name]
		val blob = JSONObject(String(Base64.decode(link.removePrefix("vmess://"), Base64.DEFAULT)))
		return blob.optString(name).takeIf { it.isNotEmpty() }
	}

	// TLS for h.example.com verified against a CA: the server's own certificate, or one that signs others.
	private fun verifiedBy(lines: List<String>, more: String = "") =
		"""{"serverName":"h.example.com"$more,"certificates":${verifying(lines)}}"""

	private val own = verifiedBy(OWN_CERTIFICATE_LINES)
	private val issuing = verifiedBy(ISSUING_CERTIFICATE_LINES)
	private val ownPem = OWN_CERTIFICATE_LINES.joinToString("\n")
	private val issuingPem = ISSUING_CERTIFICATE_LINES.joinToString("\n")

	@Test
	fun `the server's own certificate as its CA is pinned, and carried whole where husi reads one`() {
		for (protocol in listOf("vless", "trojan")) {
			val result = links(node(protocol, own))
			assertEquals(result.text, OWN_CERTIFICATE_PIN, param(result.text, "pcs"))
			assertEquals(result.text, ownPem, param(result.text, "cert"))
			assertTrue("${result.notes}", result.notes.any { "the link pins it, and carries it whole" in it })
			assertTrue("${result.notes}", result.notes.none { "certificates has no link form" in it })
		}
		val vmess = links(node("vmess", own))
		assertEquals(vmess.text, OWN_CERTIFICATE_PIN, param(vmess.text, "pcs"))
		assertNull(vmess.text, param(vmess.text, "cert"))
		assertTrue("${vmess.notes}", vmess.notes.any { "mihomo and sing-box clients take this CA" in it })
		val hysteria2 = links(node("hysteria2", own))
		assertEquals(hysteria2.text, OWN_CERTIFICATE_PIN, param(hysteria2.text, "pinSHA256"))
		assertTrue("${hysteria2.notes}", hysteria2.notes.any { "sing-box clients take this CA" in it })
	}

	@Test
	fun `a CA that is no server's own certificate goes whole where husi reads one, and nowhere else`() {
		for (protocol in listOf("vless", "trojan")) {
			val result = links(node(protocol, issuing))
			assertNull(result.text, param(result.text, "pcs"))
			assertEquals(result.text, issuingPem, param(result.text, "cert"))
			assertTrue("${result.notes}", result.notes.any { "Xray and mihomo clients take this CA" in it })
		}
		// No client reads it from these: the node has no link form and stays as it was written.
		for (protocol in listOf("vmess", "hysteria2", "hysteria", "tuic", "shadowsocks")) {
			val body = node(protocol, issuing)
			val result = links(body)
			assertEquals(result.text, JSONObject(body).getJSONArray("outbounds").getJSONObject(0).toString(),
				JSONObject(result.text).getJSONArray("outbounds").getJSONObject(0).toString())
			assertEquals(0, result.xraySkipped)
			assertTrue("${result.notes}", result.notes.any { "no client takes from" in it })
		}
		// mihomo dials an https link's server without checking its certificate at all.
		val https = links(node("http", issuing))
		assertTrue(https.text, https.text.startsWith("https://"))
		assertTrue("${https.notes}", https.notes.any { "mihomo checks no certificate there" in it })
	}

	@Test
	fun `a node kept as written is told only why, and beside a CA carried only the rest is dropped`() {
		// Kept whole, it loses nothing a link would - its sockopt included.
		val dialing = node("vmess", issuing).replace("\"tcp\",", "\"tcp\",\"sockopt\":{\"mark\":1},")
		val kept = links(dialing)
		assertEquals("${kept.notes}", 2, kept.notes.size)
		val reason = "no client takes from vmess links, whole or as a pin"
		assertTrue("${kept.notes}", kept.notes[0].endsWith(reason))
		assertTrue("${kept.notes}", kept.notes[1].endsWith("has no link form and was kept as it was written"))
		val pair = """{"certificate":["x"],"key":["y"]}"""
		val beside = """{"serverName":"h.example.com","certificates":[""" +
			"""${verifying(OWN_CERTIFICATE_LINES).removeSurrounding("[", "]")},$pair]}"""
		val result = links(node("vless", beside))
		assertEquals(result.text, ownPem, param(result.text, "cert"))
		val second = "tlsSettings.certificates[1] has no link form"
		assertTrue("${result.notes}", result.notes.any { second in it })
		assertTrue("${result.notes}", result.notes.none { "tlsSettings.certificates has no link form" in it })
	}

	@Test
	fun `the sing-box box keeps what husi can verify and leaves out the rest`() {
		for (protocol in listOf("vless", "trojan")) {
			for (tls in listOf(own, issuing)) {
				val kept = links(node(protocol, tls), singBox = true)
				assertTrue(kept.text, kept.text.startsWith("$protocol://"))
				assertTrue(kept.text, param(kept.text, "cert") != null)
			}
		}
		for (protocol in listOf("vmess", "hysteria2", "hysteria", "tuic", "http", "shadowsocks")) {
			val dropped = links(node(protocol, own), singBox = true)
			assertEquals(dropped.text, "", dropped.text)
			assertEquals(1, dropped.xraySkipped)
			assertTrue("${dropped.notes}", dropped.notes.single().startsWith("skipped: ") &&
				"a sing-box client takes from" in dropped.notes.single())
		}
	}

	@Test
	fun `the mihomo box keeps what mihomo can verify and leaves out the rest`() {
		for (protocol in listOf("vless", "trojan", "hysteria2")) {
			val kept = links(node(protocol, own), mihomo = true)
			assertTrue(kept.text, kept.text.startsWith("$protocol://"))
			assertEquals(0, kept.xraySkipped)
		}
		for (protocol in listOf("vmess", "hysteria", "tuic", "shadowsocks")) {
			val dropped = links(node(protocol, own), mihomo = true)
			assertEquals(protocol, "", dropped.text)
			assertEquals(protocol, 1, dropped.xraySkipped)
		}
		// No pin stands for a CA that signs, so mihomo verifies the server from none of its links.
		for (protocol in listOf("vless", "trojan")) {
			val dropped = links(node(protocol, issuing), mihomo = true)
			assertEquals(protocol, "", dropped.text)
			assertTrue("${dropped.notes}", dropped.notes.any { "a mihomo client takes from" in it })
		}
		assertTrue(links(node("http", own), mihomo = true).text.startsWith("https://"))
		// mihomo reads TLS into a v2ray-plugin link whose text holds "tls" anywhere - here, in the host.
		val plain = """{"outbounds":[{"protocol":"shadowsocks","tag":"s","settings":{"servers":[""" +
			"""{"address":"h.example.com","port":80,"method":"aes-128-gcm","password":"pw"}]},""" +
			""""streamSettings":{"network":"ws","wsSettings":{"path":"/p","host":"tls.example.com"}}}]}"""
		assertTrue(links(plain).text, links(plain).text.startsWith("ss://"))
		val unread = links(plain, mihomo = true)
		assertEquals(unread.text, "", unread.text)
		val why = "a mihomo client reads TLS into the link"
		assertTrue("${unread.notes}", unread.notes.single().contains(why))
	}

	@Test
	fun `the mihomo box leaves out a transport its clients cannot dial from a link`() {
		val upgrade = """"network":"httpupgrade","httpupgradeSettings":{"path":"/u"}"""
		val protocols = listOf("vless", "vmess", "trojan")
		for (stream in listOf(upgrade, """"network":"quic"""")) for (protocol in protocols) {
			val body = node(protocol, """{"serverName":"h.example.com"}""")
				.replace(""""network":"tcp"""", stream)
			assertTrue(protocol, links(body).text.startsWith("$protocol://"))
			assertTrue(protocol, links(body, singBox = true).text.startsWith("$protocol://"))
			val dropped = links(body, mihomo = true)
			assertEquals(protocol, "", dropped.text)
			// QUIC alone in its configuration is the configuration mihomo takes nothing from.
			val why = if (stream == upgrade) "a mihomo client runs no httpupgrade read from $protocol links"
				else "mihomo has no QUIC transport"
			assertTrue("${dropped.notes}", dropped.notes.single().contains(why))
		}
		// Beside a node mihomo carries, keeping the configuration under its box, the QUIC link alone goes.
		val tcp = node("vless", """{"serverName":"h.example.com"}""")
		val overQuic = JSONObject(tcp.replace(""""network":"tcp"""", """"network":"quic""""))
			.getJSONArray("outbounds").getJSONObject(0).put("tag", "q")
		val pair = JSONObject(tcp).apply { getJSONArray("outbounds").put(overQuic) }.toString()
		assertEquals(2, links(pair).text.lines().count { it.startsWith("vless://") })
		val one = links(pair, mihomo = true)
		assertEquals(one.text, listOf("tcp"), one.text.lines().map { queryOf(it)["type"] })
		assertTrue("${one.notes}", one.notes.any { "runs no QUIC transport read from vless links" in it })
		// mKCP goes where nothing masks it, as in mihomo's own document: no link takes a seed or a header.
		fun kcp(settings: String) = """{"outbounds":[{"protocol":"vmess","tag":"k","settings":{"vnext":[""" +
			"""{"address":"h.example.com","port":443,"users":[$user]}]},""" +
			""""streamSettings":{"network":"kcp","kcpSettings":$settings}}]}"""
		assertTrue(links(kcp("{}"), mihomo = true).text.startsWith("vmess://"))
		for (masked in listOf("""{"seed":"s"}""", """{"header":{"type":"wechat-video"}}""")) {
			assertTrue(masked, links(kcp(masked)).text.startsWith("vmess://"))
			val dropped = links(kcp(masked), mihomo = true)
			assertEquals(masked, "", dropped.text)
			val why = "a mihomo client reads no mKCP seed or header from vmess links"
			assertTrue("${dropped.notes}", dropped.notes.single().contains(why))
		}
		// A v2ray-plugin over quic, beside a node mihomo carries: its link would cost mihomo the whole file.
		val server = """{"address":"h.example.com","port":443,"method":"aes-128-gcm","password":"pw""""
		val quic = """{"outbounds":[{"protocol":"shadowsocks","tag":"q","settings":{"servers":[$server,""" +
			""""plugin":"v2ray-plugin","plugin_opts":"mode=quic;tls;host=h.example.com"}]}},""" +
			"""{"protocol":"shadowsocks","tag":"p","settings":{"servers":[$server}]}}]}"""
		assertEquals(2, links(quic).text.lines().count { it.startsWith("ss://") })
		val kept = links(quic, mihomo = true)
		assertEquals(kept.text, 1, kept.text.lines().count { it.startsWith("ss://") })
		assertTrue("${kept.notes}", kept.notes.single().contains("v2ray-plugin runs over quic"))
	}

	@Test
	fun `the mihomo box writes a Hysteria link as mihomo reads it, or leaves it out`() {
		val tls = """{"serverName":"h.example.com"}"""
		// mihomo takes the secret itself from a v1 link's obfs, where the scheme names the mode; the sing-box
		// clients take it from obfsParam, which stays for them should both boxes be ticked.
		val v1 = node("hysteria", tls).replace(""""auth_str":"pw",""", """"auth_str":"pw","obfs":"secret",""")
		assertEquals("xplus", param(links(v1).text, "obfs"))
		assertEquals("secret", param(links(v1).text, "obfsParam"))
		for (singBox in listOf(false, true)) {
			val forMihomo = links(v1, singBox = singBox, mihomo = true).text
			assertEquals(forMihomo, "secret", param(forMihomo, "obfs"))
			assertEquals(forMihomo, "secret", param(forMihomo, "obfsParam"))
		}
		val forSingBox = links(v1, singBox = true).text
		assertEquals(forSingBox, "xplus", param(forSingBox, "obfs"))
		assertEquals(forSingBox, "secret", param(forSingBox, "obfsParam"))
		// And a Hysteria2 password as Go writes a URL's user part back: escaped past a plain few.
		fun hysteria2(password: String) =
			node("hysteria2", tls).replace(""""auth":"pw"""", """"auth":"$password"""")
		assertTrue(links(hysteria2("a-b_c.d~$&+,;=1"), mihomo = true).text.startsWith("hysteria2://"))
		for (password in listOf("p@ss", "a b", "x:y", "пароль")) {
			assertTrue(password, links(hysteria2(password)).text.startsWith("hysteria2://"))
			val dropped = links(hysteria2(password), mihomo = true)
			assertEquals(password, "", dropped.text)
			assertTrue("${dropped.notes}", dropped.notes.single().contains("in their escaped form"))
		}
	}

	@Test
	fun `a skipped check stands for the CA only with the clients that read the switch from that link`() {
		val insecure = verifiedBy(OWN_CERTIFICATE_LINES, ""","allowInsecure":true""")
		val signer = verifiedBy(ISSUING_CERTIFICATE_LINES, ""","allowInsecure":true""")
		// Neither mihomo nor husi reads it from a VLESS link: the CA is pinned and carried all the same.
		val vless = links(node("vless", insecure))
		assertEquals(vless.text, OWN_CERTIFICATE_PIN, param(vless.text, "pcs"))
		assertEquals(vless.text, ownPem, param(vless.text, "cert"))
		assertEquals(vless.text, "1", param(vless.text, "allowInsecure"))
		assertNull(links(node("trojan", insecure)).text, param(links(node("trojan", insecure)).text, "pcs"))
		val unpinned = links(node("vless", signer))
		assertTrue("${unpinned.notes}", unpinned.notes.any { it.contains("mihomo clients take this CA") })
		// mihomo connects from a VLESS link by the pin, from Trojan and Hysteria2 by the switch, and from a
		// VLESS link with a CA that signs, a VMess or a TUIC one not at all.
		assertEquals(OWN_CERTIFICATE_PIN, param(links(node("vless", insecure), mihomo = true).text, "pcs"))
		for (protocol in listOf("trojan", "hysteria2")) {
			assertTrue(protocol, links(node(protocol, signer), mihomo = true).text.startsWith("$protocol://"))
		}
		for (body in listOf(node("vless", signer), node("vmess", insecure), node("tuic", insecure))) {
			val dropped = links(body, mihomo = true)
			assertEquals(body, "", dropped.text)
			assertTrue("${dropped.notes}", dropped.notes.single().contains("a mihomo client takes from"))
		}
		// husi checks a VLESS link's CA and takes the switch from VMess and TUIC ones, but not from https.
		for (protocol in listOf("vless", "vmess", "tuic")) {
			assertTrue(protocol, links(node(protocol, signer), singBox = true).text.isNotEmpty())
		}
		assertEquals("", links(node("http", signer), singBox = true).text)
	}

	@Test
	fun `a pin of the node's own stands in for the CA`() {
		val pin = "aa".repeat(32)
		val pinned = verifiedBy(OWN_CERTIFICATE_LINES, ""","pinnedPeerCertSha256":"$pin"""")
		for (mihomo in listOf(false, true)) {
			val result = links(node("vless", pinned), mihomo = mihomo)
			assertEquals(result.text, pin, param(result.text, "pcs"))
		}
		val vmess = links(node("vmess", pinned))
		assertEquals(vmess.text, pin, param(vmess.text, "pcs"))
		assertTrue("${vmess.notes}", vmess.notes.any { "the node's own pin stands in for it" in it })
	}

	@Test
	fun `a mihomo client gets one pin it can read, where a list would fail the node or the whole file`() {
		val both = "$OWN_CERTIFICATE_PIN,${"bb".repeat(32)}"
		val pins = """{"serverName":"h.example.com","pinnedPeerCertSha256":"$both"}"""
		val plain = links(node("vless", pins))
		assertEquals(plain.text, both, param(plain.text, "pcs"))
		val mihomo = links(node("vless", pins), mihomo = true)
		assertEquals(mihomo.text, OWN_CERTIFICATE_PIN, param(mihomo.text, "pcs"))
		assertTrue("${mihomo.notes}", mihomo.notes.any { "mihomo takes one, so the first was used" in it })
		val hysteria2 = links(node("hysteria2", pins), mihomo = true)
		assertEquals(hysteria2.text, OWN_CERTIFICATE_PIN, param(hysteria2.text, "pinSHA256"))
		// A pin mihomo cannot read is left out rather than written for it to refuse.
		val unread = links(node("vless", """{"serverName":"h.example.com","pinnedPeerCertSha256":"zz"}"""),
			mihomo = true)
		assertNull(unread.text, param(unread.text, "pcs"))
		assertTrue("${unread.notes}", unread.notes.any { "could not decode" in it })
	}

	@Test
	fun `a name to verify is sent where the link's clients check the name they send`() {
		val names = """{"serverName":"fake.example.org","verifyPeerCertByName":"h.example.com"}"""
		val kept = links(node("vless", names))
		assertEquals("fake.example.org", param(kept.text, "sni"))
		assertEquals("h.example.com", param(kept.text, "vcn"))
		assertTrue("${kept.notes}", kept.notes.isEmpty())
		for ((singBox, mihomo) in listOf(true to false, false to true, true to true)) {
			val sent = links(node("vless", names), singBox, mihomo)
			assertEquals(sent.text, "h.example.com", param(sent.text, "sni"))
			assertEquals(sent.text, "h.example.com", param(sent.text, "vcn"))
			assertTrue("${sent.notes}", sent.notes.any { "was sent as the server name" in it })
		}
		// Links that carry no names send the one to verify for every client.
		for ((protocol, field) in listOf("hysteria2" to "sni", "hysteria" to "peer", "tuic" to "sni",
				"http" to "sni")) {
			val sent = links(node(protocol, names))
			assertEquals(sent.text, "h.example.com", param(sent.text, field))
		}
		// The server's own certificate pinned, a mihomo client checks no name at all.
		val pinned = """{"serverName":"fake.example.org","verifyPeerCertByName":"h.example.com",""" +
			""""certificates":${verifying(OWN_CERTIFICATE_LINES)}}"""
		assertEquals("fake.example.org", param(links(node("vless", pinned), mihomo = true).text, "sni"))
		assertEquals("h.example.com", param(links(node("vless", pinned), singBox = true).text, "sni"))
		// Nothing checked, or the name sent among the names, and the name sent stays.
		val insecure = """{"serverName":"fake.example.org","verifyPeerCertByName":"h.example.com",""" +
			""""allowInsecure":true}"""
		assertEquals("fake.example.org", param(links(node("hysteria2", insecure)).text, "sni"))
		val among = """{"serverName":"h.example.com","verifyPeerCertByName":"x.example.com,h.example.com"}"""
		val stays = links(node("hysteria2", among))
		assertEquals("h.example.com", param(stays.text, "sni"))
		// The Host header is what Xray sends, the server name, where clients would send another: the name
		// sent in its place, or the address; one that is the address goes unwritten.
		val trojanWs = node("trojan", names).replace(""""network":"tcp"""", """"network":"ws"""")
		val sentFor = links(trojanWs, singBox = true).text
		assertEquals(sentFor, "h.example.com", param(sentFor, "sni"))
		assertEquals(sentFor, "fake.example.org", param(sentFor, "host"))
		val upgrade = node("vless", names).replace(""""network":"tcp"""", """"network":"httpupgrade"""")
		assertEquals("fake.example.org", param(links(upgrade, singBox = true).text, "host"))
		assertEquals("fake.example.org", param(links(upgrade).text, "host"))
		val ws = node("vless", """{"serverName":"h.example.com"}""").replace("\"tcp\"", "\"ws\"")
		assertNull(param(links(ws).text, "host"))
		val dropped = "which the hysteria2 link form has no field for"
		assertTrue("${stays.notes}", stays.notes.any { dropped in it })
	}

	@Test
	fun `a husi client checking the CA against a name it does not cover is named`() {
		val names = """{"serverName":"fake.example.org","verifyPeerCertByName":"h.example.com",""" +
			""""certificates":${verifying(OWN_CERTIFICATE_LINES)}}"""
		val plain = links(node("vless", names))
		assertEquals("fake.example.org", param(plain.text, "sni"))
		val unnamed = "sing-box clients check this CA against"
		assertTrue("${plain.notes}", plain.notes.any { it.contains(unnamed) })
		val boxed = links(node("vless", names), singBox = true)
		assertTrue("${boxed.notes}", boxed.notes.none { it.contains(unnamed) })
	}

	@Test
	fun `a node that never worked is refused, not kept for its CA`() {
		val masked = node("tuic", issuing).replace("\"security\":\"tls\",",
			"\"finalmask\":{\"udp\":[{\"type\":\"gecko\"}]},\"security\":\"tls\",")
		val refused = links(masked)
		assertEquals(refused.text, "", refused.text)
		assertEquals(1, refused.xraySkipped)
		assertTrue("${refused.notes}", refused.notes.single().contains("never worked"))
	}

	@Test
	fun `of several names the one the server's own certificate covers is sent`() {
		val names = """{"serverName":"fake.example.org","verifyPeerCertByName":""" +
			""""x.example.com,a.w.example.com","certificates":${verifying(OWN_CERTIFICATE_LINES)}}"""
		assertEquals("a.w.example.com", param(links(node("vless", names), singBox = true).text, "sni"))
		assertEquals("a.w.example.com", nameToVerify(JSONObject(names), "fake.example.org"))
		assertNull(nameToVerify(JSONObject(names), "A.W.Example.com."))
	}

	@Test
	fun `REALITY offers mihomo the key share, and a mihomo client chrome`() {
		val key = "yPNRx8rTdkUp89A-J76KxmGFeexuyVG4BiVl1PJ1kCk"
		val reality = """{"serverName":"r.example.com","publicKey":"$key","shortId":"ab",""" +
			""""fingerprint":"firefox"}"""
		val stream = """{"network":"raw","security":"reality","realitySettings":$reality}"""
		val vless = """{"outbounds":[{"protocol":"vless","tag":"r","settings":{"vnext":[""" +
			"""{"address":"r.example.com","port":443,"users":[$user]}]},"streamSettings":$stream}]}"""
		val plain = links(vless)
		assertEquals("true", param(plain.text, "support-x25519mlkem768"))
		assertEquals("firefox", param(plain.text, "fp"))
		assertTrue("${plain.notes}", plain.notes.isEmpty())
		val mihomo = links(vless, mihomo = true)
		assertEquals("chrome", param(mihomo.text, "fp"))
		assertTrue("${mihomo.notes}", mihomo.notes.any { REALITY_MIHOMO_NOTE in it })
		assertTrue("${mihomo.notes}", mihomo.notes.any { "uTLS fingerprint \"firefox\"" in it })
		val singBox = links(vless, singBox = true)
		assertEquals("firefox", param(singBox.text, "fp"))
		assertTrue("${singBox.notes}", singBox.notes.any { REALITY_SING_BOX_NOTE in it })
		// mihomo reads no REALITY from a Trojan link, and would dial the server as plain TLS.
		val trojan = """{"outbounds":[{"protocol":"trojan","tag":"t","settings":{"servers":[""" +
			"""{"address":"r.example.com","port":443,"password":"pw"}]},"streamSettings":$stream}]}"""
		assertTrue(links(trojan).text.startsWith("trojan://"))
		assertFalse("support-x25519mlkem768" in links(trojan).text)
		val dropped = links(trojan, mihomo = true)
		assertEquals("", dropped.text)
		assertTrue("${dropped.notes}", dropped.notes.any { "reads no REALITY from trojan links" in it })
	}

	@Test
	fun `a socks link's name and password reach every reader, and mihomo only as it reads them`() {
		fun socks(name: String, pass: String) =
			"""{"outbounds":[{"protocol":"socks","tag":"s","settings":{"servers":[""" +
				"""{"address":"h.example.com","port":1080,"users":[{"user":"$name","pass":"$pass"}]}]}}]}"""
		// "admin:Qw?x" is YWRtaW46UXc/eA in base64, whose "/" would end the address unescaped.
		val slashed = links(socks("admin", "Qw?x")).text
		val uri = URI(slashed)
		assertEquals(slashed, "h.example.com", uri.host)
		assertEquals("admin:Qw?x", String(Base64.decode(uri.userInfo, Base64.DEFAULT)))
		// A mihomo client reads that "/" escaped - one a password past ASCII puts there too - and splits the
		// pair at every ":".
		for (body in listOf(socks("admin", "Qw?x"), socks("admin", "пароль"), socks("admin", "a:b"))) {
			val dropped = links(body, mihomo = true)
			assertEquals(body, "", dropped.text)
			assertTrue("${dropped.notes}", dropped.notes.single().contains("a mihomo client"))
		}
		val kept = links(socks("admin", "p@ss~1"), mihomo = true).text
		assertEquals(kept, "admin:p@ss~1", String(Base64.decode(URI(kept).userInfo, Base64.DEFAULT)))
		// A sing-box client splits the base64 at its first ":", so a name holding one goes to it plain.
		val named = links(socks("a:b", "c")).text
		assertEquals(named, "a:b:c", String(Base64.decode(URI(named).userInfo, Base64.DEFAULT)))
		val plain = links(socks("a:b", "c"), singBox = true).text
		assertEquals(plain, "a%3Ab:c", URI(plain).rawUserInfo)
		assertEquals("", links(socks("a:b", "c"), singBox = true, mihomo = true).text)
	}

	@Test
	fun `an http link goes to a mihomo client only with a name and password it reads unescaped`() {
		fun http(pass: String) = """{"outbounds":[{"protocol":"http","tag":"h","settings":{"servers":[""" +
			"""{"address":"h.example.com","port":8080,"users":[{"user":"u","pass":"$pass"}]}]}}]}"""
		assertEquals("u:p@ss", URI(links(http("p@ss")).text).userInfo)
		val dropped = links(http("p@ss"), mihomo = true)
		assertEquals("", dropped.text)
		val why = "from an http link in their escaped form"
		assertTrue("${dropped.notes}", dropped.notes.single().contains(why))
		val plain = "a-b_c.d~$&+,;=1"
		assertEquals("u:$plain", URI(links(http(plain), mihomo = true).text).userInfo)
	}

	@Test
	fun `a VLESS ws link without TLS names the address as its Host for a mihomo client`() {
		val body = """{"outbounds":[{"protocol":"vless","tag":"v","settings":{"vnext":[""" +
			"""{"address":"h.example.com","port":80,"users":[$user]}]},""" +
			""""streamSettings":{"network":"ws","wsSettings":{"path":"/p"}}}]}"""
		assertNull(param(links(body).text, "host"))
		assertNull(param(links(body, singBox = true).text, "host"))
		assertEquals("h.example.com", param(links(body, mihomo = true).text, "host"))
		val named = body.replace(""""path":"/p"""", """"path":"/p","host":"cdn.example.com"""")
		assertEquals("cdn.example.com", param(links(named, mihomo = true).text, "host"))
		// Xray sends an IPv6 address in brackets.
		val v6 = body.replace("h.example.com", "2001:db8::1")
		assertEquals("[2001:db8::1]", param(links(v6, mihomo = true).text, "host"))
	}

	@Test
	fun `a trojan ws link goes to a mihomo client only where the server name it sends is the Host`() {
		fun trojanWs(ws: String, tls: String) =
			node("trojan", tls).replace(""""network":"tcp"""", """"network":"ws","wsSettings":$ws""")
		val server = """{"serverName":"h.example.com"}"""
		val apart = trojanWs("""{"path":"/p","host":"cdn.example.com"}""", server)
		assertEquals("cdn.example.com", param(links(apart).text, "host"))
		assertTrue(links(apart, singBox = true).text.startsWith("trojan://"))
		val header = trojanWs("""{"path":"/p","headers":{"Host":"cdn.example.com"}}""", server)
		for (ws in listOf(apart, header)) {
			val dropped = links(ws, mihomo = true)
			assertEquals(dropped.text, "", dropped.text)
			assertTrue("${dropped.notes}", dropped.notes.single().contains("reads no Host from trojan links"))
		}
		val alike = trojanWs("""{"path":"/p","host":"H.example.com"}""", server)
		assertTrue(links(alike, mihomo = true).text.startsWith("trojan://"))
		// An Xray server compares the Host without its port.
		val ported = trojanWs("""{"path":"/p","host":"h.example.com:443"}""", server)
		assertTrue(links(ported, mihomo = true).text.startsWith("trojan://"))
		// An IPv6 address and an internationalised name go out as one name however each side wrote it.
		val v6 = trojanWs("""{"path":"/p","host":"2001:0db8:0::1"}""", "{}")
			.replace("h.example.com", "2001:db8::1")
		assertTrue(links(v6, mihomo = true).text.startsWith("trojan://"))
		val idn = trojanWs("""{"path":"/p","host":"xn--e1afmkfd.xn--p1ai"}""", "{}")
			.replace("h.example.com", "пример.рф")
		assertTrue(links(idn, mihomo = true).text.startsWith("trojan://"))
		// A name to verify sent in the server name's place becomes the Host, which is named - the server
		// name written as the Host as well.
		val names = """{"serverName":"fake.example.org","verifyPeerCertByName":"h.example.com"}"""
		for (ws in listOf("""{"path":"/p"}""", """{"path":"/p","host":"fake.example.org"}""")) {
			val renamed = links(trojanWs(ws, names), mihomo = true)
			assertEquals(renamed.text, "h.example.com", param(renamed.text, "sni"))
			val becomes = "as its Host, \"h.example.com\" where Xray sends \"fake.example.org\""
			assertTrue("${renamed.notes}", renamed.notes.any { becomes in it })
		}
	}

	@Test
	fun `what the box's clients send in place of an https server name or a gRPC authority is named`() {
		val https = node("http", """{"serverName":"sni.example.com"}""")
		val byAddress = "by its address, \"h.example.com\", rather than \"sni.example.com\""
		assertTrue("${links(https).notes}", links(https).notes.none { "names the server by" in it })
		assertTrue("${links(https, singBox = true).notes}",
			links(https, singBox = true).notes.none { "names the server by" in it })
		val forMihomo = links(https, mihomo = true)
		assertEquals(forMihomo.text, "sni.example.com", param(forMihomo.text, "sni"))
		assertTrue("${forMihomo.notes}", forMihomo.notes.any { byAddress in it })
		val idn = links(node("http", """{"serverName":"xn--e1afmkfd.xn--p1ai"}""")
			.replace("h.example.com", "пример.рф"), mihomo = true)
		assertTrue("${idn.notes}", idn.notes.isEmpty())
		val server = """{"serverName":"h.example.com"}"""
		assertTrue("${links(node("http", server), mihomo = true).notes}",
			links(node("http", server), mihomo = true).notes.isEmpty())
		fun grpc(authority: String) = node("vless", server).replace(""""network":"tcp"""",
			""""network":"grpc","grpcSettings":{"serviceName":"g","authority":"$authority"}""")
		val apart = grpc("a.example.com")
		assertEquals("a.example.com", param(links(apart).text, "authority"))
		assertTrue("${links(apart).notes}", links(apart).notes.isEmpty())
		val unread = "read no authority from gRPC links and send one made of the server name, " +
			"\"h.example.com\", where Xray sends \"a.example.com\""
		for ((who, singBox, mihomo) in listOf(Triple("sing-box", true, false), Triple("mihomo", false, true),
				Triple("sing-box and mihomo", true, true))) {
			val result = links(apart, singBox, mihomo)
			assertEquals(result.text, "a.example.com", param(result.text, "authority"))
			assertTrue("${result.notes}", result.notes.single().endsWith(": $who clients $unread"))
		}
		assertTrue(links(grpc("H.example.com"), singBox = true, mihomo = true).notes.isEmpty())
		// An authority with the port, as husi sends one, is the name sent.
		assertTrue(links(grpc("h.example.com:443"), singBox = true, mihomo = true).notes.isEmpty())
		// A VMess link carries no authority for any client, and says that alone.
		val vmess = links(apart.replace(""""protocol":"vless"""", """"protocol":"vmess""""), singBox = true)
		val dropped = "the vmess link form has no field for authority, so it was dropped"
		assertTrue("${vmess.notes}", vmess.notes.single().endsWith(dropped))
	}
}
