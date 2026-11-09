package com.happwner.convert

import com.happwner.text.decodeBase64Any
import com.happwner.text.withoutComments
import java.net.URLDecoder
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// The forms Xray writes, read alike by every pass.
class XrayFormsTest {
	private val trojan = """{"outbounds":[{"protocol":"trojan","tag":"t",
		"settings":{"address":"tj.example.com","port":443,"password":"pw"},
		"streamSettings":{"security":"tls","tlsSettings":{"serverName":"tj.example.com"}}}]}"""
		.replace("\n", "")
	private val shadowsocks = """{"outbounds":[{"protocol":"shadowsocks","tag":"s",
		"settings":{"address":"ss.example.com","port":8388,"method":"aes-256-gcm","password":"pw"}}]}"""
		.replace("\n", "")

	private fun singBoxServers(body: String): List<String> {
		val config = (SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok).config
		val outbounds = config.getJSONArray("outbounds")
		return (0 until outbounds.length()).map { outbounds.getJSONObject(it) }.filter { it.has("server") }
			.map { "${it.optString("type")} ${it.optString("server")}:${it.optInt("server_port")}" }
	}

	private fun link(body: String) =
		SubscriptionConverter.convertWithStats(body, ConversionFlags(true, false, false, false))

	private fun mihomo(body: String) = (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).yaml

	@Test
	fun `a trojan server written into settings reaches every pass`() {
		assertTrue("trojan tj.example.com:443" in singBoxServers(trojan))
		assertTrue(link(trojan).text, link(trojan).text.startsWith("trojan://pw@tj.example.com:443"))
		assertTrue(mihomo(trojan).contains("server: tj.example.com"))
	}

	@Test
	fun `a shadowsocks server written into settings reaches every pass`() {
		assertTrue("shadowsocks ss.example.com:8388" in singBoxServers(shadowsocks))
		val text = link(shadowsocks).text
		assertTrue(text, text.startsWith("ss://") && text.contains("@ss.example.com:8388"))
		assertTrue(mihomo(shadowsocks).contains("server: ss.example.com"))
	}

	@Test
	fun `a configuration with its one outbound under outbound reaches every pass`() {
		val older = """{"outbound":{"protocol":"vless","tag":"v","settings":{"vnext":[
			{"address":"l.example.com","port":443,
			"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]}}}"""
			.replace("\n", "")
		assertTrue("vless l.example.com:443" in singBoxServers(older))
		val text = link(older).text
		assertTrue(text, text.startsWith("vless://b831381d-6324-4d53-ad4f-8cda48b30811@l.example.com:443"))
		assertTrue(mihomo(older).contains("server: l.example.com"))
	}

	@Test
	fun `a stream named none is refused in every pass, as no Xray ever read it`() {
		// "none" is a header type, never a transport: Xray from 1.0 on refuses the configuration over
		// it ("unknown transport protocol"), as v2ray has since 2.15 (2017); only v2ray 1.17-2.1.2
		// (2016), years before Xray, read an unknown name as raw TCP, so no node of Xray's ever had it.
		val socks = JSONObject("""{"protocol":"socks","tag":"s","streamSettings":{"network":"none"},
			"settings":{"servers":[{"address":"s.example.com","port":1080}]}}""")
		val body = JSONObject().put("outbounds", JSONArray().put(socks)).toString()
		val reason = "transport \"none\" is not one Xray or any core knows, so the node never worked"
		val links = link(body)
		assertFalse(links.text, links.text.contains("://"))
		assertTrue(links.notes.toString(), links.notes.any { reason in it })
		val singBox = SingBoxConverter.convert(body, "N")
		assertTrue(singBox.toString(), singBox is SingBoxConverter.Result.Unsupported)
		assertTrue(singBox.toString(), reason in singBox.toString())
		val mihomo = MihomoConverter.convert(body)
		assertTrue(mihomo.toString(), mihomo is MihomoConverter.Result.Unsupported)
		assertTrue(mihomo.toString(), reason in mihomo.toString())
	}

	@Test
	fun `Xray's own XDRIVE and MASQUE are refused by the cores, and the link pass keeps what Xray runs`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val vnext = """{"vnext":[{"address":"x.example.com","port":443,"users":[$user]}]}"""
		fun vless(network: String) =
			"""{"outbounds":[{"protocol":"vless","tag":"x","settings":$vnext,""" +
				""""streamSettings":{"network":"$network"}}]}"""
		val masque = """{"outbounds":[{"protocol":"masque","tag":"m",""" +
			""""settings":{"address":"m.example.com","port":443}}]}"""
		val cases = listOf(
			vless("xdrive") to "transport \"xdrive\" is Xray's own",
			masque to MASQUE_OUTBOUND_REFUSAL
		)
		for ((body, reason) in cases) {
			val singBox = SingBoxConverter.convert(body, "N")
			assertTrue("$singBox", singBox is SingBoxConverter.Result.Unsupported && reason in "$singBox")
			val mihomo = MihomoConverter.convert(body)
			assertTrue("$mihomo", mihomo is MihomoConverter.Result.Unsupported && reason in "$mihomo")
			// No link form holds either, and Xray runs both, so the node stays the configuration it was.
			val links = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
			assertTrue(links.text, links.text.trim().startsWith("{"))
			assertFalse(links.text, "://" in links.text)
		}
		// MASQUE as a transport runs under its own outbound alone: Xray refuses it anywhere else.
		val misplaced = vless("masque")
		val links = SubscriptionConverter.convertWithStats(misplaced, jsonToUri = true)
		assertTrue("${links.notes}", links.text.isBlank() && links.notes.any { "never worked" in it })
		assertTrue(SingBoxConverter.convert(misplaced, "N") is SingBoxConverter.Result.Unsupported)
		assertTrue(MihomoConverter.convert(misplaced) is MihomoConverter.Result.Unsupported)
	}

	private fun proxyTags(body: String): List<String> {
		val singBox = ConversionFlags(false, true, false, false)
		val text = SubscriptionConverter.convertWithStats(body, singBox).text
		val outbounds = JSONObject(text).getJSONArray("outbounds")
		return (0 until outbounds.length()).map { outbounds.getJSONObject(it) }
			.filter { it.optString("type") !in setOf("selector", "direct") }.map { it.optString("tag") }
	}

	private val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""

	private fun vless(tag: String?, vararg servers: String): JSONObject {
		val vnext = JSONArray()
		for (host in servers) vnext.put(JSONObject("""{"address":"$host","port":443,"users":[$user]}"""))
		val outbound = JSONObject().put("protocol", "vless").put("settings", JSONObject().put("vnext", vnext))
		return if (tag != null) outbound.put("tag", tag) else outbound
	}

	@Test
	fun `nodes without a tag of their own are all kept, named as the other passes name them`() {
		// They were named after their protocol or left blank, and sing-box takes no two under one tag.
		val outbounds = JSONArray().put(vless(null, "a.example.com")).put(vless("", "b.example.com"))
			.put(vless(null, "c.example.com", "d.example.com"))
		val tags = proxyTags(JSONObject().put("outbounds", outbounds).toString())
		val wanted = listOf("a", "b", "c", "d").map { "vless-$it.example.com:443" }
		assertTrue(tags.toString(), tags.containsAll(wanted) && "" !in tags)
	}

	@Test
	fun `users sharing one server stay two nodes under their outbound`() {
		val multi = vless("multi", "a.example.com")
		val users = multi.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
			.getJSONArray("users")
		users.put(JSONObject().put("id", "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e").put("encryption", "none"))
		val tags = proxyTags(JSONObject().put("outbounds", JSONArray().put(multi)).toString())
		val members = listOf("multi a.example.com:443", "multi a.example.com:443 #2")
		assertTrue(tags.toString(), tags.containsAll(members + "multi"))
	}

	@Test
	fun `a vmess security is read as Xray reads it, the same in every pass`() {
		// Xray matches its three regardless of case and with nothing trimmed, and reads anything else as
		// auto: " none" with a space encrypts, as "none" itself does.
		val cases = listOf("XHTTP" to "auto", " none" to "auto", "AES-128-GCM" to "aes-128-gcm")
		for ((written, read) in cases) {
			val user = JSONObject(this.user).put("security", written)
			val server = JSONObject().put("address", "m.example.com").put("port", 443)
				.put("users", JSONArray().put(user))
			val vmess = JSONObject().put("protocol", "vmess").put("tag", "m")
				.put("settings", JSONObject().put("vnext", JSONArray().put(server)))
			val body = JSONObject().put("outbounds", JSONArray().put(vmess)).toString()
			val singBox = (SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok).config
			val first = singBox.getJSONArray("outbounds").getJSONObject(0)
			assertTrue(written, first.optString("security") == read)
			assertTrue(written, mihomo(body).contains("cipher: $read"))
			val blob = String(decodeBase64Any(link(body).text.removePrefix("vmess://"))!!)
			assertTrue(blob, JSONObject(blob).optString("scy") == read)
		}
	}

	@Test
	fun `a lone outbound naming several servers gives each its link, as inside a configuration`() {
		// It went out as the first server alone, the rest dropped without a word.
		val text = link(vless(null, "a.example.com", "b.example.com").toString()).text
		assertTrue(text, text.contains("@a.example.com:443") && text.contains("@b.example.com:443"))
	}

	@Test
	fun `each user of an outbound is judged alone in sing-box`() {
		// A flaw in the first took the sound second down with it, and one in the second slipped through
		// behind the first into a document the core then refused whole.
		val bad = """{"id":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","flow":"xtls-rprx-vision"}"""
		for (users in listOf("$user,$bad", "$bad,$user")) {
			val body = """{"outbounds":[{"protocol":"vless","tag":"pair","settings":{"vnext":[
				{"address":"a.example.com","port":443,"users":[$users]}]},
				"streamSettings":{"network":"ws","wsSettings":{"path":"/"}}}]}""".replace("\n", "")
			val singBox = ConversionFlags(false, true, false, false)
			val result = SubscriptionConverter.convertWithStats(body, singBox)
			assertTrue(result.text, result.text.contains("b831381d") && !result.text.contains("9b4b0b7e"))
			assertTrue(result.notes.toString(), result.notes.any { it.startsWith("skipped:") })
		}
	}

	private fun ruled(rule: JSONObject): String {
		val block = JSONObject().put("protocol", "blackhole").put("tag", "block")
		val routing = JSONObject().put("rules", JSONArray().put(rule.put("outboundTag", "block")))
		return JSONObject().put("outbounds", JSONArray().put(vless("p", "a.example.com")).put(block))
			.put("routing", routing).toString()
	}

	private fun singBoxRules(body: String): String {
		val result = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		return result.config.getJSONObject("route").getJSONArray("rules").toString()
	}

	@Test
	fun `domains and sourceIP are read as Xray reads them in both documents`() {
		val domains = ruled(JSONObject().put("domains", JSONArray().put("domain:x.example.com")))
		assertTrue(singBoxRules(domains), singBoxRules(domains).contains("x.example.com"))
		assertTrue(mihomo(domains), mihomo(domains).contains("x.example.com,REJECT"))
		// "sourceIP" replaces "source" when both are written.
		val both = JSONObject().put("sourceIP", JSONArray().put("10.0.0.0/8"))
			.put("source", JSONArray().put("192.168.0.0/16"))
		for (written in listOf(singBoxRules(ruled(both)), mihomo(ruled(JSONObject(both.toString()))))) {
			// org.json writes "/" as "\/".
			val text = written.replace("\\/", "/")
			assertTrue(text, text.contains("10.0.0.0/8") && !text.contains("192.168.0.0/16"))
		}
	}

	@Test
	fun `a rule naming a condition the document cannot say is dropped, never widened`() {
		// Read as no condition at all, such a rule sent every connection where it was meant to send a few.
		val values = mapOf("vlessRoute" to "443", "localIP" to "127.0.0.1", "localPort" to "443",
			"process" to "chrome")
		for ((field, value) in values) {
			val body = ruled(JSONObject().put(field, JSONArray().put(value)))
			if (field != "process") assertFalse(field, singBoxRules(body).contains("\"reject\""))
			assertFalse(field, mihomo(body).contains("MATCH,REJECT"))
		}
	}

	private fun domain() = JSONArray().put("domain:x.example.com")

	@Test
	fun `a condition Xray reads as none leaves the rule standing on the rest, as in Xray`() {
		// Empty or null, it is no condition to Xray, which then routes by the others.
		val kept = listOf(
			JSONObject().put("process", JSONArray()).put("domain", domain()),
			JSONObject().put("localPort", JSONObject.NULL).put("domain", domain()),
			JSONObject().put("vlessRoute", JSONObject.NULL).put("domain", domain()),
			JSONObject().put("localIP", JSONArray()).put("domain", domain()),
			JSONObject().put("domains", JSONArray()).put("domain", domain())
		)
		for (rule in kept) {
			val body = ruled(rule)
			assertTrue(body, singBoxRules(body).contains("x.example.com"))
			assertTrue(body, mihomo(body).contains("x.example.com,REJECT"))
		}
		// A null sourceIP leaves "source" in force.
		val nullSourceIp = JSONObject().put("sourceIP", JSONObject.NULL)
		val source = ruled(nullSourceIp.put("source", JSONArray().put("10.0.0.0/8")))
		assertTrue(source, singBoxRules(source).replace("\\/", "/").contains("10.0.0.0/8"))
		assertTrue(source, mihomo(source).contains("10.0.0.0/8,REJECT"))
		// Both networks are a condition Xray matches everything by, a null one beside them none.
		val everything = ruled(JSONObject().put("network", "tcp,udp").put("localPort", JSONObject.NULL))
		assertTrue(everything, singBoxRules(everything).contains("\"reject\""))
		assertTrue(everything, mihomo(everything).contains("MATCH,REJECT"))
	}

	@Test
	fun `a rule whose only condition Xray reads as none is dropped, never made a catch-all`() {
		// Xray refuses such a rule outright.
		val alone = listOf(
			JSONObject().put("process", JSONArray()), JSONObject().put("localIP", JSONArray()),
			JSONObject().put("domains", JSONArray()), JSONObject().put("sourceIP", JSONObject.NULL),
			JSONObject().put("localPort", JSONObject.NULL)
		)
		for (rule in alone) {
			val body = ruled(rule)
			assertFalse(body, singBoxRules(body).contains("\"reject\""))
			assertFalse(body, mihomo(body).contains("MATCH,REJECT"))
		}
	}

	@Test
	fun `a webhook is noted only when Xray would call it`() {
		fun hooked(url: String) =
			ruled(JSONObject().put("domain", domain()).put("webhook", JSONObject().put("url", url)))
		fun notes(body: String) = (SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok).notes +
			SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true).notes
		assertTrue(notes(hooked("")).none { it.contains("webhook") })
		assertTrue(notes(hooked("https://h.example.com")).count { it.contains("webhook") } == 2)
	}

	private fun shadowsocks(method: String, extra: String) = """{"outbounds":[{"protocol":"shadowsocks",
		"tag":"s","settings":{"servers":[{"address":"s.example.com","port":443,"method":"$method",
		"password":"MTIzNDU2Nzg5MDEyMzQ1Ng=="$extra}]}}]}""".replace("\n", "")

	private fun singBoxUot(body: String): JSONObject? {
		val config = (SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok).config
		val outbounds = config.getJSONArray("outbounds")
		return (0 until outbounds.length()).map { outbounds.getJSONObject(it) }
			.firstOrNull { it.has("server") }?.optJSONObject("udp_over_tcp")
	}

	@Test
	fun `udp over tcp is not carried, as Xray sends UDP as it is and its servers take none over TCP`() {
		// Against an Xray server a node asking for uot gets no UDP at all - the server dials the uot
		// magic address - and plain UDP gets through, so the node is written as Xray runs it.
		for (method in listOf("2022-blake3-aes-128-gcm", "aes-128-gcm")) {
			for (extra in listOf(",\"uot\":true", ",\"uot\":true,\"uotVersion\":1")) {
				val body = shadowsocks(method, extra)
				assertEquals(body, null, singBoxUot(body))
				assertFalse(mihomo(body), mihomo(body).contains("udp-over-tcp"))
			}
		}
		val socks = """{"outbounds":[{"protocol":"socks","tag":"k","settings":{"servers":[
			{"address":"k.example.com","port":1080,"uot":true}]}}]}""".replace("\n", "")
		assertEquals(null, singBoxUot(socks))
	}

	private fun packetEncoding(proto: String, written: String): String? {
		val id = "b831381d-6324-4d53-ad4f-8cda48b30811"
		val user = if (proto == "vless") """{"id":"$id","encryption":"none"}""" else """{"id":"$id"}"""
		val body = """{"outbounds":[{"protocol":"$proto","tag":"p","settings":{"packetEncoding":"$written",
			"vnext":[{"address":"p.example.com","port":443,"users":[$user]}]}}]}""".replace("\n", "")
		val config = (SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok).config
		val node = config.getJSONArray("outbounds").getJSONObject(0)
		return if (node.has("packet_encoding")) node.getString("packet_encoding") else null
	}

	@Test
	fun `a packet encoding Xray servers carry no UDP over is not written`() {
		// Xray reads no packetEncoding, and an Xray server sends nothing back over packetaddr.
		assertEquals(null, packetEncoding("vless", "packet"))
		assertEquals(null, packetEncoding("vmess", "packet"))
		assertEquals("xudp", packetEncoding("vmess", "xudp"))
		assertEquals("", packetEncoding("vless", "none"))
	}

	private fun routed(strategy: String): String {
		val rule = JSONObject().put("type", "field").put("ip", JSONArray().put("10.1.0.0/16"))
			.put("outboundTag", "block")
		val routing = JSONObject().put("domainStrategy", strategy).put("rules", JSONArray().put(rule))
		val block = JSONObject().put("protocol", "blackhole").put("tag", "block")
		return JSONObject().put("outbounds", JSONArray().put(vless("p", "a.example.com")).put(block))
			.put("routing", routing).toString()
	}

	@Test
	fun `routing domain strategies are read without regard to case, anything else as AsIs`() {
		// Xray resolves for address rules under IPIfNonMatch and IPOnDemand alone, in any case.
		for (strategy in listOf("IPIfNonMatch", "ipifnonmatch", "IPONDEMAND")) {
			assertTrue(strategy, singBoxRules(routed(strategy)).contains("\"resolve\""))
			val yaml = mihomo(routed(strategy))
			val kept = yaml.contains("IP-CIDR,10.1.0.0/16,REJECT")
			assertTrue(strategy, kept && !yaml.contains("REJECT,no-resolve"))
		}
		for (strategy in listOf("AsIs", "asis", "foo", "")) {
			assertFalse(strategy, singBoxRules(routed(strategy)).contains("\"resolve\""))
			assertTrue(strategy, mihomo(routed(strategy)).contains("IP-CIDR,10.1.0.0/16,REJECT,no-resolve"))
		}
	}

	@Test
	fun `a sockopt domain strategy reaches both documents in any case, preferences included`() {
		fun dialed(strategy: String): String {
			val node = vless("p", "a.example.com")
			val sockopt = JSONObject().put("domainStrategy", strategy)
			node.put("streamSettings", JSONObject().put("sockopt", sockopt))
			return JSONObject().put("outbounds", JSONArray().put(node)).toString()
		}
		val versions =
			listOf("UseIPv4v6" to "ipv4-prefer", "forceipv6v4" to "ipv6-prefer", "useipv4" to "ipv4")
		for ((strategy, version) in versions) {
			assertTrue(strategy, mihomo(dialed(strategy)).contains("ip-version: $version"))
		}
		val config = (SingBoxConverter.convert(dialed("useipv4"), "N") as SingBoxConverter.Result.Ok).config
		val resolver = config.getJSONArray("outbounds").getJSONObject(0).optJSONObject("domain_resolver")
		assertEquals(config.toString(), "ipv4_only", resolver?.optString("strategy"))
	}

	@Test
	fun `a strategy name is lowered as Go lowers it, and routing takes only its own`() {
		// Go lowers one character at a time: a dotted capital I becomes i, a dotless i stays as it is.
		assertEquals("UseIPv4", xrayDomainStrategyName("Use\u0130Pv4"))
		assertEquals("Use\u0131Pv4", xrayDomainStrategyName("Use\u0131Pv4"))
		assertEquals("U\u017Feipv4", xrayDomainStrategyName("U\u017Feipv4"))
		// A sockopt name in routing is AsIs to Xray, which gives the default resolver no strategy.
		val config = (SingBoxConverter.convert(routed("UseIPv4"), "N") as SingBoxConverter.Result.Ok).config
		val resolver = config.getJSONObject("route").getJSONObject("default_domain_resolver")
		assertFalse(resolver.toString(), resolver.has("strategy"))
	}

	@Test
	fun `vmess experiments reach both documents, written in the user or in the flat form`() {
		// Xray reads AuthenticatedLength and NoTerminationSignal from experiments as plain substrings.
		val id = "b831381d-6324-4d53-ad4f-8cda48b30811"
		val experiments = "\"experiments\":\"AuthenticatedLength|NoTerminationSignal\""
		val user = """{"id":"$id",$experiments}"""
		val nested = """{"vnext":[{"address":"m.example.com","port":443,"users":[$user]}]}"""
		val flat = """{"address":"m.example.com","port":443,"id":"$id",$experiments}"""
		for (settings in listOf(nested, flat)) {
			val body = """{"outbounds":[{"protocol":"vmess","tag":"m","settings":$settings}]}"""
			val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
			val node = singBox.config.getJSONArray("outbounds").getJSONObject(0)
			assertTrue(settings, node.optBoolean("authenticated_length"))
			assertTrue(settings, singBox.notes.any { it.contains("NoTerminationSignal") })
			assertTrue(settings, mihomo(body).contains("authenticated-length: true"))
		}
	}

	@Test
	fun `a condition written as one string counts as Xray counts it`() {
		// Xray takes a lone string for a one-entry list, so it is a condition like any other.
		val process = ruled(JSONObject().put("process", "chrome"))
		assertTrue(singBoxRules(process), singBoxRules(process).contains("\"process_name\":[\"chrome\"]"))
		assertFalse(mihomo(process), mihomo(process).contains("MATCH,REJECT"))
		val domains = ruled(JSONObject().put("domains", "domain:x.example.com"))
		assertTrue(singBoxRules(domains), singBoxRules(domains).contains("x.example.com"))
		assertTrue(mihomo(domains), mihomo(domains).contains("x.example.com,REJECT"))
		val localIp = ruled(JSONObject().put("localIP", "127.0.0.1"))
		assertFalse(singBoxRules(localIp), singBoxRules(localIp).contains("\"reject\""))
		assertFalse(mihomo(localIp), mihomo(localIp).contains("MATCH,REJECT"))
	}

	@Test
	fun `vless encryption paddings are read as Xray reads them`() {
		val key = "A".repeat(43)
		fun enc(tokens: String) = "mlkem768x25519plus.native.1rtt.$tokens"
		assertEquals(null, vlessEncryptionRefusal(enc("100-35-35.$key")))
		assertEquals(null, vlessEncryptionRefusal(enc(".$key")))
		// Xray cuts the paddings from the front, so one after a key takes part of the key instead.
		assertTrue(vlessEncryptionRefusal(enc("$key.100-35-35")) != null)
		// Go reads 64-bit numbers in ASCII digits only.
		assertEquals(null, vlessEncryptionRefusal(enc("100-35-35.99999999999-1-1.$key")))
		assertTrue(vlessEncryptionRefusal(enc("\u0661\u0660\u0660-35-35.$key")) != null)
		// Lengths summed as Go sums them: no 32-bit wrap lets an oversized total through.
		val wide = "0-0-0.0-2147483647-2147483647"
		assertTrue(vlessEncryptionRefusal(enc("100-35-35.$wide.$wide.$key")) != null)
		assertEquals(null, vlessEncryptionRefusal(enc("100-35-35.0-0-0.0-65518-1.$key")))
		assertTrue(vlessEncryptionRefusal(enc("100-35-35.0-0-0.0-65519-1.$key")) != null)
	}

	@Test
	fun `an ml-kem key is read as Go reads one, every coefficient below 3329`() {
		// A wrong one makes Xray refuse the node and mihomo the whole file; the bounds are Xray's own.
		fun key(first: Int, second: Int, third: Int): String {
			val bytes = ByteArray(1184)
			bytes[0] = first.toByte()
			bytes[1] = second.toByte()
			bytes[2] = third.toByte()
			return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
		}
		fun enc(key: String) = "mlkem768x25519plus.native.1rtt.100-35-35.$key"
		assertEquals(null, vlessEncryptionRefusal(enc(key(0x00, 0x0D, 0x00))))
		assertTrue(vlessEncryptionRefusal(enc(key(0x01, 0x0D, 0x00))) != null)
		assertEquals(null, vlessEncryptionRefusal(enc(key(0x00, 0x00, 0xD0))))
		assertTrue(vlessEncryptionRefusal(enc(key(0x00, 0x10, 0xD0))) != null)
	}

	@Test
	fun `http proxy headers come from settings in either form and reach both documents`() {
		// Xray reads them beside the servers and sends them with every CONNECT; a server has none.
		val stray = """"headers":{"X-Stray":"no"}"""
		val servers = """"servers":[{"address":"h.example.com","port":8080,$stray}]"""
		val flat = """"address":"h.example.com","port":8080"""
		for (form in listOf(servers, flat)) {
			val settings = """{$form,"headers":{"X-Token":"abc"}}"""
			val body = """{"outbounds":[{"protocol":"http","tag":"h","settings":$settings}]}"""
			val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
			val node = singBox.config.getJSONArray("outbounds").getJSONObject(0)
			assertEquals(form, "abc", node.getJSONObject("headers").optString("X-Token"))
			assertFalse(form, node.getJSONObject("headers").has("X-Stray"))
			val yaml = mihomo(body)
			assertTrue(yaml, yaml.contains("X-Token: abc"))
			assertFalse(yaml, yaml.contains("X-Stray"))
		}
	}

	@Test
	fun `socks and http without a server list reach every pass, a lone password unused`() {
		// Xray reads the address beside the rest when there is no list, and a user only when named.
		val named = """{"address":"p.example.com","port":1080,"user":"u","pass":"pw"}"""
		val lone = """{"address":"p.example.com","port":1080,"pass":"pw"}"""
		for (protocol in listOf("socks", "http")) {
			for ((settings, authed) in listOf(named to true, lone to false)) {
				val body = """{"outbounds":[{"protocol":"$protocol","tag":"p","settings":$settings}]}"""
				val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
				val node = singBox.config.getJSONArray("outbounds").getJSONObject(0)
				assertEquals(body, authed, node.optString("password").isNotEmpty())
				val link = SubscriptionConverter.convert(body, jsonToUri = true, base64Result = false)
				assertTrue(link, link.contains("p.example.com:1080"))
				assertEquals(link, authed, link.contains("@p.example.com"))
				val yaml = mihomo(body)
				assertTrue(yaml, yaml.contains("server: p.example.com"))
				assertEquals(yaml, authed, yaml.contains("password: pw"))
			}
		}
	}

	@Test
	fun `a wireguard peer Xray fails the tunnel over is dropped, and the one a core can reach stays`() {
		// As the real Xray showed, such an endpoint fails its whole tunnel and a missing one the load;
		// a core reaches the first peer all the same, so the node keeps it and names the second.
		val key = "cKX1G0yg4Uyq6M6l7xX6h4L3s8m3Jo2eZk1v7d9n2ZA="
		fun body(second: String): String {
			val first = """{"publicKey":"$key","endpoint":"1.2.3.4:51820"}"""
			val peers = """[$first,{"publicKey":"$key","endpoint":"$second"}]"""
			val settings = """{"secretKey":"$key","address":["10.0.0.2/32"],"peers":$peers}"""
			return """{"outbounds":[{"protocol":"wireguard","tag":"w","settings":$settings}]}"""
		}
		val empty = body("")
		val nulled = empty.replace("\"endpoint\":\"\"", "\"endpoint\":null")
		for (second in listOf(body("5.6.7.8"), empty, nulled, empty.replace(",\"endpoint\":\"\"", ""))) {
			val singBox = SingBoxConverter.convert(second, "N") as SingBoxConverter.Result.Ok
			val peers = singBox.config.getJSONArray("endpoints").getJSONObject(0).getJSONArray("peers")
			assertEquals(second, 1, peers.length())
			assertEquals("1.2.3.4", peers.getJSONObject(0).getString("address"))
			assertTrue("${singBox.notes}", singBox.notes.any { "WireGuard peer 2 was dropped" in it })
			val mihomo = MihomoConverter.convert(second) as MihomoConverter.Result.Ok
			assertTrue(mihomo.yaml, mihomo.yaml.contains("server: 1.2.3.4"))
			assertTrue("${mihomo.notes}", mihomo.notes.any { "WireGuard peer 2 was dropped" in it })
		}
	}

	@Test
	fun `a vless seed is said to do nothing, by every pass in the same words`() {
		// Xray reads it beside the server and never hands it on, so no pass may call it lost.
		val id = "b831381d-6324-4d53-ad4f-8cda48b30811"
		val settings = """{"address":"v.example.com","port":443,"id":"$id","encryption":"none","seed":"s"}"""
		val outbound = """{"protocol":"vless","tag":"v","settings":$settings}"""
		val body = """{"outbounds":[$outbound]}"""
		val singBox = (SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok).notes
		assertTrue("$singBox", singBox.any { UNUSED_VLESS_SEED in it })
		val mihomo = (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).notes
		assertTrue("$mihomo", mihomo.any { UNUSED_VLESS_SEED in it })
		val links = mutableListOf<String>()
		assertTrue(LinkBuilders.buildVless(JSONObject(outbound), "N", links, LinkClients.ANY) != null)
		assertTrue("$links", links.any { UNUSED_VLESS_SEED in it })
	}

	@Test
	fun `a node dialed through freedom goes straight out and through blackhole nowhere, in both passes`() {
		// As the real Xray ran them: through freedom the node works, through blackhole it never does.
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val vnext = """{"vnext":[{"address":"v.example.com","port":443,"users":[$user]}]}"""
		val stream = """{"sockopt":{"dialerProxy":"via"}}"""
		val node = """{"protocol":"vless","tag":"node","settings":$vnext,"streamSettings":$stream}"""
		val fragment = """{"fragment":{"packets":"tlshello","length":"100-200","interval":"10-20"}}"""
		val freedom = """{"outbounds":[$node,{"protocol":"freedom","tag":"via","settings":$fragment}]}"""
		val singBox = SingBoxConverter.convert(freedom, "N") as SingBoxConverter.Result.Ok
		// No detour: sing-box dials through no direct outbound that has nothing of its own.
		val first = singBox.config.getJSONArray("outbounds").getJSONObject(0)
		assertFalse("$first", first.has("detour"))
		val mihomo = MihomoConverter.convert(freedom) as MihomoConverter.Result.Ok
		assertEquals(1, mihomo.converted)
		assertFalse(mihomo.yaml, mihomo.yaml.contains("dialer-proxy"))
		assertTrue("${mihomo.notes}", mihomo.notes.any { "without its fragment" in it })
		val blackhole = """{"outbounds":[$node,{"protocol":"blackhole","tag":"via"}]}"""
		val singBoxDropped = SingBoxConverter.convert(blackhole, "N")
		assertTrue("$singBoxDropped", singBoxDropped !is SingBoxConverter.Result.Ok)
		val mihomoDropped = MihomoConverter.convert(blackhole)
		assertTrue("$mihomoDropped", mihomoDropped !is MihomoConverter.Result.Ok)
	}

	// A freedom that dials through a node stands for that node - for the rules sending traffic to it and
	// the nodes dialing through it - in both passes; one with a setting of its own stays a detour.
	@Test
	fun `a freedom dialing through a node stands for that node, in both passes`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		fun node(tag: String, via: String?): String {
			val stream = if (via == null) "" else ""","streamSettings":{"sockopt":{"dialerProxy":"$via"}}"""
			val vnext = """{"vnext":[{"address":"$tag.example.com","port":443,"users":[$user]}]}"""
			return """{"protocol":"vless","tag":"$tag","settings":$vnext$stream}"""
		}
		val freedoms = """{"protocol":"freedom","tag":"out",""" +
			""""streamSettings":{"sockopt":{"dialerProxy":"p"}}},{"protocol":"freedom","tag":"plain"},""" +
			"""{"protocol":"freedom","tag":"ipv4","settings":{"domainStrategy":"UseIPv4"}}"""
		val rule = """"routing":{"rules":[{"type":"field","domain":["domain:x.example.com"],""" +
			""""outboundTag":"out"}]}"""
		val nodes = listOf(node("p", null), node("a", "out"), node("b", "plain"), node("c", "ipv4"))
		val body = """{"outbounds":[${nodes.joinToString(",")},$freedoms],$rule}"""
		val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		val outbounds = singBox.config.getJSONArray("outbounds")
		val written = (0 until outbounds.length()).map { outbounds.getJSONObject(it) }
		val byServer = written.associateBy { it.optString("server") }
		val p = byServer.getValue("p.example.com").getString("tag")
		assertEquals(p, byServer.getValue("a.example.com").optString("detour"))
		assertFalse("${byServer["b.example.com"]}", byServer.getValue("b.example.com").has("detour"))
		assertEquals("ipv4", byServer.getValue("c.example.com").optString("detour"))
		assertTrue("$written", written.none { it.optString("type") == "direct" && it.has("detour") })
		val rules = singBox.config.getJSONObject("route").getJSONArray("rules")
		val routed = (0 until rules.length()).map { rules.getJSONObject(it) }
		assertTrue("$routed", routed.any { "x.example.com" in "$it" && it.optString("outbound") == p })
		assertTrue("${singBox.notes}", singBox.notes.any { "so \"$p\" takes what goes to it" in it })
		val mihomo = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
		val a = mihomo.yaml.substringAfter("name: a\n").substringBefore("  - name:")
		assertTrue(a, a.contains("dialer-proxy: p\n"))
		assertTrue(mihomo.yaml, mihomo.yaml.contains("x.example.com,p\n"))
		// Xray connects that chain, so the link - which carries none - keeps the node.
		val links = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
		assertTrue(links.text, "@a.example.com:443" in links.text)
	}

	// A freedom whose own chain never connects - through a node left out, a blackhole, round in a circle -
	// is no way out either: a node dialing through it goes in every pass, and a rule to it is dropped
	// rather than sent straight out. What a freedom passed on the way holds of its own is named.
	@Test
	fun `a freedom whose own chain never connects takes its nodes and rules, in every pass`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		fun node(tag: String, via: String?, security: String = "none"): String {
			val sockopt = if (via == null) "" else ""","sockopt":{"dialerProxy":"$via"}"""
			val vnext = """{"vnext":[{"address":"$tag.example.com","port":443,"users":[$user]}]}"""
			return """{"protocol":"vless","tag":"$tag","settings":$vnext,""" +
				""""streamSettings":{"network":"tcp","security":"$security"$sockopt}}"""
		}
		fun freedom(tag: String, via: String) =
			"""{"protocol":"freedom","tag":"$tag","streamSettings":{"sockopt":{"dialerProxy":"$via"}}}"""
		val rule = """"routing":{"rules":[{"type":"field","domain":["domain:x.example.com"],""" +
			""""outboundTag":"f1"}]}"""
		val ends = listOf(
			listOf(freedom("f1", "bad"), node("bad", null, security = "bogus")),
			listOf(freedom("f1", "bh"), """{"protocol":"blackhole","tag":"bh"}"""),
			listOf(freedom("f1", "f2"), freedom("f2", "f1"))
		)
		for (end in ends) {
			val nodes = "${node("c", null)},${node("a", "f1")}"
			val body = """{"outbounds":[$nodes,${end.joinToString(",")}],$rule}"""
			val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
			val written = singBox.config.toString()
			assertTrue(written, "c.example.com" in written && "a.example.com" !in written)
			assertFalse(written, "x.example.com" in written)
			val mihomo = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
			assertFalse(mihomo.yaml, "a.example.com" in mihomo.yaml || "x.example.com" in mihomo.yaml)
			assertTrue("${mihomo.notes}", mihomo.notes.any { "the rule was dropped" in it })
			val links = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
			assertFalse(links.text, "a.example.com" in links.text)
		}
		val own = """"settings":{"domainStrategy":"UseIPv4","fragment":{"packets":"1-3","length":"1-5"}}"""
		val chain = """"streamSettings":{"sockopt":{"dialerProxy":"c"}}"""
		val holding = """{"protocol":"freedom","tag":"f1",$own,$chain}"""
		val body = """{"outbounds":[${node("c", null)},${node("a", "f1")},$holding]}"""
		val mihomo = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
		val lost = "dials through freedom \"f1\", which dials through \"c\", but without its fragment"
		assertTrue("${mihomo.notes}", mihomo.notes.any { lost in it })
		val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		assertTrue("${singBox.notes}", singBox.notes.any { "without the freedom's domainStrategy" in it })
	}

	@Test
	fun `a chain through a node left out, or in a circle, takes the node too, in both passes`() {
		// Either would leave a dangling or circular detour, which each core refuses for the whole file.
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		fun node(tag: String, via: String?): String {
			val stream = if (via == null) "" else ""","streamSettings":{"sockopt":{"dialerProxy":"$via"}}"""
			val vnext = """{"vnext":[{"address":"$tag.example.com","port":443,"users":[$user]}]}"""
			return """{"protocol":"vless","tag":"$tag","settings":$vnext$stream}"""
		}
		val blackhole = """{"protocol":"blackhole","tag":"bh"}"""
		val cascade = """{"outbounds":[${node("a", "b")},${node("b", "bh")},${node("c", null)},$blackhole]}"""
		val circle = """{"outbounds":[${node("a", "b")},${node("b", "a")},${node("c", null)}]}"""
		val cases = listOf(cascade to "was left out itself", circle to "leads back to it in a circle")
		for ((body, why) in cases) {
			val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
			val written = singBox.config.toString()
			assertTrue(written, written.contains("c.example.com") && !written.contains("a.example.com"))
			assertFalse(written, written.contains("b.example.com") || written.contains("\"detour\""))
			assertTrue("${singBox.notes}", singBox.notes.any { why in it })
			val mihomo = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
			assertEquals(1, mihomo.converted)
			assertFalse(mihomo.yaml, mihomo.yaml.contains("dialer-proxy"))
			assertFalse(mihomo.yaml, mihomo.yaml.contains("a.example.com"))
			assertTrue("${mihomo.notes}", mihomo.notes.any { why in it })
		}
		val rule = """"routing":{"rules":[{"type":"field","domain":["x.example.com"],"outboundTag":"a"}]}"""
		val ruled = """{"outbounds":[${node("c", null)},${node("a", "bh")},$blackhole],$rule}"""
		val mihomo = MihomoConverter.convert(ruled) as MihomoConverter.Result.Ok
		assertFalse(mihomo.yaml, mihomo.yaml.contains("x.example.com"))
		assertTrue("${mihomo.notes}", mihomo.notes.any { "the rule was dropped" in it })
	}

	@Test
	fun `a chain is read as Xray reads it, by every pass`() {
		// Xray refuses both chain fields at once - the node follows proxySettings.tag then - reads
		// dialerProxy in sockopt alone, and a link whose chain it never connects through is no link.
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		fun node(tag: String, extra: String = ""): String {
			val vnext = """{"vnext":[{"address":"$tag.example.com","port":443,"users":[$user]}]}"""
			return """{"protocol":"vless","tag":"$tag","settings":$vnext$extra}"""
		}
		fun via(tag: String) = ""","streamSettings":{"sockopt":{"dialerProxy":"$tag"}}"""
		fun links(body: String) = SubscriptionConverter.convert(body, jsonToUri = true, base64Result = false)
		val both = ""","proxySettings":{"tag":"p1"},"streamSettings":{"sockopt":{"dialerProxy":"p2"}}"""
		val bothBody = """{"outbounds":[${node("a", both)},${node("p1")},${node("p2")}]}"""
		val singBox = SingBoxConverter.convert(bothBody, "N") as SingBoxConverter.Result.Ok
		assertTrue(singBox.config.toString(), singBox.config.toString().contains("a.example.com"))
		assertTrue("${singBox.notes}", singBox.notes.any { "proxySettings.tag \"p1\" was followed" in it })
		val mihomo = MihomoConverter.convert(bothBody) as MihomoConverter.Result.Ok
		assertTrue(mihomo.yaml, mihomo.yaml.contains("a.example.com"))
		assertTrue(links(bothBody), links(bothBody).contains("@a.example.com"))
		val misplaced = ""","streamSettings":{"dialerProxy":"p1"}"""
		val misplacedBody = """{"outbounds":[${node("a", misplaced)},${node("p1")}]}"""
		val quiet = SingBoxConverter.convert(misplacedBody, "N") as SingBoxConverter.Result.Ok
		assertFalse(quiet.config.toString(), quiet.config.toString().contains("\"detour\""))
		assertTrue("${quiet.notes}", quiet.notes.any { MISPLACED_DIALER_PROXY in it })
		val quietMihomo = MihomoConverter.convert(misplacedBody) as MihomoConverter.Result.Ok
		assertFalse(quietMihomo.yaml, quietMihomo.yaml.contains("dialer-proxy"))
		assertTrue("${quietMihomo.notes}", quietMihomo.notes.any { MISPLACED_DIALER_PROXY in it })
		val linkNotes = mutableListOf<String>()
		LinkBuilders.reportOutboundExtrasNotCarried(JSONObject(node("a", misplaced)), linkNotes)
		assertTrue("$linkNotes", linkNotes.any { MISPLACED_DIALER_PROXY in it })
		val ends = """{"protocol":"blackhole","tag":"bh"},{"protocol":"freedom","tag":"f"}"""
		val dead = listOf(node("a", via("bh")), node("b", via("zz")), node("c", via("d")))
		val live = listOf(node("d", via("c")), node("e", via("f")), node("g", via("h")), node("h"))
		val deadBody = """{"outbounds":[${(dead + live).joinToString(",")},$ends]}"""
		val written = links(deadBody)
		for (host in listOf("e", "g", "h")) assertTrue(written, written.contains("@$host.example.com"))
		for (host in listOf("a", "b", "c", "d")) assertFalse(written, written.contains("@$host.example.com"))
	}

	@Test
	fun `what Xray 26 refuses but the cores run is kept and said, by every pass alike`() {
		// Decided: such a configuration written for an earlier Xray keeps working, each such reading named.
		val id = "b831381d-6324-4d53-ad4f-8cda48b30811"
		fun outbound(stream: String, encryption: String = "\"encryption\":\"none\","): String {
			val user = """{$encryption"id":"$id"}"""
			val vnext = """{"vnext":[{"address":"v.example.com","port":443,"users":[$user]}]}"""
			return """{"protocol":"vless","tag":"v","settings":$vnext,"streamSettings":$stream}"""
		}
		fun notesOf(xray: String): List<List<String>> {
			val body = """{"outbounds":[$xray]}"""
			val links = mutableListOf<String>()
			LinkBuilders.reportOutboundExtrasNotCarried(JSONObject(xray), links)
			val singBox = (SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok).notes
			return listOf(singBox, (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).notes, links)
		}
		val key = "A".repeat(43)
		val realitySettings = """{"serverName":"v.example.com","publicKey":"$key","shortIds":["ab"]}"""
		val reality = """{"realitySettings":$realitySettings}"""
		val xtls = """{"security":"xtls","tlsSettings":{"serverName":"v.example.com"}}"""
		val cases = listOf(
			outbound("""{"security":"auto"}""") to listOf("security \"auto\""),
			outbound(xtls) to listOf("security \"xtls\""),
			outbound(reality) to listOf("security is not set", "its first was taken as shortId"),
			outbound("""{"network":"tcp"}""", encryption = "") to listOf("names no encryption")
		)
		for ((xray, said) in cases) {
			for (notes in notesOf(xray)) for (part in said) assertTrue("$notes", notes.any { part in it })
		}
		val realityBody = """{"outbounds":[${outbound(reality)}]}"""
		val link = SubscriptionConverter.convert(realityBody, jsonToUri = true, base64Result = false)
		assertTrue(link, link.contains("sid=ab"))
	}

	@Test
	fun `a verify certificate that does not read is dropped and the node kept, as Xray keeps it`() {
		// Xray logs "failed to append cert" and verifies against the system store; sing-box would refuse
		// the whole document over the certificate, so it goes and the node stays.
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val vnext = """{"vnext":[{"address":"v.example.com","port":443,"users":[$user]}]}"""
		val cert = """{"usage":"verify","certificate":"garbage"}"""
		val tls = """{"serverName":"v.example.com","certificates":[$cert]}"""
		val stream = """{"security":"tls","tlsSettings":$tls}"""
		val outbound = """{"protocol":"vless","tag":"v","settings":$vnext,"streamSettings":$stream}"""
		val body = """{"outbounds":[$outbound]}"""
		val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		val node = singBox.config.getJSONArray("outbounds").getJSONObject(0)
		assertFalse(node.toString(), node.getJSONObject("tls").has("certificate"))
		val notes = singBox.notes
		assertTrue("$notes", notes.any { "against the system store" in it })
		assertEquals(1, (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).converted)
	}

	@Test
	fun `a brutal rate Xray owns is read as Xray reads it, and one it refuses is dropped`() {
		// As the real Xray showed: binary units, a bare number in bits, at least 65536 bytes a second.
		fun body(rate: String): String {
			val tls = """"security":"tls","tlsSettings":{"serverName":"h.example.com"}"""
			val mask = """"finalmask":{"quicParams":{"brutalUp":"$rate"}}"""
			val stream = """{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"pw"},$tls,$mask}"""
			val settings = """{"version":2,"address":"h.example.com","port":443}"""
			val fields = """"settings":$settings,"streamSettings":$stream"""
			val outbound = """{"protocol":"hysteria","tag":"h",$fields}"""
			return """{"outbounds":[$outbound]}"""
		}
		val singBox = SingBoxConverter.convert(body("100 mbps"), "N") as SingBoxConverter.Result.Ok
		assertEquals(105, singBox.config.getJSONArray("outbounds").getJSONObject(0).optInt("up_mbps"))
		val yaml = (MihomoConverter.convert(body("100 mbps")) as MihomoConverter.Result.Ok).yaml
		assertTrue(yaml, yaml.contains("up: 104857600 bps"))
		assertTrue(SingBoxConverter.convert(body("524288"), "N") is SingBoxConverter.Result.Ok)
		// One Xray would refuse the configuration over goes; the node connects at the core's own pace.
		for (dropped in listOf("524287", "511 kbps", "100 MiB")) {
			val kept = SingBoxConverter.convert(body(dropped), "N") as SingBoxConverter.Result.Ok
			assertFalse(dropped, kept.config.getJSONArray("outbounds").getJSONObject(0).has("up_mbps"))
			assertTrue("${kept.notes}", kept.notes.any { "brutalUp" in it && "dropped" in it })
			val keptYaml = (MihomoConverter.convert(body(dropped)) as MihomoConverter.Result.Ok).yaml
			assertFalse(keptYaml, keptYaml.contains("up:"))
		}
	}

	@Test
	fun `an address beside a server list is the one Xray reads, in every pass`() {
		// Xray builds its one server from the address and drops the list beside it ("if c.Address != nil").
		val id = "b831381d-6324-4d53-ad4f-8cda48b30811"
		val user = """{"id":"$id","encryption":"none"}"""
		val listed = """{"address":"list.example.com","port":443,"users":[$user]}"""
		val vless = """{"vnext":[$listed],"address":"flat.example.com",""" +
			""""port":443,"id":"$id","encryption":"none"}"""
		val socksList = """[{"address":"list.example.com","port":1080}]"""
		val socks = """{"address":"flat.example.com","port":1080,"servers":$socksList}"""
		for ((protocol, settings) in listOf("vless" to vless, "socks" to socks)) {
			val body = """{"outbounds":[{"protocol":"$protocol","tag":"t","settings":$settings}]}"""
			val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
			val written = singBox.config.toString()
			assertTrue(written, written.contains("flat.example.com") && !written.contains("list.example.com"))
			assertTrue("${singBox.notes}", singBox.notes.any { "is not read by Xray" in it })
			val yaml = (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).yaml
			assertTrue(yaml, yaml.contains("flat.example.com") && !yaml.contains("list.example.com"))
			val links = SubscriptionConverter.convert(body, jsonToUri = true, base64Result = false)
			assertTrue(links, links.contains("flat.example.com") && !links.contains("list.example.com"))
		}
	}

	@Test
	fun `sip003 options read as sing-box reads them and write back the same`() {
		// v2ray-plugin's args.go, which sing-box carries: a key alone is "1", the first of a repeat counts.
		val obfs = mapOf("obfs" to "http", "obfs-host" to "a.example.com")
		assertEquals(obfs, sip003Options("obfs=http;obfs-host=a.example.com"))
		assertEquals(mapOf("tls" to "1", "host" to "h"), sip003Options("tls;host=h"))
		val escaped = "path=/a\\;b;mode=websocket;mode=quic"
		assertEquals(mapOf("path" to "/a;b", "mode" to "websocket"), sip003Options(escaped))
		assertEquals(mapOf("a" to "1"), sip003Options("a=1;"))
		for (refused in listOf(";;", "=x", "a=b\\", "a=1;;b=2")) {
			assertEquals(refused, null, sip003Options(refused))
		}
		val options = linkedMapOf("path" to "/a;b=c\\d", "tls" to "")
		val written = TransportPlugin("v2ray-plugin", options, insecure = false)
		val back = sip003Options(written.sip003().substringAfter(';'))
		assertEquals(mapOf("path" to "/a;b=c\\d", "tls" to "1"), back)
	}

	@Test
	fun `a server plugin reaches every pass in its form, and one a core refuses takes the node`() {
		// Decided: carried with a note, though Xray never reads it; refused where a core would refuse it all.
		fun body(plugin: String, opts: String): String {
			val server = """{"address":"s.example.com","port":8388,"method":"aes-128-gcm",""" +
				""""password":"pw","plugin":"$plugin","plugin_opts":"$opts"}"""
			val settings = """{"servers":[$server]}"""
			val outbound = """{"protocol":"shadowsocks","tag":"s","settings":$settings}"""
			return """{"outbounds":[$outbound]}"""
		}
		fun links(body: String) = SubscriptionConverter.convert(body, jsonToUri = true, base64Result = false)
		val obfs = body("simple-obfs", "obfs=tls;obfs-host=b.example.com")
		val singBox = SingBoxConverter.convert(obfs, "N") as SingBoxConverter.Result.Ok
		val node = singBox.config.getJSONArray("outbounds").getJSONObject(0)
		assertEquals("obfs-local", node.optString("plugin"))
		assertEquals("obfs=tls;obfs-host=b.example.com", node.optString("plugin_opts"))
		assertTrue("${singBox.notes}", singBox.notes.any { "which Xray never reads" in it })
		val yaml = (MihomoConverter.convert(obfs) as MihomoConverter.Result.Ok).yaml
		for (part in listOf("plugin: obfs", "mode: tls", "host: b.example.com")) {
			assertTrue(yaml, yaml.contains(part))
		}
		assertTrue(links(obfs), links(obfs).contains("plugin=obfs-local"))
		val v2ray = (MihomoConverter.convert(body("v2ray-plugin", "")) as MihomoConverter.Result.Ok).yaml
		assertTrue(v2ray, v2ray.contains("host: cloudfront.com") && v2ray.contains("mux: true"))
		val quic = body("v2ray-plugin", "mode=quic;tls")
		assertTrue(SingBoxConverter.convert(quic, "N") is SingBoxConverter.Result.Ok)
		assertTrue(MihomoConverter.convert(quic) !is MihomoConverter.Result.Ok)
		val refused = listOf(
			body("kcptun", ""), body("obfs-local", "obfs=nonsense"), body("v2ray-plugin", "mode=quic"),
			body("v2ray-plugin", "mux=x")
		)
		for (each in refused) {
			assertTrue(each, SingBoxConverter.convert(each, "N") !is SingBoxConverter.Result.Ok)
			assertTrue(each, MihomoConverter.convert(each) !is MihomoConverter.Result.Ok)
			assertFalse(each, links(each).contains("ss://"))
		}
	}

	@Test
	fun `a server plugin reads as written, and what it takes by default is written out for every reader`() {
		fun body(plugin: String, opts: String): String {
			val server = """{"address":"s.example.com","port":8388,"method":"aes-128-gcm",""" +
				""""password":"pw","plugin":"$plugin","plugin_opts":$opts}"""
			val outbound = """{"protocol":"shadowsocks","tag":"s","settings":{"servers":[$server]}}"""
			return """{"outbounds":[$outbound]}"""
		}
		fun singBox(body: String): JSONObject {
			val ok = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
			return ok.config.getJSONArray("outbounds").getJSONObject(0)
		}
		fun mihomo(body: String) = (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).yaml
		fun links(body: String) = SubscriptionConverter.convert(body, jsonToUri = true, base64Result = false)
		fun linkPlugin(link: String) =
			URLDecoder.decode(link.substringAfter("plugin=").substringBefore('#'), "UTF-8")
		// An object says what it means: tls is on by presence, so false is none; mux false is 0.
		val json = body("v2ray-plugin", """{"tls":false,"mux":false,"host":"a;b"}""")
		assertEquals("mux=0;host=a\\;b", singBox(json).optString("plugin_opts"))
		val written = mihomo(json)
		assertTrue(written, written.contains("mux: false") && !written.contains("tls: true"))
		// mihomo's own name for the plugin comes with its own names for the options.
		val clash = body("obfs", """{"mode":"tls","host":"c.example.com"}""")
		assertEquals("obfs=tls;obfs-host=c.example.com", singBox(clash).optString("plugin_opts"))
		assertTrue(mihomo(clash), mihomo(clash).contains("mode: tls"))
		// The host each plugin takes when none is written goes to every reader - mihomo would send another,
		// sing-box none from obfs-local; a link writes the mode too, which mihomo refuses the proxy without.
		val bare = body("obfs-local", "\"obfs=http\"")
		assertEquals("obfs=http;obfs-host=cloudfront.net", singBox(bare).optString("plugin_opts"))
		assertTrue(mihomo(bare), mihomo(bare).contains("host: cloudfront.net"))
		assertEquals("obfs-local;obfs=http;obfs-host=cloudfront.net", linkPlugin(links(bare)))
		val v2ray = body("v2ray-plugin", "\"tls\"")
		assertEquals("tls=1;host=cloudfront.com", singBox(v2ray).optString("plugin_opts"))
		assertEquals("v2ray-plugin;mode=websocket;tls=1;host=cloudfront.com", linkPlugin(links(v2ray)))
		val modeless = body("obfs-local", "\"obfs-host=d.example.com\"")
		assertEquals("obfs-local;obfs=http;obfs-host=d.example.com", linkPlugin(links(modeless)))
		// A node written as sing-box writes one keeps its server on the outbound: the same plugin rules.
		val flat = """{"protocol":"shadowsocks","tag":"f","server":"f.example.com","server_port":8388,""" +
			""""method":"aes-128-gcm","password":"pw","plugin":"simple-obfs","plugin_opts":"obfs=http"}"""
		val flatLinks = links("""{"outbounds":[$flat]}""")
		assertTrue(flatLinks, flatLinks.contains("plugin=obfs-local%3B"))
	}

	@Test
	fun `a transport the server's own plugin takes the place of is named alike in every pass`() {
		val server = """{"address":"s.example.com","port":8388,"method":"aes-128-gcm","password":"pw",""" +
			""""plugin":"obfs-local","plugin_opts":"obfs=http"}"""
		val stream = """{"network":"ws","security":"tls","tlsSettings":{"allowInsecure":true}}"""
		val outbound = """{"protocol":"shadowsocks","tag":"s","settings":{"servers":[$server]},""" +
			""""streamSettings":$stream}"""
		val body = """{"outbounds":[$outbound]}"""
		val note = "the server's own plugin \"obfs-local\" takes the place of the ws transport over tls " +
			"under the outbound, so that was dropped"
		val passes = listOf(
			SubscriptionConverter.convertWithStats(body, jsonToUri = true),
			SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true),
			SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true)
		)
		for (pass in passes) {
			assertTrue(pass.notes.toString(), pass.notes.any { note in it })
			// Its allowInsecure went with it, so no plugin is said to verify in its place.
			assertFalse(pass.notes.toString(), pass.notes.any { "no place in the v2ray-plugin" in it })
		}
	}

	@Test
	fun `a server address is written as Xray writes it`() {
		// Each pair is what the real Xray sent as the Host header for that written address.
		val sent = linkedMapOf(
			"127.0.0.1" to "127.0.0.1", "::ffff:127.0.0.1" to "127.0.0.1", "localhost" to "localhost",
			"Example.COM" to "Example.COM", "0:0:0:0:0:0:0:1" to "[::1]", "[::1]" to "[::1]",
			"2001:0DB8:0:0:0:0:0:1" to "[2001:db8::1]", "1:0:0:2:0:0:0:3" to "[1:0:0:2::3]",
			"1:0:0:2:0:0:3:4" to "[1::2:0:0:3:4]", "1:2:3:4:5:6:7:0" to "[1:2:3:4:5:6:7:0]",
			"::1.2.3.4" to "[::102:304]", "fe80::1%eth0" to "fe80::1%eth0"
		)
		for ((written, wire) in sent) assertEquals(written, wire, xrayAddressString(written))
	}

	@Test
	fun `a websocket plugin sends the host and path Xray sends`() {
		// No host, Host header or server name: Xray sends the address; a path gets its leading slash.
		fun body(security: String): String {
			val server = """{"address":"2001:0DB8:0:0:0:0:0:1","port":8388,""" +
				""""method":"aes-128-gcm","password":"pw"}"""
			val stream = """{"network":"ws","wsSettings":{"path":"ws"}$security}"""
			val settings = """{"servers":[$server]}"""
			val fields = """"settings":$settings,"streamSettings":$stream"""
			val outbound = """{"protocol":"shadowsocks","tag":"s",$fields}"""
			return """{"outbounds":[$outbound]}"""
		}
		val plain = body("")
		val singBox = SingBoxConverter.convert(plain, "N") as SingBoxConverter.Result.Ok
		val options = singBox.config.getJSONArray("outbounds").getJSONObject(0).optString("plugin_opts")
		assertEquals("mode=websocket;host=[2001:db8::1];path=/ws", options)
		val yaml = (MihomoConverter.convert(plain) as MihomoConverter.Result.Ok).yaml
		assertTrue(yaml, yaml.contains("2001:db8::1]") && yaml.contains("path: /ws"))
		val link = SubscriptionConverter.convert(plain, jsonToUri = true, base64Result = false)
		val plugin = URLDecoder.decode(link.substringAfter("plugin=").substringBefore('#'), "UTF-8")
		assertEquals("v2ray-plugin;mode=websocket;host=[2001:db8::1];path=/ws", plugin)
		// A server name written for TLS is the host, ahead of the address.
		val named = body(""","security":"tls","tlsSettings":{"serverName":"sni.example.com"}""")
		val namedOptions = (SingBoxConverter.convert(named, "N") as SingBoxConverter.Result.Ok).config
			.getJSONArray("outbounds").getJSONObject(0).optString("plugin_opts")
		assertEquals("mode=websocket;host=sni.example.com;path=/ws;tls", namedOptions)
	}

	@Test
	fun `a vmess security Xray reads as auto is written as auto, so the node connects`() {
		// As the real cores showed: Xray's own server takes auto from sing-box and mihomo but refuses
		// none and zero, and Xray itself runs both as auto.
		fun body(security: String): String {
			val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"$security"}"""
			val settings = """{"vnext":[{"address":"v.example.com","port":443,"users":[$user]}]}"""
			return """{"outbounds":[{"protocol":"vmess","tag":"v","settings":$settings}]}"""
		}
		val expected = linkedMapOf("none" to "auto", "zero" to "auto", "AES-128-GCM" to "aes-128-gcm",
			"chacha20-poly1305" to "chacha20-poly1305", "aes-256" to "auto")
		for ((written, runs) in expected) {
			val noted = written.lowercase() != runs
			val singBox = SingBoxConverter.convert(body(written), "N") as SingBoxConverter.Result.Ok
			val node = singBox.config.getJSONArray("outbounds").getJSONObject(0)
			assertEquals(written, runs, node.optString("security"))
			assertEquals("${singBox.notes}", noted, singBox.notes.any { "vmess security" in it })
			val mihomo = MihomoConverter.convert(body(written)) as MihomoConverter.Result.Ok
			assertTrue(mihomo.yaml, mihomo.yaml.contains("cipher: $runs"))
			val link = SubscriptionConverter.convert(body(written), jsonToUri = true, base64Result = false)
			val blob = String(decodeBase64Any(link.trim().removePrefix("vmess://"))!!)
			assertEquals(blob, runs, JSONObject(blob).optString("scy"))
		}
	}

	@Test
	fun `an inbound listens on an IP literal, and anything else falls back rather than fail the document`() {
		// sing-box refuses the whole document over a listen address that is not an IP literal.
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val server = """{"address":"v.example.com","port":443,"users":[$user]}"""
		val node = """{"protocol":"vless","tag":"v","settings":{"vnext":[$server]}}"""
		fun listened(protocol: String, listen: String): Pair<String, List<String>> {
			val inbound = """{"protocol":"$protocol","port":1080,"listen":$listen,"settings":{"port":443}}"""
			val body = """{"inbounds":[$inbound],"outbounds":[$node]}"""
			val ok = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
			return ok.config.getJSONArray("inbounds").getJSONObject(0).getString("listen") to ok.notes
		}
		val expected = listOf(
			Triple("socks", "null", "127.0.0.1"), Triple("socks", "\"10.0.0.1\"", "10.0.0.1"),
			Triple("socks", "\"[::1]\"", "::1"), Triple("socks", "\"h2,http/1.1\"", "127.0.0.1"),
			Triple("socks", "\"/tmp/x.sock\"", "127.0.0.1"),
			Triple("dokodemo-door", "\"example.com\"", "0.0.0.0")
		)
		for ((protocol, listen, address) in expected) {
			val (written, notes) = listened(protocol, listen)
			assertEquals(listen, address, written)
			val fellBack = listen != "null" && address != listen.trim('"').removeSurrounding("[", "]")
			assertEquals("$listen $notes", fellBack, notes.any { "inbound listen" in it })
		}
	}

	@Test
	fun `an address is private exactly where Xray takes it as private`() {
		val private = listOf(
			"100.64.0.0", "172.31.255.255", "::1", "::ffff:192.168.1.1", "[fe80::1]", "10.1.2.3",
			"a.lan", "lan", "MyHost", "host.", "x.home.arpa", "printer.local"
		)
		val public = listOf(
			"100.63.255.255", "172.32.0.0", "::2", "2001:db8::1", "1.2.3.4", "lan.com",
			"my_host", "v.example.com", "fe80::1%eth0"
		)
		for (address in private) assertTrue(address, xrayPrivateAddress(address))
		for (address in public) assertFalse(address, xrayPrivateAddress(address))
	}

	@Test
	fun `a transport named by method reaches every pass, and a plain public flat node is noted`() {
		// "method" stands for "network"; Xray refuses a flat vless or trojan without TLS to a public address.
		val id = "b831381d-6324-4d53-ad4f-8cda48b30811"
		fun flat(proto: String, address: String, stream: String = "{}"): String {
			val vless = """"id":"$id","encryption":"none""""
			val auth = if (proto == "vless") vless else "\"password\":\"pw\""
			val settings = """{"address":"$address","port":80,$auth}"""
			val fields = """"settings":$settings,"streamSettings":$stream"""
			val outbound = """{"protocol":"$proto","tag":"t",$fields}"""
			return """{"outbounds":[$outbound]}"""
		}
		val ws = flat("vless", "1.2.3.4", """{"method":"ws","wsSettings":{"path":"/w"}}""")
		val singBox = SingBoxConverter.convert(ws, "N") as SingBoxConverter.Result.Ok
		val node = singBox.config.getJSONArray("outbounds").getJSONObject(0)
		assertEquals("ws", node.getJSONObject("transport").optString("type"))
		val yaml = (MihomoConverter.convert(ws) as MihomoConverter.Result.Ok).yaml
		assertTrue(yaml, yaml.contains("network: ws"))
		val link = SubscriptionConverter.convert(ws, jsonToUri = true, base64Result = false)
		assertTrue(link, link.contains("type=ws"))
		fun noted(body: String): Boolean {
			val ok = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
			return ok.notes.any { "public address" in it }
		}
		assertTrue(noted(ws))
		assertTrue(noted(flat("trojan", "v.example.com")))
		assertFalse(noted(flat("vless", "192.168.1.10")))
		assertFalse(noted(flat("vless", "1.2.3.4", """{"security":"tls"}""")))
		val user = """{"id":"$id","encryption":"none"}"""
		val listed = """{"vnext":[{"address":"1.2.3.4","port":80,"users":[$user]}]}"""
		assertFalse(noted("""{"outbounds":[{"protocol":"vless","tag":"t","settings":$listed}]}"""))
	}

	@Test
	fun `shadowsocks none and uot, which Xray 26 no longer runs, are each noted where they mattered`() {
		fun notes(method: String, uot: Boolean): List<String> {
			val key = if (method.startsWith("2022")) "AAAAAAAAAAAAAAAAAAAAAA==" else "pw"
			val server = """{"address":"s.example.com","port":8388,"method":"$method",""" +
				""""password":"$key","uot":$uot}"""
			val outbound = """{"protocol":"shadowsocks","tag":"s","settings":{"servers":[$server]}}"""
			val body = """{"outbounds":[$outbound]}"""
			return (SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok).notes
		}
		for (method in listOf("none", "plain")) {
			assertTrue(method, notes(method, false).any { "method none" in it })
		}
		assertTrue(notes("2022-blake3-aes-128-gcm", true).any { "shadowsocks uot" in it })
		assertFalse(notes("aes-128-gcm", true).any { "shadowsocks uot" in it })
		assertFalse(notes("aes-128-gcm", false).any { "method none" in it })
	}

	@Test
	fun `an IP rule is turned over as Xray turns it, by every exclamation mark before and after geoip`() {
		val read = linkedMapOf(
			"!geoip:cn" to XrayConditions.Address.NotCountry("cn"),
			"!!geoip:cn" to XrayConditions.Address.Country("cn"),
			"!geoip:!cn" to XrayConditions.Address.Country("cn"),
			"geoip:!!cn" to XrayConditions.Address.Country("cn"),
			"!geoip:!private" to XrayConditions.Address.Private,
			"geoip:!private" to XrayConditions.Address.NotPrivate,
			"!10.0.0.0/8" to XrayConditions.Address.Unusable,
			"!ext:geoip.dat:cn" to XrayConditions.Address.Unusable
		)
		for ((rule, address) in read) assertEquals(rule, address, XrayConditions.address(rule))
		assertEquals(XrayConditions.Name.External, XrayConditions.name("ext-site:site.dat:cn"))
	}

	@Test
	fun `xhttp session names Xray reads come first, and three forms Xray refuses or ignores are noted`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val vnext = """{"vnext":[{"address":"x.example.com","port":443,"users":[$user]}]}"""
		val xhttp = """{"path":"/x","sessionPlacement":"cookie","sessionIDPlacement":"header"}"""
		val tls = """"security":"tls","tlsSettings":{"serverName":"x.example.com"}"""
		val stream = """{"network":"xhttp",$tls,"xhttpSettings":$xhttp}"""
		val fields = """"settings":$vnext,"streamSettings":$stream"""
		val body = """{"outbounds":[{"protocol":"vless","tag":"x",$fields}]}"""
		val yaml = (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).yaml
		assertTrue(yaml, yaml.contains("session-placement: header"))
		fun notes(stream: String): List<String> {
			val outbound = JSONObject("""{"protocol":"vmess","streamSettings":$stream}""")
			return olderConfigLeniencies(outbound)
		}
		val insecure = notes("""{"security":"tls","tlsSettings":{"allowInsecure":true}}""")
		assertTrue("$insecure", insecure.any { "allowInsecure" in it })
		val names = """{"verifyPeerCertInNames":["a.example.com"]}"""
		val inNames = notes("""{"security":"tls","tlsSettings":$names}""")
		assertTrue("$inNames", inNames.any { "verifyPeerCertInNames" in it })
		val kcp = notes("""{"network":"kcp","kcpSettings":{"header":{"type":"srtp"},"seed":"s"}}""")
		assertTrue("$kcp", kcp.any { "Xray from 26.1.31 to 26.9.8 refuses and from 26.9.9 reads past" in it })
		assertTrue(notes("""{"security":"reality","tlsSettings":{"allowInsecure":true}}""").isEmpty())
		val hop = notes("""{"finalmask":{"quicParams":{"udpHop":{"ports":"20000-30000"}}}}""")
		assertTrue("$hop", hop.any { "udpHop is read by Xray from 26.3.23 to 26.9.8, not from 26.9.9" in it })
		val chainedOutbound = JSONObject("""{"protocol":"vmess","proxySettings":{"tag":"p"}}""")
		val chained = olderConfigLeniencies(chainedOutbound)
		assertTrue("$chained", chained.any { "proxySettings is one Xray 26.9 refuses" in it })
	}

	@Test
	fun `a dns outbound names what it loses, and no rule is written twice in either core`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val vnext = """{"vnext":[{"address":"p.example.com","port":443,"users":[$user]}]}"""
		val proxy = """{"protocol":"vless","tag":"proxy","settings":$vnext}"""
		val dnsSettings = """{"nonIPQuery":"skip","rewriteAddress":"1.1.1.1"}"""
		val dns = """{"protocol":"dns","tag":"dns-out","settings":$dnsSettings}"""
		val rules = """[{"port":"53","outboundTag":"dns-out"},{"network":"tcp,udp","outboundTag":"proxy"}]"""
		val body = """{"outbounds":[$proxy,$dns],"routing":{"rules":$rules}}"""
		val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		val lost = "nonIPQuery, rewriteAddress of the dns outbound"
		assertTrue("${singBox.notes}", singBox.notes.any { "outbounds[1] (dns): $lost" in it })
		val routeRules = singBox.config.getJSONObject("route").getJSONArray("rules")
		val port53 = (0 until routeRules.length()).count {
			val rule = routeRules.getJSONObject(it)
			rule.optString("action") == "hijack-dns" && rule.has("port")
		}
		assertEquals(routeRules.toString(), 1, port53)
		val mihomo = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
		assertTrue("${mihomo.notes}", mihomo.notes.any { "outbounds[1] (dns)" in it && lost in it })
		// The converted catch-all decides what nothing else matches; a closing MATCH after it would be
		// dead. A MATCH may be quoted in YAML.
		val matches = Regex("^\\s*- '?MATCH,", RegexOption.MULTILINE).findAll(mihomo.yaml).count()
		assertEquals(mihomo.yaml, 1, matches)
	}

	@Test
	fun `a note about an outbound read once for each of its servers is said once`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}"""
		val vnext = """{"vnext":[{"address":"d.example.com","port":443,"users":[$user,$user]}]}"""
		val body = """{"outbounds":[{"protocol":"vless","tag":"d","settings":$vnext}]}"""
		fun flags(uri: Boolean, singBox: Boolean, mihomo: Boolean) =
			ConversionFlags(uri, singBox, mihomo, base64Result = false)
		val modes = listOf(flags(false, true, false), flags(false, false, true), flags(true, false, false))
		for (flags in modes) {
			val notes = SubscriptionConverter.convertWithStats(body, flags).notes
			assertEquals("$flags $notes", 1, notes.count { "names no encryption" in it })
		}
	}

	@Test
	fun `an inbound login is read from accounts or users as Xray reads it, never dropped`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val vnext = """{"vnext":[{"address":"v.example.com","port":443,"users":[$user]}]}"""
		val node = """{"protocol":"vless","tag":"v","settings":$vnext}"""
		val login = """[{"user":"u","pass":"p"}]"""
		fun users(protocol: String, settings: String): String {
			val inbound = """{"protocol":"$protocol","port":1080,"listen":"0.0.0.0","settings":$settings}"""
			val ok = SingBoxConverter.convert("""{"inbounds":[$inbound],"outbounds":[$node]}""", "N") as
				SingBoxConverter.Result.Ok
			val made = ok.config.getJSONArray("inbounds").getJSONObject(0)
			return made.optJSONArray("users")?.toString() ?: "none"
		}
		val named = """[{"username":"u","password":"p"}]"""
		for (protocol in listOf("socks", "http")) {
			assertEquals(protocol, named, users(protocol, """{"users":$login}"""))
			assertEquals(protocol, named, users(protocol, """{"accounts":$login}"""))
			assertEquals(protocol, named, users(protocol, """{"accounts":null,"users":$login}"""))
			assertEquals(protocol, "none", users(protocol, """{"accounts":[],"users":$login}"""))
		}
	}

	@Test
	fun `sniffing exclusions reach mihomo in its own forms and the rest is named lost in both cores`() {
		val names = """["full:a.example.com","domain:b.example.com","geosite:cn","keyword:x","plain"]"""
		val ips = """["10.0.0.0/8","geoip:cn","geoip:private","!geoip:cn","ext:geoip.dat:cn"]"""
		val excluded = """"domainsExcluded":$names,"ipsExcluded":$ips"""
		val sniffing = """{"enabled":true,"destOverride":["tls"],$excluded}"""
		val inbound = """{"protocol":"socks","port":1080,"sniffing":$sniffing}"""
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val vnext = """{"vnext":[{"address":"v.example.com","port":443,"users":[$user]}]}"""
		val outbound = """{"protocol":"vless","tag":"v","settings":$vnext}"""
		val body = """{"inbounds":[$inbound],"outbounds":[$outbound]}"""
		val mihomo = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
		val skipDomain = "skip-domain: [a.example.com, +.b.example.com, geosite:cn, plain]"
		assertTrue(mihomo.yaml, mihomo.yaml.contains(skipDomain))
		val skipAddress = "skip-dst-address: [10.0.0.0/8, geoip:cn, geoip:private]"
		assertTrue(mihomo.yaml, mihomo.yaml.contains(skipAddress))
		val lost = mihomo.notes.single { "sniffing excludes" in it && "has no form for" in it }
		for (entry in listOf("keyword:x", "!geoip:cn", "ext:geoip.dat:cn")) {
			assertTrue(lost, "\"$entry\"" in lost)
		}
		assertFalse(lost, "\"plain\"" in lost)
		val narrowed = "\"plain\" wherever Xray finds it inside a name"
		assertTrue("${mihomo.notes}", mihomo.notes.any { narrowed in it })
		val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		assertTrue("${singBox.notes}", singBox.notes.any { "sniffing.ipsExcluded keeps 5 address(es)" in it })
	}

	@Test
	fun `a shared mask refuses the node where it cannot go, by the side the node sends through`() {
		val id = "b831381d-6324-4d53-ad4f-8cda48b30811"
		fun node(proto: String, masks: String): String {
			val server = """{"address":"m.example.com","port":443"""
			val user = """{"id":"$id","encryption":"none"}"""
			val settings = if (proto == "hysteria2") """{"servers":[$server,"password":"pw"}]}"""
			else """{"vnext":[$server,"users":[$user]}]}"""
			val stream = """{"network":"tcp","security":"tls","finalmask":$masks}"""
			val fields = """"settings":$settings,"streamSettings":$stream"""
			return """{"outbounds":[{"protocol":"$proto","tag":"m",$fields}]}"""
		}
		val shared = """{"tcp":[{"type":"sudoku","settings":{"password":"p"}}]}"""
		val clientSide = """{"tcp":[{"type":"fragment","settings":{}}]}"""
		fun singBoxOk(body: String) = SingBoxConverter.convert(body, "N") is SingBoxConverter.Result.Ok
		fun mihomoOk(body: String) = MihomoConverter.convert(body) is MihomoConverter.Result.Ok
		fun link(body: String) = SubscriptionConverter.convert(body, jsonToUri = true, base64Result = false)
		assertFalse(singBoxOk(node("vless", shared)))
		assertFalse(mihomoOk(node("vless", shared)))
		assertTrue(link(node("vless", shared)).contains("fm="))
		assertFalse(link(node("vmess", shared)).startsWith("vmess://"))
		assertTrue(singBoxOk(node("vless", clientSide)) && mihomoOk(node("vless", clientSide)))
		assertTrue(link(node("vmess", clientSide)).startsWith("vmess://"))
		// A UDP protocol never sends through a TCP mask.
		assertTrue(singBoxOk(node("hysteria2", shared)) && mihomoOk(node("hysteria2", shared)))
	}

	// Xray 26.7.28 answers "gecko: invalid min/max packet size" below 1 or past 2048, and "unknown config
	// id: gecko" to a mask typed so, refusing the configuration; mihomo 1.19.31 refuses the whole file
	// over such a size. The node never worked, so no pass writes it.
	@Test
	fun `a salamander mask Xray refuses refuses the node in every pass`() {
		fun node(mask: String): String {
			val hysteria = """"network":"hysteria","hysteriaSettings":{"version":2,"auth":"pw"}"""
			val stream = """{$hysteria,"security":"tls","finalmask":{"udp":[$mask]}}"""
			val settings = """{"version":2,"address":"h.example.com","port":443}"""
			val fields = """"settings":$settings,"streamSettings":$stream"""
			return """{"outbounds":[{"protocol":"hysteria","tag":"h",$fields}]}"""
		}
		fun salamander(size: String) =
			"""{"type":"salamander","settings":{"password":"o","packetSize":$size}}"""
		val refused = mapOf(
			salamander("\"-5-10\"") to "gecko takes",
			salamander("\"0-10\"") to "gecko takes",
			salamander("\"100-2049\"") to "gecko takes",
			"""{"type":"gecko","settings":{"password":"o"}}""" to "mask \"gecko\" is no mask type Xray has"
		)
		val linksOnly = ConversionFlags(true, false, false, false)
		for ((mask, reason) in refused) {
			val body = node(mask)
			assertFalse(mask, SingBoxConverter.convert(body, "N") is SingBoxConverter.Result.Ok)
			val mihomo = MihomoConverter.convert(body)
			assertTrue("$mask: $mihomo", mihomo is MihomoConverter.Result.Unsupported)
			assertTrue("$mask: $mihomo", reason in mihomo.toString())
			val link = SubscriptionConverter.convertWithStats(body, linksOnly)
			assertFalse(link.text, link.text.contains("://"))
			assertTrue("$mask: ${link.notes}", link.notes.any { reason in it })
		}
		val kept = MihomoConverter.convert(node(salamander("\"1-2048\""))) as MihomoConverter.Result.Ok
		assertTrue(kept.yaml, kept.yaml.contains("obfs-max-packet-size: 2048"))
	}

	@Test
	fun `QUIC receive windows reach mihomo and are named lost where no field holds them`() {
		val windows = """{"initStreamReceiveWindow":8388608,"maxConnectionReceiveWindow":20971520}"""
		val hysteria = """{"version":2,"auth":"pw"}"""
		val mask = """{"quicParams":$windows}"""
		val transport = """"network":"hysteria","hysteriaSettings":$hysteria"""
		val stream = """{$transport,"security":"tls","finalmask":$mask}"""
		val settings = """{"version":2,"address":"h.example.com","port":443}"""
		val outbound = """{"protocol":"hysteria","tag":"h","settings":$settings,"streamSettings":$stream}"""
		val body = """{"outbounds":[$outbound]}"""
		val lost = "receive windows have no field in"
		val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		assertTrue("${singBox.notes}", singBox.notes.any { "$lost sing-box" in it })
		val mihomo = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
		assertTrue(mihomo.yaml, mihomo.yaml.contains("initial-stream-receive-window: 8388608"))
		assertFalse("${mihomo.notes}", mihomo.notes.any { lost in it })
		val link = SubscriptionConverter.convertWithStats(body, ConversionFlags(true, false, false, false))
		assertTrue("${link.notes}", link.notes.any { "$lost this link form" in it })
	}

	@Test
	fun `a transport no core knows refuses a node that sends through it, in the same words everywhere`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val vnext = """{"vnext":[{"address":"t.example.com","port":443,"users":[$user]}]}"""
		fun vless(stream: String): String {
			val outbound = """{"protocol":"vless","tag":"t","settings":$vnext,"streamSettings":$stream}"""
			return """{"outbounds":[$outbound]}"""
		}
		val unknown = vless("""{"network":100}""")
		val reason = "transport \"100\" is not one Xray or any core knows"
		val singBox = SingBoxConverter.convert(unknown, "N")
		assertTrue("$singBox", singBox !is SingBoxConverter.Result.Ok && "$singBox".contains(reason))
		val mihomo = MihomoConverter.convert(unknown)
		assertTrue("$mihomo", mihomo !is MihomoConverter.Result.Ok && "$mihomo".contains(reason))
		val link = SubscriptionConverter.convertWithStats(unknown, ConversionFlags(true, false, false, false))
		assertFalse(link.text, link.text.contains("://"))
		assertTrue("${link.notes}", link.notes.any { reason in it })
		// A protocol carrying its own transport is not held to the stream's.
		val hysteria = """{"version":2,"auth":"pw"}"""
		val settings = """{"version":2,"address":"h.example.com","port":443}"""
		val stream = """{"network":"nonsense","hysteriaSettings":$hysteria,"security":"tls"}"""
		val fields = """"settings":$settings,"streamSettings":$stream"""
		val hy = """{"outbounds":[{"protocol":"hysteria","tag":"h",$fields}]}"""
		assertTrue(SingBoxConverter.convert(hy, "N") is SingBoxConverter.Result.Ok)
		// The HTTP/2 transport Xray refuses is one a core runs with a server that has it: kept, as quic is.
		val h2 = vless("""{"network":"h2","security":"tls"}""")
		assertTrue(SingBoxConverter.convert(h2, "N") is SingBoxConverter.Result.Ok)
		assertEquals("ws", streamNetwork(JSONObject("""{"network":"tcp","method":"ws"}""")))
	}

	@Test
	fun `a WireGuard tunnel keeps the peers a core can reach and names each one left out`() {
		val peerKey = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
		val good = """{"publicKey":"$peerKey","endpoint":"good.example.com:51820"}"""
		val badEndpoint = """{"publicKey":"$peerKey","endpoint":"nowhere"}"""
		val noKey = """{"endpoint":"other.example.com:51820","allowedIPs":["10.9.0.0/16"]}"""
		fun body(peers: String): String {
			val key = "cKX1G0yg4Uyq6M6l7xX6h4L3s8m3Jo2eZk1v7d9n2ZA="
			val settings = """{"secretKey":"$key","address":["10.0.0.2/32"],"peers":[$peers]}"""
			return """{"outbounds":[{"protocol":"wireguard","tag":"w","settings":$settings}]}"""
		}
		val first = SingBoxConverter.convert(body("$badEndpoint,$good"), "N") as SingBoxConverter.Result.Ok
		val endpoint = first.config.getJSONArray("endpoints").getJSONObject(0)
		val kept = endpoint.getJSONArray("peers")
		assertEquals(1, kept.length())
		assertEquals("good.example.com", kept.getJSONObject(0).getString("address"))
		val droppedFirst = "WireGuard peer 1 was dropped because its endpoint"
		assertTrue("${first.notes}", first.notes.any { droppedFirst in it })
		val mihomo = MihomoConverter.convert(body("$badEndpoint,$good")) as MihomoConverter.Result.Ok
		assertTrue(mihomo.yaml, mihomo.yaml.contains("server: good.example.com"))
		assertTrue("${mihomo.notes}", mihomo.notes.any { "WireGuard peer 1 was dropped" in it })
		val second = SingBoxConverter.convert(body("$good,$noKey"), "N") as SingBoxConverter.Result.Ok
		val routed = "10.9.0.0/16 reaches none"
		val droppedSecond = "peer 2 was dropped because it has no publicKey"
		assertTrue("${second.notes}", second.notes.any { droppedSecond in it && routed in it })
		val none = SingBoxConverter.convert(body("$badEndpoint,$noKey"), "N")
		val reason = "endpoint \"nowhere\" is not host:port"
		assertTrue("$none", none !is SingBoxConverter.Result.Ok && "$none".contains(reason))
	}

	@Test
	fun `a WireGuard interface address is a prefix every core reads, and Xray gets no broken tunnel`() {
		val peerKey = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
		val good = """{"publicKey":"$peerKey","endpoint":"good.example.com:51820"}"""
		fun body(address: String, peers: String = good): String {
			val key = "cKX1G0yg4Uyq6M6l7xX6h4L3s8m3Jo2eZk1v7d9n2ZA="
			val settings = """{"secretKey":"$key","address":$address,"peers":[$peers]}"""
			return """{"outbounds":[{"protocol":"wireguard","tag":"w","settings":$settings}]}"""
		}
		fun singBox(body: String): SingBoxConverter.Result.Ok =
			SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		val junk = singBox(body("\"d.example.com:51820\""))
		val endpoint = junk.config.getJSONArray("endpoints").getJSONObject(0)
		fun addresses(node: JSONObject): List<String> {
			val list = node.getJSONArray("address")
			return (0 until list.length()).map { list.getString(it) }
		}
		assertEquals(listOf(WIREGUARD_ASSUMED_ADDRESS), addresses(endpoint))
		assertTrue("${junk.notes}", junk.notes.any { "is no interface address" in it })
		val mihomo = MihomoConverter.convert(body("\"d.example.com:51820\"")) as MihomoConverter.Result.Ok
		assertTrue("${mihomo.notes}", mihomo.notes.any { "is no interface address" in it })
		val bareConfig = singBox(body("""["10.0.0.2","fd00::2"]""")).config
		val bare = bareConfig.getJSONArray("endpoints").getJSONObject(0)
		assertEquals(listOf("10.0.0.2/32", "fd00::2/128"), addresses(bare))
		// A link hands the tunnel on to Xray as written, and Xray fails it over the broken peer.
		val broken = body("""["10.0.0.2/32"]""", """{"publicKey":"$peerKey","endpoint":"nowhere"},$good""")
		val link = SubscriptionConverter.convertWithStats(broken, ConversionFlags(true, false, false, false))
		assertTrue("${link.notes}", link.notes.any { "endpoint \"nowhere\" is not host:port" in it })
		assertFalse(link.text, link.text.contains("wireguard"))
	}

	@Test
	fun `ports reach a core only where it can dial or listen on them, and the rest is named`() {
		val hop = hopPorts("20000-30000,70000,abc,9000-8000,443,30000:40000")
		assertEquals(listOf(20000..30000, 443..443, 30000..40000), hop.ranges)
		assertEquals(listOf("70000", "abc", "9000-8000"), hop.dropped)
		// Xray 26.7.28 refuses a colon in a port list; read as a dash, the part is named.
		assertEquals(listOf("30000:40000"), hop.colons)
		assertTrue("${hop.notes()}", hop.notes().any { "\"30000:40000\" is written with a colon" in it })
		// The server port a node names only in its hopping list comes from the same reading: the first
		// port of the first range kept, never one of a range dropped.
		assertEquals(443, firstPortOfRange("443:8443"))
		assertEquals(443, firstPortOfRange("500-100,443-8443"))
		assertEquals(null, firstPortOfRange("abc"))
		val hops = """{"ports":"20000-30000,abc","interval":"30"}"""
		val quic = """{"quicParams":{"udpHop":$hops}}"""
		val tls = """"security":"tls","tlsSettings":{"serverName":"h.example.com"}"""
		val hysteria = """"network":"hysteria","hysteriaSettings":{"version":2,"auth":"pw"}"""
		val stream = """{$hysteria,$tls,"finalmask":$quic}"""
		val settings = """{"version":2,"address":"h.example.com","port":443}"""
		val fields = """"settings":$settings,"streamSettings":$stream"""
		val body = """{"outbounds":[{"protocol":"hysteria","tag":"h",$fields}]}"""
		val named = "port hopping \"abc\" names no port range"
		val singBox = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		val node = singBox.config.getJSONArray("outbounds").getJSONObject(0)
		assertEquals("20000:30000", node.getJSONArray("server_ports").getString(0))
		assertTrue("${singBox.notes}", singBox.notes.any { named in it })
		val mihomo = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
		assertTrue(mihomo.yaml, mihomo.yaml.contains("ports: 20000-30000\n"))
		assertTrue("${mihomo.notes}", mihomo.notes.any { named in it })
		val link = SubscriptionConverter.convertWithStats(body, ConversionFlags(true, false, false, false))
		assertTrue(link.text, link.text.contains("mport=20000-30000"))
		for (port in listOf(70000, 4294967296L, 1.5, 0, -1, "99999999999")) {
			assertNull("$port", SingBoxRouting.parseListenPort(port))
		}
		assertEquals(1080, SingBoxRouting.parseListenPort("1080"))
		assertEquals(1080, SingBoxRouting.parseListenPort(1080.0))
	}

	@Test
	fun `XHTTP over HTTP3 sends through UDP, so only a UDP mask both ends share refuses it`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val vnext = """{"vnext":[{"address":"x.example.com","port":443,"users":[$user]}]}"""
		fun node(alpn: String, side: String): String {
			val tls = """"security":"tls","tlsSettings":{"serverName":"x.example.com","alpn":$alpn}"""
			val mask = """{"$side":[{"type":"sudoku","settings":{"password":"p"}}]}"""
			val stream = """{"network":"xhttp",$tls,"xhttpSettings":{"path":"/x"},"finalmask":$mask}"""
			val fields = """"settings":$vnext,"streamSettings":$stream"""
			return """{"outbounds":[{"protocol":"vless","tag":"x",$fields}]}"""
		}
		fun kept(body: String) = MihomoConverter.convert(body) is MihomoConverter.Result.Ok
		assertTrue(kept(node("""["h3"]""", "tcp")))
		assertFalse(kept(node("""["h3"]""", "udp")))
		assertFalse(kept(node("""["h2"]""", "tcp")))
		assertTrue(kept(node("""["h2"]""", "udp")))
	}

	@Test
	fun `a configuration Xray reads past its comments is read the same way here`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val vnext = """{"vnext":[{"address":"c.example.com","port":443,"users":[$user]}]}"""
		val stream = """{"network":"ws","wsSettings":{"path":"//path#not-a-comment"}}"""
		val fields = """"settings":$vnext,"streamSettings":$stream"""
		val plain = """{"outbounds":[{"protocol":"vless","tag":"p",$fields}]}"""
		val head = "// a subscription\n{\n  # python style\n  \"outbounds\": [ /* block\n */ "
		val node = "{\"protocol\":\"vless\",\"tag\":\"p\", // trailing\n$fields}"
		val commented = "$head$node]\n}"
		val flags = ConversionFlags(false, true, false, false)
		val read = SubscriptionConverter.convertWithStats(commented, flags).text
		// The document is the same; only its layout follows the input's, as for any input.
		fun content(text: String) = JSONObject(text).toString()
		val expected = content(SubscriptionConverter.convertWithStats(plain, flags).text)
		assertEquals(expected, content(read))
		// Opening with a bracket, comments further in already read as JSON.
		val inside = "{ \"outbounds\": [ /* block */ $node] # end\n}"
		assertEquals(expected, content(SubscriptionConverter.convertWithStats(inside, flags).text))
		// A comma left before a closer by a line commented out reads as the mihomo pass reads it.
		val trailing = "{\"outbounds\":[$node,\n// {\"protocol\":\"freedom\"}\n]}"
		assertEquals(expected, content(SubscriptionConverter.convertWithStats(trailing, flags).text))
		// A body with nothing to convert goes back exactly as written, comments and all.
		val nothing = "// no proxies here\n{\"a\":1,}"
		assertEquals(nothing, SubscriptionConverter.convertWithStats(nothing, flags).text)
		// A "#" line ahead is a Happ parameter, never a comment to strip.
		assertEquals("#profile-title: x\n$plain", withoutComments("#profile-title: x\n$plain"))
		val first = JSONObject(read).getJSONArray("outbounds").getJSONObject(0)
		assertEquals("vless", first.getString("type"))
		assertEquals("//path#not-a-comment", first.getJSONObject("transport").getString("path"))
		val links = "# not JSON\nvless://b831381d-6324-4d53-ad4f-8cda48b30811@l.example.com:443?type=tcp#l"
		assertEquals(links, withoutComments(links))
		assertEquals(plain, withoutComments(plain))
	}

	@Test
	fun `a CA the server is verified against goes where each client trusts one`() {
		val pem = testAuthorityLines.joinToString(",") { "\"$it\"" }
		val verify = """"certificates":[{"usage":"verify","certificate":[$pem]}]"""
		val tls = """"security":"tls","tlsSettings":{"serverName":"tls.example.com",$verify}"""
		val flat = """{"address":"t.example.com","port":443,"password":"pw"}"""
		val trojanFields = """"settings":$flat,"streamSettings":{$tls}"""
		val trojan = """{"outbounds":[{"protocol":"trojan","tag":"t",$trojanFields}]}"""
		val mihomo = MihomoConverter.convert(trojan) as MihomoConverter.Result.Ok
		assertTrue(mihomo.yaml, mihomo.yaml.contains("custom-certifactes:"))
		// A link takes a CA that is no server's own certificate only as the cert husi reads.
		val link = SubscriptionConverter.convertWithStats(trojan, ConversionFlags(true, false, false, false))
		val cert = URLDecoder.decode(link.text.substringAfter("cert=").substringBefore("&"), "UTF-8")
		assertEquals(link.text, testAuthorityLines.joinToString("\n"), cert)
		assertTrue("${link.notes}", link.notes.any { "Xray and mihomo clients take this CA" in it })
		val hy = """{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"pw"},$tls}"""
		val hysteria = """{"outbounds":[{"protocol":"hysteria","tag":"h","settings":{"version":2,""" +
			""""address":"h.example.com","port":443},"streamSettings":$hy}]}"""
		val singBox = SingBoxConverter.convert(hysteria, "N") as SingBoxConverter.Result.Ok
		val node = singBox.config.getJSONArray("outbounds").getJSONObject(0)
		assertTrue("$node", node.getJSONObject("tls").has("certificate"))
		val quic = MihomoConverter.convert(hysteria)
		val refused = "mihomo QUIC proxy cannot be given"
		assertTrue("$quic", quic !is MihomoConverter.Result.Ok && "$quic".contains(refused))
	}

	// A real CA certificate, line by line as Xray takes one, so every reader that parses it accepts it.
	private val testAuthorityLines = listOf(
		"-----BEGIN CERTIFICATE-----",
		"MIIBdjCCAR2gAwIBAgIURxzAB9VHEYwTJwd7IScMFCRAM44wCgYIKoZIzj0EAwIw",
		"ETEPMA0GA1UEAwwGZTJlIENBMB4XDTI2MTAwNDIyNDEzMFoXDTI2MTEwMzIyNDEz",
		"MFowETEPMA0GA1UEAwwGZTJlIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
		"d7fqRRGYXBFybgwoV1X+6cmyG5Rgj6M3pnAXI1RJEpKcG1MGZPcfWPua3IJ9JizU",
		"ANps9BGx87mILXpH5XHYg6NTMFEwHQYDVR0OBBYEFL+jrelIAhiw0lPPkmM7BBZN",
		"D4FMMB8GA1UdIwQYMBaAFL+jrelIAhiw0lPPkmM7BBZND4FMMA8GA1UdEwEB/wQF",
		"MAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgS0rULJ7bv1xLKOcZm/EDfymtBUQYH8Tp",
		"xFlTUXuD7E0CIB7wBZ6keFf1tuSgZEfRrzqfIU7nmhfjsfO1TwKD2VFr",
		"-----END CERTIFICATE-----",
	)

	@Test
	fun `REALITY tells a core who lets it in, and a CA reaches HTTPS proxies but no mihomo QUIC one`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val key = "yPNRx8rTdkUp89A-J76KxmGFeexuyVG4BiVl1PJ1kCk"
		val reality = """{"serverName":"r.example.com","publicKey":"$key",""" +
			""""shortId":"0123abcd","fingerprint":"chrome"}"""
		val stream = """{"network":"raw","security":"reality","realitySettings":$reality}"""
		val vnext = """{"vnext":[{"address":"r.example.com","port":443,"users":[$user]}]}"""
		val vlessFields = """"settings":$vnext,"streamSettings":$stream"""
		val vless = """{"outbounds":[{"protocol":"vless","tag":"r",$vlessFields}]}"""
		val singBox = SingBoxConverter.convert(vless, "N") as SingBoxConverter.Result.Ok
		assertTrue("${singBox.notes}", singBox.notes.any { REALITY_SING_BOX_NOTE in it })
		val mihomo = MihomoConverter.convert(vless) as MihomoConverter.Result.Ok
		assertTrue("${mihomo.notes}", mihomo.notes.any { REALITY_MIHOMO_NOTE in it })
		// X25519MLKEM768 offered as Xray's own client offers it, which Xray from 26.9.8 asks for.
		assertTrue(mihomo.yaml, mihomo.yaml.contains("support-x25519mlkem768: true"))
		val links = SubscriptionConverter.convertWithStats(vless, ConversionFlags(true, false, false, false))
		assertFalse("${links.notes}", links.notes.any { "minClientVer" in it })
		val pem = testAuthorityLines.joinToString(",") { "\"$it\"" }
		val verify = """"certificates":[{"usage":"verify","certificate":[$pem]}]"""
		val tls = """"security":"tls","tlsSettings":{"serverName":"tls.example.com",$verify}"""
		val tuicNode = """"protocol":"tuic","tag":"q","server":"q.example.com","server_port":443"""
		val tuicFields = """"uuid":"$tuicUuid","password":"pw","streamSettings":{$tls}"""
		val tuic = """{"outbounds":[{$tuicNode,$tuicFields}]}"""
		val quic = MihomoConverter.convert(tuic)
		val refusal = "mihomo QUIC proxy cannot be given"
		assertTrue("$quic", quic !is MihomoConverter.Result.Ok && "$quic".contains(refusal))
		val proxy = """{"address":"p.example.com","port":443,"user":"u","pass":"p"}"""
		val httpsFields = """"settings":$proxy,"streamSettings":{$tls}"""
		val https = """{"outbounds":[{"protocol":"http","tag":"p",$httpsFields}]}"""
		val httpsResult = MihomoConverter.convert(https)
		assertTrue("$httpsResult", "$httpsResult".contains("a mihomo HTTP proxy cannot be given"))
		// socks5 in mihomo checks the certificate against the address, having no server name to give.
		val socksTls = """"security":"tls","tlsSettings":{"serverName":"other.example.com"}"""
		val socksFields = """"settings":$proxy,"streamSettings":{$socksTls}"""
		val socks = """{"outbounds":[{"protocol":"socks","tag":"s",$socksFields}]}"""
		val socksResult = MihomoConverter.convert(socks)
		assertTrue("$socksResult", "$socksResult".contains("socks5 takes no server name for TLS"))
	}

	@Test
	fun `a REALITY node whose fingerprint the core cannot key runs chrome, and the link keeps the name`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val key = "yPNRx8rTdkUp89A-J76KxmGFeexuyVG4BiVl1PJ1kCk"
		fun body(fingerprint: String?): String {
			val named = fingerprint?.let { ""","fingerprint":"$it"""" } ?: ""
			val reality = """{"serverName":"r.example.com","publicKey":"$key","shortId":"ab"$named}"""
			val stream = """{"network":"raw","security":"reality","realitySettings":$reality}"""
			val vnext = """{"vnext":[{"address":"r.example.com","port":443,"users":[$user]}]}"""
			val fields = """"settings":$vnext,"streamSettings":$stream"""
			return """{"outbounds":[{"protocol":"vless","tag":"r",$fields}]}"""
		}
		fun singBox(fingerprint: String?): Pair<String, List<String>> {
			val result = SingBoxConverter.convert(body(fingerprint), "N") as SingBoxConverter.Result.Ok
			val node = result.config.getJSONArray("outbounds").getJSONObject(0)
			return node.getJSONObject("tls").getJSONObject("utls").getString("fingerprint") to result.notes
		}
		// mihomo refuses a REALITY node with no fingerprint, and "android" and "360" send no X25519 key
		// share - Xray runs chrome where none is named, and cannot connect over the other two either.
		for (fingerprint in listOf(null, "android", "360", "Android", "unsafe")) {
			val (used, notes) = singBox(fingerprint)
			assertEquals("$fingerprint", "chrome", used)
			assertTrue("$fingerprint: $notes", notes.any { "chrome was used" in it })
			val mihomo = MihomoConverter.convert(body(fingerprint)) as MihomoConverter.Result.Ok
			assertTrue("$fingerprint: ${mihomo.yaml}", mihomo.yaml.contains("client-fingerprint: chrome"))
			assertTrue("$fingerprint: ${mihomo.notes}", mihomo.notes.any { "chrome was used" in it })
		}
		assertTrue(singBox("android").second.any { "sends no X25519 key share" in it })
		// A name read in any case, as Xray reads it; mihomo runs chrome for it too, the one fingerprint it
		// offers X25519MLKEM768 with in REALITY, which an Xray server from 26.9.8 asks for.
		assertEquals("firefox", singBox("Firefox").first)
		assertTrue(singBox("Firefox").second.none { "fingerprint" in it })
		val mihomo = MihomoConverter.convert(body("firefox")) as MihomoConverter.Result.Ok
		assertTrue(mihomo.yaml, mihomo.yaml.contains("client-fingerprint: chrome"))
		assertTrue("${mihomo.notes}", mihomo.notes.any { "\"firefox\" sends no X25519MLKEM768" in it })
		// A name that is chrome to mihomo says nothing; random picks chrome on some runs only, and says so.
		for (name in listOf("chrome", "hellochrome_auto")) {
			val chrome = MihomoConverter.convert(body(name)) as MihomoConverter.Result.Ok
			assertTrue("$name: ${chrome.notes}", chrome.notes.none { "uTLS fingerprint" in it })
		}
		val random = MihomoConverter.convert(body("random")) as MihomoConverter.Result.Ok
		assertTrue("${random.notes}", random.notes.any { "\"random\" picks a browser at random" in it })
		// The link is read by Xray itself, so it says what the configuration says.
		val link = SubscriptionConverter.convert(body("android"), jsonToUri = true)
		assertTrue(link, link.contains("fp=android"))
	}

	private val tuicUuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"

	// A client certificate with its key in two forms, and a key of another pair, made for these tests.
	private val clientCertificateLines = listOf(
		"-----BEGIN CERTIFICATE-----",
		"MIIBHTCBwwIUGfrmKZGHBs4P/z5ACcYuh71iy/4wCgYIKoZIzj0EAwIwETEPMA0G",
		"A1UEAwwGZTJlIENBMB4XDTI2MTAwNDIyNDEzMFoXDTI2MTEwMzIyNDEzMFowETEP",
		"MA0GA1UEAwwGY2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbsEkNCMd",
		"M9w5T7FqdUgRIPh0lO+XSp/1b/V5mUpJoQ+EhbsEBHUwy4JOvPIIC5j1X7ehCLzu",
		"PT5gtsH91fGwuDAKBggqhkjOPQQDAgNJADBGAiEA6zF1uRj4ybdLmDaiZLrgHQF+",
		"IKV8zZxc2+P1VYtH7kMCIQDEWpXGxPXseGniwRHPPPuHh2sk32Z6+Cna0yKV1Q+s",
		"2g==",
		"-----END CERTIFICATE-----",
	)
	private val clientKeyPkcs8Lines = listOf(
		"-----BEGIN PRIVATE KEY-----",
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggdyHiR+mu7XV3wrI",
		"hhITZoFq93RNkoJ/PvNSKZDJ7b2hRANCAARuwSQ0Ix0z3DlPsWp1SBEg+HSU75dK",
		"n/Vv9XmZSkmhD4SFuwQEdTDLgk688ggLmPVft6EIvO49PmC2wf3V8bC4",
		"-----END PRIVATE KEY-----",
	)
	private val clientKeySec1Lines = listOf(
		"-----BEGIN EC PRIVATE KEY-----",
		"MHcCAQEEIIHch4kfpru11d8KyIYSE2aBavd0TZKCfz7zUimQye29oAoGCCqGSM49",
		"AwEHoUQDQgAEbsEkNCMdM9w5T7FqdUgRIPh0lO+XSp/1b/V5mUpJoQ+EhbsEBHUw",
		"y4JOvPIIC5j1X7ehCLzuPT5gtsH91fGwuA==",
		"-----END EC PRIVATE KEY-----",
	)
	private val otherKeyLines = listOf(
		"-----BEGIN PRIVATE KEY-----",
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQSaZhZcrVHTFn43W",
		"Hv6kvf4L7kfO7JIYMAsec6Dws+mhRANCAAQ6qfbHtfXTJAsHkZ0EHNtT5btNeo4j",
		"S8p6j0afUU1dcdsPtlVCT2iKhj1tCuTZvReXUyf6MFIVveAh1ylg2bLx",
		"-----END PRIVATE KEY-----",
	)

	@Test
	fun `a client certificate goes only as a pair a core loads, and a link loses none Xray would send`() {
		val cert = clientCertificateLines.joinToString("\n")
		assertTrue(isClientKeyPair(cert, clientKeyPkcs8Lines.joinToString("\n")))
		assertTrue(isClientKeyPair(cert, clientKeySec1Lines.joinToString("\n")))
		assertFalse(isClientKeyPair(cert, otherKeyLines.joinToString("\n")))
		assertFalse(isClientKeyPair(cert, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"))
		fun lines(of: List<String>) = of.joinToString(",") { "\"$it\"" }
		fun body(key: List<String>): String {
			val client = """{"certificate":[${lines(clientCertificateLines)}],"key":[${lines(key)}]}"""
			val settings = """{"serverName":"m.example.com","certificates":[$client]}"""
			val tls = """"security":"tls","tlsSettings":$settings"""
			val server = """{"address":"m.example.com","port":443,"password":"pw"}"""
			val fields = """"settings":$server,"streamSettings":{$tls}"""
			return """{"outbounds":[{"protocol":"trojan","tag":"m",$fields}]}"""
		}
		val good = SingBoxConverter.convert(body(clientKeySec1Lines), "N") as SingBoxConverter.Result.Ok
		val goodTls = good.config.getJSONArray("outbounds").getJSONObject(0).getJSONObject("tls")
		assertTrue("$goodTls", goodTls.has("client_certificate") && goodTls.has("client_key"))
		val wrong = SingBoxConverter.convert(body(otherKeyLines), "N") as SingBoxConverter.Result.Ok
		val wrongTls = wrong.config.getJSONArray("outbounds").getJSONObject(0).getJSONObject("tls")
		assertFalse("$wrongTls", wrongTls.has("client_key"))
		assertTrue("${wrong.notes}", wrong.notes.any { "make no pair" in it })
		val mihomo = MihomoConverter.convert(body(clientKeyPkcs8Lines)) as MihomoConverter.Result.Ok
		assertTrue(mihomo.yaml, mihomo.yaml.contains("private-key:"))
		val mihomoWrong = MihomoConverter.convert(body(otherKeyLines)) as MihomoConverter.Result.Ok
		assertFalse(mihomoWrong.yaml, mihomoWrong.yaml.contains("private-key:"))
		val asLinks = ConversionFlags(true, false, false, false)
		val link = SubscriptionConverter.convertWithStats(body(clientKeyPkcs8Lines), asLinks)
		// Xray presents no client certificate on an outbound, so the link a Happ reads works as the
		// configuration itself does there.
		assertTrue(link.text, link.text.startsWith("trojan://"))
	}

	@Test
	fun `a share link with no room for a mask both ends need is refused, and a client-side mask is named`() {
		val asLinks = ConversionFlags(true, false, false, false)
		val ss = """{"servers":[{"address":"s.example.com","port":8388,"method":"aes-256-gcm",""" +
			""""password":"pw"}]}"""
		val proxy = """{"servers":[{"address":"s.example.com","port":1080}]}"""
		fun body(protocol: String, settings: String, mask: String): String {
			val stream = """{"network":"raw","finalmask":{"tcp":[{"type":"$mask"}]}}"""
			val fields = """"settings":$settings,"streamSettings":$stream"""
			val outbound = """{"protocol":"$protocol","tag":"n",$fields}"""
			return """{"outbounds":[$outbound]}"""
		}
		for ((protocol, settings) in listOf("shadowsocks" to ss, "socks" to proxy, "http" to proxy)) {
			val symmetric = body(protocol, settings, "header-custom")
			val refused = SubscriptionConverter.convertWithStats(symmetric, asLinks)
			assertFalse("$protocol: ${refused.text}", refused.text.contains("://"))
			val reason = "rewrites the bytes for both ends"
			assertTrue("$protocol: ${refused.notes}", refused.notes.any { reason in it })
			val kept = SubscriptionConverter.convertWithStats(body(protocol, settings, "fragment"), asLinks)
			assertTrue("$protocol: ${kept.text}", kept.text.contains("://"))
			assertTrue("$protocol: ${kept.notes}", kept.notes.any { "finalmask" in it })
		}
	}
}
