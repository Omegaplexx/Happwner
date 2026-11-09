package com.happwner.convert

import android.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// Both cores refuse a whole file over one name that points at nothing, and both read names the
// person chose - which may be the core's own word for something, or may break the markup around it.
class DocumentCoherenceTest {

	private fun config(name: String) = """
        {"remarks":${JSONObject.quote(name)},"outbounds":[
          {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
          {"protocol":"freedom","tag":"DIRECT"}],
         "routing":{"rules":[{"domain":["ex.com"],"outboundTag":"DIRECT"}]}}
	""".trimIndent().replace("\n", " ")

	private val awkwardNames = listOf(
		"PROXY", "AUTO", "direct", "block", "DIRECT",           // the cores' own words
		"the \"best\" node", "line one\nline two", "key: value", // markup the writer must survive
		"- item", "# not a comment", "   ", "", "yes", "12345"
	)

	@Test
	fun `every reference in a sing-box document points at something that exists`() {
		for (name in awkwardNames) {
			val doc = JSONObject(SubscriptionConverter.convert(config(name), jsonToUri = false,
				xrayToSingBox = true))
			val outs = doc.getJSONArray("outbounds")
			val tags = (0 until outs.length()).map { outs.getJSONObject(it).optString("tag") }
			assertEquals("duplicate tags for [$name]: $tags", tags.size, tags.toSet().size)
			for (i in 0 until outs.length()) {
				val members = outs.getJSONObject(i).optJSONArray("outbounds") ?: continue
				for (j in 0 until members.length()) {
					assertTrue(
						"group of [$name] lists ${members.getString(j)}, which is not an outbound",
						members.getString(j) in tags
					)
				}
			}
			val route = doc.getJSONObject("route")
			val defined = route.optJSONArray("rule_set")?.let { ruleSets ->
				(0 until ruleSets.length()).map { ruleSets.getJSONObject(it).optString("tag") }.toSet()
			} ?: emptySet()
			val rules = route.getJSONArray("rules")
			for (i in 0 until rules.length()) {
				val rule = rules.getJSONObject(i)
				val target = rule.optString("outbound", "")
				assertTrue("[$name] rule $i points at $target", target.isEmpty() || target in tags)
				rule.optJSONArray("rule_set")?.let {
					for (j in 0 until it.length()) {
						assertTrue("[$name] rule $i uses an undefined rule_set", it.getString(j) in defined)
					}
				}
			}
			val final = route.optString("final", "")
			assertTrue("[$name] route.final points at $final", final.isEmpty() || final in tags)
		}
	}

	@Test
	fun `a mihomo document names every proxy once and points nowhere else`() {
		for (name in awkwardNames) {
			val yaml = SubscriptionConverter.convert(config(name), jsonToUri = false, xrayToMihomo = true)
			val proxies = Regex("^  - \\{name: (.+?), type:", RegexOption.MULTILINE)
				.findAll(yaml).map { it.groupValues[1].trim().trim('\'') }.toList()
			val groups = Regex("^  - name: (.+)$", RegexOption.MULTILINE)
				.findAll(yaml.substringAfter("proxy-groups:").substringBefore("\nrules:"))
				.map { it.groupValues[1].trim().trim('\'') }.toList()
			val all = proxies + groups
			assertEquals("duplicate names for [$name]: $all", all.size, all.toSet().size)
			// a name the writer had to quote must not have broken out of its quotes
			assertTrue("[$name] left a bare newline in the document", !yaml.contains("\n\n\n"))
		}
	}

	// A subscription can serve a sing-box document, and the app's own output can be handed back to
	// it. Either way it is one configuration rather than Xray outbounds to render one by one:
	// reading it the other way handed back a fragment for each outbound.
	@Test
	fun `a document that is already sing-box comes back unchanged`() {
		val xray = """
			[{"remarks":"A","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
			  {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
			  "streamSettings":{"network":"tcp"}}],"routing":{"rules":[{"domain":["x.com"],
			    "outboundTag":"proxy"}]}},
			 {"remarks":"B","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
			  {"address":"b.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
			  "streamSettings":{"network":"tcp"}}]}]
		""".trimIndent().replace("\n", " ")

		val singbox = SubscriptionConverter.convert(xray, jsonToUri = false, xrayToSingBox = true)
		assertEquals(singbox.trim(), SubscriptionConverter.convert(singbox, jsonToUri = true).trim())
		assertEquals(singbox.trim(),
			SubscriptionConverter.convert(singbox, jsonToUri = false, xrayToSingBox = true).trim())

		val mihomo = SubscriptionConverter.convert(xray, jsonToUri = false, xrayToMihomo = true)
		assertEquals(mihomo.trim(), SubscriptionConverter.convert(mihomo, jsonToUri = true).trim())

		// Links are links whichever pass reads them.
		val links = SubscriptionConverter.convert(xray, jsonToUri = true)
		for (again in listOf(
			SubscriptionConverter.convert(links, jsonToUri = true),
			SubscriptionConverter.convert(links, jsonToUri = false, xrayToSingBox = true),
			SubscriptionConverter.convert(links, jsonToUri = false, xrayToMihomo = true)
		)) {
			assertEquals(links.trim(), again.trim())
		}
	}

	// sing-box has the same switch Xray calls disableCache.
	@Test
	fun `a dns setting sing-box has is carried rather than dropped`() {
		val body = """
			{"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
			"streamSettings":{"network":"tcp"}}],
			"dns":{"servers":["8.8.8.8"],"disableCache":true,"queryStrategy":"UseIPv4",
			  "disableFallback":true}}
		""".trimIndent().replace("\n", " ")
		val result = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		assertTrue(result.config.toString(), result.config.getJSONObject("dns").optBoolean("disable_cache"))
		// and so is disableFallback: the first server Xray asks alone is the default
		assertFalse(
			result.notes.toString(),
			result.notes.any { it.contains("disableFallback") }
		)
		// queryStrategy is carried where sing-box keeps it
		assertEquals(
			"ipv4_only",
			result.config.getJSONObject("route").getJSONObject(
				"default_domain_resolver").optString("strategy")
		)
	}

	// Both cores refuse a whole document over a key that is missing, not just the node that lacks
	// it - so one such node would take every other node down. A REALITY outbound without its key
	// and a WireGuard peer without one are left out with their reason, and the rest survive.
	@Test
	fun `a node missing a key it cannot work without is left out, and takes nothing with it`() {
		val good = """{"protocol":"vless","tag":"good",
          "settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}"""
		val keylessReality = """{"protocol":"vless","tag":"r",
          "settings":{"vnext":[{"address":"b.example.com","port":443,
            "users":[{"id":"u",
              "encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality",
            "realitySettings":{"serverName":"s.example.com","shortId":"aa"}}}"""
		val keylessPeer = """{"protocol":"wireguard","tag":"w",
          "settings":{"secretKey":"cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5cHI=",
            "address":["10.0.0.2/32"],"peers":[{"endpoint":"c.example.com:51820"}]}}"""
		val body = """{"remarks":"N","outbounds":[$good,$keylessReality,$keylessPeer]}""".replace("\n", " ")

		val singBox = SubscriptionConverter.convert(body, jsonToUri = false, xrayToSingBox = true)
		assertFalse("an empty key reached the sing-box document", singBox.contains("\"public_key\":\"\""))
		assertTrue(singBox.contains("a.example.com"))
		assertFalse(singBox.contains("b.example.com") || singBox.contains("c.example.com"))

		val mihomo = SubscriptionConverter.convert(body, jsonToUri = false, xrayToMihomo = true)
		assertTrue(mihomo.contains("a.example.com"))
		assertFalse(mihomo.contains("b.example.com") || mihomo.contains("c.example.com"))
	}

	// A node with nothing to authenticate with imports and connects nowhere, and an empty uuid is
	// one sing-box refuses the whole document over. Neither pass writes such a node; both say why.
	@Test
	fun `a node without its credential is left out of both documents`() {
		val good = """{"protocol":"vless","tag":"good",
          "settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}"""
		val bad = listOf(
			"""{"protocol":"vless","tag":"x","settings":{"vnext":[{"address":"b.example.com",
                 "port":443,"users":[{"id":"","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}""",
			"""{"protocol":"vmess","tag":"x","settings":{"vnext":[{"address":"b.example.com",
                 "port":443,"users":[{"id":""}]}]},"streamSettings":{"network":"tcp"}}""",
			"""{"protocol":"trojan","tag":"x","settings":{"servers":[{"address":"b.example.com",
                 "port":443,"password":""}]},"streamSettings":{"network":"tcp","security":"tls"}}""",
			"""{"protocol":"shadowsocks","tag":"x",
                 "settings":{"servers":[{"address":"b.example.com","port":443,
                   "method":"aes-256-gcm","password":""}]}}"""
		)
		for (node in bad) {
			val body = """{"remarks":"N","outbounds":[$good,$node]}"""
			val singBox = SubscriptionConverter.convert(body, jsonToUri = false, xrayToSingBox = true)
			assertTrue(singBox, singBox.contains("a.example.com"))
			assertFalse("a credential-less node reached sing-box: $singBox",
				singBox.contains("b.example.com"))
			val mihomo = SubscriptionConverter.convert(body, jsonToUri = false, xrayToMihomo = true)
			assertTrue(mihomo, mihomo.contains("a.example.com"))
			assertFalse("a credential-less node reached mihomo: $mihomo", mihomo.contains("b.example.com"))
		}
	}

	// Xray picks a balancer's members by tag prefix, and a selector that matches nothing leaves it
	// with no outbound - it does not fall back to every outbound there is. Neither pass invents
	// members: the balancer is dropped, said so, and the rule pointing at it goes with it.
	@Test
	fun `a balancer that selects nothing is dropped rather than given every node`() {
		fun cfg(selector: String) = """
            {"remarks":"N","outbounds":[
              {"protocol":"vless","tag":"node-a","settings":{"vnext":[{"address":"a.example.com","port":443,
                "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
              {"protocol":"vless","tag":"other","settings":{"vnext":[{"address":"c.example.com","port":443,
                "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}],
             "routing":{"rules":[{"domain":["x.com"],"balancerTag":"bal"}],
               "balancers":[{"tag":"bal","selector":$selector}]}}
		""".trimIndent().replace("\n", " ")
		for (selector in listOf("""["zzz"]""", "[]")) {
			val singBox = JSONObject(SubscriptionConverter.convert(cfg(selector),
				jsonToUri = false, xrayToSingBox = true))
			val outs = singBox.getJSONArray("outbounds")
			for (i in 0 until outs.length()) assertNotEquals("bal", outs.getJSONObject(i).optString("tag"))
			assertFalse(singBox.getJSONObject("route").getJSONArray("rules").toString().contains(
				"\"outbound\":\"bal\""))

			val mihomo = SubscriptionConverter.convert(cfg(selector), jsonToUri = false, xrayToMihomo = true)
			assertFalse(mihomo, mihomo.contains("pool"))
		}
		// and a selector that matches keeps exactly what it matched
		val matched = JSONObject(SubscriptionConverter.convert(cfg("""["node-"]"""),
			jsonToUri = false, xrayToSingBox = true))
		val outs = matched.getJSONArray("outbounds")
		val bal = (0 until outs.length()).map { outs.getJSONObject(it) }.first { it.optString(
			"tag") == "bal" }
		assertEquals(1, bal.getJSONArray("outbounds").length())
	}

	// Xray knows four balancer strategies and refuses to load a configuration naming anything else,
	// so such a balancer never ran; and the address it was told to measure with is carried, not
	// replaced by a default nobody chose.
	@Test
	fun `a balancer names an unknown strategy and carries its probe`() {
		fun body(strategy: String) = """
            {"remarks":"N","outbounds":[{"protocol":"vless","tag":"node-a","settings":{"vnext":[
              {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
              "streamSettings":{"network":"tcp"}}],
             "observatory":{"subjectSelector":["node"],"probeURL":"https://probe.example.com/204",
              "probeInterval":"90s"},
             "routing":{"balancers":[{"tag":"bal","selector":["node"],"strategy":{"type":"$strategy"}}],
              "rules":[{"type":"field","network":"tcp","balancerTag":"bal"}]}}
		""".trimIndent().replace("\n", " ")

		val unknown = SubscriptionConverter.convertWithStats(body("quantumPing"),
			jsonToUri = false, xrayToSingBox = true)
		assertTrue(unknown.notes.toString(), unknown.notes.any { "Xray does not have" in it })
		val known = SubscriptionConverter.convertWithStats(body("leastPing"),
			jsonToUri = false, xrayToSingBox = true)
		assertTrue(known.notes.toString(), known.notes.none { "Xray does not have" in it })

		val group = JSONObject(known.text).getJSONArray("outbounds").let { outbounds ->
			(0 until outbounds.length()).map { outbounds.getJSONObject(it) }
				.first { it.optString("type") == "urltest" }
		}
		assertEquals("https://probe.example.com/204", group.getString("url"))
		assertEquals("90s", group.getString("interval"))

		val mihomo = SubscriptionConverter.convert(body("leastPing"), jsonToUri = false, xrayToMihomo = true)
		assertTrue(mihomo, mihomo.contains("url: https://probe.example.com/204"))
	}

	// sing-box refuses to start over a group member that is not an outbound, so a balancer keeps
	// only the members that were written, and goes when none was; its fallbackTag has no field.
	@Test
	fun `a balancer keeps only written members and names its lost fallback`() {
		fun cfg(port: Int) = """
            {"remarks":"N","outbounds":[
              {"protocol":"vless","tag":"node-a","settings":{"vnext":[{"address":"a.example.com","port":$port,
                "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
              {"protocol":"vless","tag":"node-b","settings":{"vnext":[{"address":"b.example.com","port":443,
                "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
              {"protocol":"vless","tag":"spare","settings":{"vnext":[{"address":"c.example.com","port":443,
                "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}],
             "routing":{"rules":[{"domain":["x.com"],"balancerTag":"bal"}],
              "balancers":[{"tag":"bal","selector":["node-"],"fallbackTag":"spare"}]}}
		""".trimIndent().replace("\n", " ")
		val result = SubscriptionConverter.convertWithStats(cfg(0), jsonToUri = false, xrayToSingBox = true)
		val outs = JSONObject(result.text).getJSONArray("outbounds")
		val tags = (0 until outs.length()).map { outs.getJSONObject(it).optString("tag") }
		val bal = (0 until outs.length()).map { outs.getJSONObject(it) }.first { it.optString(
			"tag") == "bal" }
		assertEquals(listOf("N #node-b"),
			(0 until bal.getJSONArray("outbounds").length()).map { bal.getJSONArray(
				"outbounds").getString(it) })
		assertTrue(tags.toString(), "N #node-a" !in tags)
		assertTrue(result.notes.toString(), result.notes.any { it.contains("\"spare\" as its fallback") })

		// Every member gone: the balancer goes too, with the rule that named it.
		val none = cfg(0).replace("\"b.example.com\",\"port\":443", "\"b.example.com\",\"port\":0")
		val gone = SubscriptionConverter.convertWithStats(none, jsonToUri = false, xrayToSingBox = true)
		assertTrue(gone.notes.toString(), gone.notes.any { it.contains("selects no outbound written here") })
		assertFalse(gone.text, gone.text.contains("\"tag\": \"bal\""))
	}

	// Alone, a configuration sends its DNS through its proxy; merged, "its proxy" is whichever the
	// person selects, so the queries follow the selector, and the same resolver written by every
	// configuration becomes one server every DNS rule still names.
	@Test
	fun `merged dns follows the selector and keeps one copy of each resolver`() {
		fun cfg(name: String) = """
            {"remarks":"$name","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
              {"address":"${name.lowercase()}.example.com","port":443,
               "users":[{"id":"u","encryption":"none"}]}]},
              "streamSettings":{"network":"tcp"}}],
             "dns":{"servers":["8.8.8.8",{"address":"1.1.1.1","domains":["geosite:cn"]}]}}
		""".trimIndent()
		val body = listOf(cfg("A"), cfg("B"), cfg("C")).joinToString(",", "[", "]").replace("\n", " ")
		val doc = JSONObject(SubscriptionConverter.convert(body, jsonToUri = false, xrayToSingBox = true))
		val dns = doc.getJSONObject("dns")
		val servers = dns.getJSONArray("servers")
		val tags = (0 until servers.length()).map { servers.getJSONObject(it).optString("tag") }
		// three configurations naming two resolvers: two servers and the local one, not six
		assertTrue("$tags", servers.length() <= 3)
		for (i in 0 until servers.length()) {
			val detour = servers.getJSONObject(i).optString("detour", "")
			assertTrue("dns goes through $detour rather than the " +
				"selector", detour.isEmpty() || detour == "proxy")
		}
		val rules = dns.getJSONArray("rules")
		for (i in 0 until rules.length()) {
			assertTrue(rules.getJSONObject(i).optString("server") in tags)
		}
		assertEquals("the same rule once, not three times", 1, rules.length())
	}

	// Hysteria2 authenticates by password alone. All three passes treat a node without one the
	// same way - no link, no outbound, no proxy - and each says why, so a node left out never
	// looks like a node that was never there.
	@Test
	fun `a hysteria2 node without a password is left out by every pass, with the reason`() {
		val body = """
			{"remarks":"N","outbounds":[
			  {"protocol":"vless","tag":"good","settings":{"vnext":[{"address":"g.example.com","port":443,
			    "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
			  {"protocol":"hysteria2","tag":"h","settings":{"servers":[{"address":"a.example.com",
			    "port":443,"password":""}]},
			    "streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}]}
		""".trimIndent().replace("\n", " ")
		assertFalse(SubscriptionConverter.convert(body, jsonToUri = true).contains("hysteria2://"))
		val singBox = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true)
		assertFalse(singBox.text, singBox.text.contains("\"type\":\"hysteria2\""))
		assertTrue(singBox.notes.toString(), singBox.notes.any { it.contains("no password") })
		val mihomo = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true)
		assertFalse(mihomo.text, mihomo.text.contains("type: hysteria2"))
		assertTrue(mihomo.text, mihomo.text.contains("g.example.com"))
	}

	// An outbound naming several servers spreads over them in Xray, and every pass hands back every
	// server: the sing-box pass one outbound each plus a urltest group under the original tag.
	@Test
	fun `every server of a multi-server outbound reaches the sing-box document`() {
		val body = """
			{"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
			  {"address":"a.example.com","port":443,"users":[{"id":"u1","encryption":"none"}]},
			  {"address":"b.example.com","port":8443,"users":[{"id":"u2","encryption":"none"}]}]},
			  "streamSettings":{"network":"tcp"}},{"protocol":"freedom","tag":"DIRECT"}],
			 "routing":{"rules":[{"domain":["x.com"],"outboundTag":"proxy"}]}}
		""".trimIndent().replace("\n", " ")
		val doc = JSONObject(SubscriptionConverter.convert(body, jsonToUri = false, xrayToSingBox = true))
		val outs = doc.getJSONArray("outbounds")
		val all = (0 until outs.length()).map { outs.getJSONObject(it) }
		val servers = all.filter { it.has("server") }.map { it.optString("server") }
		assertEquals(listOf("a.example.com", "b.example.com"), servers)
		val group = all.first { it.optString("type") == "urltest" && it.optString("tag") == "N" }
		assertEquals(2, group.getJSONArray("outbounds").length())
		val rules = doc.getJSONObject("route").getJSONArray("rules")
		val forX = (0 until rules.length()).map { rules.getJSONObject(
			it) }.first { it.toString().contains("x.com") }
		assertEquals("the rule reaches the group that holds both servers", "N", forX.optString("outbound"))
		val tags = all.map { it.optString("tag") }
		assertEquals(tags.size, tags.toSet().size)
	}

	// A subscription arrives in every shape a panel or an editor gives it - a byte-order mark, links
	// beside configurations, base64 wrapped at 76 columns - and each has to read as the plain one.
	@Test
	fun `a byte-order mark and mixed lines do not stop the passes`() {
		val config = """{"remarks":"A","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
            {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
              "streamSettings":{"network":"tcp"}}]}"""
			.replace("\n", " ")

		val withMark = "\uFEFF$config"
		assertTrue(SubscriptionConverter.convert(withMark, jsonToUri = true).contains("vless://"))
		assertTrue(SubscriptionConverter.convert(withMark, jsonToUri = false,
			xrayToSingBox = true).contains("\"outbounds\""))
		assertTrue(SubscriptionConverter.convert(withMark, jsonToUri = false,
			xrayToMihomo = true).contains("proxies:"))
		val markInsideBase64 = Base64.encodeToString("\uFEFF$config".toByteArray(),
			Base64.NO_WRAP)
		assertTrue(SubscriptionConverter.convert(markInsideBase64, jsonToUri = true).contains("vless://"))

		// A link beside a configuration: the configuration converts, and the link, which has no
		// place in a YAML document, is counted in the log rather than lost in silence.
		val mixed = "vless://u@c.example.com:443?encryption=none&type=tcp#C\n$config"
		val mihomo = SubscriptionConverter.convertWithStats(mixed, jsonToUri = false, xrayToMihomo = true)
		assertTrue(mihomo.text, mihomo.text.contains("proxies:") && mihomo.text.contains("a.example.com"))
		assertEquals(1, mihomo.notes.count { it.contains("no place in a mihomo document") })
	}

	// Vision runs inside TLS or REALITY. On a plain stream there is nothing for it to run in, and
	// Xray refuses the configuration outright - so the node never worked, and every pass leaves it
	// out with the reason rather than writing a flow the other end cannot answer.
	@Test
	fun `a flow on a plain stream is refused by every pass`() {
		val body = """
			{"remarks":"N","outbounds":[
			  {"protocol":"vless","tag":"good","settings":{"vnext":[{"address":"g.example.com","port":443,
			    "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
			  {"protocol":"vless","tag":"bad","settings":{"vnext":[{"address":"b.example.com","port":443,
			    "users":[{"id":"u","encryption":"none",
			      "flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp"}}]}
		""".trimIndent().replace("\n", " ")
		val uri = SubscriptionConverter.convert(body, jsonToUri = true)
		assertTrue(uri.contains("g.example.com") && !uri.contains("vless://u@b.example.com"))
		val singBox = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true)
		assertTrue(singBox.text.contains("g.example.com") && !singBox.text.contains("b.example.com"))
		assertTrue(singBox.notes.toString(), singBox.notes.any { it.contains("needs TLS or REALITY") })
		val mihomo = SubscriptionConverter.convert(body, jsonToUri = false, xrayToMihomo = true)
		assertTrue(mihomo.contains("g.example.com") && !mihomo.contains("b.example.com"))
	}

	// Xray runs a flow over the connection it dials: with encryption off, only where that connection
	// is TLS or REALITY itself; anything wrapped (ws, grpc, xhttp, a masquerade) never connects.
	// VLESS encryption carries the flow over any transport, even without TLS.
	@Test
	fun `a flow under a wrapped transport is refused by every pass, and kept where Xray runs it`() {
		fun node(stream: String, user: String = "\"encryption\":\"none\",\"flow\":\"xtls-rprx-vision\"") = """
            {"remarks":"F","outbounds":[{"protocol":"vless","tag":"p",
              "settings":{"vnext":[{"address":"f.example.com",
              "port":443,"users":[{"id":"u",$user}]}]},"streamSettings":{"security":"tls",
              "tlsSettings":{"serverName":"f.example.com"},$stream}}]}
		""".trimIndent().replace("\n", " ")
		fun passes(body: String) = listOf(
			SubscriptionConverter.convertWithStats(body, jsonToUri = true),
			SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true),
			SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true)
		)
		val wrapped = listOf(
			"grpc" to """"network":"grpc","grpcSettings":{"serviceName":"s"}""",
			"ws" to """"network":"ws","wsSettings":{"path":"/"}""",
			"xhttp" to """"network":"xhttp","xhttpSettings":{"path":"/"}""",
			"raw with an HTTP masquerade" to """"network":"raw","rawSettings":{"header":{"type":"http"}}"""
		)
		for ((under, stream) in wrapped) {
			for (pass in passes(node(stream))) {
				assertFalse("$under: ${pass.text}",
					pass.text.contains("f.example.com") && !pass.text.contains("\"vnext\""))
				// sing-box has no xhttp at all, and says that first.
				assertTrue("$under: ${pass.notes}", pass.notes.any {
					it.contains("refuses it under $under") ||
						it.contains("\"xhttp\" has no sing-box equivalent")
				})
			}
		}
		for (pass in passes(node(""""network":"raw""""))) {
			assertTrue(pass.text,
				pass.text.contains("f.example.com") && pass.text.contains("xtls-rprx-vision"))
		}
		// sing-box has no mKCP and mihomo runs it under vmess only, so the link alone carries the node.
		val kcp = passes(node(""""network":"kcp","kcpSettings":{"seed":"k"}"""))[0]
		assertTrue(kcp.text, kcp.text.startsWith("vless://") && kcp.text.contains("flow=xtls-rprx-vision"))
		// Encryption carries the flow over gRPC, so the link keeps it; sing-box refuses the
		// encryption itself, and says so rather than blaming the flow.
		val enc = node(""""network":"grpc","grpcSettings":{"serviceName":"s"}""",
			"\"encryption\":\"mlkem768x25519plus.native.1rtt.RvI5xPRmxvhVMSxOsCUDIF1uu4sN0-1Z9RXTVIrGYFk\"," +
				"\"flow\":\"xtls-rprx-vision\"")
		val (link, singBox, _) = passes(enc)
		assertTrue(link.text, link.text.contains("flow=xtls-rprx-vision"))
		assertTrue(singBox.notes.toString(),
			singBox.notes.any { it.contains("vless encryption") } &&
				singBox.notes.none { it.contains("flow") })
	}

	// A node dialing through another is written as a chain to that node's given name, never the Xray
	// tag; both cores refuse a dangling chain. A target that produced nothing takes the node with it.
	@Test
	fun `a chain resolves to the emitted name, and goes with a target that is gone`() {
		fun node(tag: String, host: String, extra: String = "", user: String = "") = """
            {"protocol":"vless","tag":"$tag","settings":{"vnext":[{"address":"$host","port":443,
             "users":[{"id":"u","encryption":"none"$user}]}]},
             "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"$host"}}$extra}
		""".trimIndent().replace("\n", " ")
		val chained =
			"""{"remarks":"C","outbounds":[${node("A", "a.example.com", ""","proxySettings":{"tag":"B"}""")},
              ${node("B", "b.example.com")}]}"""

		val singBox = JSONObject(SubscriptionConverter.convert(chained, jsonToUri = false,
			xrayToSingBox = true))
		val outs = singBox.getJSONArray("outbounds")
		val all = (0 until outs.length()).map { outs.getJSONObject(it) }
		val nodeA = all.first { it.optString("server") == "a.example.com" }
		assertTrue(nodeA.optString("detour") in all.map { it.optString("tag") })
		assertEquals("b.example.com",
			all.first { it.optString("tag") == nodeA.optString("detour") }.optString("server"))

		val mihomo = SubscriptionConverter.convert(chained, jsonToUri = false, xrayToMihomo = true)
		val names = Regex("name: (.+)").findAll(mihomo).map { it.groupValues[1].trim().trim('\'',
			'"') }.toSet()
		val dial = Regex("dialer-proxy: (.+)").find(mihomo)!!.groupValues[1].trim().trim('\'', '"')
		assertTrue("$dial not among $names", dial in names)

		// The target is a node no pass writes - its flow is one Xray dropped in 1.8 - so the
		// chained node goes with it.
		val gone =
			"""{"remarks":"C","outbounds":[${node("A", "a.example.com", ""","proxySettings":{"tag":"B"}""")},
              ${node("B", "b.example.com", user = ""","flow":"xtls-rprx-direct"""")}]}"""
		val miGone = SubscriptionConverter.convertWithStats(gone, jsonToUri = false, xrayToMihomo = true)
		assertTrue(miGone.notes.toString(), miGone.notes.any { it.contains("dials through") })
		assertFalse(miGone.text, miGone.text.contains("proxies:"))
		val sbGone = SubscriptionConverter.convertWithStats(gone, jsonToUri = false, xrayToSingBox = true)
		assertTrue(sbGone.notes.toString(), sbGone.notes.any { it.contains("dials through") })
	}

	// The probe a configuration names - probeUrl and probeInterval in observatory, destination and
	// interval in burstObservatory's pingConfig - reaches the groups of both documents, the
	// interval read as a duration and written as each core reads one.
	@Test
	fun `the observatory probe reaches the groups in both shapes`() {
		fun cfg(observatory: String) = """
            {"remarks":"O","outbounds":[
              {"protocol":"vless","tag":"p1","settings":{"vnext":[{"address":"a.example.com","port":443,
                "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
              {"protocol":"vless","tag":"p2","settings":{"vnext":[{"address":"b.example.com","port":443,
                "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}],
             "routing":{"balancers":[{"tag":"bal","selector":["p"]}]},$observatory}
		""".trimIndent().replace("\n", " ")
		val plain = cfg(
			""""observatory":{"probeUrl":"https://probe.example.com/ok","probeInterval":"1m",
                 "subjectSelector":["p"]}""")
		val burst = cfg(
			""""burstObservatory":{"pingConfig":{"destination":"https://probe.example.com/ok",
                 "interval":"90s"},"subjectSelector":["p"]}""")
		for ((body, seconds) in listOf(plain to 60, burst to 90)) {
			val mihomo = SubscriptionConverter.convert(body, jsonToUri = false, xrayToMihomo = true)
			assertTrue(mihomo,
				mihomo.contains("url: https://probe.example.com/ok") && mihomo.contains("interval: $seconds"))
			val singBox = JSONObject(SubscriptionConverter.convert(body, jsonToUri = false,
				xrayToSingBox = true)).getJSONArray("outbounds")
			val urltest = (0 until singBox.length()).map { singBox.getJSONObject(it) }.first { it.optString(
				"tag") == "bal" }
			assertEquals("https://probe.example.com/ok", urltest.optString("url"))
			assertEquals("${seconds}s", urltest.optString("interval"))
		}
	}

	// dns.hosts keys that are not names (keyword, regexp, geosite) and values that are names rather
	// than addresses have no hosts form; written as they stand they would be names nothing asks for.
	@Test
	fun `hosts entries neither core can hold are named, not written literally`() {
		val body = """
			{"remarks":"H","outbounds":[{"protocol":"vless","tag":"p",
			  "settings":{"vnext":[{"address":"a.example.com","port":443,
			  "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}],
			 "dns":{"servers":["8.8.8.8"],"hosts":{"one.example.com":"1.2.3.4","keyword:kw":"7.7.7.7",
			  "domain:s.example.com":"9.9.9.9","alias.example.com":"real.example.com"}}}
		""".trimIndent().replace("\n", " ")
		val mihomo = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true)
		assertFalse(mihomo.text, mihomo.text.contains("keyword:kw"))
		assertTrue(mihomo.text, mihomo.text.contains("+.s.example.com: 9.9.9.9"))
		assertTrue(mihomo.notes.any { it.contains("keyword:kw") })
		val singBox = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true)
		val predefined = JSONObject(singBox.text).getJSONObject("dns").getJSONArray("servers")
			.let { servers -> (0 until servers.length()).map { servers.getJSONObject(
				it) }.first { it.optString(
				"type") == "hosts" } }
			.getJSONObject("predefined")
		// A "domain:" key carries its own name; the hosts server matches whole names only.
		assertEquals(setOf("one.example.com", "s.example.com"), predefined.keys().asSequence().toSet())
		assertTrue(singBox.notes.any { it.contains("keyword:kw") } &&
			singBox.notes.any { it.contains("alias.example.com") } &&
			singBox.notes.any { it.contains("domain:s.example.com") })
	}

	// The hosts server goes in front by replacing the servers array, so the local server, which
	// the route and every encrypted resolver name, has to land in the array the document keeps.
	@Test
	fun `the resolvers a document names exist when hosts are present`() {
		val body = """
			{"remarks":"H","outbounds":[{"protocol":"vless","tag":"p",
			  "settings":{"vnext":[{"address":"a.example.com","port":443,
			  "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}],
			 "dns":{"servers":["https://dns.google/dns-query"],"hosts":{"dns.google":"8.8.8.8"}}}
		""".trimIndent().replace("\n", " ")
		val doc = JSONObject(SubscriptionConverter.convert(body, jsonToUri = false, xrayToSingBox = true))
		val dns = doc.getJSONObject("dns")
		val servers = dns.getJSONArray("servers")
		val tags = (0 until servers.length()).map { servers.getJSONObject(it).getString("tag") }
		assertEquals(listOf("hosts", "dns-0", "local"), tags)
		assertEquals("local", servers.getJSONObject(1).getString("domain_resolver"))
		assertEquals("local",
			doc.getJSONObject("route").getJSONObject("default_domain_resolver").getString("server"))
		assertEquals("dns-0", dns.getString("final"))
		// With no remote server the default falls to local, never to the hosts server.
		val onlyHosts = body.replace("\"servers\":[\"https://dns.google/dns-query\"],", "")
		val doc2 = JSONObject(
			SubscriptionConverter.convert(onlyHosts, jsonToUri = false, xrayToSingBox = true)
		)
		assertEquals("local", doc2.getJSONObject("dns").getString("final"))
	}

	// Read as Xray reads: names in any case ("VLESS" over "WS" under "TLS" runs there), a
	// fractional port refused rather than truncated, and a key written twice - Xray takes the later
	// value, this reader none - left as it is with the reason in the log.
	@Test
	fun `case, fractional ports and doubled keys are read as Xray reads them`() {
		val upper = """
			{"remarks":"N","outbounds":[{"protocol":"VLESS","tag":"proxy","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
			"streamSettings":{"network":"WS","security":"TLS",
			  "tlsSettings":{"serverName":"a.example.com"},"wsSettings":{"path":"/w"}}}]}
		""".trimIndent().replace("\n", " ")
		assertTrue(SubscriptionConverter.convert(upper, jsonToUri = true).startsWith("vless://"))
		assertTrue(SubscriptionConverter.convert(upper, jsonToUri = false,
			xrayToSingBox = true).contains("\"type\":\"vless\""))
		assertTrue(SubscriptionConverter.convert(upper, jsonToUri = false,
			xrayToMihomo = true).contains("type: vless"))

		val fraction = upper.replace("\"port\":443", "\"port\":443.7")
		assertFalse(SubscriptionConverter.convert(fraction, jsonToUri = true).contains("vless://"))

		// A key written twice keeps the later value, in Xray's reader and in Android's alike.
		val doubled = upper.replace("{\"remarks\":\"N\",", "{\"remarks\":\"A\",\"remarks\":\"B\",")
		val link = SubscriptionConverter.convert(doubled, jsonToUri = true)
		assertTrue(link, link.contains("#B") && !link.contains("#A"))
	}

	@Test
	fun `a configuration holding a number out of range is left out, not the whole subscription`() {
		// On a device org.json wrote such a configuration back as null, taking every other one with it.
		val good = """{"outbounds":[{"protocol":"vless","tag":"v","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]}}]}"""
			.replace("\n", "")
		val bad = good.replace("\"tag\":\"v\"", "\"tag\":\"v\",\"x\":[1e400]")
		val mihomo = ConversionFlags(false, false, true, false)
		val lines = SubscriptionConverter.convertWithStats("$good\n$bad", mihomo)
		assertTrue(lines.text, lines.text.contains("server: a.example.com"))
		val singBox = ConversionFlags(false, true, false, false)
		val merged = SubscriptionConverter.convertWithStats("[$good,$bad]", singBox)
		assertTrue(merged.text, merged.text.contains("a.example.com") && merged.xraySkipped == 1)
		val filteredLinks = ConversionFlags(true, true, false, false)
		val links = SubscriptionConverter.convertWithStats("[$good,$bad]", filteredLinks)
		assertTrue(links.text, links.text.startsWith("vless://") && links.xraySkipped == 1)
		val raw = SubscriptionConverter.convertWithStats("[1e400,$good]", filteredLinks)
		assertTrue(raw.notes.toString(), raw.text.startsWith("vless://"))
		assertTrue(raw.notes.toString(), raw.notes.any { "out of range" in it })
	}

	@Test
	fun `a server beside a number out of range keeps its node in every pass`() {
		// Copied by writing out and reading back, the outbound came back null on a device and the
		// working server beside the broken entry went with it, unsaid.
		val spare = """{"remarks":"S","outbounds":[{"protocol":"vless","tag":"spare","settings":{"vnext":[
			{"address":"sp.example.com","port":443,"users":[{"id":"u","encryption":"none"}]},
			["x",1e400]]}}]}""".replace("\n", "")
		val singBoxFlags = ConversionFlags(false, true, false, false)
		val singBox = SubscriptionConverter.convertWithStats(spare, singBoxFlags)
		assertTrue(singBox.text, singBox.text.contains("sp.example.com"))
		val links = SubscriptionConverter.convertWithStats(spare, ConversionFlags(true, false, false, false))
		assertTrue(links.text, links.text.contains("@sp.example.com:443"))
	}

	@Test
	fun `configurations sharing a name and their servers merge with every reference resolving`() {
		// The second configuration's nodes are renamed apart from the first's; its groups have to follow.
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val servers = listOf("a", "b").joinToString(",") {
			"""{"address":"$it.example.com","port":443,"users":[$user]}"""
		}
		val node = """{"protocol":"vless","tag":"proxy","settings":{"vnext":[$servers]}}"""
		val one = """{"remarks":"A","outbounds":[$node]}"""
		val text = SubscriptionConverter.convert(
			"[$one,$one]", jsonToUri = false, base64Result = false, xrayToSingBox = true
		)
		val outbounds = JSONObject(text).getJSONArray("outbounds")
		val all = (0 until outbounds.length()).map { outbounds.getJSONObject(it) }
		val tags = all.map { it.getString("tag") }.toSet()
		assertEquals(tags.toString(), all.size, tags.size)
		for (group in all) {
			val members = group.optJSONArray("outbounds") ?: continue
			for (k in 0 until members.length()) assertTrue(members.getString(k), members.getString(k) in tags)
		}
		assertEquals(4, all.count { it.has("server") })
	}
}
