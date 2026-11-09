package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Tests for the inbound, routing and DNS side of the converter; the outbound suites leave this side alone.
class SingBoxRoutingTest {

	private fun config(xray: String): JSONObject {
		val result = SingBoxConverter.convert(xray, "FB")
		assertTrue("expected Ok, got $result", result is SingBoxConverter.Result.Ok)
		return (result as SingBoxConverter.Result.Ok).config
	}

	private fun inbound(xray: String, index: Int = 0): JSONObject =
		config(xray).optJSONArray("inbounds")?.optJSONObject(index)!!

	private fun proxyOutbound() = """
		{"tag":"p","protocol":"vless",
		 "settings":{"vnext":[{"address":"a.com","port":443,
		   "users":[{"id":"u","encryption":"none"}]}]},
		 "streamSettings":{"network":"tcp","security":"tls"}}
	""".trimIndent()

	// Xray does not sniff unless told to. A document that sniffs anyway lets domain rules match
	// traffic Xray routed by address, so a configuration that declares its own inbounds is read as
	// written; one that declares none says nothing about it, and the client brings its own inbound.
	@Test
	fun `the document sniffs only where the configuration asked to`() {
		fun document(inbound: String?): SubscriptionConverter.ConversionResult {
			val inbounds = if (inbound == null) "" else ""","inbounds":[$inbound]"""
			val body = """
                {"remarks":"N"$inbounds,"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
                  {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
                  "streamSettings":{"network":"tcp"}}]}
			""".trimIndent().replace("\n", " ")
			return SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true)
		}
		fun sniffs(result: SubscriptionConverter.ConversionResult): Boolean {
			val rules = JSONObject(result.text).getJSONObject("route").getJSONArray("rules")
			return (0 until rules.length()).any { rules.getJSONObject(it).optString("action") == "sniff" }
		}
		val listening = """{"tag":"in","port":10808,"protocol":"socks","settings":{}"""
		assertTrue(sniffs(document(null)))
		assertTrue(sniffs(document("""$listening,"sniffing":{"enabled":true,"destOverride":["tls"]}}""")))
		val quiet = document("$listening}")
		assertFalse(quiet.text, sniffs(quiet))
		assertTrue(quiet.notes.toString(), quiet.notes.any { "does not either" in it })
		val off = document("""$listening,"sniffing":{"enabled":false}}""")
		assertFalse(off.text, sniffs(off))
	}

	// An inbound is what the client listens on. Dropped in silence, the document comes back with
	// nothing to listen on and no reason given, which reads as the converter having lost it.
	@Test
	fun `an inbound that cannot be carried says why it was dropped`() {
		fun document(inbound: String) = """
            {"remarks":"N","inbounds":[$inbound],"outbounds":[{"protocol":"vless","tag":"proxy",
             "settings":{"vnext":[{"address":"a.example.com","port":443,
              "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}]}
		""".trimIndent().replace("\n", " ")
		val cases = listOf(
			"""{"tag":"in","protocol":"tun","settings":{"mtu":9000}}""" to "tun inbound has no form",
			"""{"tag":"in","port":"10000-10100","protocol":"socks","settings":{}}""" to "no single port",
			"""{"tag":"in","port":443,"protocol":"vless","settings":{"clients":[]}}""" to
				"listens for other clients"
		)
		for ((inbound, reason) in cases) {
			val result = SubscriptionConverter.convertWithStats(document(inbound),
				jsonToUri = false, xrayToSingBox = true)
			assertTrue(result.text, result.text.contains("\"inbounds\":[]"))
			assertTrue("$inbound -> ${result.notes}", result.notes.any { reason in it })
		}
	}

	@Test
	fun `a quoted listen port is read as a number`() {
		val xray = """
            {"remarks":"S","inbounds":[{"tag":"in","protocol":"socks",
             "port":"10808","listen":"127.0.0.1"}],
             "outbounds":[${proxyOutbound()}]}
		""".trimIndent()
		val port = inbound(xray).opt("listen_port")
		assertTrue("expected a number, got ${'$'}{port?.javaClass?.simpleName}", port is Int)
		assertEquals(10808, port)
	}

	@Test
	fun `a dokodemo destination port is read as a number`() {
		// A quoted port has to become a number: written as text it is a config sing-box cannot load.
		val xray = """
            {"remarks":"D","inbounds":[{"tag":"dns-in","protocol":"dokodemo-door",
             "port":"10853","listen":"127.0.0.1",
             "settings":{"address":"1.1.1.1","port":"53","network":"tcp,udp"}}],
             "outbounds":[${proxyOutbound()}]}
		""".trimIndent()
		val inb = inbound(xray)
		assertEquals("direct", inb.optString("type"))
		assertEquals("1.1.1.1", inb.optString("override_address"))
		val port = inb.opt("override_port")
		assertTrue("expected a number, got ${'$'}{port?.javaClass?.simpleName}", port is Int)
		assertEquals(53, port)
	}

	@Test
	fun `a dokodemo listening on both networks pins neither`() {
		// sing-box treats a missing network as "both", which is what
		// Xray's "tcp,udp" means.
		val xray = """
            {"remarks":"D","inbounds":[{"tag":"dns-in","protocol":"dokodemo-door",
             "port":10853,"settings":{"address":"1.1.1.1","port":53,"network":"tcp,udp"}}],
             "outbounds":[${proxyOutbound()}]}
		""".trimIndent()
		assertFalse(inbound(xray).has("network"))
	}

	@Test
	fun `sniffing turns into a sniff rule`() {
		val xray = """
            {"remarks":"S","inbounds":[{"tag":"in","protocol":"socks","port":10808,
             "sniffing":{"enabled":true,"destOverride":["http","tls"]}}],
             "outbounds":[${proxyOutbound()}]}
		""".trimIndent()
		val rules = config(xray).optJSONObject("route")?.optJSONArray("rules")!!
		val actions = (0 until rules.length()).map { rules.optJSONObject(it)?.optString("action") }
		assertTrue("expected a sniff rule, got $actions", actions.contains("sniff"))
	}

	@Test
	fun `a server-side inbound is dropped rather than half converted`() {
		val xray = """
            {"remarks":"V","inbounds":[{"tag":"srv","protocol":"vless","port":443,
             "settings":{"clients":[{"id":"u"}]}}],
             "outbounds":[${proxyOutbound()}]}
		""".trimIndent()
		assertEquals(0, config(xray).optJSONArray("inbounds")?.length())
	}

	@Test
	fun `a port list splits into single ports and ranges`() {
		val xray = """
            {"remarks":"R","routing":{"rules":[{"type":"field",
             "port":"53,80,443-8443","outboundTag":"p"}]},
             "outbounds":[${proxyOutbound()}]}
		""".trimIndent()
		val rules = config(xray).optJSONObject("route")?.optJSONArray("rules")!!
		var seen: JSONObject? = null
		for (i in 0 until rules.length()) {
			val rule = rules.optJSONObject(i) ?: continue
			if (rule.has("port") || rule.has("port_range")) seen = rule
		}
		assertTrue("no port rule was emitted", seen != null)
		val ports = seen!!.optJSONArray("port")!!
		assertEquals(listOf(53, 80), (0 until ports.length()).map { ports.optInt(it) })
		val ranges = seen.optJSONArray("port_range")!!
		assertEquals(listOf("443:8443"), (0 until ranges.length()).map { ranges.optString(it) })
	}

	@Test
	fun `geosite and geoip entries become rule set references`() {
		val xray = """
            {"remarks":"G","routing":{"rules":[
              {"type":"field","domain":["geosite:category-ads-all"],"outboundTag":"block"},
              {"type":"field","ip":["geoip:private"],"outboundTag":"direct"}]},
             "outbounds":[${proxyOutbound()},
              {"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}
		""".trimIndent()
		val cfg = config(xray)
		val sets = cfg.optJSONObject("route")?.optJSONArray("rule_set")
		assertTrue("expected rule_set entries", (sets?.length() ?: 0) > 0)
		val tags = (0 until sets!!.length()).map { sets.optJSONObject(it)?.optString("tag") }
		assertTrue("$tags", tags.any { it?.contains("category-ads-all") == true })
	}

	@Test
	fun `a plain cidr stays inline instead of becoming a rule set`() {
		val xray = """
            {"remarks":"C","routing":{"rules":[{"type":"field",
             "ip":["10.0.0.0/8"],"outboundTag":"direct"}]},
             "outbounds":[${proxyOutbound()},{"tag":"direct","protocol":"freedom"}]}
		""".trimIndent()
		val rules = config(xray).optJSONObject("route")?.optJSONArray("rules")!!
		var found = false
		for (i in 0 until rules.length()) {
			val cidrs = rules.optJSONObject(i)?.optJSONArray("ip_cidr") ?: continue
			if ((0 until cidrs.length()).any { cidrs.optString(it) == "10.0.0.0/8" }) found = true
		}
		assertTrue("the cidr should be inline on the rule", found)
	}

	@Test
	fun `a quoted dns server port is read as a number`() {
		val xray = """
            {"remarks":"N","dns":{"servers":[{"address":"8.8.8.8","port":"5353"}]},
             "outbounds":[${proxyOutbound()}]}
		""".trimIndent()
		val servers = config(xray).optJSONObject("dns")?.optJSONArray("servers")!!
		var port: Any? = null
		for (i in 0 until servers.length()) {
			servers.optJSONObject(i)?.opt("server_port")?.let { port = it }
		}
		assertTrue("expected a number, got ${'$'}{port?.javaClass?.simpleName}", port is Int)
		assertEquals(5353, port)
	}

	@Test
	fun `a dns over https address keeps its type`() {
		val xray = """
            {"remarks":"H","dns":{"servers":["https://1.1.1.1/dns-query"]},
             "outbounds":[${proxyOutbound()}]}
		""".trimIndent()
		val servers = config(xray).optJSONObject("dns")?.optJSONArray("servers")!!
		val types = (0 until servers.length()).map { servers.optJSONObject(it)?.optString("type") }
		assertTrue("$types", types.contains("https"))
	}

	@Test
	fun `a config without dns still gets a local server`() {
		val xray = """{"remarks":"P","outbounds":[${proxyOutbound()}]}"""
		val dns = config(xray).optJSONObject("dns")!!
		assertEquals("local", dns.optString("final"))
		assertEquals("local", dns.optJSONArray("servers")?.optJSONObject(0)?.optString("tag"))
	}

	@Test
	fun `fakedns pools are carried over`() {
		val xray = """
            {"remarks":"F","fakedns":[{"ipPool":"198.18.0.0/15","poolSize":65535}],
             "dns":{"servers":["fakedns","8.8.8.8"]},
             "outbounds":[${proxyOutbound()}]}
		""".trimIndent()
		val dns = config(xray).optJSONObject("dns")!!
		val servers = dns.optJSONArray("servers")!!
		val types = (0 until servers.length()).map { servers.optJSONObject(it)?.optString("type") }
		assertTrue("expected a fakeip server, got $types", types.contains("fakeip"))
	}

	@Test
	fun `the xray log level is mapped and unknown levels fall back to warn`() {
		val debug = """{"remarks":"L","log":{"loglevel":"debug"},"outbounds":[${proxyOutbound()}]}"""
		assertEquals("debug", config(debug).optJSONObject("log")?.optString("level"))

		val nonsense = """{"remarks":"L","log":{"loglevel":"chatty"},"outbounds":[${proxyOutbound()}]}"""
		assertEquals("warn", config(nonsense).optJSONObject("log")?.optString("level"))
	}

	private fun routedRules(rules: String): List<JSONObject> {
		val xray = """{"outbounds":[${proxyOutbound()},{"protocol":"freedom","tag":"direct"}],
			"routing":{"rules":$rules}}""".replace("\n", "")
		val routes = config(xray).getJSONObject("route").getJSONArray("rules")
		return (0 until routes.length()).map { routes.getJSONObject(it) }
			.filter { it.optString("outbound") == "direct" }
	}

	@Test
	fun `a rule keeps its countries when an earlier rule named them first`() {
		val rules = routedRules("""[{"type":"field","ip":["geoip:cn"],"outboundTag":"direct"},
			{"type":"field","domain":["geosite:google"],"ip":["geoip:cn"],"outboundTag":"direct"}]""")
		assertEquals("both rules are kept: $rules", 2, rules.size)
		assertEquals("logical", rules[1].optString("type"))
	}

	@Test
	fun `a country of the source matches the source address`() {
		val rule = routedRules(
			"""[{"type":"field","source":["geoip:cn"],"outboundTag":"direct"}]"""
		).single()
		assertEquals("[\"geoip-cn\"]", rule.getJSONArray("rule_set").toString())
		assertTrue(rule.getBoolean("rule_set_ip_cidr_match_source"))
	}

	@Test
	fun `source countries join the source addresses, apart from the destination ones`() {
		val rule = routedRules("""[{"type":"field","source":["10.0.0.0/8","geoip:cn"],"ip":["geoip:us"],
			"outboundTag":"direct"}]""").single()
		assertEquals("and", rule.optString("mode"))
		val parts = rule.getJSONArray("rules").let { p -> (0 until p.length()).map { p.getJSONObject(it) } }
		// The source's own addresses and its countries are alternatives of their own, as 1.12 needs.
		val source = parts.single { it.optString("mode") == "or" }.getJSONArray("rules")
			.let { r -> (0 until r.length()).map { r.getJSONObject(it) } }
		assertEquals("[\"10.0.0.0/8\"]", jsonText(source.single { it.has("source_ip_cidr") }
			.getJSONArray("source_ip_cidr")))
		assertTrue(source.single { it.has("rule_set") }.getBoolean("rule_set_ip_cidr_match_source"))
		val destination = parts.single { it.optJSONArray("rule_set")?.toString() == "[\"geoip-us\"]" }
		assertFalse(
			"the switch must not turn the destination countries",
			destination.has("rule_set_ip_cidr_match_source")
		)
	}

	@Test
	fun `a negated country of the source is its rule-set inverted`() {
		val rule = routedRules(
			"""[{"type":"field","source":["geoip:!ru"],"outboundTag":"direct"}]"""
		).single()
		assertEquals("[\"geoip-ru\"]", rule.getJSONArray("rule_set").toString())
		assertTrue(rule.getBoolean("rule_set_ip_cidr_match_source"))
		assertTrue(rule.getBoolean("invert"))
	}

	@Test
	fun `not-private is the core's own answer, the destination one held to known addresses`() {
		// Nothing to fetch: the core knows the private ranges. Inverted alone, a destination condition
		// matches every name (measured); a source always has its address.
		val source = routedRules(
			"""[{"type":"field","source":["geoip:!private"],"outboundTag":"direct"}]"""
		).single()
		assertTrue(source.toString(), source.getBoolean("source_ip_is_private"))
		assertTrue(source.toString(), source.getBoolean("invert"))
		val destination = routedRules(
			"""[{"type":"field","ip":["geoip:!private"],"outboundTag":"direct"}]"""
		).single()
		val text = destination.toString()
		assertEquals(text, "and", destination.optString("mode"))
		val parts = destination.getJSONArray("rules")
		assertEquals(text, "0.0.0.0/0", parts.getJSONObject(0).getJSONArray("ip_cidr").getString(0))
		assertTrue(text, parts.getJSONObject(1).getBoolean("ip_is_private"))
		assertTrue(text, parts.getJSONObject(1).getBoolean("invert"))
		assertFalse("no rule-set is needed: $text", "rule_set" in text || "rule_set" in source.toString())
	}

	@Test
	fun `plain private stays the core's own answer too`() {
		for ((field, key) in listOf("source" to "source_ip_is_private", "ip" to "ip_is_private")) {
			val rule = routedRules(
				"""[{"type":"field","$field":["geoip:private"],"outboundTag":"direct"}]"""
			).single()
			assertTrue(rule.getBoolean(key))
			assertFalse("a plain private rule is not inverted", rule.optBoolean("invert"))
			assertFalse(rule.has("rule_set"))
		}
	}

	@Test
	fun `a negated country still needs its set - only private is built in`() {
		val rule = routedRules(
			"""[{"type":"field","ip":["geoip:!ru"],"outboundTag":"direct"}]"""
		).single()
		assertTrue("a country has no built-in answer", rule.toString().contains("geoip-ru"))
	}

	@Test
	fun `a rule pointing at nothing is named by its place, as mihomo names it`() {
		val xray = """{"outbounds":[${proxyOutbound()},{"protocol":"freedom","tag":"direct"}],
			"routing":{"rules":[{"type":"field","domain":["domain:a.example"],"outboundTag":"direct"},
			{"type":"field","domain":["domain:b.example"],"outboundTag":"nowhere"}]}}""".replace("\n", "")
		val notes = (SingBoxConverter.convert(xray, "FB") as SingBoxConverter.Result.Ok).notes
		assertTrue("$notes", notes.any { it.startsWith("routing.rules[1] points at \"nowhere\"") })
	}

	@Test
	fun `a source the core cannot read leaves the rule on the addresses it can`() {
		val xray = """{"outbounds":[${proxyOutbound()},{"protocol":"blackhole","tag":"block"}],
			"routing":{"rules":[{"type":"field","source":["ext:geoip.dat:cn","10.0.0.0/8"],
			"outboundTag":"block"}]}}"""
		val result = SingBoxConverter.convert(xray, "FB") as SingBoxConverter.Result.Ok
		val rules = result.config.getJSONObject("route").getJSONArray("rules").toString().replace("\\/", "/")
		assertTrue(rules, rules.contains("10.0.0.0/8") && !rules.contains("ext:"))
		val noted = result.notes.any { it.contains("ext:geoip.dat:cn is not an address") }
		assertTrue(result.notes.toString(), noted)
	}
}
