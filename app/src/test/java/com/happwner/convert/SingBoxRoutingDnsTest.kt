package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Routing and DNS, as the core will actually run them.
class SingBoxRoutingDnsTest {

	private val uuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"

	private fun proxyOutbound() = """
        {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
        "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
        "streamSettings":{"network":"tcp","security":"tls",
        "tlsSettings":{"serverName":"a.example.com"}}}
	""".trimIndent().replace("\n", "")

	private fun convert(body: String): JSONObject {
		val out = SubscriptionConverter.convert(body, jsonToUri = false, base64Result = false,
			xrayToSingBox = true)
		return JSONObject(out)
	}

	private fun dnsServers(cfg: JSONObject): List<JSONObject> {
		val arr = cfg.getJSONObject("dns").optJSONArray("servers") ?: JSONArray()
		return (0 until arr.length()).map { arr.getJSONObject(it) }
	}

	private fun routeRules(cfg: JSONObject): List<JSONObject> {
		val arr = cfg.getJSONObject("route").optJSONArray("rules") ?: JSONArray()
		return (0 until arr.length()).map { arr.getJSONObject(it) }
	}

	// Xray reads queryStrategy loosely - lower case, "_" or "-" between the words - and treats
	// anything it does not know as UseIP. Read strictly, a legal spelling would be ignored and the
	// document would resolve differently from the configuration it came from.
	@Test
	fun `every spelling Xray takes for queryStrategy is read the same way`() {
		fun strategyOf(value: String): String {
			val body = """
                {"remarks":"N","dns":{"servers":["8.8.8.8"],"queryStrategy":"$value"},
                 "outbounds":[{"protocol":"vless","tag":"p","settings":{"vnext":[{"address":"a.example.com",
                  "port":443,"users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}]}
			""".trimIndent().replace("\n", " ")
			val document = JSONObject(
				SubscriptionConverter.convert(body, jsonToUri = false, xrayToSingBox = true)
			)
			return document.getJSONObject("route").getJSONObject("default_domain_resolver")
				.optString("strategy", "")
		}
		for (spelling in listOf("UseIPv4", "useipv4", "use_ip_v4", "USE-IP4", "useip4")) {
			assertEquals(spelling, "ipv4_only", strategyOf(spelling))
		}
		for (spelling in listOf("UseIPv6", "useip6", "use-ipv6")) {
			assertEquals(spelling, "ipv6_only", strategyOf(spelling))
		}
		// Not a strategy Xray has: it falls back to UseIP there, and so does this.
		for (spelling in listOf("UseIP", "UseIPv4v6", "nonsense")) {
			assertEquals(spelling, "prefer_ipv4", strategyOf(spelling))
		}
	}

	// Xray dials a "+local" resolver itself rather than routing the query, so it never leaves by the
	// proxy. Sent through the tunnel instead, a resolver kept outside it answers from the wrong side
	// of the network - and the person never asked for that.
	@Test
	fun `a plus-local resolver is asked outside the tunnel`() {
		val body = """
			{"remarks":"N","dns":{"servers":["tcp+local://9.9.9.9",
			  {"address":"https+local://dns.google/dns-query","domains":["geosite:google"]},"1.1.1.1"]},
			 "outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
			  "port":443,"users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}]}
		""".trimIndent().replace("\n", " ")
		val document = JSONObject(
			SubscriptionConverter.convert(body, jsonToUri = false, xrayToSingBox = true)
		)
		val servers = document.getJSONObject("dns").getJSONArray("servers")
		val byServer = (0 until servers.length()).map { servers.getJSONObject(it) }
			.associateBy { it.optString("server", it.optString("type")) }
		// Straight out with no detour: sing-box will not start with a resolver dialing through a direct
		// outbound that holds nothing of its own, and with none a resolver dials straight out.
		assertFalse("${byServer["9.9.9.9"]}", byServer.getValue("9.9.9.9").has("detour"))
		assertFalse("${byServer["dns.google"]}", byServer.getValue("dns.google").has("detour"))
		assertEquals("N", byServer.getValue("1.1.1.1").getString("detour"))

		val yaml = SubscriptionConverter.convert(body, jsonToUri = false, xrayToMihomo = true)
		assertTrue(yaml, yaml.contains("direct-nameserver: [tcp://9.9.9.9]"))
	}

	// Xray dials a "+local" resolver itself, whatever the freedom tagged "direct" does: where that freedom
	// dials through a node and so leaves the document, the resolver dials straight out regardless - and one
	// written by name, in the udp spelling the reader takes, finds its server through the local resolver.
	@Test
	fun `a plus-local resolver dials straight out whatever the freedom tagged direct does`() {
		val freedom = """{"protocol":"freedom","tag":"direct",""" +
			""""streamSettings":{"sockopt":{"dialerProxy":"proxy"}}}"""
		val servers = """["tcp+local://9.9.9.9","udp+local://dns.example.com"]"""
		val body = """{"remarks":"N","dns":{"servers":$servers},""" +
			""""outbounds":[${proxyOutbound()},$freedom]}"""
		val cfg = convert(body)
		val outbounds = cfg.getJSONArray("outbounds")
		val tags = (0 until outbounds.length()).map { outbounds.getJSONObject(it).optString("tag") }
		val byServer = dnsServers(cfg).associateBy { it.optString("server") }
		assertFalse("$cfg", byServer.getValue("9.9.9.9").has("detour"))
		val named = byServer.getValue("dns.example.com")
		assertFalse("$named", named.has("detour"))
		assertEquals("local", named.optString("domain_resolver"))
		assertTrue("$cfg", dnsServers(cfg).all { !it.has("detour") || it.getString("detour") in tags })
	}

	// Merged, the first configuration's direct outbound is the one the others' turn into, so a resolver or
	// a node that dialed through a direct holding something of its own may come to dial through one
	// holding nothing - and then dials straight out.
	@Test
	fun `no resolver or node of a merged document dials through the empty direct outbound`() {
		val viaDirect = proxyOutbound().replace("a.example.com", "b.example.com")
			.replace(""""network":"tcp",""", """"network":"tcp","sockopt":{"dialerProxy":"direct"},""")
		val freedom = """{"protocol":"freedom","tag":"direct","settings":{"domainStrategy":"UseIPv4"}}"""
		val second = """{"remarks":"B","dns":{"servers":["tcp+local://9.9.9.9"]},""" +
			""""outbounds":[$viaDirect,$freedom]}"""
		val alone = dnsServers(convert(second)).single { it.optString("server") == "9.9.9.9" }
		assertEquals("$alone", "direct", alone.optString("detour"))

		val cfg = convert("""[{"remarks":"A","outbounds":[${proxyOutbound()}]},$second]""")
		val outbounds = cfg.getJSONArray("outbounds")
		val dialing = (0 until outbounds.length()).map { outbounds.getJSONObject(it) } + dnsServers(cfg)
		assertTrue("$cfg", dialing.any { it.optString("server") == "9.9.9.9" })
		assertTrue("$cfg", dialing.any { it.optString("server") == "b.example.com" })
		assertTrue("$dialing", dialing.none { it.optString("detour") == "direct" })
	}

	@Test
	fun `an HTTP3 DNS server is spelled the way the core spells it`() {
		// The core knows this transport as "h3" and answers "http3" with "unknown transport type",
		// which refuses the whole document: one such server would cost the entire configuration.
		val cfg = convert(
			"""{"dns":{"servers":["h3://1.1.1.1/dns-query"]},"outbounds":[${proxyOutbound()}]}"""
		)
		val remoteServers = dnsServers(cfg).filter { it.optString("type") !in setOf("local",
			"hosts", "fakeip") }
		assertTrue("no DNS server was emitted: $cfg", remoteServers.isNotEmpty())
		assertEquals("h3", remoteServers.first().optString("type"))
		assertFalse("the rejected spelling must be gone", cfg.toString().contains("\"http3\""))
	}

	@Test
	fun `a per-server query strategy uses the field name the core accepts`() {
		// "strategy" on a server is the legacy spelling; the core answers it
		// with `unknown field "strategy"` and refuses the document.
		val cfg = convert(
			"""{"dns":{"servers":[{"address":"1.1.1.1","queryStrategy":"UseIPv4"}]},
               "outbounds":[${proxyOutbound()}]}""".trimIndent().replace("\n", "")
		)
		val server = dnsServers(cfg).first { it.optString("type") == "udp" }
		// domain_strategy on a new-format server is the dial field that resolves the server's own
		// name (it replaced address_strategy), not the query strategy, so it is not written here.
		assertFalse("domain_strategy is the wrong field for queryStrategy: $server",
			server.has("domain_strategy"))
		assertFalse("the rejected field must not appear", server.has("strategy"))
	}

	@Test
	fun `the default server is one that answers every name, not one narrowed to a few`() {
		// Xray asks the next server when a narrowed one has no answer; sing-box asks its default
		// and stops, so a default narrowed to a few names leaves every other name unanswered.
		val cfg = convert(
			"""{"dns":{"servers":[{"address":"1.1.1.1","domains":["domain:scoped.example"]},
               {"address":"8.8.8.8"}]},"outbounds":[${proxyOutbound()}]}"""
				.trimIndent().replace("\n", "")
		)
		val byTag = dnsServers(cfg).associateBy { it.optString("tag") }
		val finalTag = cfg.getJSONObject("dns").optString("final")
		assertEquals(
			"the default has to be the server with no domains of its own",
			"8.8.8.8", byTag[finalTag]?.optString("server")
		)
		// and the narrowed one is still there, with the rule that feeds it
		val rules = cfg.getJSONObject("dns").optJSONArray("rules") ?: JSONArray()
		val scoped = requireNotNull((0 until rules.length()).map { rules.getJSONObject(it) }
			.firstOrNull { it.optJSONArray("domain_suffix") != null }) {
			"the scoped server needs a rule to send it its names"
		}
		assertEquals("1.1.1.1", byTag[scoped.optString("server")]?.optString("server"))
	}

	@Test
	fun `when every server is narrowed the first is still named as the default`() {
		// Named anyway: with no final, sing-box takes whichever server comes first in the document.
		val cfg = convert(
			"""{"dns":{"servers":[{"address":"1.1.1.1","domains":["domain:a.example"]},
               {"address":"8.8.8.8","domains":["domain:b.example"]}]},
               "outbounds":[${proxyOutbound()}]}"""
				.trimIndent().replace("\n", "")
		)
		val byTag = dnsServers(cfg).associateBy { it.optString("tag") }
		val finalTag = cfg.getJSONObject("dns").optString("final")
		assertTrue("a default server should still be named", finalTag.isNotEmpty())
		assertEquals("1.1.1.1", byTag[finalTag]?.optString("server"))
	}

	@Test
	fun `the servers nothing will ever ask are named in the log`() {
		// Xray moves on to the next server when one has no answer; sing-box asks its default and
		// stops, so a spare resolver the subscription listed is never asked.
		val notes = SubscriptionConverter.convertWithStats(
			"""{"dns":{"servers":["1.1.1.1","8.8.8.8","9.9.9.9"]},"outbounds":[${proxyOutbound()}]}""",
			jsonToUri = false, xrayToSingBox = true
		).notes
		assertTrue(
			"the unreachable servers should be counted: $notes",
			notes.any { it.contains("2 servers") && it.contains("never reached") }
		)
	}

	@Test
	fun `a server a rule feeds is reachable, so it is not counted as lost`() {
		val notes = SubscriptionConverter.convertWithStats(
			"""{"dns":{"servers":[{"address":"1.1.1.1","domains":["domain:scoped.example"]},
               {"address":"8.8.8.8"}]},"outbounds":[${proxyOutbound()}]}"""
				.trimIndent().replace("\n", ""),
			jsonToUri = false, xrayToSingBox = true
		).notes
		assertFalse(
			"the narrowed server has a rule of its own and is asked: $notes",
			notes.any { it.contains("never reached") }
		)
	}

	@Test
	fun `one server alone says nothing`() {
		val notes = SubscriptionConverter.convertWithStats(
			"""{"dns":{"servers":["1.1.1.1"]},"outbounds":[${proxyOutbound()}]}""",
			jsonToUri = false, xrayToSingBox = true
		).notes
		assertFalse("nothing was lost: $notes", notes.any { it.contains("never reached") })
	}

	@Test
	fun `a single unnarrowed server is the default`() {
		val cfg = convert(
			"""{"dns":{"servers":["1.1.1.1"]},"outbounds":[${proxyOutbound()}]}"""
		)
		val byTag = dnsServers(cfg).associateBy { it.optString("tag") }
		val finalTag = cfg.getJSONObject("dns").optString("final")
		assertEquals("1.1.1.1", byTag[finalTag]?.optString("server"))
	}

	@Test
	fun `a server skipFallback keeps out of Xray's order is neither the default nor a lost spare`() {
		// Xray never asks such a server about names outside its domains, so sing-box must not
		// make it the default, and leaving it unasked loses nothing.
		val body = """{"dns":{"servers":[{"address":"1.1.1.1","skipFallback":true},{"address":"8.8.8.8"}]},
			"outbounds":[${proxyOutbound()}]}""".replace("\n", "")
		val cfg = convert(body)
		val byTag = dnsServers(cfg).associateBy { it.optString("tag") }
		assertEquals("8.8.8.8", byTag[cfg.getJSONObject("dns").optString("final")]?.optString("server"))
		val notes = SubscriptionConverter.convertWithStats(
			body, jsonToUri = false, xrayToSingBox = true
		).notes
		assertFalse("nothing Xray would ask was lost: $notes", notes.any { it.contains("never reached") })
	}

	@Test
	fun `with every server narrowed, the default is the first Xray still asks about other names`() {
		val cfg = convert(
			"""{"dns":{"servers":[{"address":"1.1.1.1","domains":["domain:a.example"],"skipFallback":true},
				{"address":"8.8.8.8","domains":["domain:b.example"]}]},"outbounds":[${proxyOutbound()}]}"""
				.replace("\n", "")
		)
		val byTag = dnsServers(cfg).associateBy { it.optString("tag") }
		assertEquals("8.8.8.8", byTag[cfg.getJSONObject("dns").optString("final")]?.optString("server"))
	}

	@Test
	fun `a fakedns-only configuration does not make fakeip the default server`() {
		// "default server cannot be fakeip": the core refuses to start with one there, and a
		// configuration whose only DNS entry is fakedns would land exactly on it.
		val cfg = convert(
			"""{"dns":{"servers":["fakedns"]},"outbounds":[${proxyOutbound()}]}"""
		)
		val finalTag = cfg.getJSONObject("dns").optString("final")
		val byTag = dnsServers(cfg).associateBy { it.optString("tag") }
		assertTrue("a final server should be named", finalTag.isNotEmpty())
		assertEquals(
			"the default server must not be the fakeip one",
			"local", byTag[finalTag]?.optString("type")
		)
		// and the fakeip server is still there for the rules to use
		assertTrue("the fakeip server should still be present",
			dnsServers(cfg).any { it.optString("type") == "fakeip" })
	}

	@Test
	fun `fakedns listed twice is one fakeip server, its rules sent to it`() {
		// sing-box 1.14.2 refuses a second one: "multiple fakeip server are not supported".
		val repeat = """{"address":"fakedns","domains":["full:b.example.com"]}"""
		val cfg = convert(
			"""{"dns":{"servers":["fakedns","1.1.1.1",$repeat]},"outbounds":[${proxyOutbound()}]}"""
		)
		val fakeip = dnsServers(cfg).filter { it.optString("type") == "fakeip" }
		assertEquals("one fakeip server", 1, fakeip.size)
		val rules = cfg.getJSONObject("dns").getJSONArray("rules")
		val toFakeip = (0 until rules.length()).map { rules.getJSONObject(it) }
			.filter { it.optString("server") == fakeip.single().optString("tag") }
		assertTrue("$rules", toFakeip.any { it.toString().contains("b.example.com") })
	}

	@Test
	fun `an address rule under IPIfNonMatch gets a resolve in front of it`() {
		// Without it the address rules never match a domain destination, so a configuration that
		// sends its own country direct sends it to the proxy instead - silently, because the
		// document is valid either way.
		val cfg = convert(
			"""{"routing":{"domainStrategy":"IPIfNonMatch","rules":[
               {"type":"field","ip":["127.0.0.0/8"],"outboundTag":"direct"}]},
               "outbounds":[${proxyOutbound()},{"protocol":"freedom","tag":"direct"}]}"""
				.trimIndent().replace("\n", "")
		)
		val rules = routeRules(cfg)
		val ipAt = rules.indexOfFirst { it.has("ip_cidr") }
		val resolveAt = rules.indexOfFirst { it.optString("action") == "resolve" }
		assertTrue("no address rule was emitted: $rules", ipAt >= 0)
		assertTrue("no resolve action was emitted: $rules", resolveAt >= 0)
		assertTrue("the resolve must come before the address rule: $rules", resolveAt < ipAt)
	}

	@Test
	fun `a domain rule keeps its place ahead of the resolve`() {
		// The resolve replaces the destination with the address it found, so anything matched
		// before it still reaches its outbound as a name.
		val cfg = convert(
			"""{"routing":{"domainStrategy":"IPIfNonMatch","rules":[
               {"type":"field","domain":["full:a.example.org"],"outboundTag":"proxy"},
               {"type":"field","ip":["127.0.0.0/8"],"outboundTag":"direct"}]},
               "outbounds":[${proxyOutbound()},{"protocol":"freedom","tag":"direct"}]}"""
				.trimIndent().replace("\n", "")
		)
		val rules = routeRules(cfg)
		val domainAt = rules.indexOfFirst { it.has("domain") }
		val resolveAt = rules.indexOfFirst { it.optString("action") == "resolve" }
		val ipAt = rules.indexOfFirst { it.has("ip_cidr") }
		assertTrue("expected domain, then resolve, then address: $rules",
			domainAt in 0 until resolveAt && resolveAt < ipAt)
	}

	@Test
	fun `AsIs does not resolve anything`() {
		// AsIs is the strategy that says not to, and resolving anyway would
		// hand the proxy an address where the configuration meant a name.
		val cfg = convert(
			"""{"routing":{"domainStrategy":"AsIs","rules":[
               {"type":"field","ip":["127.0.0.0/8"],"outboundTag":"direct"}]},
               "outbounds":[${proxyOutbound()},{"protocol":"freedom","tag":"direct"}]}"""
				.trimIndent().replace("\n", "")
		)
		assertTrue("AsIs must not add a resolve: ${routeRules(cfg)}",
			routeRules(cfg).none { it.optString("action") == "resolve" })
	}

	@Test
	fun `a configuration with no address rule is left alone`() {
		// Nothing to resolve for, and resolving would only cost the domain.
		val cfg = convert(
			"""{"routing":{"domainStrategy":"IPIfNonMatch","rules":[
               {"type":"field","domain":["full:a.example.org"],"outboundTag":"direct"}]},
               "outbounds":[${proxyOutbound()},{"protocol":"freedom","tag":"direct"}]}"""
				.trimIndent().replace("\n", "")
		)
		assertTrue("no address rule means no resolve: ${routeRules(cfg)}",
			routeRules(cfg).none { it.optString("action") == "resolve" })
	}

	@Test
	fun `a negated country becomes an inverted rule, not a broken rule-set`() {
		// "geoip:!cn" must not become a rule-set tagged geoip-!cn: the URL built from that tag is
		// a 404, and the document passes every check and then has nothing to match against.
		val cfg = convert(
			"""{"routing":{"rules":[
               {"type":"field","ip":["geoip:!cn"],"outboundTag":"direct"}]},
               "outbounds":[${proxyOutbound()},{"protocol":"freedom","tag":"direct"}]}"""
				.trimIndent().replace("\n", "")
		)
		val sets = cfg.getJSONObject("route").optJSONArray("rule_set") ?: JSONArray()
		val tags = (0 until sets.length()).map { sets.getJSONObject(it).optString("tag") }
		assertTrue("a rule-set tag must never carry a negation: $tags",
			tags.none { it.contains("!") })
		assertTrue("the positive set is what an inverted rule references: $tags",
			tags.contains("geoip-cn"))
		val urls = (0 until sets.length()).map { sets.getJSONObject(it).optString("url") }
		assertTrue("no rule-set URL may carry a negation: $urls",
			urls.none { it.contains("!") })
		// The negation lives inside the rule as an alternative, paired with a match-any address so
		// it only speaks for destinations whose address is known - on its own it would match every
		// unresolved name.
		val rule = routeRules(cfg).last()
		assertEquals("direct", rule.optString("outbound"))
		val flat = jsonText(rule)
		assertTrue("the negation should be inverted: $flat", flat.contains("\"invert\":true"))
		assertTrue("it must be tied to a known address: $flat", flat.contains("0.0.0.0/0"))
		assertTrue("and it must reference the positive set: $flat", flat.contains("geoip-cn"))
	}

	@Test
	fun `a rule naming both a domain and an address means both`() {
		// The core reads every destination field of one rule as an alternative, while Xray reads a
		// name condition and an address condition as two things that must both hold.
		val cfg = convert(
			"""{"routing":{"domainStrategy":"IPIfNonMatch","rules":[
               {"type":"field","domain":["full:a.example.org"],"ip":["10.0.0.0/8"],
                "outboundTag":"direct"}]},
               "outbounds":[${proxyOutbound()},{"protocol":"freedom","tag":"direct"}]}"""
				.trimIndent().replace("\n", "")
		)
		val rule = routeRules(cfg).last()
		assertEquals("logical", rule.optString("type"))
		assertEquals("and", rule.optString("mode"))
		val inner = rule.getJSONArray("rules")
		assertEquals("a name part and an address part", 2, inner.length())
		val flat = jsonText(rule)
		assertTrue(flat.contains("a.example.org"))
		assertTrue(flat.contains("10.0.0.0/8"))
	}

	@Test
	fun `a rule naming only domains stays flat`() {
		// All of these are alternatives to the core as well, so nothing needs
		// rearranging - and a rule left alone is one fewer thing to get wrong.
		val cfg = convert(
			"""{"routing":{"rules":[
               {"type":"field","domain":["full:a.test","domain:b.test"],
                "outboundTag":"direct"}]},
               "outbounds":[${proxyOutbound()},{"protocol":"freedom","tag":"direct"}]}"""
				.trimIndent().replace("\n", "")
		)
		val rule = routeRules(cfg).last()
		assertFalse("no conjunction needed: $rule", rule.has("type"))
		assertTrue(rule.has("domain") && rule.has("domain_suffix"))
	}

	@Test
	fun `a geoip rule counts as an address rule`() {
		// geoip becomes a rule-set rather than a CIDR list, and it needs the
		// resolve just as much.
		val cfg = convert(
			"""{"routing":{"domainStrategy":"IPIfNonMatch","rules":[
               {"type":"field","ip":["geoip:cn"],"outboundTag":"direct"}]},
               "outbounds":[${proxyOutbound()},{"protocol":"freedom","tag":"direct"}]}"""
				.trimIndent().replace("\n", "")
		)
		val rules = routeRules(cfg)
		val resolveAt = rules.indexOfFirst { it.optString("action") == "resolve" }
		val geoAt = rules.indexOfFirst {
			val ruleSets = it.optJSONArray("rule_set") ?: return@indexOfFirst false
			(0 until ruleSets.length()).any { i -> ruleSets.optString(i).startsWith("geoip-") }
		}
		assertTrue("no geoip rule-set rule: $rules", geoAt >= 0)
		assertTrue("the resolve must precede the geoip rule: $rules",
			resolveAt in 0 until geoAt)
	}

	@Test
	fun `dns servers that would share a tag each keep a tag of their own`() {
		val cases = listOf(
			"""["localhost","localhost","8.8.8.8"]""" to "local",
			"""[{"address":"8.8.8.8","tag":"a"},{"address":"1.1.1.1","tag":"a"}]""" to "a"
		)
		for ((servers, stem) in cases) {
			val body = """{"remarks":"N","dns":{"servers":$servers},"outbounds":[${proxyOutbound()}]}"""
			val tags = dnsServers(convert(body)).map { it.getString("tag") }
			assertEquals(tags.toString(), tags.size, tags.toSet().size)
			assertEquals(tags.toString(), 2, tags.count { it == stem || it.startsWith("$stem-") })
		}
	}
}
