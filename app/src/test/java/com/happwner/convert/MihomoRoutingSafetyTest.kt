package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// A rule list is read top to bottom and the first match wins, so a rule that reaches more traffic
// than the source meant does not merely differ - it takes everything below it out of the file.
class MihomoRoutingSafetyTest {

	private fun rules(vararg configs: String): List<String> {
		val body = configs.joinToString(",", "[", "]")
		val result = MihomoConverter.convert(body.replace("\n", " "))
		assertTrue("refused: $result", result is MihomoConverter.Result.Ok)
		return (result as MihomoConverter.Result.Ok).yaml.substringAfter("\nrules:").trim()
			.lines().map { it.trim().removePrefix("- ").trim('\'') }
	}

	private fun config(name: String, rules: String) = """
        {"remarks":"$name","outbounds":[
          {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
          {"protocol":"blackhole","tag":"BLOCK"},{"protocol":"freedom","tag":"DIRECT"}],
         "routing":{"rules":[$rules]}}
	""".trimIndent()

	// A rule whose only condition is the protocol, which mihomo has no rule for: dropping the
	// condition and keeping the target would reject everything.
	@Test
	fun `a rule that only matches on protocol never becomes a catch-all`() {
		val out = rules(config("N", """{"protocol":["bittorrent"],"outboundTag":"BLOCK"}"""))
		assertFalse("everything was rejected: $out", out.contains("MATCH,REJECT"))
		assertEquals("MATCH,PROXY", out.last())
	}

	// The same applies when the condition is only narrowed rather than lost entirely.
	@Test
	fun `a rule keeps only the traffic its conditions describe`() {
		val out = rules(
			config("N", """{"domain":["ads.example.com"],"protocol":["bittorrent"],"outboundTag":"BLOCK"}""")
		)
		assertFalse("the domain rule was widened past its protocol: $out",
			out.any { it.startsWith("DOMAIN") && it.endsWith("REJECT") })
	}

	// Losing one alternative inside a condition only makes a rule match less, which is safe, and
	// the rest of the condition still stands.
	@Test
	fun `an entry mihomo cannot read is dropped without taking the rule with it`() {
		val out = rules(config("N",
			"""{"domain":["ext:geoip.dat:cn","full:ok.example.com"],"outboundTag":"BLOCK"}"""))
		assertTrue(out.toString(), out.any { it.contains("DOMAIN,ok.example.com") && it.endsWith("REJECT") })
	}

	// One configuration's "everything else through me" is true of that configuration alone. Held
	// beside others it would route every connection through the first one's servers, whatever the
	// person picked, and nothing below it would ever be read.
	@Test
	fun `one configuration does not route for all the others`() {
		val out = rules(
			config("First",
				"""{"domain":["x.example.com"],"outboundTag":"DIRECT"},{"network":"tcp,udp",
                     "outboundTag":"proxy"}"""),
			config("Second", """{"network":"tcp,udp","outboundTag":"proxy"}""")
		)
		assertEquals("the only catch-all is the one into the selector", 1,
			out.count { it.startsWith("MATCH,") })
		assertEquals("MATCH,PROXY", out.last())
		assertTrue("the conditional rule still stands: $out", out.any { it.contains("x.example.com") })
	}

	// With a single configuration its catch-all is exactly what it says, and it stays.
	@Test
	fun `a single configuration keeps its own catch-all`() {
		val out = rules(config("Only", """{"network":"tcp,udp","outboundTag":"proxy"}"""))
		assertTrue(out.toString(), out.any { it.startsWith("MATCH,") && it != "MATCH,PROXY" })
	}

	// A resolver that answers differently from the one the configuration asked for is not a visible
	// failure, which is exactly why what could not be carried has to be said.
	@Test
	fun `dns settings mihomo has no place for are named`() {
		val body = """
			[{"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
			  {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
			  "streamSettings":{"network":"tcp"}}],
			  "dns":{"servers":["8.8.8.8"],"disableCache":true,"disableFallback":true}}]
		""".trimIndent().replace("\n", " ")
		val result = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
		val notes = result.notes.joinToString("\n")
		assertTrue(notes, notes.contains("disableCache"))
		// disableFallback has a place: the first server, the one Xray asks alone, is the whole list
		assertFalse(notes, notes.contains("disableFallback"))
		// and the resolver it could carry is still there
		assertTrue(result.yaml, result.yaml.contains("nameserver: [8.8.8.8]"))
	}

	// The sing-box pass reads the same rules: a rule that keeps its action and loses what narrowed
	// it matches every connection there is.
	@Test
	fun `sing-box drops a rule that lost its condition instead of widening it`() {
		fun route(rule: String): List<JSONObject> {
			val body = """
                {"remarks":"N","outbounds":[
                  {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
                    "port":443,"users":[{"id":"u",
                      "encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
                  {"protocol":"blackhole","tag":"BLOCK"},{"protocol":"freedom","tag":"DIRECT"}],
                 "routing":{"rules":[$rule]}}
			""".trimIndent().replace("\n", " ")
			val result = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
			val rules = result.config.getJSONObject("route").getJSONArray("rules")
			return (0 until rules.length()).map { rules.getJSONObject(it) }
		}
		// Its only condition was one sing-box cannot state, so the rule is gone rather than
		// rejecting everything.
		assertFalse(
			route("""{"attrs":{":method":"GET"},"outboundTag":"BLOCK"}""").toString(),
			route("""{"attrs":{":method":"GET"},"outboundTag":"BLOCK"}""")
				.any { it.optString("action") == "reject" }
		)
		// A pattern the core cannot read, as the only condition, likewise.
		assertFalse(
			route("""{"domain":["regexp:((("],"outboundTag":"BLOCK"}""").toString(),
			route("""{"domain":["regexp:((("],"outboundTag":"BLOCK"}""")
				.any { it.optString("action") == "reject" }
		)
		// But a rule that genuinely stated no condition is Xray's way of writing "everything".
		assertTrue(
			route("""{"outboundTag":"BLOCK"}""").any { it.optString("action") == "reject" }
		)
		// And what the core can read still stands beside what it cannot.
		assertTrue(
			route("""{"domain":["regexp:(((","full:ok.example.com"],"outboundTag":"BLOCK"}""")
				.any { it.optJSONArray("domain")?.toString()?.contains("ok.example.com") == true }
		)
	}

	// sing-box refuses a whole file over a rule naming an outbound it does not hold, so the
	// subscription would not start at all.
	@Test
	fun `sing-box drops a rule naming an outbound the document does not hold`() {
		val body = """
			{"remarks":"N","outbounds":[
			  {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
			    "port":443,"users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}],
			 "routing":{"rules":[{"domain":["ex.com"],"outboundTag":"nosuch"}]}}
		""".trimIndent().replace("\n", " ")
		val result = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		val outs = result.config.getJSONArray("outbounds")
		val tags = (0 until outs.length()).map { outs.getJSONObject(it).optString("tag") }
		val rules = result.config.getJSONObject("route").getJSONArray("rules")
		for (i in 0 until rules.length()) {
			val ref = rules.getJSONObject(i).optString("outbound")
			assertTrue("rule $i points at $ref, which is not in $tags", ref.isEmpty() || ref in tags)
		}
		assertTrue(result.notes.toString(), result.notes.any { it.contains("nosuch") })
	}

	// Each configuration's rules name its own nodes, so together they say where each wants its
	// traffic, and every configuration's rules are kept.
	@Test
	fun `every configuration's rules reach the document, each of them once`() {
		fun cfg(name: String, dom: String) = """
            {"remarks":"$name","outbounds":[
              {"protocol":"vless","tag":"proxy",
               "settings":{"vnext":[{"address":"${name.lowercase()}.example.com",
                "port":443,"users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
              {"protocol":"freedom","tag":"DIRECT"}],
             "routing":{"rules":[{"domain":["$dom"],"outboundTag":"DIRECT"},
               {"domain":["shared.example.com"],"outboundTag":"DIRECT"},
               {"network":"tcp,udp","outboundTag":"proxy"}]}}
		""".trimIndent()
		val out = rules(cfg("A", "only-a.com"), cfg("B", "only-b.com"), cfg("C", "only-c.com"))

		for (domain in listOf("only-a.com", "only-b.com", "only-c.com")) {
			assertTrue("$domain was thrown away: $out", out.any { it.contains(domain) })
		}
		// The rule all three share is read once, not three times.
		assertEquals(1, out.count { it.contains("shared.example.com") })
		// And their catch-alls are gone, so the selector still chooses.
		assertEquals(1, out.count { it.startsWith("MATCH,") })
		assertEquals("MATCH,PROXY", out.last())
	}

	// The sing-box pass merges them too, and repeats none of them.
	@Test
	fun `sing-box keeps one copy of a rule several configurations share`() {
		fun cfg(name: String) = """
            {"remarks":"$name","outbounds":[
              {"protocol":"vless","tag":"proxy",
               "settings":{"vnext":[{"address":"${name.lowercase()}.example.com",
                "port":443,"users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
              {"protocol":"freedom","tag":"DIRECT"}],
             "routing":{"rules":[{"domain":["shared.example.com"],"outboundTag":"DIRECT"}]}}
		""".trimIndent()
		val body = listOf(cfg("A"), cfg("B"), cfg("C")).joinToString(",", "[", "]").replace("\n", " ")
		val doc = JSONObject(SubscriptionConverter.convert(body, jsonToUri = false, xrayToSingBox = true))
		val rules = doc.getJSONObject("route").getJSONArray("rules")
		val texts = (0 until rules.length()).map { rules.getJSONObject(it).toString() }
		assertEquals("a rule was written more than once: $texts", texts.size, texts.toSet().size)
		assertEquals(1, texts.count { it.contains("shared.example.com") })
	}

	// Two configurations can want opposite things: one routes a site around the proxy, the other
	// through it. One rule list cannot hold both, so the first decides, the second is left out
	// rather than sitting in the file unreachable, and the person is told they disagree.
	@Test
	fun `configurations that disagree are resolved by the first, and said so`() {
		fun cfg(name: String, target: String) = """
            {"remarks":"$name","outbounds":[
              {"protocol":"vless","tag":"proxy",
               "settings":{"vnext":[{"address":"${name.lowercase()}.example.com",
                "port":443,"users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
              {"protocol":"freedom","tag":"DIRECT"}],
             "routing":{"rules":[{"domain":["vk.com"],"outboundTag":"$target"},
               {"network":"tcp,udp","outboundTag":"proxy"}]}}
		""".trimIndent()
		val body = listOf(cfg("Bypass", "DIRECT"), cfg("Plain", "proxy"))
			.joinToString(",", "[", "]").replace("\n", " ")

		val mihomo = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true)
		val rules = mihomo.text.substringAfter("\nrules:").trim().lines()
			.map { it.trim().removePrefix("- ").trim('\'') }
		assertEquals("one decision for vk.com, not two: $rules", 1, rules.count { it.contains("vk.com") })
		assertTrue(rules.toString(), rules.first().contains("vk.com") && rules.first().endsWith("DIRECT"))
		assertTrue(
			mihomo.notes.toString(),
			mihomo.notes.any { it.contains("same traffic to different places") }
		)

		val singBox = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true)
		val route = JSONObject(singBox.text).getJSONObject("route").getJSONArray("rules")
		val texts = (0 until route.length()).map { route.getJSONObject(it).toString() }
		assertEquals("one decision for vk.com, not two: $texts", 1, texts.count { it.contains("vk.com") })
		assertTrue(singBox.notes.toString(),
			singBox.notes.any { it.contains("same traffic to different places") })
		// and neither configuration's closing rule pins everything to its own servers
		assertTrue(
			"a rule for everything else survived: $texts",
			texts.none { it.contains("\"network\":[\"tcp\",\"udp\"]") && it.contains("outbound") }
		)
	}

	// A stated condition that produced nothing a core can say takes the rule with it, in both passes:
	// kept, the rule would reach traffic the source never routed here. Losing some alternatives narrows.
	@Test
	fun `a condition that produced nothing takes the rule with it, in both passes`() {
		fun body(rule: String) = """
            {"remarks":"N","outbounds":[
              {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com","port":443,
                "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
              {"protocol":"freedom","tag":"DIRECT"}],
             "routing":{"rules":[$rule]}}
		""".trimIndent().replace("\n", " ")
		fun mihomoYaml(body: String): String = (MihomoConverter.convert(
			body) as MihomoConverter.Result.Ok).yaml
		fun singBoxRules(body: String): List<String> {
			val arr = (SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok)
				.config.getJSONObject("route").getJSONArray("rules")
			return (0 until arr.length()).map { jsonText(arr.getJSONObject(it)) }
				.filter { it.contains("outbound") }
		}

		// The domain condition names nothing a core can read; the ip one alone would be wider.
		val widened = body("""{"domain":["ext:x.dat:cn"],"ip":["203.0.113.0/24"],"outboundTag":"DIRECT"}""")
		assertFalse(mihomoYaml(widened), mihomoYaml(widened).contains("203.0.113.0/24,DIRECT"))
		assertTrue(singBoxRules(widened).toString(),
			singBoxRules(widened).none { it.contains("203.0.113.0/24") })

		// Part of the domain condition is readable: the rule narrows to that part and stays.
		val narrowed = body(
			"""{"domain":["ext:x.dat:cn","full:ok.com"],"ip":["203.0.113.0/24"],"outboundTag":"DIRECT"}""")
		assertTrue(mihomoYaml(narrowed),
			mihomoYaml(narrowed).contains("AND,((DOMAIN,ok.com),(IP-CIDR,203.0.113.0/24"))
		assertTrue(singBoxRules(narrowed).toString(),
			singBoxRules(narrowed).any { it.contains("ok.com") && it.contains("203.0.113.0/24") })
	}

	// A resolver is written the way mihomo reads one: an IPv6 address keeps its port, and is
	// bracketed wherever a port follows it or a scheme precedes it; a keyword condition has no
	// nameserver-policy form and is named rather than turned into a suffix that matches nothing.
	@Test
	fun `dns resolvers keep their ports and their brackets`() {
		fun dnsBlock(servers: String): String {
			val body = """
                {"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
                {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
                "streamSettings":{"network":"tcp"}}],"dns":{"servers":[$servers]}}
			""".trimIndent().replace("\n", " ")
			return (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).yaml
				.substringAfter("\ndns:").substringBefore("\nproxies:")
		}
		assertTrue(dnsBlock("""{"address":"2001:4860:4860::8888","port":5353}""").contains(
			"[2001:4860:4860::8888]:5353"))
		assertTrue(dnsBlock("\"tcp://[2001:4860:4860::8888]:5353\"").contains(
			"tcp://[2001:4860:4860::8888]:5353"))
		// bare, it stands as it is - mihomo reads that
		assertTrue(dnsBlock("\"2001:4860:4860::8888\"").contains("nameserver: [2001:4860:4860::8888]"))
		assertFalse(dnsBlock("""{"address":"8.8.8.8","domains":["keyword:goog"]}""").contains("keyword"))
	}

	// Xray and sing-box run Go's RE2 and mihomo an engine of its own: a pattern using what RE2
	// lacks compiles here and is refused with the whole file, so it goes; what RE2 reads,
	// "(?P<name>...)" included, is carried in the spelling each core reads.
	@Test
	fun `a pattern outside RE2 is left out, one inside it is carried`() {
		fun rules(pattern: String): Pair<String, String> {
			val body = """
                {"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
                {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
                "streamSettings":{"network":"tcp"}},{"protocol":"freedom","tag":"DIRECT"}],
                "routing":{"rules":[{"domain":["regexp:$pattern"],"outboundTag":"DIRECT"}]}}
			""".trimIndent().replace("\n", " ")
			val singBox = JSONObject(SubscriptionConverter.convert(body, jsonToUri = false,
				xrayToSingBox = true))
				.getJSONObject("route").getJSONArray("rules").toString()
			return singBox to SubscriptionConverter.convert(body, jsonToUri = false, xrayToMihomo = true)
		}
		for (bad in listOf("^(?!ads).*", "^(a)\\\\1$", "(?>ab)c", "a++b")) {
			val (singBox, mihomo) = rules(bad)
			assertFalse("$bad reached sing-box", singBox.contains("domain_regex"))
			assertFalse("$bad reached mihomo", mihomo.contains("DOMAIN-REGEX"))
		}
		for (fine in listOf("^.*\\\\.example\\\\.com$", "(?i)google", "(?P<host>ab)+")) {
			val (singBox, mihomo) = rules(fine)
			assertTrue("$fine was refused by sing-box", singBox.contains("domain_regex"))
			assertTrue("$fine was refused by mihomo", mihomo.contains("DOMAIN-REGEX"))
		}
	}

	// A rule names either an outbound or a balancer. When it names both, Xray takes the outbound
	// and ignores the balancer - its documentation says so in as many words - and both passes read
	// it the same way.
	@Test
	fun `a rule naming both an outbound and a balancer goes to the outbound`() {
		val body = """
			{"remarks":"R","outbounds":[
			  {"protocol":"vless","tag":"p1","settings":{"vnext":[{"address":"a.example.com","port":443,
			    "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
			  {"protocol":"vless","tag":"p2","settings":{"vnext":[{"address":"b.example.com","port":443,
			    "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
			  {"protocol":"freedom","tag":"DIRECT"}],
			 "routing":{"rules":[{"domain":["x.com"],"outboundTag":"DIRECT","balancerTag":"bal"}],
			            "balancers":[{"tag":"bal","selector":["p"]}]}}
		""".trimIndent().replace("\n", " ")
		val singBox = (SingBoxConverter.convert(body, "R") as SingBoxConverter.Result.Ok).config
		val rules = singBox.getJSONObject("route").getJSONArray("rules")
		val forX = (0 until rules.length()).map { rules.getJSONObject(
			it) }.first { it.toString().contains("x.com") }
		assertEquals("DIRECT", forX.optString("outbound"))
		val mihomo = (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).yaml
		assertTrue(mihomo, Regex("x\\.com,DIRECT").containsMatchIn(mihomo))
	}
}
