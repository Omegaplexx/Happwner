package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Routing and DNS carried into mihomo.
class MihomoRoutingTest {

	private val uuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"

	private fun convert(routing: String, dns: String = "", fakedns: String = ""): String {
		val dnsPart = if (dns.isEmpty()) "" else ""","dns":$dns"""
		val fakednsPart = if (fakedns.isEmpty()) "" else ""","fakedns":$fakedns"""
		val body = """
            {"outbounds":[
              {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
               "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
               "streamSettings":{"network":"tcp","security":"tls",
               "tlsSettings":{"serverName":"a.example.com"}}},
              {"protocol":"freedom","tag":"direct"},
              {"protocol":"blackhole","tag":"block"}],
             "routing":$routing$dnsPart$fakednsPart}
		""".trimIndent().replace("\n", "")
		return SubscriptionConverter.convert(body, jsonToUri = false, base64Result = false,
			xrayToSingBox = false, xrayToMihomo = true)
	}

	private fun rulesOf(yaml: String): List<String> =
		yaml.substringAfter("\nrules:").lines()
			.map { it.trim() }.filter { it.startsWith("- ") }.map { it.removePrefix("- ") }

	// What an Xray inbound was told to sniff becomes mihomo's sniffer: the same protocols on every
	// port, the destination rewritten only where Xray would rewrite it, and the names the person
	// kept out of sniffing kept out here too. No inbound asking means no sniffer, as in mihomo.
	@Test
	fun `the sniffer follows what the inbound asked for`() {
		fun document(sniffing: String?): String {
			val inbound =
				if (sniffing == null) """{"tag":"in","port":10808,"protocol":"socks","settings":{}}"""
				else """{"tag":"in","port":10808,"protocol":"socks","settings":{},"sniffing":$sniffing}"""
			val body = """
                {"remarks":"N","inbounds":[$inbound],"outbounds":[{"protocol":"vless","tag":"proxy",
                 "settings":{"vnext":[{"address":"a.example.com","port":443,
                  "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}]}
			""".trimIndent().replace("\n", " ")
			return SubscriptionConverter.convert(body, jsonToUri = false, xrayToMihomo = true)
		}
		assertFalse(document(null).contains("sniffer:"))
		assertFalse(document("""{"enabled":false}""").contains("sniffer:"))

		val full = document("""{"enabled":true,"destOverride":["http","tls","quic"],
            "domainsExcluded":["courier.push.apple.com"]}""")
		assertTrue(full, full.contains("override-destination: true"))
		for (protocol in listOf("HTTP", "TLS", "QUIC")) assertTrue(full, full.contains("$protocol:"))
		assertTrue(full, full.contains("ports: [1-65535]"))
		assertTrue(full, full.contains("skip-domain: [courier.push.apple.com]"))

		val routeOnly = document("""{"enabled":true,"destOverride":["tls"],"routeOnly":true}""")
		assertTrue(routeOnly, routeOnly.contains("override-destination: false"))
		assertFalse(routeOnly, routeOnly.contains("HTTP:"))
	}

	@Test
	fun `the domain forms each become their own rule type`() {
		val yaml = convert(
			"""{"rules":[{"type":"field","domain":["full:a.test","domain:b.test",
               "regexp:^c.*$","geosite:google","keyword"],"outboundTag":"direct"}]}"""
				.trimIndent().replace("\n", "")
		)
		val rule = rulesOf(yaml).first()
		assertTrue("exact name: $rule", rule.contains("DOMAIN,a.test"))
		assertTrue("suffix: $rule", rule.contains("DOMAIN-SUFFIX,b.test"))
		assertTrue("regex: $rule", rule.contains("DOMAIN-REGEX,^c.*$"))
		assertTrue("geosite: $rule", rule.contains("GEOSITE,google"))
		assertTrue("a bare entry matches anywhere in the name: $rule",
			rule.contains("DOMAIN-KEYWORD,keyword"))
		assertTrue("alternatives are a disjunction: $rule", rule.startsWith("OR,(("))
	}

	@Test
	fun `two conditions in one rule mean both`() {
		val yaml = convert(
			"""{"rules":[{"type":"field","domain":["full:a.test"],"port":"443",
               "outboundTag":"direct"}]}"""
		)
		val rule = rulesOf(yaml).first()
		assertTrue("expected a conjunction: $rule", rule.startsWith("AND,(("))
		assertTrue(rule.contains("DOMAIN,a.test"))
		assertTrue(rule.contains("DST-PORT,443"))
		assertTrue("and it still names its target: $rule", rule.endsWith(",DIRECT"))
	}

	@Test
	fun `a modifier is written after the target`() {
		// "IP-CIDR,cidr,no-resolve,DIRECT" reads as a rule pointing at a proxy
		// called no-resolve, and mihomo refuses the whole file over it.
		val yaml = convert(
			"""{"domainStrategy":"AsIs","rules":[{"type":"field","ip":["127.0.0.0/8"],
               "outboundTag":"direct"}]}"""
		)
		val rule = rulesOf(yaml).first()
		assertTrue("expected the modifier last: $rule", rule == "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
	}

	@Test
	fun `a resolving strategy leaves the modifier off`() {
		val yaml = convert(
			"""{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","ip":["127.0.0.0/8"],
               "outboundTag":"direct"}]}"""
		)
		assertFalse("this strategy asks for resolution: ${rulesOf(yaml).first()}",
			rulesOf(yaml).first().contains("no-resolve"))
	}

	@Test
	fun `a negated country is a negation held to known addresses`() {
		// Unresolved, a name would pass the negation as an address outside the set (measured).
		val yaml = convert(
			"""{"rules":[{"type":"field","ip":["geoip:!cn"],"outboundTag":"direct"}]}"""
		)
		val rule = rulesOf(yaml).first()
		val known = "AND,((OR,((IP-CIDR,0.0.0.0/0,no-resolve),(IP-CIDR6,::/0,no-resolve)))"
		assertTrue(rule, rule.startsWith(known))
		assertTrue(rule, "(NOT,((GEOIP,cn,no-resolve)))" in rule)
	}

	@Test
	fun `not-private is written as a negation like any other`() {
		// mihomo answers "private" from its own table, so the negation needs no country data; a
		// source always has its address, so only the destination one is held to known addresses.
		val expectations = listOf(
			"ip" to "(NOT,((GEOIP,private,no-resolve)))", "source" to "NOT,((SRC-GEOIP,private"
		)
		for ((field, expected) in expectations) {
			val yaml = convert(
				"""{"rules":[{"type":"field","$field":["geoip:!private"],"outboundTag":"direct"}]}"""
			)
			val rule = rulesOf(yaml).first()
			assertTrue("expected a negation of private for $field: $rule", expected in rule)
			assertEquals(rule, field == "ip", rule.startsWith("AND,((OR,((IP-CIDR,0.0.0.0/0,no-resolve)"))
		}
	}

	@Test
	fun `blackhole and freedom become the builtin targets`() {
		val yaml = convert(
			"""{"rules":[{"type":"field","domain":["full:a.test"],"outboundTag":"block"},
               {"type":"field","domain":["full:b.test"],"outboundTag":"direct"}]}"""
				.trimIndent().replace("\n", "")
		)
		val rules = rulesOf(yaml)
		assertTrue("a blackhole is a rejection: $rules", rules.any { it == "DOMAIN,a.test,REJECT" })
		assertTrue("freedom is direct: $rules", rules.any { it == "DOMAIN,b.test,DIRECT" })
	}

	@Test
	fun `nothing of ours is placed ahead of the source's own rules`() {
		// The default set starts with the private ranges, which is right for a configuration that
		// says nothing about routing.
		val yaml = convert(
			"""{"rules":[{"type":"field","domain":["full:a.test"],"outboundTag":"block"}]}"""
		)
		val rules = rulesOf(yaml)
		assertTrue("the source's rule comes first: $rules", rules.first().startsWith("DOMAIN,a.test"))
		assertTrue("and MATCH closes the list: $rules", rules.last().startsWith("MATCH,"))
	}

	@Test
	fun `the DNS servers and their domains cross over`() {
		val yaml = convert(
			"""{"rules":[]}""",
			"""{"servers":["8.8.8.8",{"address":"https://1.1.1.1/dns-query",
               "domains":["domain:a.test","full:b.test","geosite:google"]}],
               "queryStrategy":"UseIPv4","hosts":{"pinned.test":"9.9.9.9"}}"""
				.trimIndent().replace("\n", "")
		)
		assertTrue("the plain server is a nameserver: $yaml", yaml.contains("nameserver: [8.8.8.8]"))
		assertTrue("a server with domains becomes a policy: $yaml", yaml.contains("nameserver-policy:"))
		assertTrue("suffix form: $yaml", yaml.contains("+.a.test:"))
		assertTrue("exact form: $yaml", yaml.contains("b.test:"))
		assertTrue("geosite passes through: $yaml", yaml.contains("geosite:google:"))
		assertTrue("UseIPv4 turns IPv6 off: $yaml", yaml.contains("ipv6: false"))
		assertTrue("hosts carry over: $yaml", yaml.contains("pinned.test: 9.9.9.9"))
	}

	@Test
	fun `fakedns turns on fake-ip with the pool it named`() {
		val yaml = convert(
			"""{"rules":[]}""",
			"""{"servers":["fakedns","8.8.8.8"]}"""
		)
		assertTrue("expected fake-ip: $yaml", yaml.contains("enhanced-mode: fake-ip"))
	}

	@Test
	fun `a hosts list keeps its addresses and loses the names mihomo cannot list`() {
		val hosts = """{"a.example":["1.2.3.4","n.example","5.6.7.8"],"b.example":["n1.example","n2.example"],
			"c.example":["9.9.9.9","n.example"]}""".replace("\n", "")
		val yaml = convert("""{"rules":[]}""", """{"servers":["8.8.8.8"],"hosts":$hosts}""")
		assertTrue(yaml, yaml.contains("a.example: [1.2.3.4, 5.6.7.8]"))
		assertTrue(yaml, yaml.contains("c.example: 9.9.9.9"))
		assertTrue(yaml, !yaml.contains("b.example"))
	}

	@Test
	fun `a single hosts value mihomo would refuse is dropped and a name of two labels kept`() {
		// mihomo refuses the whole file over a lone value that is neither an address nor a name of
		// two labels or more.
		val hosts = """{"a.example":"","b.example":"LOCALHOST","c.example":"::zz","d.example":"fe80::1%",
			"e.example":"n.example.com","f.example":"fd00::1","g.example":["01.2.3.4"]}""".replace("\n", "")
		val yaml = convert("""{"rules":[]}""", """{"servers":["8.8.8.8"],"hosts":$hosts}""")
		for (gone in listOf("a.example", "b.example", "c.example", "d.example")) {
			assertTrue(yaml, "  $gone:" !in yaml)
		}
		assertTrue(yaml, yaml.contains("e.example: n.example.com"))
		assertTrue(yaml, yaml.contains("f.example: fd00::1") || yaml.contains("f.example: 'fd00::1'"))
		assertTrue(yaml, yaml.contains("g.example: 01.2.3.4"))
	}

	private fun fakeIpRanges(fakedns: String): List<String> =
		convert("""{"rules":[]}""", """{"servers":["fakedns","8.8.8.8"]}""", fakedns)
			.lines().map { it.trim() }.filter { it.startsWith("fake-ip-range") }

	@Test
	fun `each fakedns pool goes to the fake-ip range of its family`() {
		assertEquals(listOf("fake-ip-range: 198.18.0.0/15"), fakeIpRanges("""{"ipPool":"198.18.0.0/15"}"""))
		// mihomo refuses an IPv6 prefix in fake-ip-range, so an IPv6 pool has a range of its own.
		assertEquals(listOf("fake-ip-range: 198.18.0.1/16", "fake-ip-range6: fc00::/18"),
			fakeIpRanges("""{"ipPool":"fc00::/18"}"""))
		assertEquals(listOf("fake-ip-range: 198.18.0.0/15", "fake-ip-range6: fc00::/18"),
			fakeIpRanges("""[{"ipPool":"fc00::/18"},{"ipPool":"198.18.0.0/15"}]"""))
	}

	@Test
	fun `a fakedns pool mihomo would refuse leaves its range to the default`() {
		// No mask, a zone, a length with a leading zero, a range too small for the gateway and the
		// first address: mihomo refuses the whole document over any of them - fake-ip-range6 too,
		// on a device with IPv6.
		assertEquals(listOf("fake-ip-range: 198.18.0.0/15"),
			fakeIpRanges("""[{"ipPool":"198.18.0.0/15"},{"ipPool":"::1"}]"""))
		assertEquals(listOf("fake-ip-range: 198.18.0.1/16"),
			fakeIpRanges("""[{"poolSize":10},{"ipPool":"1.2.3.4"}]"""))
		assertEquals(listOf("fake-ip-range: 198.18.0.1/16"),
			fakeIpRanges("""{"ipPool":"fe80::%eth0/64"}"""))
		assertEquals(listOf("fake-ip-range: 198.18.0.1/16"),
			fakeIpRanges("""[{"ipPool":"198.18.0.0/30"},{"ipPool":"fc00::/126"}]"""))
		val bounds = """[{"ipPool":"198.18.0.0/08"},{"ipPool":"198.18.0.0/29"},{"ipPool":"fc00::/125"}]"""
		assertEquals(listOf("fake-ip-range: 198.18.0.0/29", "fake-ip-range6: fc00::/125"),
			fakeIpRanges(bounds))
	}

	@Test
	fun `a configuration with no routing keeps the default set`() {
		val body = """
            {"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
             "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls",
             "tlsSettings":{"serverName":"a.example.com"}}}]}
		""".trimIndent().replace("\n", "")
		val yaml = SubscriptionConverter.convert(body, jsonToUri = false, base64Result = false,
			xrayToSingBox = false, xrayToMihomo = true)
		assertTrue("the default set leaves the local network alone: $yaml",
			yaml.contains("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"))
	}

	@Test
	fun `the source is read as the destination is`() {
		val yaml = convert("""{"rules":[{"type":"field","source":["geoip:!cn","1.2.3.4","ext:geoip.dat:x"],
			"outboundTag":"proxy"}]}""".replace("\n", ""))
		val rule = rulesOf(yaml).single { it.contains("SRC-") }
		assertTrue(rule, rule.contains("NOT,((SRC-GEOIP,cn))"))
		assertTrue(rule, rule.contains("SRC-IP-CIDR,1.2.3.4/32"))
		assertFalse(rule, rule.contains("ext:"))
	}

	private fun nameservers(dns: String): String =
		convert("""{"rules":[]}""", dns).lines().first { it.trim().startsWith("nameserver:") }

	@Test
	fun `a server Xray never asks is no nameserver, and the first one it would ask stands in`() {
		// Narrowed to no names and kept out of the order by skipFallback: never asked.
		assertFalse(nameservers("""{"servers":[{"address":"4.2.2.2","skipFallback":true},"8.8.8.8"]}""")
			.contains("4.2.2.2"))
		// Every server narrowed: the first Xray asks about other names answers them, as in sing-box.
		val narrowed = nameservers("""{"servers":[{"address":"1.1.1.1","domains":["domain:a.example"],
			"skipFallback":true},{"address":"9.9.9.9","domains":["domain:b.example"]}]}""".replace("\n", ""))
		assertTrue(narrowed, narrowed.contains("9.9.9.9") && !narrowed.contains("system"))
		assertTrue(nameservers("""{"servers":["localhost"]}""").contains("system"))
	}
}
