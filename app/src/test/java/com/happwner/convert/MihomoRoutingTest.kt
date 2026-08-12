package com.happwner.convert

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Routing and DNS carried into mihomo.
class MihomoRoutingTest {

    private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

    private fun convert(routing: String, dns: String = ""): String {
        val dnsPart = if (dns.isEmpty()) "" else ""","dns":$dns"""
        val body = """
            {"outbounds":[
              {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
               "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
               "streamSettings":{"network":"tcp","security":"tls",
               "tlsSettings":{"serverName":"a.example.com"}}},
              {"protocol":"freedom","tag":"direct"},
              {"protocol":"blackhole","tag":"block"}],
             "routing":$routing$dnsPart}
        """.trimIndent().replace("\n", "")
        return LinkConverter.convert(body, jsonToUri = false, base64Result = false,
            xrayToSb = false, xrayToMihomo = true)
    }

    private fun rulesOf(yaml: String): List<String> =
        yaml.substringAfter("\nrules:").lines()
            .map { it.trim() }.filter { it.startsWith("- ") }.map { it.removePrefix("- ") }

    @Test
    fun `the domain forms each become their own rule type`() {
        val y = convert(
            """{"rules":[{"type":"field","domain":["full:a.test","domain:b.test",
               "regexp:^c.*$","geosite:google","keyword"],"outboundTag":"direct"}]}"""
                .trimIndent().replace("\n", "")
        )
        val r = rulesOf(y).first()
        assertTrue("exact name: $r", r.contains("DOMAIN,a.test"))
        assertTrue("suffix: $r", r.contains("DOMAIN-SUFFIX,b.test"))
        assertTrue("regex: $r", r.contains("DOMAIN-REGEX,^c.*$"))
        assertTrue("geosite: $r", r.contains("GEOSITE,google"))
        assertTrue("a bare entry matches anywhere in the name: $r",
            r.contains("DOMAIN-KEYWORD,keyword"))
        assertTrue("alternatives are a disjunction: $r", r.startsWith("OR,(("))
    }

    @Test
    fun `two conditions in one rule mean both`() {
        val y = convert(
            """{"rules":[{"type":"field","domain":["full:a.test"],"port":"443",
               "outboundTag":"direct"}]}"""
        )
        val r = rulesOf(y).first()
        assertTrue("expected a conjunction: $r", r.startsWith("AND,(("))
        assertTrue(r.contains("DOMAIN,a.test"))
        assertTrue(r.contains("DST-PORT,443"))
        assertTrue("and it still names its target: $r", r.endsWith(",DIRECT"))
    }

    @Test
    fun `a modifier is written after the target`() {
        // "IP-CIDR,cidr,no-resolve,DIRECT" reads as a rule pointing at a proxy
        // called no-resolve, and mihomo refuses the whole file over it.
        val y = convert(
            """{"domainStrategy":"AsIs","rules":[{"type":"field","ip":["127.0.0.0/8"],
               "outboundTag":"direct"}]}"""
        )
        val r = rulesOf(y).first()
        assertTrue("expected the modifier last: $r", r == "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
    }

    @Test
    fun `a resolving strategy leaves the modifier off`() {
        val y = convert(
            """{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","ip":["127.0.0.0/8"],
               "outboundTag":"direct"}]}"""
        )
        assertFalse("this strategy asks for resolution: ${rulesOf(y).first()}",
            rulesOf(y).first().contains("no-resolve"))
    }

    @Test
    fun `a negated country is written as a negation`() {
        val y = convert(
            """{"rules":[{"type":"field","ip":["geoip:!cn"],"outboundTag":"direct"}]}"""
        )
        val r = rulesOf(y).first()
        assertTrue("expected NOT around the positive set: $r", r.startsWith("NOT,((GEOIP,cn"))
    }

    @Test
    fun `blackhole and freedom become the builtin targets`() {
        val y = convert(
            """{"rules":[{"type":"field","domain":["full:a.test"],"outboundTag":"block"},
               {"type":"field","domain":["full:b.test"],"outboundTag":"direct"}]}"""
                .trimIndent().replace("\n", "")
        )
        val r = rulesOf(y)
        assertTrue("a blackhole is a rejection: $r", r.any { it == "DOMAIN,a.test,REJECT" })
        assertTrue("freedom is direct: $r", r.any { it == "DOMAIN,b.test,DIRECT" })
    }

    @Test
    fun `nothing of ours is placed ahead of the source's own rules`() {
        // The default set starts with the private ranges, which is right for a configuration that
        // says nothing about routing.
        val y = convert(
            """{"rules":[{"type":"field","domain":["full:a.test"],"outboundTag":"block"}]}"""
        )
        val r = rulesOf(y)
        assertTrue("the source's rule comes first: $r", r.first().startsWith("DOMAIN,a.test"))
        assertTrue("and MATCH closes the list: $r", r.last().startsWith("MATCH,"))
    }

    @Test
    fun `the DNS servers and their domains cross over`() {
        val y = convert(
            """{"rules":[]}""",
            """{"servers":["8.8.8.8",{"address":"https://1.1.1.1/dns-query",
               "domains":["domain:a.test","full:b.test","geosite:google"]}],
               "queryStrategy":"UseIPv4","hosts":{"pinned.test":"9.9.9.9"}}"""
                .trimIndent().replace("\n", "")
        )
        assertTrue("the plain server is a nameserver: $y", y.contains("nameserver: [8.8.8.8]"))
        assertTrue("a server with domains becomes a policy: $y", y.contains("nameserver-policy:"))
        assertTrue("suffix form: $y", y.contains("+.a.test:"))
        assertTrue("exact form: $y", y.contains("b.test:"))
        assertTrue("geosite passes through: $y", y.contains("geosite:google:"))
        assertTrue("UseIPv4 turns IPv6 off: $y", y.contains("ipv6: false"))
        assertTrue("hosts carry over: $y", y.contains("pinned.test: 9.9.9.9"))
    }

    @Test
    fun `fakedns turns on fake-ip with the pool it named`() {
        val y = convert(
            """{"rules":[]}""",
            """{"servers":["fakedns","8.8.8.8"]}"""
        )
        assertTrue("expected fake-ip: $y", y.contains("enhanced-mode: fake-ip"))
    }

    @Test
    fun `a configuration with no routing keeps the default set`() {
        val body = """
            {"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
             "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls",
             "tlsSettings":{"serverName":"a.example.com"}}}]}
        """.trimIndent().replace("\n", "")
        val y = LinkConverter.convert(body, jsonToUri = false, base64Result = false,
            xrayToSb = false, xrayToMihomo = true)
        assertTrue("the default set leaves the local network alone: $y",
            y.contains("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"))
    }
}
