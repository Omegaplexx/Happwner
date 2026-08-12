package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Routing and DNS, as the core will actually run them.
class SingBoxRoutingDnsTest {

    private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

    private fun proxyOutbound() = """
        {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
        "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
        "streamSettings":{"network":"tcp","security":"tls",
        "tlsSettings":{"serverName":"a.example.com"}}}
    """.trimIndent().replace("\n", "")

    private fun convert(body: String): JSONObject {
        val out = LinkConverter.convert(body, jsonToUri = false, base64Result = false, xrayToSb = true)
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

    // ------------------------------------------------------------- DNS ----

    @Test
    fun `an HTTP3 DNS server is spelled the way the core spells it`() {
        // The core knows this transport as "h3" and answers "http3" with "unknown transport type",
        // which refuses the whole document: one such server cost the entire configuration.
        val cfg = convert(
            """{"dns":{"servers":["h3://1.1.1.1/dns-query"]},"outbounds":[${proxyOutbound()}]}"""
        )
        val h3 = dnsServers(cfg).filter { it.optString("type") !in setOf("local", "hosts", "fakeip") }
        assertTrue("no DNS server was emitted: $cfg", h3.isNotEmpty())
        assertEquals("h3", h3.first().optString("type"))
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
        val s = dnsServers(cfg).first { it.optString("type") == "udp" }
        // domain_strategy on a new-format server is the dial field that resolves the server's own
        // name (it replaced address_strategy), not the query strategy, so it is not written here.
        assertFalse("domain_strategy is the wrong field for queryStrategy: $s", s.has("domain_strategy"))
        assertFalse("the rejected field must not appear", s.has("strategy"))
    }

    @Test
    fun `a fakedns-only configuration does not make fakeip the default server`() {
        // "default server cannot be fakeip": the core refuses to start with one there, and a
        // configuration whose only DNS entry is fakedns landed exactly on it.
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

    // --------------------------------------------------------- routing ----

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
        // "geoip:!cn" used to become a rule-set tagged geoip-!cn, and the URL built from that tag
        // is a 404: the document passes every check and then has nothing to match against once it
        // runs.
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
        val flat = rule.toString()
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
        val flat = rule.toString()
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
            val rs = it.optJSONArray("rule_set") ?: return@indexOfFirst false
            (0 until rs.length()).any { i -> rs.optString(i).startsWith("geoip-") }
        }
        assertTrue("no geoip rule-set rule: $rules", geoAt >= 0)
        assertTrue("the resolve must precede the geoip rule: $rules",
            resolveAt in 0 until geoAt)
    }
}
