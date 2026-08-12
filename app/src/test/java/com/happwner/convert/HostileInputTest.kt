package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Input nobody meant to write, and what it must not cost.
class HostileInputTest {

    private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

    private fun cfg(rule: String, remarks: String = "N"): String = """
        {"remarks":"$remarks","outbounds":[
          {"protocol":"vless","tag":"prox","settings":{"vnext":[{"address":"a.example.com",
           "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
           "streamSettings":{"network":"tcp","security":"tls",
           "tlsSettings":{"serverName":"a.example.com"}}},
          {"protocol":"freedom","tag":"direct"}],
         "routing":{"rules":[{"type":"field",$rule,"outboundTag":"direct"}]}}
    """.trimIndent().replace("\n", "")

    private fun singbox(body: String) =
        LinkConverter.convert(body, jsonToUri = false, base64Result = false, xrayToSb = true)

    private fun mihomo(body: String) =
        LinkConverter.convert(body, jsonToUri = false, base64Result = false,
            xrayToSb = false, xrayToMihomo = true)

    private fun mihomoRules(y: String): List<String> =
        y.substringAfter("\nrules:").lines().map { it.trim() }
            .filter { it.startsWith("- ") }.map { it.removePrefix("- ") }

    @Test
    fun `a label with a comma cannot break a rule line`() {
        // The name is also the rule's target, and a comma inside it splits the
        // line: mihomo answers "proxy [US] not found" and refuses everything.
        val y = mihomo(cfg("""\"domain\":[\"full:a.test\"]""".replace("\\\"", "\""),
            remarks = "US, Los Angeles"))
        val rule = mihomoRules(y).first { it.startsWith("DOMAIN,") }
        assertEquals("one comma before the target, none inside it",
            2, rule.count { it == ',' })
        assertFalse("no name may carry a comma: $y", y.contains("name: US, "))
    }

    @Test
    fun `an address the core cannot read is dropped, not the rule`() {
        val body = cfg("""\"ip\":[\"10.0.0.0\",\"not-an-address\",\"192.168.0.0/16\"]"""
            .replace("\\\"", "\""))
        val sb = singbox(body)
        assertTrue("the good addresses survive: $sb", sb.contains("192.168.0.0/16"))
        assertTrue("a bare address means one host", sb.contains("10.0.0.0/32"))
        assertFalse("the bad one is gone: $sb", sb.contains("not-an-address"))
        val y = mihomo(body)
        assertTrue(y.contains("IP-CIDR,192.168.0.0/16"))
        assertFalse(y.contains("not-an-address"))
    }

    @Test
    fun `a pattern that will not compile is dropped, not the rule`() {
        val body = cfg("""\"domain\":[\"regexp:(((\",\"full:ok.test\"]""".replace("\\\"", "\""))
        val sb = singbox(body)
        assertTrue("the good name survives: $sb", sb.contains("ok.test"))
        assertFalse("the broken pattern is gone: $sb", sb.contains("((("))
        val y = mihomo(body)
        assertTrue(y.contains("DOMAIN,ok.test"))
        assertFalse(y.contains("((("))
    }

    @Test
    fun `an empty condition value is dropped`() {
        val body = cfg("""\"domain\":[\"full:\",\"domain:\",\"\",\"full:ok.test\"]"""
            .replace("\\\"", "\""))
        val sb = singbox(body)
        assertTrue(sb.contains("ok.test"))
        assertFalse("no empty name condition may be written: $sb",
            sb.contains("\"domain\":[\"\"") || sb.contains("\"domain_suffix\":[\"\""))
        val y = mihomo(body)
        assertFalse("no empty condition in a rule line: $y",
            mihomoRules(y).any { it.startsWith("DOMAIN,,") || it.startsWith("DOMAIN-SUFFIX,,") })
    }

    @Test
    fun `a port outside the range is dropped, the rest of the list survives`() {
        val body = cfg("""\"port\":\"80,abc,443,70000\"""".replace("\\\"", "\""))
        val sb = singbox(body)
        assertTrue("valid ports survive: $sb", sb.contains("80") && sb.contains("443"))
        assertFalse("an impossible port must not be written: $sb", sb.contains("70000"))
        val y = mihomo(body)
        val rule = mihomoRules(y).first { it.startsWith("DST-PORT") }
        assertEquals("DST-PORT,80/443,DIRECT", rule)
    }

    @Test
    fun `an unusable value never leaves an empty rule behind`() {
        // A rule whose every condition was dropped would match everything, so it
        // must not be written at all.
        val body = cfg("""\"ip\":[\"nonsense\"]""".replace("\\\"", "\""))
        val y = mihomo(body)
        assertFalse("no bare target line: ${mihomoRules(y)}",
            mihomoRules(y).any { it == "DIRECT" || it.startsWith("IP-CIDR,,") })
    }

    @Test
    fun `converting the same input twice gives the same answer`() {
        // The mihomo converter now carries routing and DNS across, which means it holds state while
        // it works; state that outlived one conversion would show up as a second run differing from
        // the first.
        val body = cfg("""\"domain\":[\"full:a.test\"]""".replace("\\\"", "\""))
        assertEquals(mihomo(body), mihomo(body))
        assertEquals(singbox(body), singbox(body))
    }
}
