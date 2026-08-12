package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Tests for the inbound, routing and DNS side of the converter. This part had no coverage at all:
// the earlier suites all work on outbounds.
class SingBoxRoutingTest {

    private fun config(xray: String): JSONObject {
        val r = SingBoxConverter.convert(xray, "FB")
        assertTrue("expected Ok, got $r", r is SingBoxConverter.Result.Ok)
        return (r as SingBoxConverter.Result.Ok).config
    }

    private fun inbound(xray: String, index: Int = 0): JSONObject =
        config(xray).optJSONArray("inbounds")?.optJSONObject(index)!!

    private fun proxyOutbound() = """
        {"tag":"p","protocol":"vless",
         "settings":{"vnext":[{"address":"a.com","port":443,
           "users":[{"id":"u","encryption":"none"}]}]},
         "streamSettings":{"network":"tcp","security":"tls"}}
    """.trimIndent()

    // ------------------------------------------------------------- inbounds

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
        // This one used to be copied through with whatever type it arrived
        // as, so a quoted port produced a config sing-box could not load.
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

    // -------------------------------------------------------------- routing

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
            val r = rules.optJSONObject(i) ?: continue
            if (r.has("port") || r.has("port_range")) seen = r
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

    // ------------------------------------------------------------------ dns

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

    // ------------------------------------------------------------------ log

    @Test
    fun `the xray log level is mapped and unknown levels fall back to warn`() {
        val debug = """{"remarks":"L","log":{"loglevel":"debug"},"outbounds":[${proxyOutbound()}]}"""
        assertEquals("debug", config(debug).optJSONObject("log")?.optString("level"))

        val nonsense = """{"remarks":"L","log":{"loglevel":"chatty"},"outbounds":[${proxyOutbound()}]}"""
        assertEquals("warn", config(nonsense).optJSONObject("log")?.optString("level"))
    }
}
