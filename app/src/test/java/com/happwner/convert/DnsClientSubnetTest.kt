package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Xray's DNS clientIP: sing-box has client_subnet on dns and dns.rules[] and nowhere else, and answers
// it on a server with `unknown field` - refusing the whole document. Measured against 1.13.15.
class DnsClientSubnetTest {

    private fun xray(dns: String) = """
        {"remarks":"R","outbounds":[
          {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
           "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}},
          {"protocol":"freedom","tag":"direct"}],
         "dns":$dns}
    """.trimIndent().replace("\n", "")

    private fun convert(dns: String): Pair<JSONObject, List<String>> {
        val r = SingBoxConverter.convert(xray(dns), "Node")
        assertTrue("expected a converted config, got $r", r is SingBoxConverter.Result.Ok)
        r as SingBoxConverter.Result.Ok
        return r.config.getJSONObject("dns") to r.notes
    }

    private fun serversOf(dns: JSONObject) =
        (0 until (dns.optJSONArray("servers")?.length() ?: 0))
            .map { dns.getJSONArray("servers").getJSONObject(it) }

    private fun rulesOf(dns: JSONObject) =
        (0 until (dns.optJSONArray("rules")?.length() ?: 0))
            .map { dns.getJSONArray("rules").getJSONObject(it) }

    // ------------------------------------------ what must never be emitted ----

    @Test
    fun `no DNS server ever carries a client subnet`() {
        // The one that broke everything. Both shapes below used to put the field
        // straight onto the server object.
        for (dns in listOf(
            """{"servers":[{"address":"8.8.8.8","clientIP":"1.2.3.4"}]}""",
            """{"servers":[{"address":"8.8.8.8","clientIP":"1.2.3.4","domains":["example.com"]}]}""",
            """{"clientIp":"9.9.9.9","servers":[{"address":"8.8.8.8","clientIP":"1.2.3.4","domains":["a.com"]}]}""",
            """{"servers":[{"address":"https://dns.google/dns-query","clientIP":"1.2.3.4","domains":["geosite:cn"]}]}"""
        )) {
            val (sbDns, _) = convert(dns)
            for (s in serversOf(sbDns)) {
                assertFalse(
                    "a server carries client_subnet, which the core refuses: $s",
                    s.has("client_subnet")
                )
            }
        }
    }

    // --------------------------------------------- where it goes instead ----

    @Test
    fun `a server with domains has its subnet carried by its own rule`() {
        val (sbDns, notes) = convert(
            """{"servers":[{"address":"8.8.8.8","clientIP":"1.2.3.4","domains":["example.com"]},"1.1.1.1"]}"""
        )
        val carrying = rulesOf(sbDns).filter { it.has("client_subnet") }
        assertEquals("exactly one rule should carry it, got $carrying", 1, carrying.size)
        assertEquals("1.2.3.4", carrying[0].getString("client_subnet"))
        // And it must be the rule for that server, not some other one.
        assertTrue(
            "the rule must route to the server the clientIP belonged to: ${carrying[0]}",
            carrying[0].optString("server").isNotEmpty()
        )
        assertTrue("nothing was dropped, so there is nothing to report: $notes", notes.isEmpty())
    }

    @Test
    fun `a server without domains reports the drop instead of guessing`() {
        // No rule sends queries to this server, so there is nowhere to scope the subnet to.
        val (sbDns, notes) = convert("""{"servers":[{"address":"8.8.8.8","clientIP":"1.2.3.4"}]}""")
        assertTrue("nothing may carry it", rulesOf(sbDns).none { it.has("client_subnet") })
        assertFalse("and it must not be raised to the document level", sbDns.has("client_subnet"))
        assertTrue(
            "the drop must be reported, notes were $notes",
            notes.any { it.contains("clientIP") && it.contains("client subnet") }
        )
    }

    // ------------------------------------------- the document-level one ----

    @Test
    fun `a global clientIp still becomes the document-level subnet`() {
        // This placement was always correct and must keep working.
        val (sbDns, _) = convert("""{"clientIp":"9.9.9.9","servers":["1.1.1.1"]}""")
        assertEquals("9.9.9.9", sbDns.optString("client_subnet"))
    }

    @Test
    fun `a per-server subnet layers over the global one rather than replacing it`() {
        val (sbDns, _) = convert(
            """{"clientIp":"9.9.9.9","servers":[{"address":"8.8.8.8","clientIP":"1.2.3.4","domains":["a.com"]}]}"""
        )
        assertEquals("the global default must survive", "9.9.9.9", sbDns.optString("client_subnet"))
        val carrying = rulesOf(sbDns).filter { it.has("client_subnet") }
        assertEquals(1, carrying.size)
        assertEquals(
            "the per-server value belongs to its rule, where it takes precedence",
            "1.2.3.4", carrying[0].getString("client_subnet")
        )
    }

    @Test
    fun `a configuration with no clientIP anywhere emits none`() {
        val (sbDns, notes) = convert("""{"servers":["8.8.8.8",{"address":"1.1.1.1","domains":["a.com"]}]}""")
        assertNull(sbDns.opt("client_subnet"))
        assertTrue(rulesOf(sbDns).none { it.has("client_subnet") })
        assertTrue(serversOf(sbDns).none { it.has("client_subnet") })
        assertTrue("nothing to report: $notes", notes.none { it.contains("clientIP") })
    }

    @Test
    fun `several servers keep their subnets apart`() {
        val (sbDns, _) = convert(
            """{"servers":[
                 {"address":"8.8.8.8","clientIP":"1.1.1.1","domains":["a.com"]},
                 {"address":"9.9.9.9","clientIP":"2.2.2.2","domains":["b.com"]}]}"""
                .trimIndent().replace("\n", "")
        )
        val byServer = rulesOf(sbDns)
            .filter { it.has("client_subnet") }
            .associate { it.getString("server") to it.getString("client_subnet") }
        assertEquals("each server should keep its own: $byServer", 2, byServer.size)
        assertEquals(setOf("1.1.1.1", "2.2.2.2"), byServer.values.toSet())
    }
}
