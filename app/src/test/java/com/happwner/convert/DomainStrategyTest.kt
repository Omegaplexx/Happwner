package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Xray's domain strategy in a sing-box document: the outbound-level domain_strategy was deprecated in
// sing-box 1.12.0 and is refused from then on, so domain_resolver takes its place.
class DomainStrategyTest {

    private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

    private fun node(stream: String) =
        """{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,
           "users":[{"id":"$uuid","encryption":"none"}]}]},"streamSettings":$stream}"""
            .trimIndent().replace("\n", "")

    private fun withSockopt(ds: String) = """{"remarks":"D","outbounds":[${
        node("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"},"sockopt":{"domainStrategy":"$ds"}}""")
    }]}"""

    private fun convert(body: String): JSONObject {
        val r = SingBoxConverter.convert(body, "N")
        assertTrue("expected a converted config, got $r", r is SingBoxConverter.Result.Ok)
        return (r as SingBoxConverter.Result.Ok).config
    }

    private fun outboundsOf(cfg: JSONObject): List<JSONObject> =
        cfg.optJSONArray("outbounds")?.let { arr ->
            (0 until arr.length()).map { arr.getJSONObject(it) }
        } ?: emptyList()

    private fun dnsTagsOf(cfg: JSONObject): Set<String> =
        cfg.optJSONObject("dns")?.optJSONArray("servers")?.let { arr ->
            (0 until arr.length()).mapNotNull { arr.getJSONObject(it).optString("tag").ifEmpty { null } }
        }?.toSet() ?: emptySet()

    // ------------------------------------------ what must never be emitted ----

    @Test
    fun `the deprecated field is never written, from either source`() {
        val bodies = listOf(
            withSockopt("UseIPv4"),
            // freedom carries its own copy of the same option, through a
            // different branch, and it was writing the same dead field.
            """{"remarks":"F","outbounds":[${node("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}""")},
               {"protocol":"freedom","tag":"direct","settings":{"domainStrategy":"UseIPv4"}}]}""".trimIndent().replace("\n", "")
        )
        for (body in bodies) {
            for (o in outboundsOf(convert(body))) {
                assertFalse(
                    "an outbound still carries domain_strategy, which the core refuses: $o",
                    o.has("domain_strategy")
                )
            }
        }
    }

    // ------------------------------------------------ what goes in its place ----

    @Test
    fun `every strategy Xray spells becomes the resolver strategy it means`() {
        // The pairs are Xray's names on the left and sing-box's on the right;
        // the core validates the right-hand side and refuses anything else.
        val expected = mapOf(
            "UseIP" to "prefer_ipv4",
            "UseIPv4" to "ipv4_only",
            "UseIPv4v6" to "prefer_ipv4",
            "UseIPv6" to "ipv6_only",
            "UseIPv6v4" to "prefer_ipv6",
            "ForceIPv4" to "ipv4_only",
            "ForceIPv6" to "ipv6_only"
        )
        for ((xray, sb) in expected) {
            val cfg = convert(withSockopt(xray))
            val proxy = outboundsOf(cfg).first { it.optString("type") == "vless" }
            val resolver = proxy.optJSONObject("domain_resolver")
            assertNotNull("no resolver for $xray", resolver)
            assertEquals("strategy for $xray", sb, resolver!!.optString("strategy"))
        }
    }

    @Test
    fun `AsIs asks for nothing and gets nothing`() {
        val proxy = outboundsOf(convert(withSockopt("AsIs"))).first { it.optString("type") == "vless" }
        assertNull("AsIs is not a strategy to carry", proxy.opt("domain_resolver"))
        assertFalse(proxy.has("domain_strategy"))
    }

    @Test
    fun `the resolver names a DNS server the document actually has`() {
        // The core checks this reference and refuses a resolver pointing at a
        // tag it cannot find, so the name has to come from the same document.
        val cfg = convert(withSockopt("UseIPv4"))
        val tags = dnsTagsOf(cfg)
        assertTrue("the document has no DNS servers at all", tags.isNotEmpty())
        for (o in outboundsOf(cfg)) {
            val server = o.optJSONObject("domain_resolver")?.optString("server") ?: continue
            assertTrue("resolver points at $server, which is not among $tags", server in tags)
        }
    }

    @Test
    fun `freedom gets the same treatment as the proxies`() {
        val cfg = convert(
            """{"remarks":"F","outbounds":[${node("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}""")},
               {"protocol":"freedom","tag":"direct","settings":{"domainStrategy":"UseIPv6"}}]}"""
                .trimIndent().replace("\n", "")
        )
        val direct = outboundsOf(cfg).first { it.optString("type") == "direct" }
        assertEquals("ipv6_only", direct.optJSONObject("domain_resolver")?.optString("strategy"))
        assertTrue(direct.optJSONObject("domain_resolver")!!.optString("server") in dnsTagsOf(cfg))
    }

    // ----------------------------------------------- the bare outbounds path ----

    @Test
    fun `bare outbounds carry no resolver, because they have no DNS to point at`() {
        // These outbounds go into somebody else's document, which may have no server by that name -
        // and a resolver naming an absent tag is refused exactly as firmly as the deprecated field
        // was.
        val r = SingBoxConverter.convertToOutbounds(withSockopt("UseIPv4"), "N")
        assertTrue("expected outbounds, got $r", r is SingBoxConverter.OutboundsResult.Ok)
        for (o in (r as SingBoxConverter.OutboundsResult.Ok).outbounds) {
            assertFalse("a bare outbound must not carry a dangling resolver: $o", o.has("domain_resolver"))
            assertFalse("nor the deprecated field: $o", o.has("domain_strategy"))
        }
    }

    @Test
    fun `the rest of sockopt still comes across`() {
        // The strategy moving must not have disturbed its neighbours.
        val cfg = convert("""{"remarks":"S","outbounds":[${
            node("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"},
                 "sockopt":{"domainStrategy":"UseIPv4","tcpFastOpen":true,"tcpKeepAliveInterval":30}}""".trimIndent().replace("\n", ""))
        }]}""")
        val proxy = outboundsOf(cfg).first { it.optString("type") == "vless" }
        assertTrue(proxy.optBoolean("tcp_fast_open"))
        // The keepalive fields arrived in sing-box 1.13 and are reported instead of written.
        assertFalse(proxy.has("tcp_keep_alive_interval"))
        assertEquals("ipv4_only", proxy.optJSONObject("domain_resolver")?.optString("strategy"))
    }

    // ------------------------------------------------ the rest of sockopt ----

    // SO_MARK, SO_BINDTODEVICE and MPTCP.
    @Test
    fun `the kernel-level socket options come across`() {
        val cfg = convert("""{"remarks":"S","outbounds":[${
            node("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"},
                 "sockopt":{"mark":255,"interface":"eth0","tcpMptcp":true}}""".trimIndent().replace("\n", ""))
        }]}""")
        val proxy = outboundsOf(cfg).first { it.optString("type") == "vless" }
        assertEquals(255L, proxy.optLong("routing_mark"))
        assertEquals("eth0", proxy.optString("bind_interface"))
        assertTrue(proxy.optBoolean("tcp_multi_path"))
    }

    @Test
    fun `a value the core would refuse is left out rather than written`() {
        // routing_mark refuses a negative number and tcp_multi_path refuses anything that is not a
        // boolean; either refusal is answered by rejecting the whole document, so neither reaches
        // it.
        val cfg = convert("""{"remarks":"S","outbounds":[${
            node("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"},
                 "sockopt":{"mark":-1,"interface":"","tcpMptcp":1}}""".trimIndent().replace("\n", ""))
        }]}""")
        val proxy = outboundsOf(cfg).first { it.optString("type") == "vless" }
        assertFalse("a negative mark must not be written", proxy.has("routing_mark"))
        assertFalse("an empty interface says nothing", proxy.has("bind_interface"))
        assertFalse("mptcp is a boolean or it is nothing", proxy.has("tcp_multi_path"))
    }

    @Test
    fun `an absent sockopt leaves the outbound clean`() {
        val cfg = convert("""{"remarks":"S","outbounds":[${
            node("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}""")
        }]}""")
        val proxy = outboundsOf(cfg).first { it.optString("type") == "vless" }
        for (k in listOf("routing_mark", "bind_interface", "tcp_multi_path", "domain_resolver", "domain_strategy")) {
            assertFalse("$k appeared out of nowhere", proxy.has(k))
        }
    }
}
