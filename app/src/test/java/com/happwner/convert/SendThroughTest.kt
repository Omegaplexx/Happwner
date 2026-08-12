package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// sendThrough pins an outbound to one local address. On a machine with several addresses that is
// which route the traffic takes, so losing it does not merely drop a setting - it moves the traffic.
class SendThroughTest {

    private fun outbound(sendThrough: String): Pair<JSONObject, List<String>> {
        val xray = """
            {"remarks":"S","outbounds":[{"tag":"t","protocol":"vless",
             "sendThrough":$sendThrough,
             "settings":{"vnext":[{"address":"a.com","port":443,
               "users":[{"id":"u","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"none"}}]}
        """.trimIndent()
        val r = SingBoxConverter.convertToOutbounds(xray)
        assertTrue("expected Ok, got $r", r is SingBoxConverter.OutboundsResult.Ok)
        r as SingBoxConverter.OutboundsResult.Ok
        return r.outbounds.first() to r.notes
    }

    @Test
    fun an_ipv4_address_becomes_inet4_bind_address() {
        val (out, notes) = outbound("\"192.168.1.5\"")
        assertEquals("192.168.1.5", out.optString("inet4_bind_address"))
        assertFalse(out.has("inet6_bind_address"))
        assertTrue("carrying it must not also report it: $notes",
            notes.none { it.contains("sendThrough") })
    }

    @Test
    fun an_ipv6_address_becomes_inet6_bind_address() {
        val (out, _) = outbound("\"2001:db8::1\"")
        assertEquals("2001:db8::1", out.optString("inet6_bind_address"))
        assertFalse(out.has("inet4_bind_address"))
    }

    // Xray's own default binds nothing, and "::" is the same for IPv6, so neither is a setting.
    @Test
    fun the_any_addresses_bind_nothing_and_say_nothing() {
        for (any in listOf("\"0.0.0.0\"", "\"::\"", "null", "\"\"")) {
            val (out, notes) = outbound(any)
            assertFalse("sendThrough=$any must bind nothing", out.has("inet4_bind_address"))
            assertFalse("sendThrough=$any must bind nothing", out.has("inet6_bind_address"))
            assertTrue("sendThrough=$any must be silent: $notes",
                notes.none { it.contains("sendThrough") })
        }
    }

    // The QUIC protocols are built by a different function than the stream ones, and a node binds
    // to its local address whichever builder made it.
    @Test
    fun a_quic_outbound_binds_too() {
        val xray = """
            {"remarks":"Q","outbounds":[{"tag":"h","protocol":"hysteria",
             "sendThrough":"192.168.1.9",
             "settings":{"version":2,"servers":[{"address":"a.com","port":443,"password":"pw"}]},
             "streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.com"}}}]}
        """.trimIndent()
        val r = SingBoxConverter.convertToOutbounds(xray)
        assertTrue("expected Ok, got ${'$'}r", r is SingBoxConverter.OutboundsResult.Ok)
        val out = (r as SingBoxConverter.OutboundsResult.Ok).outbounds.first()
        assertEquals("hysteria2", out.optString("type"))
        assertEquals("192.168.1.9", out.optString("inet4_bind_address"))
    }

    // sing-box binds to an address, not a name, and which address a name resolves to on somebody
    // else's machine is not knowable here.
    @Test
    fun a_name_is_reported_rather_than_guessed() {
        val (out, notes) = outbound("\"lan.example.com\"")
        assertFalse(out.has("inet4_bind_address"))
        assertFalse(out.has("inet6_bind_address"))
        assertEquals(1, notes.count { it.contains("sendThrough") })
    }
}
