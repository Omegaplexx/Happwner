package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// A diagnostic that fires when nothing was set is worse than none: it sends somebody looking for a
// setting they never made. These pin the values that mean "not set" on both converters at once.
class DroppedSettingDiagnosticsTest {

    private fun singbox(xray: String): List<String> {
        val r = SingBoxConverter.convertToOutbounds(xray)
        assertTrue("expected Ok, got $r", r is SingBoxConverter.OutboundsResult.Ok)
        return (r as SingBoxConverter.OutboundsResult.Ok).notes
    }

    private fun mihomo(xray: String): List<String> {
        val r = MihomoConverter.convert(xray)
        assertTrue("expected Ok, got $r", r is MihomoConverter.Result.Ok)
        return (r as MihomoConverter.Result.Ok).notes
    }

    private fun both(xray: String) = singbox(xray) + mihomo(xray)

    private fun cfg(outboundExtra: String, stream: String) = """
        {"remarks":"P","outbounds":[{"tag":"t","protocol":"vless",
         "settings":{"vnext":[{"address":"a.com","port":443,
           "users":[{"id":"u","encryption":"none"}]}]},
         $outboundExtra
         "streamSettings":{$stream}}]}
    """.trimIndent()

    private val plainTcp = "\"network\":\"tcp\",\"security\":\"none\""

    private fun mentioning(notes: List<String>, needle: String) =
        notes.filter { it.contains(needle) }

    // ------------------------------------------------------------------ sendThrough Xray's own
    // default is "0.0.0.0" and "::" is the same thing for IPv6.

    @Test
    fun sendThrough_any_address_is_not_a_binding() {
        for (any in listOf("\"0.0.0.0\"", "\"::\"", "\"  0.0.0.0  \"", "null")) {
            val notes = both(cfg("\"sendThrough\":$any,", plainTcp))
            assertEquals("sendThrough=$any must be silent: $notes", emptyList<String>(), mentioning(notes, "sendThrough"))
        }
    }

    // sing-box has inet4_bind_address for this and carries it; mihomo binds by interface for the
    // whole client, so it has nowhere to put one outbound's address and says so.
    @Test
    fun sendThrough_real_address_is_carried_by_singbox_and_reported_by_mihomo() {
        val xray = cfg("\"sendThrough\":\"192.168.1.5\",", plainTcp)
        assertTrue("sing-box carries it, so it must not report it", mentioning(singbox(xray), "sendThrough").isEmpty())
        assertEquals(1, mentioning(mihomo(xray), "sendThrough").size)
    }

    // Zero and null: an absent field, an explicit JSON null and a zero all mean "not set" in Xray, and
    // org.json returns JSONObject.NULL for the second, so a bare `!= null` reports a setting nobody made.

    @Test
    fun websocket_heartbeat_only_reported_when_set() {
        for (unset in listOf("null", "0")) {
            val notes = both(cfg("", "\"network\":\"ws\",\"security\":\"none\",\"wsSettings\":{\"path\":\"/p\",\"heartbeatPeriod\":$unset}"))
            assertEquals("heartbeatPeriod=$unset must be silent: $notes", emptyList<String>(), mentioning(notes, "heartbeatPeriod"))
        }
        val set = both(cfg("", "\"network\":\"ws\",\"security\":\"none\",\"wsSettings\":{\"path\":\"/p\",\"heartbeatPeriod\":30}"))
        assertEquals(2, mentioning(set, "heartbeatPeriod").size)
    }

    @Test
    fun grpc_initial_windows_size_only_reported_when_set() {
        for (unset in listOf("null", "0")) {
            val notes = both(cfg("", "\"network\":\"grpc\",\"security\":\"none\",\"grpcSettings\":{\"serviceName\":\"s\",\"initial_windows_size\":$unset}"))
            assertEquals("initial_windows_size=$unset must be silent: $notes", emptyList<String>(), mentioning(notes, "initial_windows_size"))
        }
        val set = both(cfg("", "\"network\":\"grpc\",\"security\":\"none\",\"grpcSettings\":{\"serviceName\":\"s\",\"initial_windows_size\":65536}"))
        assertEquals(2, mentioning(set, "initial_windows_size").size)
    }

    @Test
    fun tcp_keepalive_only_reported_when_set() {
        for (unset in listOf("null", "0")) {
            val notes = both(cfg("", "\"network\":\"tcp\",\"security\":\"none\",\"sockopt\":{\"tcpKeepAliveIdle\":$unset}"))
            assertEquals("tcpKeepAliveIdle=$unset must be silent: $notes",
                emptyList<String>(), notes.filter { it.contains("tcpKeepAlive") || it.contains("keepalive") })
        }
        assertEquals(1, mentioning(mihomo(cfg("", "\"network\":\"tcp\",\"security\":\"none\",\"sockopt\":{\"tcpKeepAliveIdle\":30}")), "tcpKeepAlive").size)
    }

    // Xray spells "switch the keepalive off" as a negative value. sing-box carries that as
    // disable_tcp_keep_alive; mihomo has no per-proxy keepalive at all, so it reports the loss.
    @Test
    fun tcp_keepalive_switched_off_is_carried_by_singbox_and_reported_by_mihomo() {
        val xray = cfg("", "\"network\":\"tcp\",\"security\":\"none\",\"sockopt\":{\"tcpKeepAliveIdle\":-1}")
        assertTrue("sing-box should carry the off-switch silently", mentioning(singbox(xray), "keepalive").isEmpty())
        assertEquals(1, mentioning(mihomo(xray), "tcpKeepAlive").size)
    }

    // sing-box gained tcp_keep_alive, tcp_keep_alive_interval and disable_tcp_keep_alive in 1.13,
    // and an unknown field stops a configuration loading, so none of them is written: a 1.12 core
    // has to be able to load what comes out of here.
    @Test
    fun singbox_does_not_write_the_113_only_keepalive_fields() {
        val xray = cfg("", "\"network\":\"tcp\",\"security\":\"none\",\"sockopt\":{\"tcpKeepAliveIdle\":30,\"tcpKeepAliveInterval\":15}")
        val r = SingBoxConverter.convertToOutbounds(xray)
        val out = (r as SingBoxConverter.OutboundsResult.Ok).outbounds.first()
        for (f in listOf("tcp_keep_alive", "tcp_keep_alive_interval", "disable_tcp_keep_alive")) {
            assertFalse("$f is a 1.13 field and must not be written: $out", out.has(f))
        }
        assertEquals(1, mentioning(r.notes, "tcpKeepAlive").size)
    }

    // curve_preferences is a 1.13 field too, for the same reason.
    @Test
    fun singbox_does_not_write_curve_preferences() {
        val xray = cfg("", "\"network\":\"tcp\",\"security\":\"tls\"," +
            "\"tlsSettings\":{\"serverName\":\"a.com\",\"curvePreferences\":[\"X25519\"]}")
        val r = SingBoxConverter.convertToOutbounds(xray)
        val out = (r as SingBoxConverter.OutboundsResult.Ok).outbounds.first()
        assertFalse("curve_preferences is 1.13-only: $out", out.getJSONObject("tls").has("curve_preferences"))
        assertEquals(1, mentioning(r.notes, "curvePreferences").size)
    }

}
