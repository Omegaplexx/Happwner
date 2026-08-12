package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Hysteria2, Hysteria v1 and TUIC on the sing-box side: the core implements all three natively, verified
// by asking it for each outbound type, while this branch used to drop them and mihomo mode kept them.
class SingBoxQuicProtocolsTest {

    private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

    private fun cfg(ob: String) = """{"remarks":"Q","outbounds":[$ob]}"""

    private fun convert(body: String): Pair<JSONObject?, List<String>> =
        when (val r = SingBoxConverter.convert(body, "N")) {
            is SingBoxConverter.Result.Ok -> proxyOf(r.config) to r.notes
            is SingBoxConverter.Result.Unsupported -> null to r.notes
            else -> null to listOf("NotXray")
        }

    private fun proxyOf(cfg: JSONObject): JSONObject? {
        val skip = setOf("direct", "block", "dns", "selector", "urltest")
        val outs = cfg.optJSONArray("outbounds") ?: return null
        for (i in 0 until outs.length()) {
            val o = outs.optJSONObject(i) ?: continue
            if (o.optString("type") !in skip) return o
        }
        return null
    }

    // ----------------------------------------------------------- hysteria2 ----

    @Test
    fun `a hysteria2 node becomes a hysteria2 outbound`() {
        val (p, notes) = convert(cfg("""{"protocol":"hysteria2","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
        assertTrue("the node was dropped: $notes", p != null)
        assertEquals("hysteria2", p!!.optString("type"))
        assertEquals("a.example.com", p.optString("server"))
        assertEquals(443, p.optInt("server_port"))
        assertEquals("pw", p.optString("password"))
        // TLS is not optional for this outbound: the core answers a missing
        // block with "TLS required" and refuses the whole document.
        assertTrue(p.optJSONObject("tls")?.optBoolean("enabled") == true)
        assertEquals("a.example.com", p.optJSONObject("tls")?.optString("server_name"))
    }

    @Test
    fun `the password is found wherever the config keeps it`() {
        // Xray writes it in streamSettings; a Hysteria2-style generator writes
        // it in settings; both describe the same node.
        val native = cfg("""{"protocol":"hysteria","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443}]},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"a.example.com"},"hysteriaSettings":{"auth":"pw"}}}""")
        val (p, notes) = convert(native)
        assertTrue("the node was dropped: $notes", p != null)
        assertEquals("hysteria2", p!!.optString("type"))
        assertEquals("pw", p.optString("password"))
    }

    @Test
    fun `rates are carried across in whole Mbps, however they were spelled`() {
        for (settings in listOf(
            """{"servers":[{"address":"a.example.com","port":443,"password":"pw","up":"100 Mbps","down":"200 Mbps"}]}""",
            """{"servers":[{"address":"a.example.com","port":443,"password":"pw","upMbps":100,"downMbps":200}]}""",
            // The spelling the Hysteria v1 client itself writes, which used to
            // be read by neither converter.
            """{"servers":[{"address":"a.example.com","port":443,"password":"pw","up_mbps":100,"down_mbps":200}]}"""
        )) {
            val (p, notes) = convert(cfg("""{"protocol":"hysteria2","tag":"n","settings":$settings,"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
            assertTrue("dropped for $settings: $notes", p != null)
            assertEquals("up, for $settings", 100, p!!.optInt("up_mbps"))
            assertEquals("down, for $settings", 200, p.optInt("down_mbps"))
        }
    }

    @Test
    fun `salamander obfuscation is carried in either form`() {
        for (obfs in listOf(
            """"obfs":"salamander","obfsPassword":"secret"""",
            """"obfs":{"type":"salamander","salamander":{"password":"secret"}}"""
        )) {
            val (p, _) = convert(cfg("""{"protocol":"hysteria2","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}],$obfs},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
            val o = p?.optJSONObject("obfs")
            assertTrue("no obfs block for $obfs", o != null)
            assertEquals("salamander", o!!.optString("type"))
            assertEquals("secret", o.optString("password"))
        }
    }

    @Test
    fun `an obfuscation sing-box does not have is dropped and said out loud`() {
        // gecko is a mihomo extension. Emitting it would make the core refuse
        // the document, so the node goes out without it and the loss is named.
        val (p, notes) = convert(cfg("""{"protocol":"hysteria2","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}],"obfs":"gecko","obfsPassword":"s"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
        assertTrue("the node itself must survive", p != null)
        assertNull("gecko must not reach the core", p!!.opt("obfs"))
        assertTrue("the drop must be reported, notes were $notes", notes.any { it.contains("gecko") })
    }

    @Test
    fun `port hopping becomes the range list the core takes`() {
        val (p, _) = convert(cfg("""{"protocol":"hysteria2","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"ports":"443-8443,9000","password":"pw"}],"hopInterval":"30s"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
        val ranges = p?.optJSONArray("server_ports")
        assertTrue("no server_ports", ranges != null)
        assertEquals(2, ranges!!.length())
        // "443-8443,9000" in the source; "start:end" in the core, and a lone
        // port spelled as a range of one.
        assertEquals("443:8443", ranges.getString(0))
        assertEquals("9000:9000", ranges.getString(1))
        assertEquals("30s", p!!.optString("hop_interval"))
    }

    // ---------------------------------------------------------- hysteria v1 ----

    // The v1 credential always goes out as a plain string.
    @Test
    fun `the v1 credential is taken as a plain string, whichever name held it`() {
        for (field in listOf("auth", "auth_str", "password")) {
            val (p, _) = convert(cfg("""{"protocol":"hysteria","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"$field":"pw","up_mbps":100,"down_mbps":100}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
            assertEquals("from $field", "pw", p!!.optString("auth_str"))
            assertFalse("nothing may be handed over as base64: $field", p.has("auth"))
        }
    }

    // A rate is not always in Mbps.
    @Test
    fun `rates in other units survive rather than being dropped`() {
        val kbps = convert(cfg("""{"protocol":"hysteria","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"auth_str":"pw","up":"640 KBps","down":"640 KBps"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}""")).first
        assertEquals("640 KBps", kbps!!.optString("up"))
        assertEquals("640 KBps", kbps.optString("down"))

        // Gbps lands on a whole number of Mbps, so it goes out as a number.
        val gbps = convert(cfg("""{"protocol":"hysteria","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"auth_str":"pw","up":"2 Gbps","down":"2 Gbps"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}""")).first
        assertEquals(2000, gbps!!.optInt("up_mbps"))
    }

    @Test
    fun `a hysteria2 rate that is not whole Mbps is left out and reported`() {
        // hysteria2 has no string form for the rate, so a value that does not land on a whole Mbps
        // cannot be carried.
        val (p, notes) = convert(cfg("""{"protocol":"hysteria2","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw","up":"640 KBps","down":"640 KBps"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
        assertTrue("the node itself must survive", p != null)
        assertFalse(p!!.has("up_mbps"))
        assertTrue("the loss must be reported: $notes", notes.any { it.contains("640 KBps") })
    }

    @Test
    fun `version 1 gets port hopping too`() {
        val (p, _) = convert(cfg("""{"protocol":"hysteria","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"ports":"443-8443","auth_str":"pw","up_mbps":100,"down_mbps":100}],"hopInterval":"30s"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
        assertEquals("443:8443", p!!.getJSONArray("server_ports").getString(0))
        assertEquals("30s", p.optString("hop_interval"))
    }

    @Test
    fun `a hysteria v1 node keeps its own field names`() {
        val (p, notes) = convert(cfg("""{"protocol":"hysteria","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"auth":"pw","up_mbps":100,"down_mbps":200}],"obfs":"xplus"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
        assertTrue("the node was dropped: $notes", p != null)
        assertEquals("hysteria", p!!.optString("type"))
        // Version 1 authenticates with a plain string under auth_str, and its
        // obfuscator is a string rather than version 2's object.
        assertEquals("pw", p.optString("auth_str"))
        assertEquals("xplus", p.optString("obfs"))
        assertEquals(100, p.optInt("up_mbps"))
        assertEquals(200, p.optInt("down_mbps"))
    }

    @Test
    fun `hysteria v1 without rates is refused with the reason`() {
        // Both rates are mandatory in version 1; the core has nothing to pace
        // with otherwise.
        val (p, notes) = convert(cfg("""{"protocol":"hysteria","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"auth":"pw"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
        assertNull(p)
        assertTrue("the reason must be given, notes were $notes", notes.any { it.contains("up and down rates") })
    }

    // ---------------------------------------------------------------- TUIC ----

    @Test
    fun `a TUIC node becomes a tuic outbound with its options`() {
        val (p, notes) = convert(cfg("""{"protocol":"tuic","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"uuid":"$uuid","password":"pw"}],"congestion_control":"bbr","udp_relay_mode":"native","reduce_rtt":true,"heartbeat_interval":10000},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com","alpn":["h3"]}}}"""))
        assertTrue("the node was dropped: $notes", p != null)
        assertEquals("tuic", p!!.optString("type"))
        assertEquals(uuid, p.optString("uuid"))
        assertEquals("pw", p.optString("password"))
        assertEquals("bbr", p.optString("congestion_control"))
        assertEquals("native", p.optString("udp_relay_mode"))
        // reduce_rtt is what the source calls it; the core calls it
        // zero_rtt_handshake.
        assertTrue(p.optBoolean("zero_rtt_handshake"))
        // heartbeat_interval is in milliseconds - mihomo documents it that way and 10000 is the
        // value its own sample uses.
        assertEquals("10000ms", p.optString("heartbeat"))
        assertEquals(listOf("h3"), (0 until (p.optJSONObject("tls")!!.getJSONArray("alpn").length()))
            .map { p.optJSONObject("tls")!!.getJSONArray("alpn").getString(it) })
    }

    @Test
    fun `a value the core would refuse is dropped instead of taking the config down`() {
        // congestion_control is validated by the core, and an unknown name is answered by refusing
        // the whole document - one odd node would cost the subscription.
        val (p, notes) = convert(cfg("""{"protocol":"tuic","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"uuid":"$uuid","password":"pw"}],"congestion_control":"bbr2","udp_relay_mode":"weird"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
        assertTrue("the node must survive", p != null)
        assertFalse(p!!.has("congestion_control"))
        assertFalse(p.has("udp_relay_mode"))
        assertTrue("both losses must be named: $notes", notes.size >= 2)
    }

    @Test
    fun `a TUIC v4 node is refused rather than emitted without a credential`() {
        // sing-box implements v5, which authenticates with a uuid. A v4 node
        // carries a token instead and has no representation here.
        val (p, notes) = convert(cfg("""{"protocol":"tuic","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"token":"tok"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
        assertNull(p)
        assertTrue("the reason must name the uuid, notes were $notes", notes.any { it.contains("uuid") })
    }

    // ------------------------------------------------------- alongside others ----

    @Test
    fun `these live alongside the older protocols in one configuration`() {
        val mixed = """{"remarks":"M","outbounds":[
            {"protocol":"vless","tag":"v","settings":{"vnext":[{"address":"b.example.com","port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"b.example.com"}}},
            {"protocol":"hysteria2","tag":"h","settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}},
            {"protocol":"tuic","tag":"t","settings":{"servers":[{"address":"c.example.com","port":443,"uuid":"$uuid","password":"pw"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"c.example.com"}}}]}"""
            .trimIndent().replace("\n", "")
        val r = SingBoxConverter.convert(mixed, "N")
        assertTrue("expected a converted config, got $r", r is SingBoxConverter.Result.Ok)
        val types = (r as SingBoxConverter.Result.Ok).config.getJSONArray("outbounds").let { arr ->
            (0 until arr.length()).map { arr.getJSONObject(it).optString("type") }
        }
        for (t in listOf("vless", "hysteria2", "tuic")) {
            assertTrue("$t is missing from $types", t in types)
        }
        assertTrue("nothing should have been dropped: ${r.notes}", r.notes.isEmpty())
    }

    // -------------------------------------------------------------- as links ----

    @Test
    fun `the link form carries the credential too`() {
        // The URI builder read the password from a field name nothing writes, so every real node
        // became "hysteria2://@host:port" - a link with no credential, which connects to nothing.
        val hy = """{"remarks":"H","outbounds":[{"protocol":"hysteria2","tag":"h","settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}],"obfs":"salamander","obfsPassword":"o"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}]}"""
        val link = LinkConverter.convert(hy, jsonToUri = true)
        assertTrue("no password in $link", link.startsWith("hysteria2://pw@a.example.com:443/"))
        assertTrue("no obfs in $link", link.contains("obfs=salamander"))
        assertTrue("no obfs password in $link", link.contains("obfs-password=o"))

        val tuic = """{"remarks":"T","outbounds":[{"protocol":"tuic","tag":"t","settings":{"servers":[{"address":"a.example.com","port":443,"uuid":"$uuid","password":"pw"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}]}"""
        val tlink = LinkConverter.convert(tuic, jsonToUri = true)
        assertTrue("empty credentials in $tlink", tlink.startsWith("tuic://$uuid:pw@a.example.com:443"))
        assertFalse("the empty form must be gone", tlink.contains("tuic://:@:0"))
    }
}
