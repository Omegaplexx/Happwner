package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// Two things a config can say that used to leave no trace at all: a certificate-name check mihomo
// can actually perform, and socket options only one of the two converters bothered to mention.
class CertNameAndSockoptTest {

    private fun mihomo(xray: String): MihomoConverter.Result.Ok {
        val r = MihomoConverter.convert(xray)
        assertTrue("expected Ok, got $r", r is MihomoConverter.Result.Ok)
        return r as MihomoConverter.Result.Ok
    }

    private fun singboxNotes(xray: String): List<String> {
        val r = SingBoxConverter.convertToOutbounds(xray)
        assertTrue("expected Ok, got $r", r is SingBoxConverter.OutboundsResult.Ok)
        return (r as SingBoxConverter.OutboundsResult.Ok).notes
    }

    private fun cfg(tls: String = "", sockopt: String = "") = """
        {"remarks":"C","outbounds":[{"tag":"t","protocol":"vless",
         "settings":{"vnext":[{"address":"a.com","port":443,
           "users":[{"id":"u","encryption":"none"}]}]},
         "streamSettings":{"network":"tcp","security":"tls",
           "tlsSettings":{"serverName":"a.com"$tls}$sockopt}}]}
    """.trimIndent()

    // mihomo's name-cert-verify is exactly this check, and nobody was reading the field before.
    @Test
    fun mihomo_carries_verify_peer_cert_in_names() {
        val yaml = mihomo(cfg(tls = ",\"verifyPeerCertInNames\":[\"real.example.com\"]")).yaml
        assertTrue("name-cert-verify missing from:\n$yaml", yaml.contains("name-cert-verify: real.example.com"))
    }

    // mihomo verifies against one name, so a longer list has to say what happened to the rest.
    @Test
    fun a_longer_name_list_is_reported() {
        val r = mihomo(cfg(tls = ",\"verifyPeerCertInNames\":[\"one.example.com\",\"two.example.com\"]"))
        assertTrue("name-cert-verify missing", r.yaml.contains("name-cert-verify: one.example.com"))
        assertEquals(1, r.notes.count { it.contains("verifyPeerCertInNames") })
    }

    // sing-box verifies against server_name only, so it says so rather than staying silent.
    @Test
    fun singbox_reports_verify_peer_cert_in_names() {
        val notes = singboxNotes(cfg(tls = ",\"verifyPeerCertInNames\":[\"real.example.com\"]"))
        assertEquals(1, notes.count { it.contains("verifyPeerCertInNames") })
    }

    // A switched-off option is not a dropped one. Reporting it would send somebody looking for a
    // setting they deliberately turned off, and the two modes would disagree about the same config.
    @Test
    fun a_switched_off_sockopt_is_not_reported_by_either() {
        val sockopt = ",\"sockopt\":{\"tcpNoDelay\":false,\"V6Only\":false,\"penetrate\":false," +
            "\"tcpUserTimeout\":0,\"tcpMaxSeg\":0,\"customSockopt\":[]}"
        val sb = singboxNotes(cfg(sockopt = sockopt))
        val mh = mihomo(cfg(sockopt = sockopt)).notes
        for (f in listOf("tcpNoDelay", "V6Only", "penetrate", "tcpUserTimeout", "tcpMaxSeg", "customSockopt")) {
            assertTrue("sing-box should say nothing about a disabled $f: $sb", sb.none { it.contains(f) })
            assertTrue("mihomo should say nothing about a disabled $f: $mh", mh.none { it.contains(f) })
        }
    }

    // The same configuration must read the same way whichever mode produced it.
    @Test
    fun both_converters_name_the_same_dropped_sockopt_options() {
        val sockopt = ",\"sockopt\":{\"tcpNoDelay\":true,\"tcpUserTimeout\":10000," +
            "\"tcpWindowClamp\":600,\"tcpMaxSeg\":1440,\"V6Only\":true,\"penetrate\":true," +
            "\"happyEyeballs\":{\"tryDelayMs\":250},\"customSockopt\":[{\"level\":\"6\"}]}"
        val sb = singboxNotes(cfg(sockopt = sockopt))
        val mh = mihomo(cfg(sockopt = sockopt)).notes
        for (f in listOf("tcpNoDelay", "tcpUserTimeout", "tcpWindowClamp", "tcpMaxSeg",
                         "V6Only", "penetrate", "happyEyeballs", "customSockopt")) {
            assertTrue("sing-box says nothing about $f", sb.any { it.contains(f) })
            assertTrue("mihomo says nothing about $f", mh.any { it.contains(f) })
        }
    }
}
