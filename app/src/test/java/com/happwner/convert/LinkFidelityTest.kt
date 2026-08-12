package com.happwner.convert

import android.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// A share link that looks complete and connects to nothing is worse than no link at all: the
// fallback hands the node back as its own configuration, which the person can still import.
class LinkFidelityTest {

    private fun links(xray: String) =
        LinkConverter.convert(xray, jsonToUri = true, base64Result = false).trim().lines()

    private fun vless(flow: String) = """
        {"remarks":"F","outbounds":[{"tag":"t","protocol":"vless",
         "settings":{"vnext":[{"address":"a.com","port":443,
           "users":[{"id":"u","encryption":"none","flow":$flow}]}]},
         "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.com"}}}]}
    """.trimIndent()

    // The link is read by Xray-family clients, which understand the -udp443 variant and act on it.
    // Mapping it to the plain vision flow the way sing-box needs would change what the node does.
    @Test
    fun the_flow_travels_as_the_source_wrote_it() {
        val line = links(vless("\"xtls-rprx-vision-udp443\"")).first()
        assertTrue("expected a vless link, got $line", line.startsWith("vless://"))
        assertTrue("the -udp443 variant was lost: $line", line.contains("flow=xtls-rprx-vision-udp443"))
    }

    // "Drop profiles incompatible with sing-box" is the setting that says the answer is meant for
    // sing-box, and it is the pre-filter behind it that normalises the flow.
    @Test
    fun the_drop_incompatible_setting_governs_the_flow() {
        val xray = vless("\"xtls-rprx-vision-udp443\"")
        val plain = LinkConverter.convert(xray, jsonToUri = true, base64Result = false, xrayToSb = false)
        assertTrue("with the setting off the flow must be untouched: $plain",
            plain.contains("flow=xtls-rprx-vision-udp443"))
        val dropping = LinkConverter.convert(xray, jsonToUri = true, base64Result = false, xrayToSb = true)
        assertTrue("with the setting on the flow must be the one sing-box takes: $dropping",
            dropping.contains("flow=xtls-rprx-vision") && !dropping.contains("udp443"))
    }

    @Test
    fun a_flow_of_none_is_left_out() {
        val line = links(vless("\"none\"")).first()
        assertFalse("\"none\" is not a flow: $line", line.contains("flow="))
    }

    // vless links carry REALITY, so this one must not fall back.
    @Test
    fun a_vless_reality_node_still_becomes_a_link() {
        val xray = """
            {"remarks":"R","outbounds":[{"tag":"t","protocol":"vless",
             "settings":{"vnext":[{"address":"a.com","port":443,
               "users":[{"id":"u","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"reality",
               "realitySettings":{"serverName":"s.com","publicKey":"PK","shortId":"ab","spiderX":"/x"}}}]}
        """.trimIndent()
        val line = links(xray).first()
        assertTrue("expected a vless link, got $line", line.startsWith("vless://"))
        assertTrue("public key missing: $line", line.contains("pbk=PK"))
        assertTrue("short id missing: $line", line.contains("sid=ab"))
        assertTrue("spiderX missing: $line", line.contains("spx="))
    }

    // The vmess blob has nowhere to put a public key or short id, so a link would claim plain TLS
    // and the server would refuse it. The node comes back as a configuration instead.
    private fun vmessReality() = """
        {"remarks":"V","outbounds":[{"tag":"t","protocol":"vmess",
         "settings":{"vnext":[{"address":"a.com","port":443,
           "users":[{"id":"11111111-2222-3333-4444-555555555555","security":"auto"}]}]},
         "streamSettings":{"network":"tcp","security":"reality",
           "realitySettings":{"serverName":"s.com","publicKey":"PK","shortId":"ab"}}}]}
    """.trimIndent()

    @Test
    fun a_vmess_reality_node_comes_back_as_a_configuration() {
        val line = links(vmessReality()).first()
        assertFalse("a vmess link cannot express REALITY: $line", line.startsWith("vmess://"))
        assertTrue("the node should come back as its own configuration: $line", line.contains("\"protocol\""))
        assertTrue("and it must keep the reality settings: $line", line.contains("realitySettings"))
    }

    // The fallback is only worth anything if what comes back can actually be used: it has to be a
    // configuration the converters still read, not just text that looks like one.
    @Test
    fun the_fallback_configuration_is_still_usable() {
        val line = links(vmessReality()).first()
        val back = JSONObject(line)
        assertTrue("the fallback must be a configuration", back.has("outbounds"))
        val ob = back.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("vmess", ob.optString("protocol"))
        val reality = ob.getJSONObject("streamSettings").getJSONObject("realitySettings")
        assertEquals("PK", reality.optString("publicKey"))
        // and the mihomo side, which does have reality-opts, still converts it
        val r = MihomoConverter.convert(line)
        assertTrue("mihomo should still convert the fallback, got $r", r is MihomoConverter.Result.Ok)
        assertTrue("the public key must survive", (r as MihomoConverter.Result.Ok).yaml.contains("PK"))
    }

    // The same node arriving on its own rather than inside a configuration must say the same thing.
    @Test
    fun a_lone_outbound_reports_like_one_inside_a_configuration() {
        val lone = JSONObject(vmessReality()).getJSONArray("outbounds").getJSONObject(0).toString()
        val r = LinkConverter.convertWithStats(lone, jsonToUri = true, base64Result = false)
        assertTrue("a lone outbound went quiet: ${'$'}{r.notes}",
            r.notes.any { it.contains("vmess") && it.contains("kept as it was written") })
    }

    // An ordinary TLS vmess node is unaffected by that guard.
    @Test
    fun an_ordinary_vmess_node_still_becomes_a_link() {
        val xray = """
            {"remarks":"V","outbounds":[{"tag":"t","protocol":"vmess",
             "settings":{"vnext":[{"address":"a.com","port":443,
               "users":[{"id":"11111111-2222-3333-4444-555555555555","security":"auto"}]}]},
             "streamSettings":{"network":"ws","security":"tls",
               "wsSettings":{"path":"/p"},"tlsSettings":{"serverName":"a.com"}}}]}
        """.trimIndent()
        val line = links(xray).first()
        assertTrue("expected a vmess link, got $line", line.startsWith("vmess://"))
        val json = JSONObject(String(Base64.decode(line.removePrefix("vmess://"), Base64.DEFAULT)))
        assertEquals("tls", json.optString("tls"))
        assertEquals("/p", json.optString("path"))
    }
}
