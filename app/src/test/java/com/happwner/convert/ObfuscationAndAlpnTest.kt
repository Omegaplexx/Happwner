package com.happwner.convert

import android.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// A setting that is read from only one of the shapes it is written in is lost without a word, and
// these are the ones where losing it leaves a node that looks whole and connects to nothing.
class ObfuscationAndAlpnTest {

    private fun links(xray: String) =
        LinkConverter.convert(xray, jsonToUri = true, base64Result = false).trim().lines()

    private fun singboxOutbound(xray: String): JSONObject {
        val r = SingBoxConverter.convertToOutbounds(xray)
        assertTrue("expected Ok, got $r", r is SingBoxConverter.OutboundsResult.Ok)
        return (r as SingBoxConverter.OutboundsResult.Ok).outbounds.first()
    }

    private fun mihomoYaml(xray: String): String {
        val r = MihomoConverter.convert(xray)
        assertTrue("expected Ok, got $r", r is MihomoConverter.Result.Ok)
        return (r as MihomoConverter.Result.Ok).yaml
    }

    // The obfuscation sits beside the address here rather than beside the protocol. Both shapes are
    // written by real tools, and a hysteria2 node without it is answered by nothing at all.
    private val obfsOnServerEntry = """
        {"remarks":"H","outbounds":[{"tag":"h","protocol":"hysteria",
         "settings":{"version":2,"servers":[{"address":"a.com","port":443,"password":"pw",
           "obfs":{"type":"salamander","password":"sp"}}]},
         "streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.com"}}}]}
    """.trimIndent()

    @Test
    fun singbox_reads_obfuscation_written_beside_the_address() {
        val out = singboxOutbound(obfsOnServerEntry)
        val obfs = out.optJSONObject("obfs")
        assertTrue("no obfs in $out", obfs != null)
        assertEquals("salamander", obfs!!.optString("type"))
        assertEquals("sp", obfs.optString("password"))
    }

    @Test
    fun mihomo_reads_obfuscation_written_beside_the_address() {
        val yaml = mihomoYaml(obfsOnServerEntry)
        assertTrue("obfs missing from:\n$yaml", yaml.contains("obfs: salamander"))
        assertTrue("obfs password missing from:\n$yaml", yaml.contains("sp"))
    }

    @Test
    fun link_carries_obfuscation_written_beside_the_address() {
        val line = links(obfsOnServerEntry).first()
        assertTrue("expected a hysteria2 link, got $line", line.startsWith("hysteria2://"))
        assertTrue("obfuscation missing from $line", line.contains("obfs=salamander"))
        assertTrue("obfuscation password missing from $line", line.contains("obfs-password=sp"))
    }

    // A vmess link carries its fields in a base64 JSON blob. "alpn" is read as a comma-separated
    // list, so an empty string is a list of one empty protocol name rather than an absent field.
    @Test
    fun vmess_link_leaves_out_an_empty_alpn() {
        val xray = """
            {"remarks":"V","outbounds":[{"tag":"v","protocol":"vmess",
             "settings":{"vnext":[{"address":"a.com","port":443,
               "users":[{"id":"11111111-2222-3333-4444-555555555555","security":"auto"}]}]},
             "streamSettings":{"network":"ws","security":"tls",
               "wsSettings":{"path":"/p"},"tlsSettings":{"serverName":"a.com"}}}]}
        """.trimIndent()
        val line = links(xray).first()
        assertTrue("expected a vmess link, got $line", line.startsWith("vmess://"))
        val json = JSONObject(String(Base64.decode(line.removePrefix("vmess://"), Base64.DEFAULT)))
        assertFalse("alpn should be absent, not empty: $json", json.has("alpn"))
        assertEquals("a.com", json.optString("sni"))
    }

}
