package com.happwner.convert

import java.net.URLDecoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// A Shadowsocks plugin performs the obfuscation the server expects. A link without it points at a
// server that will not answer, while looking perfectly well formed.
class ShadowsocksLinkPluginTest {

    private fun link(extra: String): String {
        val body = """
            {"outbounds":[{"type":"shadowsocks","tag":"S","server":"a.com","server_port":8388,
             "method":"aes-256-gcm","password":"pw"$extra}]}
        """.trimIndent()
        return LinkConverter.convert(body, jsonToUri = true, base64Result = false).trim().lines().first()
    }

    @Test
    fun a_plugin_and_its_options_reach_the_link() {
        val out = link(",\"plugin\":\"obfs-local\",\"plugin_opts\":\"obfs=http;obfs-host=www.bing.com\"")
        assertTrue("expected an ss link, got $out", out.startsWith("ss://"))
        val q = out.substringAfter("/?plugin=", "").substringBefore("#")
        assertTrue("no plugin in $out", q.isNotEmpty())
        assertEquals("obfs-local;obfs=http;obfs-host=www.bing.com", URLDecoder.decode(q, "UTF-8"))
    }

    // The options can arrive as an object rather than a string; both describe one plugin.
    @Test
    fun object_options_are_serialised_too() {
        val out = link(",\"plugin\":\"obfs-local\",\"plugin_opts\":{\"obfs\":\"tls\"}")
        val q = URLDecoder.decode(out.substringAfter("/?plugin=", "").substringBefore("#"), "UTF-8")
        assertTrue("options missing from $out", q.startsWith("obfs-local;") && q.contains("obfs=tls"))
    }

    // Without a plugin the link keeps the shape every client already reads.
    @Test
    fun no_plugin_means_no_query() {
        val out = link("")
        assertTrue("expected an ss link, got $out", out.startsWith("ss://"))
        assertFalse("nothing should be added: $out", out.contains("plugin="))
        assertFalse("no stray path either: $out", out.substringBefore("#").endsWith("/?"))
    }
}
