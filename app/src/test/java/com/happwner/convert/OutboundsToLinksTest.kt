package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// Turning a whole JSON configuration into share links. The builders are pinned field by field in
// LinkBuilderTest; this file pins the pass around them - one link per outbound, in the original order.
class OutboundsToLinksTest {

    private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

    private fun convert(body: String): String =
        LinkConverter.convert(body, jsonToUri = true, base64Result = false).trim()

    private fun linkCount(s: String): Int = Regex("://").findAll(s).count()

    private val vless =
        """{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""
    private val trojan =
        """{"protocol":"trojan","tag":"n","settings":{"servers":[{"address":"b.example.com","port":8443,"password":"pw"}]},"streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"serverName":"b.example.com"},"grpcSettings":{"serviceName":"gun"}}}"""
    private val socks =
        """{"protocol":"socks","tag":"n","settings":{"servers":[{"address":"c.example.com","port":1080,"users":[{"user":"u","pass":"p"}]}]}}"""

    @Test
    fun `a pretty-printed configuration converts to a link`() {
        // The per-line pass never sees a multi-line document whole, so it used
        // to come back unconverted.
        val pretty = """
            {
              "remarks": "M",
              "outbounds": [
                $vless
              ]
            }
        """.trimIndent()
        val out = convert(pretty)
        assertTrue("a pretty config did not convert: $out", out.startsWith("vless://"))
        assertEquals(1, linkCount(out))
    }

    @Test
    fun `every outbound becomes a link, not only the first`() {
        val out = convert("""{"remarks":"R","outbounds":[$vless,$trojan]}""")
        assertEquals("both outbounds should convert: $out", 2, linkCount(out))
        assertTrue(out.contains("vless://"))
        assertTrue(out.contains("trojan://"))
    }

    @Test
    fun `the outbound order is preserved`() {
        val out = convert("""{"remarks":"R","outbounds":[$trojan,$vless]}""")
        val lines = out.lines().filter { it.isNotBlank() }
        assertEquals(2, lines.size)
        assertTrue("first line should be the trojan: $out", lines[0].startsWith("trojan://"))
        assertTrue("second line should be the vless: $out", lines[1].startsWith("vless://"))
    }

    @Test
    fun `a supported protocol later in the list does not block the rest`() {
        // socks is a protocol this converter builds, so a config mixing it with
        // vless must yield both, not fall back for want of understanding socks.
        val out = convert("""{"remarks":"R","outbounds":[$vless,$socks]}""")
        assertEquals("vless and socks should both convert: $out", 2, linkCount(out))
        assertTrue(out.contains("vless://"))
        assertTrue(out.contains("socks://"))
    }

    @Test
    fun `auxiliary outbounds are skipped, not treated as proxies`() {
        val freedom = """{"protocol":"freedom","tag":"direct"}"""
        val blackhole = """{"protocol":"blackhole","tag":"block"}"""
        val out = convert("""{"remarks":"R","outbounds":[$vless,$freedom,$blackhole]}""")
        assertEquals("only the vless is a proxy: $out", 1, linkCount(out))
        assertTrue(out.startsWith("vless://"))
    }

    @Test
    fun `a recognised protocol with no link form comes back as itself`() {
        // Dropping it left the person with a list quietly missing a server they
        // had; it is written back instead, in the place it held.
        val wireguard =
            """{"protocol":"wireguard","tag":"wg","settings":{"secretKey":"x","peers":[{"endpoint":"d.example.com:51820"}]}}"""
        val out = convert("""{"remarks":"R","outbounds":[$vless,$wireguard]}""")
        val lines = out.trim().lines()
        assertEquals("one line for each outbound: $out", 2, lines.size)
        assertTrue(lines[0].startsWith("vless://"))
        assertTrue("the wireguard is still there: $out", lines[1].startsWith("{"))
        assertTrue(lines[1].contains("wireguard"))
        assertEquals("and on one line, or a line-oriented list breaks", 0, lines[1].count { it == '\n' })
    }

    @Test
    fun `a broken outbound costs itself and nothing else`() {
        // A vless with no user or address cannot be rendered.
        val brokenVless =
            """{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"","port":0,"users":[]}]}}"""
        val out = convert("""{"remarks":"R","outbounds":[$brokenVless,$trojan]}""")
        val lines = out.trim().lines()
        assertEquals(2, lines.size)
        assertTrue("the broken one is written back: $out", lines[0].startsWith("{"))
        assertTrue("the good one still converts: $out", lines[1].startsWith("trojan://"))
    }

    @Test
    fun `an unknown protocol comes back as itself, the rest converts`() {
        // Guessing at a protocol nobody here knows would be worse than saying so,
        // but it is no reason to refuse the nodes that are understood.
        val warp = """{"protocol":"warp","tag":"n","settings":{"foo":"bar"}}"""
        val out = convert("""{"remarks":"R","outbounds":[$vless,$warp]}""")
        val lines = out.trim().lines()
        assertEquals(2, lines.size)
        assertTrue(lines[0].startsWith("vless://"))
        assertTrue("the unknown one is preserved: $out", lines[1].contains("\"warp\""))
    }

    @Test
    fun `a mixed subscription keeps every node, in order`() {
        // The shape a person actually has: some nodes with a link form, one
        // without. Every one of them has to be in the result, where it was.
        val wireguard =
            """{"protocol":"wireguard","tag":"wg","settings":{"secretKey":"x","address":["10.0.0.2/32"],
               "peers":[{"publicKey":"pk","endpoint":"d.example.com:51820","allowedIPs":["0.0.0.0/0"]}]}}"""
                .trimIndent().replace("\n", "")
        val out = convert("""{"remarks":"Sub","outbounds":[$vless,$socks,$wireguard,$trojan]}""")
        val lines = out.trim().lines()
        assertEquals("one line per outbound: $out", 4, lines.size)
        assertTrue(lines[0].startsWith("vless://"))
        assertTrue(lines[1].startsWith("socks://"))
        assertTrue("the wireguard sits where it was: $out", lines[2].startsWith("{"))
        assertTrue(lines[3].startsWith("trojan://"))
        // what comes back has to be importable on its own
        val kept = org.json.JSONObject(lines[2])
        val ob = kept.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("wireguard", ob.getString("protocol"))
        assertEquals("d.example.com:51820",
            ob.getJSONObject("settings").getJSONArray("peers").getJSONObject(0).getString("endpoint"))
        assertEquals("Sub", kept.getString("remarks"))
    }

    @Test
    fun `a hysteria v1 node becomes a hysteria link`() {
        // Version 1 is a first-class protocol in the other converters but had no
        // link form here, so a v1 outbound used to come out as raw JSON.
        val hy1 =
            """{"protocol":"hysteria","tag":"h","settings":{"servers":[{"address":"e.example.com","port":443,"auth_str":"mypass","up_mbps":50,"down_mbps":100}],"obfs":"secretobfs"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"e.example.com"}}}"""
        val out = convert("""{"remarks":"HV1","outbounds":[$hy1]}""")
        assertTrue("not a hysteria link: $out", out.startsWith("hysteria://e.example.com:443"))
        // The rates are mandatory in v1 and the credential and obfuscator are
        // the ones the documented scheme names.
        assertTrue("no upmbps: $out", out.contains("upmbps=50"))
        assertTrue("no downmbps: $out", out.contains("downmbps=100"))
        assertTrue("no auth: $out", out.contains("auth=mypass"))
        assertTrue("obfs mode should be xplus: $out", out.contains("obfs=xplus"))
        assertTrue("no obfs password: $out", out.contains("obfsParam=secretobfs"))
        assertTrue("no peer/sni: $out", out.contains("peer=e.example.com"))
    }

    @Test
    fun `a single outbound still converts to one link`() {
        val out = convert("""{"remarks":"N","outbounds":[$vless]}""")
        assertEquals(1, linkCount(out))
        assertTrue(out.startsWith("vless://"))
    }
}
