package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Characterisation tests for SingBoxConverter, written against the public entry points so that splitting
// it into smaller files, or pulling shared Xray helpers out of it, stays behaviour preserving.
class SingBoxConverterTest {

    // ------------------------------------------------------------------ util

    private fun outbounds(xray: String, nameFallback: String = ""): List<JSONObject> {
        val r = SingBoxConverter.convertToOutbounds(xray, nameFallback)
        assertTrue("expected Ok, got $r", r is SingBoxConverter.OutboundsResult.Ok)
        return (r as SingBoxConverter.OutboundsResult.Ok).outbounds
    }

    private fun single(xray: String, nameFallback: String = ""): JSONObject {
        val list = outbounds(xray, nameFallback)
        assertEquals("expected exactly one outbound", 1, list.size)
        return list[0]
    }

    private fun full(xray: String): JSONObject {
        val r = SingBoxConverter.convert(xray)
        assertTrue("expected Ok, got $r", r is SingBoxConverter.Result.Ok)
        return (r as SingBoxConverter.Result.Ok).config
    }

    private fun tags(arr: org.json.JSONArray): List<String> =
        (0 until arr.length()).map { arr.optJSONObject(it)?.optString("tag") ?: arr.optString(it) }

    // --------------------------------------------------------------- fixtures

    private fun vlessReality() = """
        {"remarks":"My Server","outbounds":[{"tag":"proxy","protocol":"vless",
         "settings":{"vnext":[{"address":"example.com","port":443,
           "users":[{"id":"11111111-2222-3333-4444-555555555555",
                     "flow":"xtls-rprx-vision","encryption":"none"}]}]},
         "streamSettings":{"network":"tcp","security":"reality",
           "realitySettings":{"serverName":"www.microsoft.com","publicKey":"PUBKEY",
                              "shortId":"abcd","fingerprint":"chrome"}}}]}
    """.trimIndent()

    private fun vlessWs() = """
        {"remarks":"WS Node","outbounds":[{"tag":"p","protocol":"vless",
         "settings":{"vnext":[{"address":"1.2.3.4","port":8443,
           "users":[{"id":"uuid-here","encryption":"none"}]}]},
         "streamSettings":{"network":"ws","security":"tls",
           "wsSettings":{"path":"/path","headers":{"Host":"cdn.example.com"}},
           "tlsSettings":{"serverName":"cdn.example.com","alpn":["h2","http/1.1"],
                          "fingerprint":"chrome"}}}]}
    """.trimIndent()

    private fun vlessTls(remarks: String, tag: String, address: String) = """
        {"remarks":"$remarks","outbounds":[{"tag":"$tag","protocol":"vless",
         "settings":{"vnext":[{"address":"$address","port":443,
           "users":[{"id":"u","encryption":"none"}]}]},
         "streamSettings":{"network":"tcp","security":"tls"}}]}
    """.trimIndent()

    // ------------------------------------------------------------ recognition

    @Test
    fun `empty and malformed input is not xray`() {
        assertEquals(SingBoxConverter.Result.NotXray, SingBoxConverter.convert(""))
        assertEquals(SingBoxConverter.Result.NotXray, SingBoxConverter.convert("   "))
        assertEquals(SingBoxConverter.Result.NotXray, SingBoxConverter.convert("not json at all"))
        // A bare array is not accepted: convert() takes one object.
        assertEquals(SingBoxConverter.Result.NotXray, SingBoxConverter.convert("[{}]"))
    }

    @Test
    fun `json without outbounds is not xray`() {
        assertEquals(SingBoxConverter.Result.NotXray, SingBoxConverter.convert("""{"a":1}"""))
        assertEquals(SingBoxConverter.Result.NotXray, SingBoxConverter.convert("""{"outbounds":[]}"""))
        // outbounds present, but no member carries a "protocol" key
        assertEquals(
            SingBoxConverter.Result.NotXray,
            SingBoxConverter.convert("""{"outbounds":[{"tag":"x"}]}""")
        )
    }

    @Test
    fun `an existing sing-box config is left alone`() {
        val singbox = """{"route":{},"outbounds":[{"type":"vless","tag":"t"}]}"""
        assertEquals(SingBoxConverter.Result.NotXray, SingBoxConverter.convert(singbox))
        assertEquals(
            SingBoxConverter.OutboundsResult.NotXray,
            SingBoxConverter.convertToOutbounds(singbox)
        )
    }

    // -------------------------------------------------------------- rejection

    @Test
    fun `xray we cannot represent is unsupported rather than wrong`() {
        // A flow sing-box has no equivalent for
        val badFlow = """
            {"outbounds":[{"tag":"x","protocol":"vless",
             "settings":{"vnext":[{"address":"a.com","port":443,
               "users":[{"id":"u","flow":"xtls-rprx-direct","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp"}}]}
        """.trimIndent()
        assertTrue(
            "expected Unsupported for badFlow",
            SingBoxConverter.convert(badFlow) is SingBoxConverter.Result.Unsupported
        )

        // mKCP transport
        val mkcp = """
            {"outbounds":[{"tag":"x","protocol":"vless",
             "settings":{"vnext":[{"address":"a","port":1,
               "users":[{"id":"u","encryption":"none"}]}]},
             "streamSettings":{"network":"kcp"}}]}
        """.trimIndent()
        assertTrue(
            "expected Unsupported for mkcp",
            SingBoxConverter.convert(mkcp) is SingBoxConverter.Result.Unsupported
        )

        // A cipher that is not in the supported set
        val badMethod = """
            {"outbounds":[{"tag":"x","protocol":"shadowsocks",
             "settings":{"servers":[{"address":"s","port":1,"method":"nope","password":"p"}]}}]}
        """.trimIndent()
        assertTrue(
            "expected Unsupported for badMethod",
            SingBoxConverter.convert(badMethod) is SingBoxConverter.Result.Unsupported
        )
    }

    // -------------------------------------------------------------- protocols

    @Test
    fun `vless over reality keeps uuid flow and reality material`() {
        val o = single(vlessReality())
        assertEquals("vless", o.optString("type"))
        assertEquals("example.com", o.optString("server"))
        assertEquals(443, o.optInt("server_port"))
        assertEquals("11111111-2222-3333-4444-555555555555", o.optString("uuid"))
        assertEquals("xtls-rprx-vision", o.optString("flow"))

        val tls = o.optJSONObject("tls")!!
        assertTrue(tls.optBoolean("enabled"))
        assertEquals("www.microsoft.com", tls.optString("server_name"))

        val reality = tls.optJSONObject("reality")!!
        assertTrue(reality.optBoolean("enabled"))
        assertEquals("PUBKEY", reality.optString("public_key"))
        assertEquals("abcd", reality.optString("short_id"))

        val utls = tls.optJSONObject("utls")!!
        assertTrue(utls.optBoolean("enabled"))
        assertEquals("chrome", utls.optString("fingerprint"))
    }

    @Test
    fun `vless over websocket carries path host and alpn`() {
        val o = single(vlessWs())
        assertEquals("vless", o.optString("type"))
        assertEquals("uuid-here", o.optString("uuid"))
        // No flow was set, so none is emitted.
        assertFalse(o.has("flow"))

        val tr = o.optJSONObject("transport")!!
        assertEquals("ws", tr.optString("type"))
        assertEquals("/path", tr.optString("path"))
        assertEquals("cdn.example.com", tr.optJSONObject("headers")?.optString("Host"))

        val alpn = o.optJSONObject("tls")?.optJSONArray("alpn")!!
        assertEquals(listOf("h2", "http/1.1"), (0 until alpn.length()).map { alpn.optString(it) })
    }

    @Test
    fun `vmess keeps security and alter id`() {
        val xray = """
            {"remarks":"V","outbounds":[{"tag":"v","protocol":"vmess",
             "settings":{"vnext":[{"address":"v.com","port":80,
               "users":[{"id":"uid","security":"auto","alterId":0}]}]},
             "streamSettings":{"network":"tcp"}}]}
        """.trimIndent()
        val o = single(xray)
        assertEquals("vmess", o.optString("type"))
        assertEquals("uid", o.optString("uuid"))
        assertEquals("auto", o.optString("security"))
        assertEquals(0, o.optInt("alter_id"))
    }

    @Test
    fun `trojan over grpc keeps the service name`() {
        val xray = """
            {"remarks":"T","outbounds":[{"tag":"t","protocol":"trojan",
             "settings":{"servers":[{"address":"b.com","port":443,"password":"pw"}]},
             "streamSettings":{"network":"grpc","security":"tls",
                               "grpcSettings":{"serviceName":"svc"}}}]}
        """.trimIndent()
        val o = single(xray)
        assertEquals("trojan", o.optString("type"))
        assertEquals("pw", o.optString("password"))
        val tr = o.optJSONObject("transport")!!
        assertEquals("grpc", tr.optString("type"))
        assertEquals("svc", tr.optString("service_name"))
    }

    @Test
    fun `shadowsocks method aliases are normalised`() {
        val xray = """
            {"remarks":"SS","outbounds":[{"tag":"ss","protocol":"shadowsocks",
             "settings":{"servers":[{"address":"9.9.9.9","port":8388,
                                     "method":"chacha20-poly1305","password":"pw"}]}}]}
        """.trimIndent()
        val o = single(xray)
        assertEquals("shadowsocks", o.optString("type"))
        assertEquals("9.9.9.9", o.optString("server"))
        assertEquals(8388, o.optInt("server_port"))
        assertEquals("pw", o.optString("password"))
        // sing-box only knows the -ietf- spelling
        assertEquals("chacha20-ietf-poly1305", o.optString("method"))
    }

    @Test
    fun `wireguard endpoint is split into address and port`() {
        val xray = """
            {"remarks":"W","outbounds":[{"tag":"w","protocol":"wireguard",
             "settings":{"secretKey":"SK","address":["10.0.0.2/32"],
                         "peers":[{"endpoint":"w.com:51820","publicKey":"PK"}],"mtu":1420}}]}
        """.trimIndent()
        val o = single(xray)
        assertEquals("wireguard", o.optString("type"))
        assertEquals("SK", o.optString("private_key"))
        assertEquals(1420, o.optInt("mtu"))

        val peer = o.optJSONArray("peers")?.optJSONObject(0)!!
        assertEquals("PK", peer.optString("public_key"))
        assertEquals("w.com", peer.optString("address"))
        assertEquals(51820, peer.optInt("port"))
    }

    @Test
    fun `socks credentials become username and password`() {
        val xray = """
            {"remarks":"S","outbounds":[{"tag":"s","protocol":"socks",
             "settings":{"servers":[{"address":"s.com","port":1080,
                                     "users":[{"user":"u","pass":"p"}]}]}}]}
        """.trimIndent()
        val o = single(xray)
        assertEquals("socks", o.optString("type"))
        assertEquals("u", o.optString("username"))
        assertEquals("p", o.optString("password"))
    }

    // ------------------------------------------------------------- transports

    @Test
    fun `tcp http masquerade becomes the http transport`() {
        val xray = """
            {"remarks":"H","outbounds":[{"tag":"h","protocol":"vmess",
             "settings":{"vnext":[{"address":"h.com","port":80,"users":[{"id":"uid"}]}]},
             "streamSettings":{"network":"tcp","tcpSettings":{"header":{"type":"http",
               "request":{"path":["/p"],"headers":{"Host":["h.example"]}}}}}}]}
        """.trimIndent()
        val tr = single(xray).optJSONObject("transport")!!
        assertEquals("http", tr.optString("type"))
        assertEquals("/p", tr.optString("path"))
        val host = tr.optJSONArray("host")!!
        assertEquals(listOf("h.example"), (0 until host.length()).map { host.optString(it) })
    }

    @Test
    fun `httpupgrade keeps path and host`() {
        val xray = """
            {"remarks":"U","outbounds":[{"tag":"u","protocol":"vless",
             "settings":{"vnext":[{"address":"u.com","port":443,
               "users":[{"id":"u","encryption":"none"}]}]},
             "streamSettings":{"network":"httpupgrade","security":"tls",
               "httpupgradeSettings":{"path":"/up","host":"up.example"}}}]}
        """.trimIndent()
        val tr = single(xray).optJSONObject("transport")!!
        assertEquals("httpupgrade", tr.optString("type"))
        assertEquals("/up", tr.optString("path"))
        assertEquals("up.example", tr.optString("host"))
    }

    @Test
    fun `plain tcp emits no transport block`() {
        assertFalse(single(vlessTls("Plain", "p", "a.com")).has("transport"))
    }

    // ----------------------------------------------------------------- naming

    @Test
    fun `a single proxy takes the config remarks as its tag`() {
        assertEquals("My Server", single(vlessReality()).optString("tag"))
    }

    @Test
    fun `several proxies are suffixed with their original tag`() {
        val xray = """
            {"remarks":"Multi","outbounds":[
             {"tag":"a","protocol":"vless",
              "settings":{"vnext":[{"address":"a.com","port":443,
                "users":[{"id":"u1","encryption":"none"}]}]},
              "streamSettings":{"network":"tcp","security":"tls"}},
             {"tag":"b","protocol":"trojan",
              "settings":{"servers":[{"address":"b.com","port":443,"password":"pw"}]},
              "streamSettings":{"network":"grpc","security":"tls",
                                "grpcSettings":{"serviceName":"svc"}}},
             {"tag":"direct","protocol":"freedom"}]}
        """.trimIndent()
        val list = outbounds(xray)
        // freedom is auxiliary and is not offered as a proxy
        assertEquals(2, list.size)
        assertEquals(listOf("Multi #a", "Multi #b"), list.map { it.optString("tag") })
    }

    @Test
    fun `without remarks the original tag is kept`() {
        assertEquals("tagOnly", single(vlessTls("", "tagOnly", "f.com")).optString("tag"))
    }

    @Test
    fun `the name fallback is used when the config carries no remarks`() {
        assertEquals("FromArg", single(vlessTls("", "t", "f.com"), "FromArg").optString("tag"))
    }

    // ------------------------------------------------------------ full config

    @Test
    fun `a full config gets route dns and a direct outbound`() {
        val cfg = full(vlessReality())

        assertEquals("My Server", cfg.optJSONObject("route")?.optString("final"))
        assertTrue(cfg.optJSONObject("route")?.optBoolean("auto_detect_interface") == true)

        val outs = cfg.optJSONArray("outbounds")!!
        assertTrue("a direct outbound is always present", tags(outs).contains("direct"))
        assertTrue(tags(outs).contains("My Server"))

        val dns = cfg.optJSONObject("dns")!!
        assertEquals("local", dns.optString("final"))
        assertEquals("local", dns.optJSONArray("servers")?.optJSONObject(0)?.optString("tag"))

        // convert() produces no inbounds; mergeUnified is what adds one.
        assertEquals(0, cfg.optJSONArray("inbounds")?.length())
    }

    // ----------------------------------------------------------------- merged

    @Test
    fun `merging one config only adds an inbound`() {
        val one = full(vlessTls("Alpha", "a", "a.com"))
        val merged = SingBoxConverter.mergeUnified(listOf(one))!!
        assertTrue(tags(merged.optJSONArray("outbounds")!!).contains("Alpha"))
        assertNotNull(merged.optJSONArray("inbounds"))
    }

    @Test
    fun `merging several configs builds a selector over a urltest group`() {
        val merged = SingBoxConverter.mergeUnified(
            listOf(full(vlessTls("Alpha", "a", "a.com")), full(vlessTls("Beta", "b", "b.com")))
        )!!

        val outs = merged.optJSONArray("outbounds")!!
        val byTag = (0 until outs.length())
            .mapNotNull { outs.optJSONObject(it) }
            .associateBy { it.optString("tag") }

        val selector = byTag["proxy"]!!
        assertEquals("selector", selector.optString("type"))
        assertEquals("auto", selector.optString("default"))
        val members = selector.optJSONArray("outbounds")!!
        assertEquals(
            listOf("auto", "Alpha", "Beta", "direct"),
            (0 until members.length()).map { members.optString(it) }
        )

        val auto = byTag["auto"]!!
        assertEquals("urltest", auto.optString("type"))
        val autoMembers = auto.optJSONArray("outbounds")!!
        assertEquals(
            listOf("Alpha", "Beta"),
            (0 until autoMembers.length()).map { autoMembers.optString(it) }
        )

        assertEquals("proxy", merged.optJSONObject("route")?.optString("final"))
        assertTrue("both servers survive the merge", byTag.containsKey("Alpha"))
        assertTrue(byTag.containsKey("Beta"))

        // A merged config is meant to be run, so it listens somewhere.
        val inbound = merged.optJSONArray("inbounds")?.optJSONObject(0)!!
        assertEquals("mixed", inbound.optString("type"))
        assertTrue(inbound.optInt("listen_port") > 0)
    }

    @Test
    fun `merging nothing yields nothing`() {
        assertNull(SingBoxConverter.mergeUnified(emptyList()))
    }

    // ---------------------------------------------------------------- helpers

    @Test
    fun `the udp443 flow variant is folded into plain vision`() {
        assertEquals("xtls-rprx-vision", SingBoxConverter.normalizeFlow("xtls-rprx-vision-udp443"))
        assertEquals("xtls-rprx-vision", SingBoxConverter.normalizeFlow("xtls-rprx-vision"))
        assertEquals("", SingBoxConverter.normalizeFlow(""))
        assertEquals("", SingBoxConverter.normalizeFlow(null))
    }
}
