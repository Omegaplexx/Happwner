package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Turning an Xray outbound into a share link.
class LinkBuilderTest {

    private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
    private val pbk = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"

    private fun link(outbound: String, remarks: String = "N"): String =
        LinkConverter.convert("""{"remarks":"$remarks","outbounds":[$outbound]}""", jsonToUri = true).trim()

    private fun vless(stream: String, user: String = """{"id":"$uuid","encryption":"none"}""") =
        """{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,
           "users":[$user]}]},"streamSettings":$stream}""".trimIndent().replace("\n", "")

    private fun trojan(stream: String) =
        """{"protocol":"trojan","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,
           "password":"pw"}]},"streamSettings":$stream}""".trimIndent().replace("\n", "")

    private fun params(uri: String): Map<String, String> {
        val q = uri.substringAfter('?', "").substringBefore('#')
        if (q.isEmpty()) return emptyMap()
        return q.split("&").mapNotNull {
            val i = it.indexOf('=')
            if (i < 0) null else java.net.URLDecoder.decode(it.substring(0, i), "UTF-8") to
                java.net.URLDecoder.decode(it.substring(i + 1), "UTF-8")
        }.toMap()
    }

    private fun vmessBlob(uri: String): JSONObject {
        assertTrue("not a vmess link: $uri", uri.startsWith("vmess://"))
        val raw = uri.removePrefix("vmess://")
        val padded = raw + "=".repeat((4 - raw.length % 4) % 4)
        return JSONObject(String(android.util.Base64.decode(padded, android.util.Base64.DEFAULT)))
    }

    // ------------------------------------------------------------ transports ----

    @Test
    fun `a websocket node carries its path and host`() {
        // Without these the link points at the right server and the wrong
        // endpoint, which fails in a way that looks like a dead node.
        val p = params(link(vless("""{"network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com"},"wsSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}}}""")))
        assertEquals("ws", p["type"])
        assertEquals("/ws", p["path"])
        assertEquals("cdn.example.com", p["host"])
    }

    @Test
    fun `a gRPC node carries its service name`() {
        val p = params(link(vless("""{"network":"grpc","security":"tls","tlsSettings":{"serverName":"a.example.com"},"grpcSettings":{"serviceName":"gun","multiMode":true}}""")))
        assertEquals("grpc", p["type"])
        assertEquals("gun", p["serviceName"])
        assertEquals("multi", p["mode"])
    }

    @Test
    fun `the HTTP-shaped transports are named as a link names them`() {
        // Xray spells the HTTP/2 transport three ways internally; links and
        // sing-box both call it http, and writing h2 here left clients guessing.
        val h2 = params(link(vless("""{"network":"h2","security":"tls","tlsSettings":{"serverName":"a.example.com"},"httpSettings":{"path":"/h2","host":["a.example.com"]}}""")))
        assertEquals("http", h2["type"])
        assertEquals("/h2", h2["path"])
        assertEquals("a.example.com", h2["host"])

        val hu = params(link(vless("""{"network":"httpupgrade","security":"tls","tlsSettings":{"serverName":"a.example.com"},"httpupgradeSettings":{"path":"/hu","host":"h.example.com"}}""")))
        assertEquals("httpupgrade", hu["type"])
        assertEquals("/hu", hu["path"])
        assertEquals("h.example.com", hu["host"])
    }

    @Test
    fun `the raw TCP masquerade is carried too`() {
        val p = params(link(vless("""{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"http","request":{"path":["/mask"],"headers":{"Host":["m.example.com"]}}}}}""")))
        assertEquals("tcp", p["type"])
        assertEquals("http", p["headerType"])
        assertEquals("/mask", p["path"])
        assertEquals("m.example.com", p["host"])
    }

    @Test
    fun `mKCP carries its seed`() {
        val p = params(link(vless("""{"network":"kcp","security":"none","kcpSettings":{"seed":"s3cr3t","header":{"type":"srtp"}}}""")))
        assertEquals("kcp", p["type"])
        assertEquals("s3cr3t", p["seed"])
        assertEquals("srtp", p["headerType"])
    }

    // ------------------------------------------------------------------ TLS ----

    @Test
    fun `a plain TLS node keeps its server name`() {
        // The SNI used to be read only from realitySettings, so every plain TLS
        // node produced a link with an empty one.
        val p = params(link(vless("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com","alpn":["h2","http/1.1"],"allowInsecure":true}}""")))
        assertEquals("tls", p["security"])
        assertEquals("a.example.com", p["sni"])
        assertEquals("h2,http/1.1", p["alpn"])
        assertEquals("1", p["allowInsecure"])
    }

    @Test
    fun `a fingerprint is written only when the source names one`() {
        // "chrome" used to be written whatever the source said, telling the
        // client to mimic a browser the configuration never asked for.
        val without = params(link(vless("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}""")))
        assertFalse("a fingerprint appeared from nowhere: $without", without.containsKey("fp"))

        val with = params(link(vless("""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com","fingerprint":"firefox"}}""")))
        assertEquals("firefox", with["fp"])
    }

    @Test
    fun `REALITY carries its key, short id and spider`() {
        val p = params(link(vless("""{"network":"tcp","security":"reality","realitySettings":{"serverName":"a.example.com","publicKey":"$pbk","shortId":"0123456789abcdef","spiderX":"/spx","fingerprint":"chrome"}}""")))
        assertEquals("reality", p["security"])
        assertEquals(pbk, p["pbk"])
        assertEquals("0123456789abcdef", p["sid"])
        assertEquals("/spx", p["spx"])
        assertEquals("chrome", p["fp"])
        assertEquals("a.example.com", p["sni"])
    }

    // ------------------------------------------------------------ well-formed ----

    @Test
    fun `an IPv6 address is bracketed`() {
        // Without the brackets the colons of the address are read as the port
        // separator and the link does not parse at all.
        val uri = link("""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"2001:db8::1","port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}}""")
        assertTrue("no brackets in $uri", uri.contains("@[2001:db8::1]:443"))
    }

    @Test
    fun `values that would break the query are escaped`() {
        val uri = link(vless("""{"network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com"},"wsSettings":{"path":"/a?b=c&d#e"}}"""))
        val p = params(uri)
        assertEquals("the path must survive intact", "/a?b=c&d#e", p["path"])
        // And the raw characters must not appear loose in the query.
        assertFalse("a raw & leaked into the query: $uri", uri.substringAfter('?').substringBefore('#').contains("&d"))
    }

    @Test
    fun `nothing is written empty`() {
        // Links used to carry flow=&pbk=&sid=&sni=, which says nothing and which
        // some parsers read as a setting rather than as its absence.
        val uri = link(vless("""{"network":"tcp","security":"none"}"""))
        for (empty in listOf("flow=&", "pbk=&", "sid=&", "sni=&", "path=&", "host=&")) {
            assertFalse("$empty in $uri", uri.contains(empty))
        }
        assertFalse("a trailing empty value in $uri", uri.substringBefore('#').endsWith("="))
    }

    @Test
    fun `the flow travels as the source wrote it`() {
        val p = params(link(vless(
            """{"network":"tcp","security":"reality","realitySettings":{"serverName":"a.example.com","publicKey":"$pbk","shortId":"aa"}}""",
            user = """{"id":"$uuid","encryption":"none","flow":"xtls-rprx-vision-udp443"}"""
        )))
        // The link is an Xray-format one and the clients that read it act on the -udp443 part, so
        // it travels whole.
        assertEquals("xtls-rprx-vision-udp443", p["flow"])
    }

    // --------------------------------------------------------------- trojan ----

    @Test
    fun `a trojan link carries the same transport detail`() {
        val uri = link(trojan("""{"network":"grpc","security":"tls","tlsSettings":{"serverName":"a.example.com"},"grpcSettings":{"serviceName":"gun"}}"""))
        val p = params(uri)
        assertTrue(uri.startsWith("trojan://pw@a.example.com:443"))
        assertEquals("grpc", p["type"])
        assertEquals("gun", p["serviceName"])
        assertEquals("tls", p["security"])
        assertEquals("a.example.com", p["sni"])
        // Trojan links have always repeated the SNI here and some parsers read
        // only this one.
        assertEquals("a.example.com", p["host"])
    }

    // ---------------------------------------------------------------- vmess ----

    @Test
    fun `a vmess blob describes its transport and TLS`() {
        val blob = vmessBlob(link("""{"protocol":"vmess","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"$uuid","alterId":0,"security":"auto"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com","alpn":["h2"],"fingerprint":"chrome"},"wsSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}}}}"""))
        assertEquals("a.example.com", blob.optString("add"))
        assertEquals("443", blob.optString("port"))
        assertEquals(uuid, blob.optString("id"))
        assertEquals("ws", blob.optString("net"))
        assertEquals("/ws", blob.optString("path"))
        assertEquals("cdn.example.com", blob.optString("host"))
        assertEquals("tls", blob.optString("tls"))
        // These four used to be missing entirely.
        assertEquals("a.example.com", blob.optString("sni"))
        assertEquals("h2", blob.optString("alpn"))
        assertEquals("chrome", blob.optString("fp"))
        assertEquals("none", blob.optString("type"))
    }

    // ------------------------------------------------------- socks and http ----

    @Test
    fun `a socks node becomes a link instead of raw JSON`() {
        val withAuth = link("""{"protocol":"socks","tag":"n","settings":{"servers":[{"address":"a.example.com","port":1080,"users":[{"user":"u","pass":"p"}]}]}}""")
        assertTrue("not a socks link: $withAuth", withAuth.startsWith("socks://"))
        assertTrue("no credentials in $withAuth", withAuth.contains("@a.example.com:1080"))

        val noAuth = link("""{"protocol":"socks","tag":"n","settings":{"servers":[{"address":"a.example.com","port":1080}]}}""")
        assertTrue(noAuth.startsWith("socks://a.example.com:1080"))
    }

    @Test
    fun `an http proxy takes the scheme its TLS implies`() {
        val plain = link("""{"protocol":"http","tag":"n","settings":{"servers":[{"address":"a.example.com","port":8080,"users":[{"user":"u","pass":"p"}]}]}}""")
        assertTrue("not an http link: $plain", plain.startsWith("http://u:p@a.example.com:8080"))

        val secure = link("""{"protocol":"http","tag":"n","settings":{"servers":[{"address":"a.example.com","port":8080}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}}""")
        assertTrue("TLS must show in the scheme: $secure", secure.startsWith("https://a.example.com:8080"))
        assertEquals("a.example.com", params(secure)["sni"])
    }

    // ------------------------------------------------------------- defaults ----

    @Test
    fun `a node with no stream settings still states what it is`() {
        val p = params(link("""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"$uuid","encryption":"none"}]}]}}"""))
        assertEquals("tcp", p["type"])
        assertEquals("none", p["security"])
        assertEquals("none", p["encryption"])
    }
}
