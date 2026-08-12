package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Pins the share links to the schemes their clients actually read: a Shadowsocks 2022 node written the
// pre-2022 way does not connect, and a base64 in the wrong alphabet is refused by a strict parser.
class LinkFormatComplianceTest {

    private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

    private fun conv(o: String): String =
        LinkConverter.convert("""{"remarks":"N","outbounds":[$o]}""", jsonToUri = true).trim()

    private fun userInfo(uri: String): String =
        uri.substringAfter("://").substringBefore("@")

    private fun query(uri: String): Map<String, String> {
        val q = uri.substringAfter('?', "").substringBefore('#')
        if (q.isEmpty()) return emptyMap()
        return q.split("&").mapNotNull {
            val i = it.indexOf('=')
            if (i < 0) null else java.net.URLDecoder.decode(it.substring(0, i), "UTF-8") to
                java.net.URLDecoder.decode(it.substring(i + 1), "UTF-8")
        }.toMap()
    }

    // -------------------------------------------------------- shadowsocks ----

    @Test
    fun `a shadowsocks link uses web-safe base64 with no padding`() {
        // SIP002: userinfo = websafe-base64(method:password). A standard-alphabet
        // '+' or '/' or a trailing '=' is what a strict SIP002 parser trips on.
        val uri = conv("""{"protocol":"shadowsocks","tag":"n","server":"a.example.com","server_port":8388,"method":"chacha20-ietf-poly1305","password":"p@ss/w+rd??"}""")
        assertTrue("not a shadowsocks link: $uri", uri.startsWith("ss://"))
        val ui = userInfo(uri)
        assertFalse("standard-alphabet '+' in userinfo: $uri", ui.contains("+"))
        assertFalse("standard-alphabet '/' in userinfo: $uri", ui.contains("/"))
        assertFalse("padding in userinfo: $uri", ui.contains("="))
        // And it must round-trip back to the credential it came from.
        val decoded = String(android.util.Base64.decode(ui, android.util.Base64.URL_SAFE))
        assertEquals("chacha20-ietf-poly1305:p@ss/w+rd??", decoded)
    }

    @Test
    fun `a 2022 cipher is written plain, not base64`() {
        // SIP022 forbids base64 for the 2022-blake3-* ciphers: method and password go in the
        // userinfo percent-encoded, and a client that follows the spec will not base64-decode them.
        val uri = conv("""{"protocol":"shadowsocks","tag":"n","server":"a.example.com","server_port":8388,"method":"2022-blake3-aes-256-gcm","password":"Xy1+Zpw/aq=="}""")
        assertTrue("not a shadowsocks link: $uri", uri.startsWith("ss://"))
        // The method is visible in the clear (base64 would hide it).
        assertTrue("method should be plain: $uri", uri.startsWith("ss://2022-blake3-aes-256-gcm:"))
        val ui = userInfo(uri)
        val method = java.net.URLDecoder.decode(ui.substringBefore(":"), "UTF-8")
        val password = java.net.URLDecoder.decode(ui.substringAfter(":"), "UTF-8")
        assertEquals("2022-blake3-aes-256-gcm", method)
        assertEquals("Xy1+Zpw/aq==", password)
    }

    // ---------------------------------------------------------------- tuic ----

    @Test
    fun `a tuic link carries every alpn value`() {
        // The TUIC URI takes a comma-separated ALPN list; cutting it to the first
        // entry negotiates a protocol the server may not have offered.
        val uri = conv("""{"protocol":"tuic","tag":"t","settings":{"servers":[{"address":"a.example.com","port":443,"uuid":"$uuid","password":"pw"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com","alpn":["h3","spdy/3.1"]}}}""")
        assertEquals("h3,spdy/3.1", query(uri)["alpn"])
    }

    // ----------------------------------------------------------- hysteria2 ----

    @Test
    fun `hysteria2 port hopping travels as mport with a single port in the authority`() {
        // Every client can still connect on the authority port; the range rides along as mport for
        // the ones that read it, and the authority stays a single valid port so a strict URI parser
        // does not reject the link.
        val uri = conv("""{"protocol":"hysteria2","tag":"h","settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw","ports":"443,5000-6000"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}""")
        assertTrue("authority must hold one valid port: $uri", uri.startsWith("hysteria2://pw@a.example.com:443/"))
        assertEquals("443,5000-6000", query(uri)["mport"])
    }

    @Test
    fun `hysteria2 without hopping writes no mport`() {
        val uri = conv("""{"protocol":"hysteria2","tag":"h","settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}""")
        assertFalse("a single-port node must not carry mport: $uri", query(uri).containsKey("mport"))
    }

    // ---------------------------------------------------------------- IPv6 ----

    @Test
    fun `an IPv6 address is bracketed in every scheme that puts it in the authority`() {
        // Without the brackets the colons of the address are read as the port separator and the
        // link does not parse. Shadowsocks, Hysteria2 and TUIC used to write it bare.
        val v6 = "2001:db8::1"
        val nodes = mapOf(
            "ss" to """{"protocol":"shadowsocks","tag":"n","server":"$v6","server_port":8388,"method":"aes-256-gcm","password":"p"}""",
            "hysteria2" to """{"protocol":"hysteria2","tag":"h","settings":{"servers":[{"address":"$v6","port":443,"password":"pw"}]}}""",
            "tuic" to """{"protocol":"tuic","tag":"t","settings":{"servers":[{"address":"$v6","port":443,"uuid":"$uuid","password":"pw"}]}}""",
            "socks" to """{"protocol":"socks","tag":"n","settings":{"servers":[{"address":"$v6","port":1080}]}}""",
            "trojan" to """{"protocol":"trojan","tag":"n","settings":{"servers":[{"address":"$v6","port":443,"password":"pw"}]}}"""
        )
        for ((name, cfg) in nodes) {
            val uri = conv(cfg)
            assertTrue("$name did not bracket the IPv6 address: $uri", uri.contains("[$v6]"))
            assertFalse("$name left a bare IPv6 address: $uri", uri.contains("@$v6:") || uri.contains("//$v6:"))
        }
    }
}
