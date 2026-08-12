package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// The DNS schemes both converters read.
class XrayDnsAddressTest {

    private fun parse(v: String) = XrayDnsAddress.parse(v)

    @Test
    fun `a bare address is plain DNS over UDP`() {
        val k = parse("8.8.8.8") as XrayDnsAddress.Kind.Remote
        assertEquals("udp", k.scheme)
        assertEquals("8.8.8.8", k.host)
        assertEquals(null, k.port)
    }

    @Test
    fun `a port is kept`() {
        val k = parse("8.8.8.8:5353") as XrayDnsAddress.Kind.Remote
        assertEquals(5353, k.port)
    }

    @Test
    fun `an HTTPS resolver keeps its query path`() {
        val k = parse("https://1.1.1.1/dns-query") as XrayDnsAddress.Kind.Remote
        assertEquals("https", k.scheme)
        assertEquals("dns-query", k.path)
    }

    @Test
    fun `every spelling of HTTP3 reads the same`() {
        for (form in listOf("h3://1.1.1.1/dns-query", "http3://1.1.1.1/dns-query",
                            "https3://1.1.1.1/dns-query", "https+h3://1.1.1.1/dns-query")) {
            val k = parse(form) as XrayDnsAddress.Kind.Remote
            assertEquals("$form should read as h3", "h3", k.scheme)
        }
    }

    @Test
    fun `the local, fake and unusable forms are told apart`() {
        assertEquals(XrayDnsAddress.Kind.Local, parse("localhost"))
        assertEquals(XrayDnsAddress.Kind.FakeDns, parse("fakedns"))
        assertEquals(XrayDnsAddress.Kind.None, parse("rcode://success"))
        assertEquals(XrayDnsAddress.Kind.None, parse(""))
        assertEquals(XrayDnsAddress.Kind.None, parse("nonsense://x"))
    }

    @Test
    fun `dhcp names its interface, or none`() {
        assertEquals(XrayDnsAddress.Kind.Dhcp(""), parse("dhcp://auto"))
        assertEquals(XrayDnsAddress.Kind.Dhcp("eth0"), parse("dhcp://eth0"))
    }

    @Test
    fun `both converters write one reading in their own spelling`() {
        val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
        fun cfg(server: String) = """
            {"outbounds":[{"protocol":"vless","tag":"p","settings":{"vnext":[{"address":"a.example.com",
             "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls",
             "tlsSettings":{"serverName":"a.example.com"}}}],
             "dns":{"servers":["$server"]}}
        """.trimIndent().replace("\n", "")

        val sb = LinkConverter.convert(cfg("h3://1.1.1.1/dns-query"), jsonToUri = false,
            base64Result = false, xrayToSb = true)
        assertTrue("sing-box names it h3: $sb", sb.contains("\"type\":\"h3\"") || sb.contains("\"h3\""))

        val mh = LinkConverter.convert(cfg("h3://1.1.1.1/dns-query"), jsonToUri = false,
            base64Result = false, xrayToSb = false, xrayToMihomo = true)
        assertTrue("mihomo takes no HTTP/3 DNS, so it becomes https: $mh",
            mh.contains("https://1.1.1.1/dns-query"))

        val mhPlain = LinkConverter.convert(cfg("8.8.8.8"), jsonToUri = false,
            base64Result = false, xrayToSb = false, xrayToMihomo = true)
        assertTrue("a bare address stays bare for mihomo: $mhPlain",
            mhPlain.contains("nameserver: [8.8.8.8]"))
    }
}
