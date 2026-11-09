package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// The DNS schemes both converters read.
class XrayDnsAddressTest {

	private fun parse(text: String) = XrayDnsAddress.parse(text)

	@Test
	fun `a bare address is plain DNS over UDP`() {
		val kind = parse("8.8.8.8") as XrayDnsAddress.Kind.Remote
		assertEquals("udp", kind.scheme)
		assertEquals("8.8.8.8", kind.host)
		assertEquals(null, kind.port)
	}

	@Test
	fun `a port is kept`() {
		val kind = parse("8.8.8.8:5353") as XrayDnsAddress.Kind.Remote
		assertEquals(5353, kind.port)
	}

	@Test
	fun `an HTTPS resolver keeps its query path`() {
		val kind = parse("https://1.1.1.1/dns-query") as XrayDnsAddress.Kind.Remote
		assertEquals("https", kind.scheme)
		assertEquals("dns-query", kind.path)
	}

	@Test
	fun `every spelling of HTTP3 reads the same`() {
		for (form in listOf("h3://1.1.1.1/dns-query", "http3://1.1.1.1/dns-query",
							"https3://1.1.1.1/dns-query", "https+h3://1.1.1.1/dns-query")) {
			val kind = parse(form) as XrayDnsAddress.Kind.Remote
			assertEquals("$form should read as h3", "h3", kind.scheme)
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
		val uuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"
		fun cfg(server: String) = """
            {"outbounds":[{"protocol":"vless","tag":"p","settings":{"vnext":[{"address":"a.example.com",
             "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls",
             "tlsSettings":{"serverName":"a.example.com"}}}],
             "dns":{"servers":["$server"]}}
		""".trimIndent().replace("\n", "")

		val singBox = SubscriptionConverter.convert(cfg("h3://1.1.1.1/dns-query"), jsonToUri = false,
			base64Result = false, xrayToSingBox = true)
		assertTrue("sing-box names it h3: $singBox",
			singBox.contains("\"type\":\"h3\"") || singBox.contains("\"h3\""))

		val mihomo = SubscriptionConverter.convert(cfg("h3://1.1.1.1/dns-query"), jsonToUri = false,
			base64Result = false, xrayToSingBox = false, xrayToMihomo = true)
		assertTrue("mihomo takes no HTTP/3 DNS, so it becomes https: $mihomo",
			mihomo.contains("https://1.1.1.1/dns-query"))

		val mhPlain = SubscriptionConverter.convert(cfg("8.8.8.8"), jsonToUri = false,
			base64Result = false, xrayToSingBox = false, xrayToMihomo = true)
		assertTrue("a bare address stays bare for mihomo: $mhPlain",
			mhPlain.contains("nameserver: [8.8.8.8]"))
	}
}
