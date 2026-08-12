package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// The prefixes both converters read, and the agreement between them.
class XrayConditionsTest {

    private fun name(v: String) = XrayConditions.name(v)
    private fun addr(v: String) = XrayConditions.address(v)

    @Test
    fun `a bare entry matches anywhere in the name`() {
        // Confirmed against Xray 26.3.27: domain ["xample"] catches
        // example.com, sub.example.com and xample.org alike.
        assertEquals(XrayConditions.Name.Keyword("xample"), name("xample"))
    }

    @Test
    fun `each prefix means what Xray means by it`() {
        assertEquals(XrayConditions.Name.Exact("a.test"), name("full:a.test"))
        assertEquals(XrayConditions.Name.Suffix("a.test"), name("domain:a.test"))
        assertEquals(XrayConditions.Name.Keyword("ab"), name("keyword:ab"))
        assertEquals(XrayConditions.Name.Geosite("google"), name("geosite:google"))
        assertEquals(XrayConditions.Name.Pattern("^a.*$"), name("regexp:^a.*$"))
        assertEquals(XrayConditions.Name.External, name("ext:geosite.dat:cn"))
    }

    @Test
    fun `a value the cores would refuse is unusable rather than passed on`() {
        assertEquals(XrayConditions.Name.Unusable, name(""))
        assertEquals(XrayConditions.Name.Unusable, name("full:"))
        assertEquals(XrayConditions.Name.Unusable, name("regexp:((("))
        assertEquals(XrayConditions.Address.Unusable, addr("not-an-address"))
        assertEquals(XrayConditions.Address.Unusable, addr("999.999.999.999/33"))
        assertEquals(XrayConditions.Address.Unusable, addr("10.0.0.0/64"))
    }

    @Test
    fun `an address without a mask means one host`() {
        assertEquals(XrayConditions.Address.Cidr("10.0.0.0/32"), addr("10.0.0.0"))
        assertEquals(XrayConditions.Address.Cidr("2001:db8::1/128"), addr("2001:db8::1"))
        assertEquals(XrayConditions.Address.Cidr("192.168.0.0/16"), addr("192.168.0.0/16"))
    }

    @Test
    fun `a country, its negation and the private set are told apart`() {
        assertEquals(XrayConditions.Address.Country("cn"), addr("geoip:cn"))
        assertEquals(XrayConditions.Address.NotCountry("cn"), addr("geoip:!cn"))
        assertEquals(XrayConditions.Address.Private, addr("geoip:private"))
        assertEquals(XrayConditions.Address.Unusable, addr("geoip:"))
        assertEquals(XrayConditions.Address.Unusable, addr("geoip:!"))
    }

    @Test
    fun `both converters read one entry the same way`() {
        // The divergence this file exists to prevent, checked end to end.
        val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
        fun cfg(entry: String) = """
            {"outbounds":[{"protocol":"vless","tag":"p","settings":{"vnext":[{"address":"a.example.com",
             "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls",
             "tlsSettings":{"serverName":"a.example.com"}}},{"protocol":"freedom","tag":"direct"}],
             "routing":{"rules":[{"type":"field","domain":["$entry"],"outboundTag":"direct"}]}}
        """.trimIndent().replace("\n", "")

        for ((entry, sbField, mihomoRule) in listOf(
            Triple("bare.test", "domain_keyword", "DOMAIN-KEYWORD"),
            Triple("full:a.test", "\"domain\"", "DOMAIN,"),
            Triple("domain:a.test", "domain_suffix", "DOMAIN-SUFFIX"),
            Triple("regexp:^a.*", "domain_regex", "DOMAIN-REGEX")
        )) {
            val sb = LinkConverter.convert(cfg(entry), jsonToUri = false, base64Result = false, xrayToSb = true)
            val mh = LinkConverter.convert(cfg(entry), jsonToUri = false, base64Result = false,
                xrayToSb = false, xrayToMihomo = true)
            assertTrue("sing-box should use $sbField for \"$entry\": $sb", sb.contains(sbField))
            assertTrue("mihomo should use $mihomoRule for \"$entry\": $mh", mh.contains(mihomoRule))
        }
    }
}
