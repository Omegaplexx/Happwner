package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// A password, a key and an identifier come back exactly as they were given.
class CredentialsPreservedTest {

    @Test
    fun `trojan password survives conversion intact`() {
        val xray = """{"outbounds":[{"protocol":"trojan","tag":"p","settings":
            {"servers":[{"address":"e.com","port":443,"password":" pw "}]}}]}"""
        val r = SingBoxConverter.convertToOutbounds(xray, "")
        assertTrue(r is SingBoxConverter.OutboundsResult.Ok)
        val out = (r as SingBoxConverter.OutboundsResult.Ok).outbounds[0]
        assertEquals(" pw ", out.getString("password"))
    }
    @Test
    fun `shadowsocks password survives conversion intact`() {
        val xray = """{"outbounds":[{"protocol":"shadowsocks","tag":"p","settings":
            {"servers":[{"address":"e.com","port":8388,"method":"aes-256-gcm","password":" pw "}]}}]}"""
        val r = SingBoxConverter.convertToOutbounds(xray, "")
        assertTrue(r is SingBoxConverter.OutboundsResult.Ok)
        val out = (r as SingBoxConverter.OutboundsResult.Ok).outbounds[0]
        assertEquals(" pw ", out.getString("password"))
    }
    // The other half of H1: machine-generated values must KEEP their trim. Widening xStrRaw to
    // cover these would put panel whitespace into a uuid.
    @Test
    fun `uuid is still trimmed`() {
        val xray = """{"outbounds":[{"protocol":"vless","tag":"p","settings":
            {"vnext":[{"address":"e.com","port":443,"users":[{"id":" abc-123 "}]}]}}]}"""
        val r = SingBoxConverter.convertToOutbounds(xray, "") as SingBoxConverter.OutboundsResult.Ok
        assertEquals("abc-123", r.outbounds[0].getString("uuid"))
    }
    @Test
    fun `mihomo trojan password survives conversion intact`() {
        val xray = """{"outbounds":[{"protocol":"trojan","tag":"p","settings":
            {"servers":[{"address":"e.com","port":443,"password":" pw "}]},
            "streamSettings":{"security":"tls","tlsSettings":{"serverName":"s.com"}}}]}"""
        val r = MihomoConverter.convert(xray)
        assertTrue(r is MihomoConverter.Result.Ok)
        val yaml = (r as MihomoConverter.Result.Ok).yaml
        // The YAML must quote it, otherwise the spaces are lost on re-parse.
        assertTrue("the password lost its spaces: $yaml", yaml.contains("\" pw \"") || yaml.contains("' pw '"))
    }
}
