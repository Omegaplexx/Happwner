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
		val result = SingBoxConverter.convertToOutbounds(xray, "")
		assertTrue(result is SingBoxConverter.OutboundsResult.Ok)
		val out = (result as SingBoxConverter.OutboundsResult.Ok).outbounds[0]
		assertEquals(" pw ", out.getString("password"))
	}
	@Test
	fun `shadowsocks password survives conversion intact`() {
		val xray = """{"outbounds":[{"protocol":"shadowsocks","tag":"p","settings":
            {"servers":[{"address":"e.com","port":8388,"method":"aes-256-gcm","password":" pw "}]}}]}"""
		val result = SingBoxConverter.convertToOutbounds(xray, "")
		assertTrue(result is SingBoxConverter.OutboundsResult.Ok)
		val out = (result as SingBoxConverter.OutboundsResult.Ok).outbounds[0]
		assertEquals(" pw ", out.getString("password"))
	}
	// Machine-generated values keep their trim: widening xStrRaw to cover these would put panel
	// whitespace into a uuid.
	@Test
	fun `uuid is still trimmed`() {
		val xray = """{"outbounds":[{"protocol":"vless","tag":"p","settings":
            {"vnext":[{"address":"e.com","port":443,"users":[{"id":" abc-123 "}]}]}}]}"""
		val result = SingBoxConverter.convertToOutbounds(xray, "") as SingBoxConverter.OutboundsResult.Ok
		assertEquals("abc-123", result.outbounds[0].getString("uuid"))
	}
	@Test
	fun `mihomo trojan password survives conversion intact`() {
		val xray = """{"outbounds":[{"protocol":"trojan","tag":"p","settings":
            {"servers":[{"address":"e.com","port":443,"password":" pw "}]},
            "streamSettings":{"security":"tls","tlsSettings":{"serverName":"s.com"}}}]}"""
		val result = MihomoConverter.convert(xray)
		assertTrue(result is MihomoConverter.Result.Ok)
		val yaml = (result as MihomoConverter.Result.Ok).yaml
		// The YAML must quote it, otherwise the spaces are lost on re-parse.
		assertTrue("the password lost its spaces: $yaml",
			yaml.contains("\" pw \"") || yaml.contains("' pw '"))
	}
}
