package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// How the mihomo pass sits in the conversion pipeline.
class MihomoPassOrderTest {

    private val xray = """
        { "remarks": "node", "outbounds": [{ "tag": "proxy", "protocol": "vless",
          "settings": { "vnext": [{ "address": "a.example.com", "port": 443,
            "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "encryption": "none" }] }] } }] }
    """.trimIndent()

    @Test
    fun `mihomo mode returns yaml`() {
        val out = LinkConverter.convertWithStats(
            xray, jsonToUri = false, base64Result = false, xrayToSb = false, xrayToMihomo = true
        )
        assertTrue(out.text.startsWith("mixed-port:"))
        assertTrue(out.text.contains("- name: node"))
        assertTrue(out.text.contains("MATCH,PROXY"))
    }

    @Test
    fun `mihomo takes priority over the uri and sing-box passes`() {
        val out = LinkConverter.convertWithStats(
            xray, jsonToUri = true, base64Result = false, xrayToSb = true, xrayToMihomo = true
        )
        assertTrue(out.text.contains("proxy-groups:"))
        assertFalse(out.text.contains("vless://"))
        assertFalse(out.text.contains("\"outbounds\""))
    }

    @Test
    fun `a config per line is gathered into one document`() {
        val body = xray.replace("\n", " ") + "\n" + xray.replace("\n", " ").replace("node", "node2")
        val out = LinkConverter.convertWithStats(
            body, jsonToUri = false, base64Result = false, xrayToSb = false, xrayToMihomo = true
        )
        assertTrue(out.text.contains("- name: node\n"))
        assertTrue(out.text.contains("- name: node2"))
    }

    @Test
    fun `a body with no xray config falls through untouched`() {
        val links = "vless://uuid@a.example.com:443#one\nvmess://abc"
        val out = LinkConverter.convertWithStats(
            links, jsonToUri = false, base64Result = false, xrayToSb = false, xrayToMihomo = true
        )
        assertEquals(links, out.text)
    }

    @Test
    fun `mihomo off leaves the body to the other passes`() {
        val out = LinkConverter.convertWithStats(
            xray, jsonToUri = false, base64Result = false, xrayToSb = false, xrayToMihomo = false
        )
        assertEquals(xray, out.text)
    }
}
