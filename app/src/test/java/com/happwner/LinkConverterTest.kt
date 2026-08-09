package com.happwner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LinkConverterTest {
    @Test
    fun prettyPrintedJsonIsConvertedAsOneDocument() {
        val input = config(
            vlessOutbound("first.example.com", "First"),
        )

        val result = LinkConverter.convert(input, jsonToUri = true, tryBase64 = false)

        assertTrue(result.startsWith("vless://"))
        assertTrue(result.contains("@first.example.com:443"))
    }

    @Test
    fun everyOutboundIsPreservedInTheResult() {
        val input = config(
            vlessOutbound("first.example.com", "First"),
            trojanOutbound("second.example.com", "Second"),
        )

        val links = LinkConverter.convert(input, jsonToUri = true, tryBase64 = false).lines()

        assertEquals(2, links.size)
        assertTrue(links[0].startsWith("vless://"))
        assertTrue(links[1].startsWith("trojan://"))
    }

    @Test
    fun malformedSupportedOutboundKeepsOriginalJson() {
        val malformedVless = """
            {
              "protocol": "vless",
              "tag": "Broken",
              "settings": {
                "vnext": [{"address": "broken.example.com", "port": 443}]
              }
            }
        """.trimIndent()
        val input = config(
            malformedVless,
            trojanOutbound("working.example.com", "Working"),
        )

        val result = LinkConverter.convert(input, jsonToUri = true, tryBase64 = false)

        assertEquals(input.trim(), result)
    }

    @Test
    fun unsupportedProxyOutboundPreventsPartialConversion() {
        val unsupportedSocks = """
            {
              "protocol": "socks",
              "tag": "Unsupported",
              "settings": {
                "servers": [{"address": "socks.example.com", "port": 1080}]
              }
            }
        """.trimIndent()
        val input = config(
            vlessOutbound("working.example.com", "Working"),
            unsupportedSocks,
        )

        val result = LinkConverter.convert(input, jsonToUri = true, tryBase64 = false)

        assertEquals(input.trim(), result)
    }

    private fun config(vararg outbounds: String): String = """
        {
          "outbounds": [
            ${outbounds.joinToString(",\n")}
          ]
        }
    """.trimIndent()

    private fun vlessOutbound(address: String, tag: String): String = """
        {
          "protocol": "vless",
          "tag": "$tag",
          "settings": {
            "vnext": [{
              "address": "$address",
              "port": 443,
              "users": [{
                "id": "11111111-1111-4111-8111-111111111111",
                "encryption": "none"
              }]
            }]
          },
          "streamSettings": {"network": "tcp", "security": "none"}
        }
    """.trimIndent()

    private fun trojanOutbound(address: String, tag: String): String = """
        {
          "protocol": "trojan",
          "tag": "$tag",
          "settings": {
            "servers": [{
              "address": "$address",
              "port": 443,
              "password": "secret"
            }]
          },
          "streamSettings": {"network": "tcp", "security": "tls"}
        }
    """.trimIndent()
}
