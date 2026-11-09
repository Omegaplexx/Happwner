package com.happwner.convert

import java.net.URLDecoder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Compatibility cases: the direct VLESS form, the transport named by streamSettings.method, the URI
// parameters of the newer TLS/REALITY/XHTTP fields, Hysteria2 certificate pinning and ECH, and
// punycode authorities.
class ConverterCompatibilityAuditTest {

	private val uuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"

	private fun toUri(body: String): String =
		SubscriptionConverter.convert(body, jsonToUri = true, base64Result = false).trim()

	private fun queryParams(uri: String): Map<String, String> {
		val query = uri.substringAfter('?', "").substringBefore('#')
		if (query.isEmpty()) return emptyMap()
		return query.split('&').mapNotNull { item ->
			val separator = item.indexOf('=')
			if (separator < 0) return@mapNotNull null
			URLDecoder.decode(item.substring(0, separator), "UTF-8") to
				URLDecoder.decode(item.substring(separator + 1), "UTF-8")
		}.toMap()
	}

	private fun legacyVless(streamSettings: String, remarks: String = "Audit"): String = """
        {
          "remarks": "$remarks",
          "outbounds": [{
            "protocol": "vless",
            "settings": {
              "vnext": [{
                "address": "a.example.com",
                "port": 443,
                "users": [{
                  "id": "$uuid",
                  "encryption": "none"
                }]
              }]
            },
            "streamSettings": $streamSettings
          }]
        }
	""".trimIndent()

	// The flow sits on the raw form: Xray runs Vision only over a connection that is TLS itself, and
	// its gRPC dialer hands back a wrapper, so a Vision node under gRPC never connects and every
	// pass refuses it. The gRPC form here carries the streamSettings.method spelling instead.
	private fun currentDirectVless(transport: String = "grpc"): String = """
        {
          "remarks": "Current VLESS",
          "outbounds": [{
            "protocol": "vless",
            "settings": {
              "address": "a.example.com",
              "port": 443,
              "id": "$uuid",
              "encryption": "none"${if (transport == "raw") ",\n              \"flow\": \"xtls-rprx-vision\""
			  else ""}
            },
            "streamSettings": {
              "method": "$transport",
              "security": "tls",
              "tlsSettings": {
                "serverName": "front.example.com"
              }${if (transport == "grpc") ",\n              \"grpcSettings\": {\n" +
                "                \"serviceName\": \"gun\"\n              }" else ""}
            }
          }]
        }
	""".trimIndent()

	@Test
	fun currentDirectVlessBecomesUri() {
		val uri = toUri(currentDirectVless())
		assertTrue("expected a VLESS URI, got: $uri", uri.startsWith("vless://"))

		val params = queryParams(uri)
		assertEquals("none", params["encryption"])
		assertEquals("grpc", params["type"])
		assertEquals("gun", params["serviceName"])
		assertEquals("tls", params["security"])
		assertEquals("front.example.com", params["sni"])

		val vision = queryParams(toUri(currentDirectVless("raw")))
		assertEquals("xtls-rprx-vision", vision["flow"])
		assertEquals("tcp", vision["type"])
	}

	@Test
	fun currentDirectVlessBecomesUsableSingBoxOutbound() {
		val result = SingBoxConverter.convertToOutbounds(currentDirectVless(), "Current VLESS")
		assertTrue("expected a supported VLESS outbound, got: $result",
			result is SingBoxConverter.OutboundsResult.Ok)

		val outbound = (result as SingBoxConverter.OutboundsResult.Ok).outbounds.first()
		assertEquals("vless", outbound.optString("type"))
		assertEquals("a.example.com", outbound.optString("server"))
		assertEquals(443, outbound.optInt("server_port"))
		assertEquals(uuid, outbound.optString("uuid"))

		val transport = outbound.optJSONObject("transport")
		assertEquals("grpc", transport?.optString("type"))
		assertEquals("gun", transport?.optString("service_name"))

		val vision = SingBoxConverter.convertToOutbounds(currentDirectVless("raw"), "Current VLESS")
		assertTrue("expected a supported VLESS outbound, got: $vision",
			vision is SingBoxConverter.OutboundsResult.Ok)
		assertEquals("xtls-rprx-vision",
			(vision as SingBoxConverter.OutboundsResult.Ok).outbounds.first().optString("flow"))
	}

	@Test
	fun currentTransportMethodReachesMihomo() {
		val result = MihomoConverter.convert(currentDirectVless())
		assertTrue("expected a Mihomo document, got: $result", result is MihomoConverter.Result.Ok)

		val yaml = (result as MihomoConverter.Result.Ok).yaml
		assertTrue("gRPC network is missing:\n$yaml", yaml.contains("network: grpc"))
		assertTrue("gRPC options are missing:\n$yaml", yaml.contains("grpc-opts:"))
		assertTrue("gRPC service name is missing:\n$yaml", yaml.contains("gun"))
	}

	@Test
	fun xhttpExtraIsCarriedByVlessUri() {
		val body = legacyVless(
			"""{
              "network": "xhttp",
              "security": "tls",
              "tlsSettings": {"serverName": "a.example.com"},
              "xhttpSettings": {
                "path": "/x",
                "host": "cdn.example.com",
                "mode": "auto",
                "extra": {"xPaddingBytes": "100-200"}
              }
            }""",
			remarks = "XHTTP extra",
		)

		val params = queryParams(toUri(body))
		assertEquals("xhttp", params["type"])
		assertEquals("/x", params["path"])
		assertEquals("cdn.example.com", params["host"])
		assertEquals("auto", params["mode"])

		val extra = params["extra"]
		assertTrue("xhttpSettings.extra is missing from the URI", !extra.isNullOrEmpty())
		assertEquals("100-200", JSONObject(extra!!).optString("xPaddingBytes"))
	}

	@Test
	fun currentTlsFieldsAreCarriedByVlessUri() {
		val pin = "10a4e6deb9672d8472d83f9ca6beaace16d1d96c7850e8a0c74fecf6cf9d6fca"
		val body = legacyVless(
			"""{
              "network": "tcp",
              "security": "tls",
              "tlsSettings": {
                "serverName": "a.example.com",
                "pinnedPeerCertSha256": "$pin",
                "verifyPeerCertByName": "verify.example.com",
                "echConfigList": "ECH-CONFIG"
              }
            }""",
			remarks = "TLS fields",
		)

		val params = queryParams(toUri(body))
		assertEquals(pin, params["pcs"])
		assertEquals("verify.example.com", params["vcn"])
		assertEquals("ECH-CONFIG", params["ech"])
	}

	@Test
	fun currentRealityFieldsAreCarriedByVlessUri() {
		val body = legacyVless(
			"""{
              "network": "tcp",
              "security": "reality",
              "realitySettings": {
                "serverName": "front.example.com",
                "password": "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw",
                "shortId": "aa",
                "mldsa65Verify": "MLDSA65-VERIFY"
              }
            }""",
			remarks = "REALITY fields",
		)

		val params = queryParams(toUri(body))
		assertEquals("reality", params["security"])
		assertEquals("HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw", params["pbk"])
		assertEquals("aa", params["sid"])
		assertEquals("MLDSA65-VERIFY", params["pqv"])
	}

	@Test
	fun finalMaskIsCarriedByVlessUri() {
		val body = legacyVless(
			"""{
              "network": "tcp",
              "security": "none",
              "finalmask": {
                "tcp": [{
                  "type": "fragment",
                  "settings": {
                    "packets": "tlshello",
                    "lengths": ["3-5"],
                    "delays": ["1-3"]
                  }
                }]
              }
            }""",
			remarks = "FinalMask",
		)

		val finalMask = queryParams(toUri(body))["fm"]
		assertTrue("streamSettings.finalmask is missing from the URI", !finalMask.isNullOrEmpty())
		assertTrue(JSONObject(finalMask!!).has("tcp"))
	}

	@Test
	fun hysteria2CertificatePinAndEchAreCarriedByUri() {
		val pin = "10a4e6deb9672d8472d83f9ca6beaace16d1d96c7850e8a0c74fecf6cf9d6fca"
		val body = """
            {
              "remarks": "HY2 TLS",
              "outbounds": [{
                "protocol": "hysteria",
                "settings": {
                  "version": 2,
                  "address": "h.example.com",
                  "port": 443
                },
                "streamSettings": {
                  "method": "hysteria",
                  "security": "tls",
                  "tlsSettings": {
                    "serverName": "h.example.com",
                    "pinnedPeerCertSha256": "$pin",
                    "echConfigList": "ECH-CONFIG"
                  },
                  "hysteriaSettings": {
                    "version": 2,
                    "auth": "pw"
                  }
                }
              }]
            }
		""".trimIndent()

		val uri = toUri(body)
		assertTrue("expected a Hysteria2 URI, got: $uri", uri.startsWith("hysteria2://"))

		val params = queryParams(uri)
		assertEquals(pin, params["pinSHA256"])
		assertEquals("ECH-CONFIG", params["ech"])
	}

	@Test
	fun idnAuthorityIsWrittenAsPunycode() {
		val body = """
            {
              "remarks": "IDN",
              "outbounds": [{
                "protocol": "vless",
                "settings": {
                  "vnext": [{
                    "address": "пример.рф",
                    "port": 443,
                    "users": [{
                      "id": "$uuid",
                      "encryption": "none"
                    }]
                  }]
                },
                "streamSettings": {
                  "network": "tcp",
                  "security": "tls",
                  "tlsSettings": {"serverName": "пример.рф"}
                }
              }]
            }
		""".trimIndent()

		val uri = toUri(body)
		assertTrue("IDN authority was not converted to Punycode: $uri",
			uri.contains("@xn--e1afmkfd.xn--p1ai:443"))
		assertFalse("Unicode hostname leaked into URI authority: $uri",
			uri.contains("@пример.рф:443"))
	}
}
