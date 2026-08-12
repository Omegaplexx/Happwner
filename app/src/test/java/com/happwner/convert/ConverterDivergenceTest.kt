package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Seam tests: the exact edges where SingBoxConverter and the mihomo converter look like they do the
// same thing but do not. Every case here is current, verified behaviour.
class ConverterDivergenceTest {

    private fun result(xray: String) = SingBoxConverter.convertToOutbounds(xray)

    private fun single(xray: String): org.json.JSONObject {
        val r = result(xray)
        assertTrue("expected Ok, got $r", r is SingBoxConverter.OutboundsResult.Ok)
        val list = (r as SingBoxConverter.OutboundsResult.Ok).outbounds
        assertEquals(1, list.size)
        return list[0]
    }

    private fun vlessFlow(flowJson: String) = """
        {"remarks":"F","outbounds":[{"tag":"t","protocol":"vless",
         "settings":{"vnext":[{"address":"a.com","port":443,
           "users":[{"id":"u","flow":$flowJson,"encryption":"none"}]}]},
         "streamSettings":{"network":"tcp","security":"tls"}}]}
    """.trimIndent()

    private fun reality(fingerprintJson: String) = """
        {"remarks":"R","outbounds":[{"tag":"t","protocol":"vless",
         "settings":{"vnext":[{"address":"a.com","port":443,
           "users":[{"id":"u","encryption":"none"}]}]},
         "streamSettings":{"network":"tcp","security":"reality",
           "realitySettings":{"serverName":"s","publicKey":"P","shortId":"a",
                              "fingerprint":$fingerprintJson}}}]}
    """.trimIndent()

    private fun wireguard(endpointJson: String) = """
        {"remarks":"W","outbounds":[{"tag":"w","protocol":"wireguard",
         "settings":{"secretKey":"SK","address":["10.0.0.2/32"],
                     "peers":[{"endpoint":$endpointJson,"publicKey":"PK"}]}}]}
    """.trimIndent()

    // ------------------------------------------------------------------ flow Trimming and "none"
    // are shared with the mihomo converter because they describe the input.

    @Test
    fun `normalizeFlow trims`() {
        assertEquals("xtls-rprx-vision", SingBoxConverter.normalizeFlow(" xtls-rprx-vision "))
    }

    @Test
    fun `normalizeFlow reads none as no flow`() {
        assertEquals("", SingBoxConverter.normalizeFlow("none"))
        assertEquals("", SingBoxConverter.normalizeFlow("  none  "))
    }

    @Test
    fun `normalizeFlow only strips udp443 from the vision flow`() {
        assertEquals("xtls-rprx-vision", SingBoxConverter.normalizeFlow("xtls-rprx-vision-udp443"))
        // Not a generic suffix strip: any other flow keeps it.
        assertEquals(
            "xtls-rprx-direct-udp443",
            SingBoxConverter.normalizeFlow("xtls-rprx-direct-udp443")
        )
    }

    @Test
    fun `normalizeFlow is case sensitive`() {
        assertEquals("XTLS-RPRX-VISION", SingBoxConverter.normalizeFlow("XTLS-RPRX-VISION"))
    }

    @Test
    fun `none and stray whitespace no longer reject the outbound`() {
        assertFalse(single(vlessFlow("\"none\"")).has("flow"))
        assertEquals(
            "xtls-rprx-vision",
            single(vlessFlow("\" xtls-rprx-vision \"")).optString("flow")
        )
    }

    @Test
    fun `a flow sing-box genuinely cannot express still rejects the outbound`() {
        // Normalisation leaves this one alone, so it fails VLESS_FLOW_OK.
        assertTrue(
            "expected Unsupported",
            result(vlessFlow("\"xtls-rprx-direct-udp443\"")) is SingBoxConverter.OutboundsResult.Unsupported
        )
    }

    @Test
    fun `a json null flow is treated as absent`() {
        val o = single(vlessFlow("null"))
        assertFalse(o.has("flow"))
    }

    // uTLS: utlsFp() falls back to "chrome" for anything it does not recognise, and the two accepted sets
    // are target vocabularies rather than a shared Xray concern - do not merge them.

    @Test
    fun `an unknown fingerprint falls back to chrome`() {
        for (fp in listOf("\"bogus\"", "123", "null", "true")) {
            val utls = single(reality(fp)).optJSONObject("tls")?.optJSONObject("utls")
            assertEquals("fingerprint $fp", "chrome", utls?.optString("fingerprint"))
        }
    }

    @Test
    fun `fingerprint matching is case sensitive so Chrome becomes chrome by fallback`() {
        val utls = single(reality("\"Chrome\"")).optJSONObject("tls")?.optJSONObject("utls")
        assertEquals("chrome", utls?.optString("fingerprint"))
    }

    @Test
    fun `versioned fingerprints mihomo knows are downgraded here`() {
        // mihomo accepts chrome120; sing-box's set does not, so it lands on
        // the fallback. A shared fingerprint set would break one of the two.
        val utls = single(reality("\"chrome120\"")).optJSONObject("tls")?.optJSONObject("utls")
        assertEquals("chrome", utls?.optString("fingerprint"))
    }

    // ------------------------------------------------------------- host:port

    @Test
    fun `a bracketed ipv6 endpoint splits into address and port`() {
        val peer = single(wireguard("\"[2001:db8::1]:51820\"")).optJSONArray("peers")?.optJSONObject(0)!!
        assertEquals("2001:db8::1", peer.optString("address"))
        assertEquals(51820, peer.optInt("port"))
    }

    @Test
    fun `an endpoint without a port yields port zero`() {
        val peer = single(wireguard("\"w.com\"")).optJSONArray("peers")?.optJSONObject(0)!!
        assertEquals("w.com", peer.optString("address"))
        assertEquals(0, peer.optInt("port"))
    }

    @Test
    fun `an unbracketed ipv6 is kept whole rather than split on its colons`() {
        val peer = single(wireguard("\"2001:db8::1\"")).optJSONArray("peers")?.optJSONObject(0)!!
        assertEquals("2001:db8::1", peer.optString("address"))
        assertEquals(0, peer.optInt("port"))
    }

    // ------------------------------------------------------- scalar coercion These pin what
    // happens with the loosely typed values the mihomo accessors were written to absorb.

    @Test
    fun `a quoted port is coerced to a number`() {
        val xray = """
            {"remarks":"P","outbounds":[{"tag":"t","protocol":"vless",
             "settings":{"vnext":[{"address":"a.com","port":"443",
               "users":[{"id":"u","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls"}}]}
        """.trimIndent()
        // sing-box wants a number here; a quoted one used to leak through and
        // make the whole generated config unloadable.
        val port = single(xray).opt("server_port")
        assertTrue("expected a number, got ${'$'}{port?.javaClass?.simpleName}", port is Int)
        assertEquals(443, port)
    }

    @Test
    fun `a quoted alterId is coerced to a number`() {
        val xray = """
            {"remarks":"P","outbounds":[{"tag":"t","protocol":"vmess",
             "settings":{"vnext":[{"address":"a.com","port":80,
               "users":[{"id":"u","alterId":"0"}]}]},
             "streamSettings":{"network":"tcp"}}]}
        """.trimIndent()
        val aid = single(xray).opt("alter_id")
        assertTrue("expected a number, got ${'$'}{aid?.javaClass?.simpleName}", aid is Int)
        assertEquals(0, aid)
    }

    @Test
    fun `a whitespace padded address and uuid are trimmed`() {
        val xray = """
            {"remarks":"P","outbounds":[{"tag":"t","protocol":"vless",
             "settings":{"vnext":[{"address":"  a.com  ","port":443,
               "users":[{"id":"  u  ","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls"}}]}
        """.trimIndent()
        val o = single(xray)
        assertEquals("a.com", o.optString("server"))
        assertEquals("u", o.optString("uuid"))
    }

    @Test
    fun `whitespace around protocol and network no longer rejects the outbound`() {
        val xray = """
            {"remarks":"P","outbounds":[{"tag":"t","protocol":" vless ",
             "settings":{"vnext":[{"address":"a.com","port":443,
               "users":[{"id":"u","encryption":" none "}]}]},
             "streamSettings":{"network":" ws ","security":" tls ",
               "wsSettings":{"path":"/p"}}}]}
        """.trimIndent()
        val o = single(xray)
        assertEquals("vless", o.optString("type"))
        assertEquals("ws", o.optJSONObject("transport")?.optString("type"))
        assertTrue(o.optJSONObject("tls")?.optBoolean("enabled") == true)
    }

    @Test
    fun `a padded plugin name is trimmed on the way out, not just on the way in`() {
        // The supported-check and the emit path read this field separately.
        val xray = """
            {"remarks":"SS","outbounds":[{"tag":"s","protocol":"shadowsocks",
             "settings":{"servers":[{"address":"s.com","port":8388,
               "method":"aes-256-gcm","password":"pw","plugin":"  obfs-local  "}]}}]}
        """.trimIndent()
        assertEquals("obfs-local", single(xray).optString("plugin"))
    }

    @Test
    fun `a boolean written as one is honoured`() {
        val xray = """
            {"remarks":"P","outbounds":[{"tag":"t","protocol":"vless",
             "settings":{"vnext":[{"address":"a.com","port":443,
               "users":[{"id":"u","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls",
               "tlsSettings":{"allowInsecure":1}}}]}
        """.trimIndent()
        assertTrue(single(xray).optJSONObject("tls")?.optBoolean("insecure") == true)
    }

    @Test
    fun `a json null security drops the tls block entirely`() {
        val xray = """
            {"remarks":"P","outbounds":[{"tag":"t","protocol":"vless",
             "settings":{"vnext":[{"address":"a.com","port":443,
               "users":[{"id":"u","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":null}}]}
        """.trimIndent()
        assertNull(single(xray).optJSONObject("tls"))
    }
}
