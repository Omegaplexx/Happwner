package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// ECH as the core reads it: sing-box takes the client-side list as PEM, inline in `config` or from
// `config_path`. Xray writes neither, and its string in config_path made the core refuse the document.
class SingBoxEchTest {

    // A real list, from `sing-box generate ech-keypair example.com`.
    private val echBody =
        "AEb+DQBCAAAgACD1Vz6VxpJMbBSfibk+Nb0r49aCMDGRPGxVY4AW+JT/ewAMAAEAAQABAAIAAQADAAtleGFtcGxlLmNvbQAA"

    private fun tlsOf(echConfigList: String): JSONObject {
        val xray = """
            {"remarks":"E","outbounds":[{"protocol":"vless","tag":"a",
            "settings":{"vnext":[{"address":"a.example.com","port":443,
            "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
            "streamSettings":{"network":"tcp","security":"tls",
            "tlsSettings":{"serverName":"a.example.com","echConfigList":"$echConfigList"}}}]}
        """.trimIndent().replace("\n", "")
        val out = LinkConverter.convert(xray, jsonToUri = false, base64Result = false, xrayToSb = true)
        val cfg = JSONObject(out)
        val outbounds = cfg.getJSONArray("outbounds")
        for (i in 0 until outbounds.length()) {
            val o = outbounds.getJSONObject(i)
            if (o.optString("type") == "vless") return o.getJSONObject("tls")
        }
        throw AssertionError("no vless outbound in $out")
    }

    @Test
    fun `a base64 config list becomes an inline PEM config`() {
        val ech = tlsOf(echBody).getJSONObject("ech")
        assertTrue("ECH should be enabled", ech.optBoolean("enabled"))
        assertFalse(
            "the body is not a file name and must not be written as one",
            ech.has("config_path")
        )
        val config = ech.getJSONArray("config")
        assertEquals("-----BEGIN ECH CONFIGS-----", config.getString(0))
        assertEquals(echBody, config.getString(1))
        assertEquals("-----END ECH CONFIGS-----", config.getString(config.length() - 1))
    }

    @Test
    fun `a resolver address enables ECH without a config`() {
        // sing-box has no field for a resolver of its own; with no config it
        // queries the HTTPS record itself, which is the same intent.
        val ech = tlsOf("https://1.1.1.1/dns-query").getJSONObject("ech")
        assertTrue(ech.optBoolean("enabled"))
        assertFalse("a URL is not a file name: $ech", ech.has("config_path"))
        assertFalse("a URL is not a PEM body: $ech", ech.has("config"))
    }

    @Test
    fun `a list that is already PEM is not wrapped twice`() {
        val pem = "-----BEGIN ECH CONFIGS-----\\n$echBody\\n-----END ECH CONFIGS-----"
        val ech = tlsOf(pem).getJSONObject("ech")
        val config = ech.getJSONArray("config")
        var begins = 0
        for (i in 0 until config.length()) {
            if (config.getString(i).startsWith("-----BEGIN")) begins++
        }
        assertEquals("exactly one PEM header expected, got $config", 1, begins)
    }

    @Test
    fun `an unreadable config list enables ECH and drops the body`() {
        val ech = tlsOf("!!!not base64 at all!!!").getJSONObject("ech")
        assertTrue(ech.optBoolean("enabled"))
        assertFalse("garbage must not be passed to the core: $ech", ech.has("config"))
        assertFalse(ech.has("config_path"))
    }
}
