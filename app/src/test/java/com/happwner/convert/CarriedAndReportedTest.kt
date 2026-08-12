package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// What a configuration carries across, and what it says about the rest.
class CarriedAndReportedTest {

    private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

    private fun proxy(stream: String? = null, extra: String = ""): String {
        val ss = stream ?: """{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}"""
        return """{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
            "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},"streamSettings":$ss$extra}"""
            .trimIndent().replace("\n", "")
    }

    private fun convert(body: String): JSONObject =
        JSONObject(LinkConverter.convert(body, jsonToUri = false, base64Result = false, xrayToSb = true))

    private fun stats(body: String) =
        LinkConverter.convertWithStats(body, jsonToUri = false, base64Result = false, xrayToSb = true)

    private fun outbound(cfg: JSONObject, type: String): JSONObject {
        val arr = cfg.getJSONArray("outbounds")
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            if (o.optString("type") == type) return o
        }
        throw AssertionError("no $type outbound in $cfg")
    }

    @Test
    fun `mux is reported rather than translated into a different multiplexer`() {
        // Xray multiplexes with mux.cool, which sing-box does not implement - it offers smux, yamux and h2mux.
        // Measured against Xray 26.3.27: the node carries traffic with no multiplex block and none with it.
        val body = """{"outbounds":[${proxy(extra = ""","mux":{"enabled":true,"concurrency":8}""")}]}"""
        val s = stats(body)
        val cfg = JSONObject(s.text)
        assertFalse(
            "a multiplex block here breaks the connection outright",
            outbound(cfg, "vless").has("multiplex")
        )
        assertTrue("and the person should be told why: ${s.notes}",
            s.notes.any { it.contains("mux") })
    }

    @Test
    fun `mux switched off says nothing at all`() {
        val s = stats("""{"outbounds":[${proxy(extra = ""","mux":{"enabled":false,"concurrency":8}""")}]}""")
        assertFalse("nothing was asked for, so there is nothing to report: ${s.notes}",
            s.notes.any { it.contains("mux") })
    }

    @Test
    fun `the TLS cipher list and curves cross over`() {
        val cfg = convert(
            """{"outbounds":[${proxy("""{"network":"tcp","security":"tls","tlsSettings":{
               "serverName":"a.example.com","cipherSuites":"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
               "curvePreferences":["X25519","P256"]}}""".trimIndent().replace("\n", ""))}]}"""
        )
        val tls = outbound(cfg, "vless").getJSONObject("tls")
        val suites = tls.getJSONArray("cipher_suites")
        assertEquals("the colon-separated list becomes an array", 2, suites.length())
        assertEquals("TLS_AES_128_GCM_SHA256", suites.getString(0))
        // curve_preferences arrived in sing-box 1.13, so it stays out for the 1.12 cores.
        assertFalse("curve_preferences is 1.13-only", tls.has("curve_preferences"))
    }

    @Test
    fun `a certificate pin is reported rather than mapped to a different one`() {
        // The core pins the public key inside a certificate; Xray pins the certificate. Writing one
        // where the other was meant would pin the wrong value and fail every handshake.
        val s = stats(
            """{"outbounds":[${proxy("""{"network":"tcp","security":"tls","tlsSettings":{
               "serverName":"a.example.com","pinnedPeerCertSha256":"deadbeef"}}""".trimIndent().replace("\n", ""))}]}"""
        )
        val cfg = JSONObject(s.text)
        assertFalse("must not be written as a public-key pin",
            outbound(cfg, "vless").getJSONObject("tls").has("certificate_public_key_sha256"))
        assertTrue("and it must be reported: ${s.notes}",
            s.notes.any { it.contains("pinnedPeerCertSha256") })
    }

    @Test
    fun `a socks version stated in settings is carried too`() {
        val cfg = convert(
            """{"outbounds":[{"protocol":"socks","tag":"p","settings":{"version":"4",
               "servers":[{"address":"a.example.com","port":1080}]}}]}""".trimIndent().replace("\n", "")
        )
        assertEquals("4", outbound(cfg, "socks").optString("version"))
    }

    @Test
    fun `dropped transport options are named`() {
        val s = stats(
            """{"outbounds":[${proxy("""{"network":"ws","security":"tls",
               "tlsSettings":{"serverName":"a.example.com"},
               "wsSettings":{"path":"/w","heartbeatPeriod":30}}""".trimIndent().replace("\n", ""))}]}"""
        )
        assertTrue("the heartbeat has no equivalent and should be reported: ${s.notes}",
            s.notes.any { it.contains("heartbeatPeriod") })
    }

    @Test
    fun `a pretty-printed configuration reports what a one-line one reports`() {
        // The line walk never sees a multi-line document whole, so an unsupported one came back as
        // itself with nothing counted and nothing said, while the same configuration on one line
        // was counted and explained.
        val body = """{"outbounds":[${proxy("""{"network":"xhttp","security":"tls",
            "tlsSettings":{"serverName":"a.example.com"},"xhttpSettings":{"path":"/x"}}"""
            .trimIndent().replace("\n", ""))}]}"""
        val oneLine = stats(body)
        val pretty = stats(JSONObject(body).toString(2))
        assertTrue("the one-line form should explain itself", oneLine.notes.isNotEmpty())
        assertEquals("and the pretty-printed form the same way",
            oneLine.notes, pretty.notes)
        assertEquals("with the same count", oneLine.xraySkipped, pretty.xraySkipped)
    }
}
