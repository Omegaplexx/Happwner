package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Values a core refuses the whole document over: a field it does not know, or a value it will not take,
// is not skipped but answered by refusing everything, so one odd node costs the whole subscription.
class CoreRejectedValuesTest {

    private val uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
    private val wgPriv = "grGFBnclQlJv+scUUq2/KutuR6p/dHnobZIEGyEtPPU="
    private val wgPub = "C2WjYAXsSBprVLiYYyVs7vW/mOhr21oYDkqkL8lkxQs="

    private fun vlessTls(tls: String) =
        """{"remarks":"T","outbounds":[{"protocol":"vless","tag":"n","settings":{"vnext":[
           {"address":"a.example.com","port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
           "streamSettings":{"network":"tcp","security":"tls","tlsSettings":$tls}}]}"""
            .trimIndent().replace("\n", "")

    private fun wireguard(settings: String) =
        """{"remarks":"W","outbounds":[{"protocol":"wireguard","tag":"n","settings":$settings}]}"""

    private fun sbProxy(body: String): Pair<JSONObject?, List<String>> =
        when (val r = SingBoxConverter.convert(body, "N")) {
            is SingBoxConverter.Result.Ok -> {
                val skip = setOf("direct", "block", "dns", "selector", "urltest")
                val outs = r.config.optJSONArray("outbounds")
                var found: JSONObject? = (0 until (outs?.length() ?: 0))
                    .map { outs!!.getJSONObject(it) }
                    .firstOrNull { it.optString("type") !in skip }
                if (found == null) {
                    val eps = r.config.optJSONArray("endpoints")
                    found = (0 until (eps?.length() ?: 0)).map { eps!!.getJSONObject(it) }.firstOrNull()
                }
                found to r.notes
            }
            is SingBoxConverter.Result.Unsupported -> null to r.notes
            else -> null to listOf("NotXray")
        }

    // ---------------------------------------------------------- TLS versions ----

    @Test
    fun `only the four TLS versions the core knows are written`() {
        // "unknown tls version: TLS1.2" refuses everything, and Xray's own
        // spellings are the four below, so anything else came from an edit.
        for (v in listOf("1.0", "1.1", "1.2", "1.3")) {
            val (p, _) = sbProxy(vlessTls("""{"serverName":"a.example.com","minVersion":"$v"}"""))
            assertEquals("version $v must be carried", v, p!!.optJSONObject("tls")?.optString("min_version"))
        }
        for (v in listOf("TLS1.2", "1.4", "nonsense", "1")) {
            val (p, notes) = sbProxy(vlessTls("""{"serverName":"a.example.com","minVersion":"$v"}"""))
            assertTrue("the node must survive", p != null)
            assertFalse("$v must not reach the core", p!!.optJSONObject("tls")!!.has("min_version"))
            assertTrue("the drop must be named for $v: $notes", notes.any { it.contains(v) })
        }
    }

    @Test
    fun `maxVersion is held to the same list`() {
        val (p, notes) = sbProxy(vlessTls("""{"serverName":"a.example.com","maxVersion":"1.4"}"""))
        assertFalse(p!!.optJSONObject("tls")!!.has("max_version"))
        assertTrue("$notes", notes.any { it.contains("maxVersion") })
    }

    // ------------------------------------------------------ certificate path ----

    @Test
    fun `a certificate file path is not carried into someone else's document`() {
        // The core opens the file as it loads and answers a missing one with "no such file or
        // directory", refusing everything.
        val (p, notes) = sbProxy(vlessTls(
            """{"serverName":"a.example.com","certificates":[{"usage":"verify","certificateFile":"/etc/xray/ca.pem"}]}"""
        ))
        assertTrue("the node must survive", p != null)
        assertFalse("a foreign path must not reach the core", p!!.optJSONObject("tls")!!.has("certificate_path"))
        assertTrue("the drop must be named: $notes", notes.any { it.contains("certificateFile") })
    }

    @Test
    fun `an inline certificate is still carried`() {
        // Only the path is a problem; the certificate itself travels fine.
        val pem = "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----"
        val (p, _) = sbProxy(vlessTls(
            """{"serverName":"a.example.com","certificates":[{"usage":"verify","certificate":["$pem"]}]}"""
        ))
        assertTrue("the inline certificate was lost", p!!.optJSONObject("tls")!!.has("certificate"))
    }

    // ------------------------------------------------- WireGuard reserved ----

    @Test
    fun `wireguard reserved is carried only at the length the core wants`() {
        // "invalid reserved value, required 3 bytes, got 4" from both cores.
        val ok = sbProxy(wireguard("""{"secretKey":"$wgPriv","address":["10.0.0.2/32"],"reserved":[1,2,3],
            "peers":[{"endpoint":"a.example.com:51820","publicKey":"$wgPub","allowedIPs":["0.0.0.0/0"]}]}"""
            .trimIndent().replace("\n", ""))).first
        val peer = ok!!.getJSONArray("peers").getJSONObject(0)
        assertTrue("three bytes must be carried", peer.has("reserved"))
        assertEquals(3, peer.getJSONArray("reserved").length())

        val (bad, notes) = sbProxy(wireguard("""{"secretKey":"$wgPriv","address":["10.0.0.2/32"],"reserved":[1,2,3,4],
            "peers":[{"endpoint":"a.example.com:51820","publicKey":"$wgPub","allowedIPs":["0.0.0.0/0"]}]}"""
            .trimIndent().replace("\n", "")))
        assertFalse("four bytes must not reach the core",
            bad!!.getJSONArray("peers").getJSONObject(0).has("reserved"))
        assertTrue("the drop must be named: $notes", notes.any { it.contains("reserved") })
    }

    @Test
    fun `wireguard reserved belongs to the peer and not to the endpoint`() {
        // sing-box has no reserved on the endpoint at all: putting it there is an unknown field and
        // the document is refused.
        val ep = sbProxy(wireguard("""{"secretKey":"$wgPriv","address":["10.0.0.2/32"],"reserved":[1,2,3],
            "peers":[{"endpoint":"a.example.com:51820","publicKey":"$wgPub","allowedIPs":["0.0.0.0/0"]},
                     {"endpoint":"b.example.com:51821","publicKey":"$wgPub","allowedIPs":["0.0.0.0/0"]}]}"""
            .trimIndent().replace("\n", ""))).first
        assertFalse("the endpoint must not carry it", ep!!.has("reserved"))
        val peers = ep.getJSONArray("peers")
        for (i in 0 until peers.length()) {
            assertTrue("peer $i lost the reserved value", peers.getJSONObject(i).has("reserved"))
        }
    }

    @Test
    fun `a peer's own reserved wins over the shared one`() {
        val ep = sbProxy(wireguard("""{"secretKey":"$wgPriv","address":["10.0.0.2/32"],"reserved":[1,2,3],
            "peers":[{"endpoint":"a.example.com:51820","publicKey":"$wgPub","allowedIPs":["0.0.0.0/0"],"reserved":[9,9,9]}]}"""
            .trimIndent().replace("\n", ""))).first
        val r = ep!!.getJSONArray("peers").getJSONObject(0).getJSONArray("reserved")
        assertEquals(9, r.getInt(0))
    }

    // ------------------------------------------------- shadowsocks methods ----

    @Test
    fun `an unknown shadowsocks method drops the node rather than the config`() {
        // mihomo answers "cipher: ... initialize error" and refuses the whole
        // file; the sing-box side has always had a list and this one had not.
        val body = """{"remarks":"S","outbounds":[{"protocol":"shadowsocks","tag":"n","settings":{"servers":[
            {"address":"a.example.com","port":8388,"method":"totalnonsense","password":"pw"}]}}]}"""
            .trimIndent().replace("\n", "")
        val r = MihomoConverter.convert(body)
        assertTrue("expected a drop, got $r", r is MihomoConverter.Result.Unsupported)
        assertTrue(
            "the method must be named: ${(r as MihomoConverter.Result.Unsupported).notes}",
            r.notes.any { it.contains("totalnonsense") }
        )
    }

    @Test
    fun `the methods both cores implement still convert`() {
        // Including 2022-blake3-aes-128-gcm, which looks unsupported if it is offered a 32-byte
        // key: the core refuses it on the key length, not on the name, and a list built from that
        // mistake would lose it.
        val keys = mapOf(
            "aes-256-gcm" to "pw",
            "chacha20-ietf-poly1305" to "pw",
            "2022-blake3-aes-128-gcm" to "AAAAAAAAAAAAAAAAAAAAAA==",
            "2022-blake3-aes-256-gcm" to "Kq2tGRQPDLnJXQ8DAtEyC0hMLoGRGGPHKDtu0FLmCqQ=",
            "rc4-md5" to "pw"
        )
        for ((method, pw) in keys) {
            val body = """{"remarks":"S","outbounds":[{"protocol":"shadowsocks","tag":"n","settings":{"servers":[
                {"address":"a.example.com","port":8388,"method":"$method","password":"$pw"}]}}]}"""
                .trimIndent().replace("\n", "")
            assertTrue("$method was dropped", MihomoConverter.convert(body) is MihomoConverter.Result.Ok)
        }
    }

    @Test
    fun `plain is mapped to the name mihomo has for it`() {
        // mihomo knows "none" and not "plain", and refuses the file over the
        // latter.
        assertEquals("none", ssCipher("plain"))
        assertEquals("none", ssCipher("none"))
        assertEquals("", ssCipher("totalnonsense"))
    }
}
