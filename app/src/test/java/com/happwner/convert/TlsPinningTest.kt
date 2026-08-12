package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Certificate pinning, spelled and meant differently by the two: a pin on the certificate crosses over,
// a pin on the public key does not - the bytes differ, so it would pin the wrong thing.
class TlsPinningTest {

    // SHA-256 of the sample pin, hex, which is the form mihomo takes.
    private val PIN_HEX = "10a4e6deb9672d8472d83f9ca6beaace16d1d96c7850e8a0c74fecf6cf9d6fca"
    private val PIN_B64 = "EKTm3rlnLYRy2D+cpr6qzhbR2Wx4UOigx0/s9s+db8o="
    // ------------------------------------------------ certificate pinning ----

    private fun `pinFor`(tlsExtra: String): Pair<String?, List<String>> {
        val xray = """{"outbounds":[{"protocol":"vless","tag":"p","settings":
            {"vnext":[{"address":"e.com","port":443,"users":[{"id":"u"}]}]},
            "streamSettings":{"network":"tcp","security":"tls",
            "tlsSettings":{"serverName":"s.com"$tlsExtra}}}]}"""
        val r = MihomoConverter.convert(xray) as MihomoConverter.Result.Ok
        val line = r.yaml.lines().firstOrNull { it.trimStart().startsWith("fingerprint:") }
        return line?.substringAfter("fingerprint:")?.trim() to r.notes
    }
    @Test
    fun `cert pin is read from both the new and the old xray spelling`() {
        // Xray replaced pinnedPeerCertificateChainSha256 (a list) with pinnedPeerCertSha256 (a
        // scalar).
        assertEquals(PIN_HEX, pinFor(""","pinnedPeerCertSha256":"$PIN_B64"""").first)
        assertEquals(PIN_HEX, pinFor(""","pinnedPeerCertificateChainSha256":["$PIN_B64"]""").first)
        // Already-hex pins pass through, with or without colons.
        assertEquals(PIN_HEX, pinFor(""","pinnedPeerCertSha256":"$PIN_HEX"""").first)
    }
    @Test
    fun `a public key pin is refused rather than mapped`() {
        // pinnedPeerCertificatePublicKeySha256 hashes the subject public key while mihomo's "fingerprint" hashes
        // the certificate, so copying it across would emit a pin that can never match.
        val (pin, notes) = pinFor(""","pinnedPeerCertificatePublicKeySha256":["$PIN_B64"]""")
        assertNull("a public-key hash must not become a certificate pin", pin)
        assertTrue(
            "the drop must be explained, notes were $notes",
            notes.any { it.contains("public key") }
        )
    }
    @Test
    fun `several pins use the first and say so`() {
        val (pin, notes) = pinFor(""","pinnedPeerCertificateChainSha256":["$PIN_B64","$PIN_HEX"]""")
        assertEquals(PIN_HEX, pin)
        assertTrue(notes.any { it.contains("mihomo takes one") })
    }
}
