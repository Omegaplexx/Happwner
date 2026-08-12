package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

// Which uTLS fingerprint names cross over: a name neither core knows makes it refuse the whole document,
// so it is dropped and said; a versioned name a core would not resolve folds onto its family.
class UtlsFingerprintTest {

    // ---- H3: client-fingerprint names mihomo actually accepts ----

    private fun `fingerprintFor`(xrayFp: String): String? {
        val xray = """{"outbounds":[{"protocol":"vless","tag":"p","settings":
            {"vnext":[{"address":"e.com","port":443,"users":[{"id":"u"}]}]},
            "streamSettings":{"network":"tcp","security":"tls",
            "tlsSettings":{"serverName":"s.com","fingerprint":"$xrayFp"}}}]}"""
        val r = MihomoConverter.convert(xray) as MihomoConverter.Result.Ok
        val line = r.yaml.lines().firstOrNull { it.contains("client-fingerprint") } ?: return null
        return line.substringAfter("client-fingerprint:").trim().trim('"', '\'')
    }
    // Measured on mihomo v1.19.29 rather than assumed: the core accepts any string here, and one it does not
    // resolve produces Go's own plain handshake - no error, no log line, and no mimicry at all.
    @Test
    fun `randomized is its own profile and is kept`() {
        // "randomized" resolves to a ClientHello distinct from "random"; folding the two together
        // would swap one working profile for another for no reason.
        assertEquals("randomized", fingerprintFor("randomized"))
        assertEquals("random", fingerprintFor("randomizedalpn"))
        assertEquals("random", fingerprintFor("randomizednoalpn"))
    }
    @Test
    fun `versioned profiles the core resolves are kept`() {
        // chrome120 is not a more precise spelling of chrome - it is the one without the
        // X25519MLKEM768 key share: chrome      X25519MLKEM768, X25519, secp256r1, secp384r1
        // chrome120                   X25519, secp256r1, secp384r1 Folding it would turn the post-
        // quantum key share back on, and the oversized ClientHello that comes with it is what the
        // versioned name exists to avoid.
        assertEquals("chrome120", fingerprintFor("chrome120"))
        assertEquals("firefox120", fingerprintFor("firefox120"))
        // The core's lookup is exact, so a separator has to be normalised away
        // rather than folded onto the family.
        assertEquals("chrome120", fingerprintFor("chrome_120"))
        assertEquals("firefox120", fingerprintFor("firefox-120"))
        assertEquals("chrome120", fingerprintFor("Chrome120"))
    }
    @Test
    fun `versioned profiles the core ignores fold onto their family`() {
        // Measured as falling back to a plain Go handshake, so folding restores
        // real mimicry in place of none.
        assertEquals("chrome", fingerprintFor("chrome124"))
        assertEquals("chrome", fingerprintFor("chrome131"))
        assertEquals("firefox", fingerprintFor("firefox125"))
        assertEquals("safari", fingerprintFor("safari18"))
        assertEquals("ios", fingerprintFor("ios17"))
        assertEquals("android", fingerprintFor("android13"))
        assertEquals("edge", fingerprintFor("edge120"))
        assertEquals("chrome", fingerprintFor("chrome_106_shuffle"))
    }
    @Test
    fun `plain family names pass through unchanged`() {
        for (fp in listOf("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random")) {
            assertEquals(fp, fingerprintFor(fp))
        }
    }
    @Test
    fun `unknown fingerprints are dropped not emitted`() {
        assertNull(fingerprintFor("hellogolang"))
        assertNull(fingerprintFor("nonsense"))
    }
    // "chromium" must not be read as the "chrome" family.
    @Test
    fun `family match does not swallow longer words`() {
        assertNull(fingerprintFor("chromium"))
    }
}
