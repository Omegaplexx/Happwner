package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Which uTLS fingerprint names cross over: a name neither core knows makes it refuse the whole document,
// so it is dropped and said; a versioned name a core would not resolve folds onto its family.
class UtlsFingerprintTest {

	// The client-fingerprint names mihomo accepts.
	private fun `fingerprintFor`(xrayFp: String): String? {
		val xray = """{"outbounds":[{"protocol":"vless","tag":"p","settings":
            {"vnext":[{"address":"e.com","port":443,"users":[{"id":"u"}]}]},
            "streamSettings":{"network":"tcp","security":"tls",
            "tlsSettings":{"serverName":"s.com","fingerprint":"$xrayFp"}}}]}"""
		val result = MihomoConverter.convert(xray) as MihomoConverter.Result.Ok
		val line = result.yaml.lines().firstOrNull { it.contains("client-fingerprint") } ?: return null
		return line.substringAfter("client-fingerprint:").trim().trim('"', '\'')
	}
	// Measured rather than assumed: the core accepts any string here, and one it does not
	// resolve produces Go's own plain handshake - no error, no log line, and no mimicry at all.
	@Test
	fun `randomized is its own profile and is kept`() {
		// "randomized" resolves to a ClientHello distinct from "random", and the ALPN variants of
		// randomized are randomized with or without ALPN - the same family, never "random".
		assertEquals("randomized", fingerprintFor("randomized"))
		assertEquals("randomized", fingerprintFor("randomizedalpn"))
		assertEquals("randomized", fingerprintFor("randomizednoalpn"))
	}
	@Test
	fun `versioned profiles the core resolves are kept`() {
		// chrome120 is not a spelling of chrome: it is the profile without the X25519MLKEM768 key share,
		// and folding it would turn the post-quantum share - and its oversized ClientHello - back on.
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
		for (fingerprint in listOf("chrome", "firefox", "safari", "ios", "android", "edge", "360",
			"qq", "random")) {
			assertEquals(fingerprint, fingerprintFor(fingerprint))
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

	// The sing-box pass maps the same names the same way, and never imposes a fingerprint the
	// configuration did not ask for: an unknown or "unsafe" name under plain TLS is no uTLS, said
	// in the log; under REALITY, which requires one, it is chrome, said as well.
	@Test
	fun `the sing-box pass maps fingerprints truthfully`() {
		val notes = mutableListOf<String>()
		assertEquals("randomized", SingBoxStream.utlsFingerprint("randomizednoalpn",
			forReality = false, notes = notes))
		assertNull(SingBoxStream.utlsFingerprint("unsafe", forReality = false, notes = notes))
		assertNull(SingBoxStream.utlsFingerprint("nonsense", forReality = false, notes = notes))
		assertEquals("chrome", SingBoxStream.utlsFingerprint("", forReality = true, notes = notes))
		assertEquals("chrome", SingBoxStream.utlsFingerprint("nonsense", forReality = true, notes = notes))
		assertEquals("firefox", SingBoxStream.utlsFingerprint("firefox", forReality = true, notes = notes))
		assertEquals(5, notes.size)
	}

	// Xray's own spellings open with "hello" ("hellochrome_120"), which neither core's names do; read
	// without it, each is the profile a core has or that profile's family, and said.
	@Test
	fun `Xray's hello names are read as each core's own`() {
		assertEquals("chrome120", fingerprintFor("hellochrome_120"))
		assertEquals("firefox", fingerprintFor("hellofirefox_auto"))
		assertEquals("ios", fingerprintFor("helloios_auto"))
		assertEquals("360", fingerprintFor("hello360_auto"))
		assertEquals("qq", fingerprintFor("helloqq_auto"))
		assertEquals("randomized", fingerprintFor("hellorandomizednoalpn"))
		val notes = mutableListOf<String>()
		for ((name, profile) in listOf("hellochrome_120" to "chrome", "HelloFirefox_Auto" to "firefox",
			"hello360_auto" to "360", "hellorandomizednoalpn" to "randomized", "chrome124" to "chrome")) {
			val used = SingBoxStream.utlsFingerprint(name, forReality = false, notes = notes)
			assertEquals(name, profile, used)
		}
		assertNull(SingBoxStream.utlsFingerprint("hellogolang", forReality = false, notes = notes))
		assertEquals("$notes", 6, notes.size)
		assertTrue("$notes", "\"hellochrome_120\" is not one sing-box has; \"chrome\" was used" in notes[0])
	}
}
