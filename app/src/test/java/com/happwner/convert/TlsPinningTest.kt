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
	private fun `pinFor`(tlsExtra: String): Pair<String?, List<String>> {
		val xray = """{"outbounds":[{"protocol":"vless","tag":"p","settings":
            {"vnext":[{"address":"e.com","port":443,"users":[{"id":"u"}]}]},
            "streamSettings":{"network":"tcp","security":"tls",
            "tlsSettings":{"serverName":"s.com"$tlsExtra}}}]}"""
		val result = MihomoConverter.convert(xray) as MihomoConverter.Result.Ok
		val line = result.yaml.lines().firstOrNull { it.trimStart().startsWith("fingerprint:") }
		return line?.substringAfter("fingerprint:")?.trim() to result.notes
	}
	@Test
	fun `cert pin is read from both the new and the old xray spelling`() {
		// Xray takes the pin as a scalar, and accepts it in base64 or in hex.
		assertEquals(PIN_HEX, pinFor(""","pinnedPeerCertSha256":"$PIN_B64"""").first)
		// Already-hex pins pass through, with or without colons.
		assertEquals(PIN_HEX, pinFor(""","pinnedPeerCertSha256":"$PIN_HEX"""").first)
	}
	@Test
	fun `a public key pin is refused rather than mapped`() {
		// pinnedPeerCertificatePublicKeySha256 hashes the subject public key while mihomo's
		// "fingerprint" hashes the certificate, so copying it across would emit a pin that can never match.
		val (pin, notes) = pinFor(""","pinnedPeerCertificatePublicKeySha256":["$PIN_B64"]""")
		assertNull("a public-key hash must not become a certificate pin", pin)
		assertTrue(
			"the drop must be explained, notes were $notes",
			notes.any { it.contains("public key") }
		)
	}
	// The chain hash folds every certificate the peer sends, while the fingerprint mihomo compares
	// is the hash of one of them. The two agree only when the peer sends exactly one certificate,
	// so it is named rather than carried: a pin that cannot match is a node that cannot connect.
	@Test
	fun `a chain hash is not carried as a certificate fingerprint`() {
		val (pin, notes) = pinFor(""","pinnedPeerCertificateChainSha256":["$PIN_B64"]""")
		assertEquals(null, pin)
		assertTrue(notes.toString(), notes.any { it.contains("pinnedPeerCertificateChainSha256") })
	}

	@Test
	fun `several pins use the first and say so`() {
		val (pin, notes) = pinFor(""","pinnedPeerCertSha256":["$PIN_B64","$PIN_HEX"]""")
		assertEquals(PIN_HEX, pin)
		assertTrue(notes.any { it.contains("mihomo takes one") })
	}


	@Test
	fun `a certificate is pinned as the server's own only when it names the host and signs no other`() {
		val own = OWN_CERTIFICATE_LINES.joinToString("\n")
		val named = listOf("h.example.com", "H.Example.COM.", "a.w.example.com", "192.0.2.10",
			"[2001:db8::1]", "2001:DB8:0:0:0:0:0:1")
		for (host in named) assertEquals(host, OWN_CERTIFICATE_PIN, ownCertificatePin(own, listOf(host)))
		val unnamed = listOf("example.com", "w.example.com", "a.b.w.example.com", "192.0.2.11",
			"h.example.co")
		for (host in unnamed) assertNull(host, ownCertificatePin(own, listOf(host)))
		val either = listOf("other.example.com", "h.example.com")
		assertEquals(OWN_CERTIFICATE_PIN, ownCertificatePin(own, either))
		assertNull(ownCertificatePin(ISSUING_CERTIFICATE_LINES.joinToString("\n"), listOf("h.example.com")))
		assertNull(ownCertificatePin("$own\n$own", listOf("h.example.com")))
		assertNull(ownCertificatePin("not a certificate", listOf("h.example.com")))
	}

	// One node of each proxy mihomo gives no CA of its own, its server at h.example.com.
	private fun node(protocol: String, tls: String): String {
		val stream = """"streamSettings":{"security":"tls","tlsSettings":$tls}"""
		return when (protocol) {
			"hysteria2" -> """{"outbounds":[{"protocol":"hysteria","tag":"n","settings":{"version":2,""" +
				""""address":"h.example.com","port":443},"streamSettings":{"network":"hysteria",""" +
				""""hysteriaSettings":{"version":2,"auth":"pw"},"security":"tls","tlsSettings":$tls}}]}"""
			"tuic" -> """{"outbounds":[{"protocol":"tuic","tag":"n","server":"h.example.com",""" +
				""""server_port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw",""" +
				"""$stream}]}"""
			else -> """{"outbounds":[{"protocol":"$protocol","tag":"n","settings":{""" +
				""""address":"h.example.com","port":443,"user":"u","pass":"p"},$stream}]}"""
		}
	}

	// mihomo's socks5, HTTP and QUIC proxies take no CA, so a server verified against its own certificate
	// pins that certificate; one that may have signed the server's is no pin, and the node goes.
	@Test
	fun `the server's own certificate as its CA is pinned where a mihomo proxy takes no CA`() {
		val own = verifying(OWN_CERTIFICATE_LINES)
		val issuing = verifying(ISSUING_CERTIFICATE_LINES)
		for (protocol in listOf("hysteria2", "tuic", "socks", "http")) {
			val pinned = MihomoConverter.convert(node(protocol, """{"certificates":$own}"""))
			assertTrue("$protocol: $pinned", pinned is MihomoConverter.Result.Ok)
			val ok = pinned as MihomoConverter.Result.Ok
			assertTrue(ok.yaml, "fingerprint: $OWN_CERTIFICATE_PIN" in ok.yaml)
			assertTrue("${ok.notes}", ok.notes.any { "the server's own certificate" in it })
			val refused = MihomoConverter.convert(node(protocol, """{"certificates":$issuing}"""))
			assertTrue("$refused", refused !is MihomoConverter.Result.Ok && "cannot be given" in "$refused")
		}
		// Another host than the one it names, and the certificate may not be the server's.
		val elsewhere = """{"serverName":"x.example.com","certificates":$own}"""
		assertTrue(MihomoConverter.convert(node("hysteria2", elsewhere)) !is MihomoConverter.Result.Ok)
		// Checked against verifyPeerCertByName rather than the server name, as Xray checks it.
		val byName = """{"serverName":"x.example.com","verifyPeerCertByName":"h.example.com",""" +
			""""certificates":$own}"""
		val checked = MihomoConverter.convert(node("hysteria2", byName)) as MihomoConverter.Result.Ok
		assertTrue(checked.yaml, "fingerprint: $OWN_CERTIFICATE_PIN" in checked.yaml)
		assertTrue(checked.yaml, "name-cert-verify: h.example.com" in checked.yaml)
		// Beside a pin of the node's own, or with the check skipped, the CA decides nothing.
		val explicit = """{"certificates":$issuing,"pinnedPeerCertSha256":"$ISSUING_CERTIFICATE_PIN"}"""
		val pinnedAlready = MihomoConverter.convert(node("hysteria2", explicit)) as MihomoConverter.Result.Ok
		assertTrue(pinnedAlready.yaml, "fingerprint: $ISSUING_CERTIFICATE_PIN" in pinnedAlready.yaml)
		val skipped = """{"certificates":$issuing,"allowInsecure":true}"""
		val insecure = MihomoConverter.convert(node("hysteria2", skipped)) as MihomoConverter.Result.Ok
		assertTrue(insecure.yaml, "skip-cert-verify: true" in insecure.yaml)
		assertTrue(insecure.yaml, "fingerprint:" !in insecure.yaml)
	}

	// Such a proxy passes by the document's list of CAs, so its own never joins it - where it would only
	// widen what every other node trusts - and a node left out over one says that alone.
	@Test
	fun `the CA of a proxy mihomo gives none never joins the document's list`() {
		val vless = """{"protocol":"vless","tag":"v","settings":{"vnext":[{"address":"v.example.com",""" +
			""""port":443,"users":[{"id":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","encryption":"none"}]}]},""" +
			""""streamSettings":{"security":"tls","tlsSettings":{"serverName":"v.example.com"}}}"""
		fun besideVless(document: String) = MihomoConverter.convert(
			document.replaceFirst("""{"outbounds":[""", """{"outbounds":[$vless,""")
		) as MihomoConverter.Result.Ok
		val issuing = verifying(ISSUING_CERTIFICATE_LINES)
		val withUnreadable = issuing.dropLast(1) + """,{"usage":"verify","certificate":["no"]}]"""
		val forms = listOf("""{"certificates":${verifying(OWN_CERTIFICATE_LINES)}}""",
			"""{"certificates":$issuing,"allowInsecure":true}""", """{"certificates":$withUnreadable}""")
		for (protocol in listOf("hysteria2", "tuic", "socks", "http")) {
			for (tls in forms) {
				val result = besideVless(node(protocol, tls))
				assertTrue("$protocol $tls: ${result.yaml}", "custom-certifactes" !in result.yaml)
			}
			val noisy = """{"fingerprint":"chrome","verifyPeerCertByName":"h.example.com,w.example.com",""" +
				""""pinnedPeerCertificatePublicKeySha256":"$PIN_B64","certificates":$withUnreadable}"""
			for (tls in listOf("""{"certificates":$withUnreadable}""", noisy)) {
				val refused = besideVless(node(protocol, tls))
				val said = refused.notes.filter { "outbounds[1]" in it }
				assertEquals("$protocol $tls: $said", 1, said.size)
				assertTrue("$protocol: $said", "cannot be given" in said.single())
			}
		}
	}

	// The pin and the name the certificate is checked against reach every proxy mihomo has them for.
	@Test
	fun `socks5, HTTP and QUIC proxies keep the pin and the name the certificate is checked against`() {
		for (protocol in listOf("hysteria2", "tuic", "socks", "http")) {
			val tls = """{"pinnedPeerCertSha256":"$PIN_B64","verifyPeerCertByName":"v.example.com"}"""
			val result = MihomoConverter.convert(node(protocol, tls)) as MihomoConverter.Result.Ok
			assertTrue("$protocol: ${result.yaml}", "fingerprint: $PIN_HEX" in result.yaml)
			assertTrue("$protocol: ${result.yaml}", "name-cert-verify: v.example.com" in result.yaml)
		}
	}
}
