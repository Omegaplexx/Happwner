package com.happwner.convert

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// Base64-wrapped subscription bodies. Panels wrap the body in base64, in either alphabet, padded or
// not, and often hard-wrapped at 64 or 76 columns.
class Base64BodyTest {

	private val config = """
		{"remarks":"N","outbounds":[{"protocol":"vless","tag":"n",
		"settings":{"vnext":[{"address":"a.example.com","port":443,
		"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		"streamSettings":{"network":"tcp","security":"tls",
		"tlsSettings":{"serverName":"a.example.com"}}}]}
	""".trimIndent().replace("\n", "")

	private fun convert(body: String): String =
		SubscriptionConverter.convert(body, jsonToUri = true, base64Result = false, xrayToSingBox = true)

	private fun assertDecoded(label: String, body: String) {
		val out = convert(body)
		assertTrue(
			"$label: expected a vless:// link, got ${out.take(80)}",
			out.startsWith("vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443")
		)
	}

	@Test
	fun `a body wrapped in either alphabet decodes`() {
		assertDecoded("standard padded", Base64.getEncoder().encodeToString(config.toByteArray()))
		assertDecoded("standard raw",
			Base64.getEncoder().withoutPadding().encodeToString(config.toByteArray()))
		assertDecoded("url-safe padded",
			Base64.getUrlEncoder().encodeToString(config.toByteArray()))
		assertDecoded("url-safe raw",
			Base64.getUrlEncoder().withoutPadding().encodeToString(config.toByteArray()))
	}

	@Test
	fun `hard-wrapped bodies decode, in either alphabet and either line ending`() {
		val std = Base64.getEncoder().encodeToString(config.toByteArray())
		val url = Base64.getUrlEncoder().withoutPadding().encodeToString(config.toByteArray())
		assertDecoded("standard, LF at 76", std.chunked(76).joinToString("\n"))
		assertDecoded("standard, CRLF at 64", std.chunked(64).joinToString("\r\n"))
		// The one a strict URL decoder rejects: it has no line-break handling.
		assertDecoded("url-safe, LF at 64", url.chunked(64).joinToString("\n"))
		assertDecoded("url-safe, CRLF at 76", url.chunked(76).joinToString("\r\n"))
	}

	@Test
	fun `a body that only looks like base64 is left alone`() {
		// Both alphabets at once is not a real encoding, so it must pass through
		// rather than be mangled into something that decodes to noise.
		val mixed = "abcd-efg+hij_klm/nop"
		assertEquals(mixed, convert(mixed))
		// Plain text stays plain text.
		val text = "just a line of text that is long enough"
		assertEquals(text, convert(text))
	}

	@Test
	fun `decoded noise is refused rather than emitted`() {
		// Valid base64 whose bytes are not UTF-8 text: decoding "succeeds" and
		// has to be rejected on the content, or the output becomes mojibake.
		val noise = Base64.getEncoder()
			.encodeToString(ByteArray(64) { (it * 7 + 0x80).toByte() })
		assertEquals(noise, convert(noise))
	}

	@Test
	fun `a wrapped body headed by Happ parameter lines still decodes`() {
		// Providers put app-management parameters above the configs, inside the wrapping. The body
		// is still a subscription, and the parameter lines have to survive into the output for
		// whatever reads it next.
		val body = "#profile-title: Name VPN\n#change-user-agent: xray\n$config"
		val out = convert(Base64.getEncoder().encodeToString(body.toByteArray()))
		assertTrue(
			"expected the parameter lines to be kept, got ${out.take(80)}",
			out.startsWith("#profile-title: Name VPN\n#change-user-agent: xray\n")
		)
		assertTrue(
			"expected the config to convert, got ${out.take(200)}",
			out.contains("vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443")
		)
	}

	@Test
	fun `a wrapped body of nothing but parameter lines is left alone`() {
		// Nothing says this is a subscription, so it must pass through untouched rather than be
		// unwrapped on the strength of the wrapping alone.
		val comments = Base64.getEncoder()
			.encodeToString("#profile-title: Name VPN\n#change-user-agent: xray\n".toByteArray())
		assertEquals(comments, convert(comments))
	}

	@Test
	fun `a line that is itself base64 is unwrapped and converted beside the plain lines`() {
		// Some bodies carry one configuration a line, each wrapped on its own.
		val id = "b831381d-6324-4d53-ad4f-8cda48b30811"
		val server = """{"address":"w.example.com","port":443,"users":[{"id":"$id","encryption":"none"}]}"""
		val inner = """{"outbounds":[{"protocol":"vless","tag":"w","settings":{"vnext":[$server]}}]}"""
		val wrapped = Base64.getEncoder().encodeToString(inner.toByteArray())
		val body = "vless://$id@p.example.com:443?encryption=none#P\n$wrapped\n"
		val text = SubscriptionConverter.convert(body, jsonToUri = true, base64Result = false)
		assertTrue(text, text.contains("@w.example.com:443") && text.contains("@p.example.com:443"))
	}
}
