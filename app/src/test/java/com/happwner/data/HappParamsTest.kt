package com.happwner.data

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

// Reading Happ's app-management parameters off a subscription, in both shapes a provider may send
// them and in the shapes that must not be mistaken for one.
class HappParamsTest {

	private val link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443#Amsterdam"

	private fun headers(vararg pairs: Pair<String, String>): Map<String, List<String>> =
		pairs.associate { (name, value) -> name to listOf(value) }

	private fun ua(headers: Map<String, List<String>>? = null, body: String? = null): String? =
		HappParams.changeUserAgent(headers, body)

	private fun wrap(body: String, urlSafe: Boolean = false): String =
		if (urlSafe) Base64.getUrlEncoder().withoutPadding().encodeToString(body.toByteArray())
		else Base64.getEncoder().encodeToString(body.toByteArray())

	@Test
	fun `the header is read whatever its case, wins over the body, and may announce base64`() {
		assertEquals("xray", ua(headers("change-user-agent" to "xray")))
		assertEquals("xray", ua(headers("Change-User-Agent" to "xray")))
		assertEquals("xray", ua(headers("CHANGE-USER-AGENT" to " xray ")))
		val body = "#change-user-agent: from-body\n$link"
		assertEquals("from-header", ua(headers("change-user-agent" to "from-header"), body))
		val encoded = Base64.getEncoder().encodeToString("xray".toByteArray())
		assertEquals("xray", ua(headers("change-user-agent" to "base64:$encoded")))
		assertEquals("xray", ua(body = "#change-user-agent: base64:$encoded\n$link"))
		// Without the prefix the value is taken literally, or a plain "Happ/4.1.0" would be
		// decoded into noise.
		assertEquals("Happ/4.1.0", ua(headers("change-user-agent" to "Happ/4.1.0")))
	}

	@Test
	fun `a parameter line in the body is found wherever it sits, wrapped or not`() {
		assertEquals("xray", ua(body = "#change-user-agent: xray\n$link"))
		// A real User-Agent has spaces in it and keeps them.
		val chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/135.0.0.0 Safari/537.36"
		assertEquals(chrome, ua(body = "#change-user-agent: $chrome\n$link"))
		assertEquals("xray", ua(body = "$link\n#change-user-agent: xray"))
		assertEquals("first", ua(body = "#change-user-agent: first\n$link\n#change-user-agent: second"))
		assertEquals("xray", ua(body = "#  change-user-agent : \txray  \n$link"))
		assertEquals("xray", ua(body = "#change-user-agent: xray\r\n$link"))
		val body = "#profile-title: Name VPN\n#change-user-agent: xray\n$link"
		assertEquals("xray", ua(body = wrap(body)))
		assertEquals("xray", ua(body = wrap(body, urlSafe = true)))
		// Hard-wrapped the way panels emit it.
		assertEquals("xray", ua(body = wrap(body).chunked(64).joinToString("\r\n")))
	}

	@Test
	fun `what is not a parameter line is not read as one`() {
		assertNull(ua(body = "vless://id@a.example.com:443#change-user-agent: xray"))
		assertNull(ua(body = "#profile-title: Name VPN\n$link"))
		assertNull(ua(body = "#change-user-agent-geo-files: chrome-win\n$link"))
		assertNull(ua(body = "#change-user-agent\n$link"))
		assertNull(ua())
		assertNull(ua(body = ""))
		assertNull(ua(headers("content-type" to "text/plain"), link))
		// Valid base64 whose bytes are not text is not searched for parameter lines.
		val noise = Base64.getEncoder().encodeToString(ByteArray(64) { (it * 7 + 0x80).toByte() })
		assertNull(ua(body = noise))
	}

	@Test
	fun `a value that could not be sent as a header is refused, and leaves the body its turn`() {
		// A CR or LF would split the request into two.
		assertNull(ua(headers("change-user-agent" to "xray\r\nX-Injected: 1")))
		// Anything the connection cannot spell would reach the provider mangled anyway.
		assertNull(ua(body = "#change-user-agent: Хапп\n$link"))
		assertNull(ua(body = "#change-user-agent: ${"x".repeat(513)}\n$link"))
		assertNull(ua(body = "#change-user-agent:   \n$link"))
		assertEquals("xray", ua(headers("change-user-agent" to "Хапп"), "#change-user-agent: xray\n$link"))
	}
}
