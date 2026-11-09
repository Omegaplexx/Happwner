package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// A subscription this converter has nothing to say about must come back as it was written.
class PassthroughFidelityTest {

	private val clashDocument = """
		mixed-port: 7890
		mode: rule
		dns:
		  enable: true
		  nameserver:
		    - https://1.1.1.1/dns-query
		proxies:
		  - name: "Node A"
		    type: vless
		    server: a.example.com
		    port: 443
		    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
		    tls: true
		proxy-groups:
		  - name: PROXY
		    type: select
		    proxies:
		      - "Node A"
		rules:
		  - MATCH,PROXY
	""".trimIndent()

	private fun convert(body: String, uri: Boolean, singBox: Boolean, mihomo: Boolean) =
		SubscriptionConverter.convert(
			body, jsonToUri = uri, base64Result = false,
			xrayToSingBox = singBox, xrayToMihomo = mihomo
		)

	@Test
	fun `an indented document survives every conversion mode`() {
		val modes = listOf(
			Triple(false, false, false),
			Triple(true, false, false),
			Triple(false, true, false),
			Triple(false, false, true)
		)
		for ((uri, singBox, mihomo) in modes) {
			val out = convert(clashDocument, uri, singBox, mihomo)
			assertEquals(
				"uri=$uri singbox=$singBox mihomo=$mihomo changed a document it cannot convert",
				clashDocument.trim(), out.trim()
			)
		}
	}

	@Test
	fun `the indentation itself is what has to survive`() {
		val out = convert(clashDocument, uri = true, singBox = false, mihomo = false)
		assertTrue("the nested keys keep their depth: $out", out.contains("\n  enable: true"))
		assertTrue("and the list items theirs", out.contains("\n    - https://1.1.1.1/dns-query"))
	}

	@Test
	fun `a link list is still tidied, since there is no structure to keep`() {
		// Leading whitespace around a link carries nothing, and the list is
		// easier to read without it - so trimming stays where it belongs.
		val uuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"
		val messy = "   vless://$uuid@a.example.com:443#A   \n\n  vless://$uuid@b.example.com:443#B"
		val out = convert(messy, uri = true, singBox = false, mihomo = false)
		val lines = out.trim().lines().filter { it.isNotBlank() }
		assertEquals(2, lines.size)
		for (line in lines) assertEquals("no stray spaces around a link: [$line]", line.trim(), line)
	}
}
