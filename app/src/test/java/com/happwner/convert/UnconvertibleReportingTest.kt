package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// What is said when something cannot be carried: dropping a server without a word is the worst outcome,
// because the document still loads and nobody looks. Everything dropped is named.
class UnconvertibleReportingTest {

	// The drop-incompatible boxes throw a whole configuration away. An empty answer with a silent
	// log reads as the converter having lost the subscription, so the throw always says why.
	@Test
	fun `a configuration dropped by the incompatible filter says why`() {
		val body = """{"remarks":"N","outbounds":[null]}"""
		for ((singBox, mihomo) in listOf(true to false, false to true, true to true)) {
			val result = SubscriptionConverter.convertWithStats(body, jsonToUri = true,
				xrayToSingBox = singBox, dropIncompatibleMihomo = mihomo)
			assertTrue("sb=$singBox mh=$mihomo: ${result.notes}", result.notes.isNotEmpty())
		}
	}

	// A pretty-printed configuration is one JSON value over several lines. When it renders to no
	// link, the reason belongs to the value, not to the lines: the per-line pass sees fragments, and
	// "this line is not valid JSON" would bury why the node was really withheld.
	@Test
	fun `a multi-line configuration that renders to no link says why, not that its lines are fragments`() {
		val body = """
			{"protocol":"shadowsocks","tag":"n","settings":{"servers":[
			{"address":"a.example.com","port":8388,"method":"aes-128-gcm","password":"pw"}]},
			"streamSettings":{"network":"grpc"}}
		""".trimIndent()
		val result = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
		assertEquals("the body stays as it is", body.trim(), result.text.trim())
		assertTrue(result.notes.toString(), result.notes.any { "no link form" in it })
		assertTrue(result.notes.toString(), result.notes.none { "starts like JSON" in it })
		// A node that works nowhere is left out instead, its reason said once.
		val dead = SubscriptionConverter.convertWithStats(body.replace("aes-128-gcm", ""), jsonToUri = true)
		assertEquals(dead.text, "", dead.text)
		assertEquals(1, dead.xraySkipped)
		assertEquals(dead.notes.toString(), 1, dead.notes.count { MISSING_SS_METHOD_REFUSAL in it })
		assertTrue(dead.notes.toString(), dead.notes.none { "starts like JSON" in it })
	}

	// A shadowsocks node with no method.
	@Test
	fun `empty shadowsocks method is rejected with a reason`() {
		val xray = """{"outbounds":[{"protocol":"shadowsocks","tag":"p","settings":
            {"servers":[{"address":"e.com","port":8388,"method":"","password":"pw"}]}}]}"""
		val result = SingBoxConverter.convert(xray, "")
		assertTrue("an empty method must not be substituted with a cipher",
			result is SingBoxConverter.Result.Unsupported)
		val notes = (result as SingBoxConverter.Result.Unsupported).notes
		assertTrue("the reason did not reach the notes: $notes", notes.any { it.contains("method is empty") })
	}
	// Xray has no default method - its parser answers an absent one with "unknown cipher method"
	// and refuses the configuration - so a node without one never worked, and supplying one here
	// would name a cipher the server may not speak. It is refused with the reason, as mihomo does.
	@Test
	fun `absent shadowsocks method is refused, not invented`() {
		val xray = """{"outbounds":[{"protocol":"shadowsocks","tag":"p","settings":
            {"servers":[{"address":"e.com","port":8388,"password":"pw"}]}}]}"""
		val result = SingBoxConverter.convertToOutbounds(xray, "")
		assertTrue("$result", result is SingBoxConverter.OutboundsResult.Unsupported)
		val notes = (result as SingBoxConverter.OutboundsResult.Unsupported).notes
		assertTrue(notes.toString(), notes.any { it.contains("method is empty") })
	}
	// Absent stream security is the same as "none".
	@Test
	fun `absent stream security is supported`() {
		val xray = """{"outbounds":[{"protocol":"vless","tag":"p","settings":
            {"vnext":[{"address":"e.com","port":443,"users":[{"id":"u"}]}]},
            "streamSettings":{"network":"tcp"}}]}"""
		assertTrue(SingBoxConverter.convert(xray, "") is SingBoxConverter.Result.Ok)
	}

	// An Xray config whose only outbound mihomo cannot express.
	private val allUnsupported = """
		{"remarks":"S","outbounds":[{"protocol":"vless","tag":"n",
		 "settings":{"vnext":[{"address":"a.example.com","port":443,
		   "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
		 "streamSettings":{"network":"quic","security":"none"}}]}
	""".trimIndent().replace("\n", "")
	@Test
	fun `a total mihomo failure still says why`() {
		// "Every node was dropped" is the failure most worth reading, and it has to carry its
		// reasons the way a partial failure carries them through Ok.notes.
		val result = MihomoConverter.convert(allUnsupported)
		assertTrue("expected Unsupported, got $result", result is MihomoConverter.Result.Unsupported)
		val notes = (result as MihomoConverter.Result.Unsupported).notes
		assertTrue("the drop must be explained, notes were $notes", notes.isNotEmpty())
		assertTrue(
			"the reason should name the transport, was $notes",
			notes.any { it.contains("QUIC", ignoreCase = true) }
		)
	}
	@Test
	fun `a total mihomo failure carries its reasons without eating the body`() {
		// The pass produces no document, so the body belongs to the conversions
		// that run after it - carrying the reasons out must not cost the text.
		val stats = SubscriptionConverter.convertWithStats(
			allUnsupported, jsonToUri = true, base64Result = false, xrayToSingBox = false, xrayToMihomo = true
		)
		assertTrue("the reasons must survive the fall-through", stats.notes.isNotEmpty())
		assertTrue(
			"the body must still be there, was ${stats.text.take(40)}",
			stats.text.isNotEmpty()
		)
	}
	// An outbound of an unimplemented protocol has to say so - the unknown protocol is the case the
	// reason exists for.
	@Test
	fun `an unimplemented protocol is named rather than dropped in silence`() {
		val unknown =
			"""{"remarks":"H","outbounds":[{"protocol":"shadowsocksr","tag":"n",
                 "settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]}}]}"""
		val result = SingBoxConverter.convert(unknown, "N")
		assertTrue("expected a drop, got $result", result is SingBoxConverter.Result.Unsupported)
		assertTrue(
			"the protocol must be named, notes were ${(result as SingBoxConverter.Result.Unsupported).notes}",
			result.notes.any { it.contains("shadowsocksr") }
		)
	}
	@Test
	fun `a dropped outbound is reported even when the rest converts`() {
		val mixed = """{"remarks":"M","outbounds":[
            {"protocol":"vless","tag":"a","settings":{"vnext":[{"address":"a.example.com","port":443,
              "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls",
               "tlsSettings":{"serverName":"a.example.com"}}},
            {"protocol":"shadowsocksr","tag":"b","settings":{"servers":[{"address":"b.example.com",
              "port":443,"password":"pw"}]}}]}"""
			.trimIndent().replace("\n", "")
		val result = SingBoxConverter.convert(mixed, "N")
		assertTrue("the vless node must still convert, got $result", result is SingBoxConverter.Result.Ok)
		assertTrue(
			"the dropped one must be in the notes, they were ${(result as SingBoxConverter.Result.Ok).notes}",
			result.notes.any { it.contains("shadowsocksr") }
		)
	}
	@Test
	fun `auxiliary outbounds are not reported as unsupported`() {
		// freedom, blackhole, dns and loopback are not proxies; they are handled
		// elsewhere and must not turn into noise in the log.
		val withAux = """{"remarks":"A","outbounds":[
            {"protocol":"vless","tag":"a","settings":{"vnext":[{"address":"a.example.com","port":443,
              "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls",
               "tlsSettings":{"serverName":"a.example.com"}}},
            {"protocol":"freedom","tag":"direct"},
            {"protocol":"blackhole","tag":"block"}]}"""
			.trimIndent().replace("\n", "")
		val result = SingBoxConverter.convert(withAux, "N")
		assertTrue("expected Ok, got $result", result is SingBoxConverter.Result.Ok)
		val notes = (result as SingBoxConverter.Result.Ok).notes
		assertTrue("aux outbounds must not be reported: $notes", notes.none {
			it.contains("freedom") || it.contains("blackhole")
		})
	}

	// A 2022-blake3 key of the wrong length makes both cores refuse the whole document ("bad key
	// length, required 16, got 32"), so the node is refused in every pass rather than handed over
	// with a warning; a multi-user "iPSK:uPSK" key is checked part by part.
	@Test
	fun `a 2022 key of the wrong length is refused by every pass`() {
		val key256 = "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI="
		val key128 = "YctPZ6U7xPPcU+gp3u+0tw=="
		fun node(method: String, key: String) = """{"remarks":"K","outbounds":[{"protocol":"shadowsocks",
			"tag":"p","settings":{"servers":[{"address":"a.example.com","port":8388,"method":"$method",
			"password":"$key"}]}}]}""".replace("\n", "")
		val wrong = node("2022-blake3-aes-128-gcm", key256)
		assertTrue(
			SingBoxConverter.convertToOutbounds(wrong, "K") is SingBoxConverter.OutboundsResult.Unsupported
		)
		assertTrue(MihomoConverter.convert(wrong) is MihomoConverter.Result.Unsupported)
		val link = SubscriptionConverter.convertWithStats(wrong, jsonToUri = true)
		assertFalse(link.text.contains("ss://"))
		assertTrue(link.notes.any { it.contains("not the length that method needs") })

		val right = node("2022-blake3-aes-128-gcm", key128)
		assertTrue(SingBoxConverter.convertToOutbounds(right, "K") is SingBoxConverter.OutboundsResult.Ok)
		assertTrue(MihomoConverter.convert(right) is MihomoConverter.Result.Ok)
		val multi = node("2022-blake3-aes-256-gcm", "$key256:$key256")
		assertTrue(SingBoxConverter.convertToOutbounds(multi, "K") is SingBoxConverter.OutboundsResult.Ok)
		val mixed = node("2022-blake3-aes-256-gcm", "$key256:$key128")
		assertTrue(MihomoConverter.convert(mixed) is MihomoConverter.Result.Unsupported)
	}
}
