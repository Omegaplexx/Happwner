package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// A rule's ports are read once for both passes, as Xray reads them: 0 is a legal port in a rule
// ("0-65535" is a common catch-all) and both cores take it, while a token that is not a port would
// cost either core the whole document, so it goes with its name in the log.
class RulePortsTest {

	private fun body(port: String) = """
        {"remarks":"P","outbounds":[{"protocol":"vless","tag":"p",
          "settings":{"vnext":[{"address":"a.example.com",
          "port":443,"users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}},
          {"protocol":"freedom","tag":"direct"}],
         "routing":{"rules":[{"type":"field","port":$port,"outboundTag":"direct"}]}}
	""".trimIndent().replace("\n", " ")

	@Test
	fun `port zero and a catch-all range reach both cores`() {
		val mihomo = SubscriptionConverter.convertWithStats(body("\"0-65535,0\""), jsonToUri = false,
			xrayToMihomo = true)
		assertTrue(mihomo.text, mihomo.text.contains("DST-PORT,0/0-65535,DIRECT"))
		val singBox = SubscriptionConverter.convertWithStats(body("\"0-65535,0\""), jsonToUri = false,
			xrayToSingBox = true)
		val rule = JSONObject(singBox.text).getJSONObject("route").getJSONArray("rules").let { rules ->
			(0 until rules.length()).map { rules.getJSONObject(it) }.first { it.has("port_range") }
		}
		assertEquals("0:65535", rule.getJSONArray("port_range").getString(0))
		assertEquals(0, rule.getJSONArray("port").getInt(0))
	}

	@Test
	fun `a token that is not a port is dropped and named, and the rest of the list stays`() {
		for (port in listOf("\"443,70000,abc,8000-100\"", "[\"443\",\"70000\",\"abc\",\"8000-100\"]")) {
			val mihomo = SubscriptionConverter.convertWithStats(body(port), jsonToUri = false,
				xrayToMihomo = true)
			assertTrue(mihomo.text, mihomo.text.contains("DST-PORT,443,DIRECT"))
			assertTrue(mihomo.notes.toString(), mihomo.notes.any { "\"70000\" is not a port" in it })
			assertTrue(mihomo.notes.toString(), mihomo.notes.any { "\"8000-100\" is not a port" in it })
			val singBox = SubscriptionConverter.convertWithStats(body(port), jsonToUri = false,
				xrayToSingBox = true)
			assertTrue(singBox.text,
				singBox.text.contains("\"port\":[443]") && !singBox.text.contains("port_range"))
			assertTrue(singBox.notes.toString(), singBox.notes.any { "\"abc\" is not a port" in it })
		}
	}
}
