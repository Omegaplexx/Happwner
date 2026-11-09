package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Hysteria2, Hysteria v1 and TUIC on the sing-box side: the core implements all three natively.
class SingBoxQuicProtocolsTest {

	private val uuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"

	private fun cfg(outboundJson: String) = """{"remarks":"Q","outbounds":[$outboundJson]}"""

	private fun convert(body: String): Pair<JSONObject?, List<String>> =
		when (val result = SingBoxConverter.convert(body, "N")) {
			is SingBoxConverter.Result.Ok -> proxyOf(result.config) to result.notes
			is SingBoxConverter.Result.Unsupported -> null to result.notes
			else -> null to listOf("NotXray")
		}

	private fun proxyOf(cfg: JSONObject): JSONObject? {
		val skip = setOf("direct", "block", "dns", "selector", "urltest")
		val outs = cfg.optJSONArray("outbounds") ?: return null
		for (i in 0 until outs.length()) {
			val outbound = outs.optJSONObject(i) ?: continue
			if (outbound.optString("type") !in skip) return outbound
		}
		return null
	}

	@Test
	fun `a hysteria2 node becomes a hysteria2 outbound`() {
		val (proxy,
			notes) = convert(cfg(
				"""{"protocol":"hysteria2","tag":"n",
                     "settings":{"servers":[{"address":"a.example.com","port":443,
                       "password":"pw"}]},"streamSettings":{"security":"tls",
                         "tlsSettings":{"serverName":"a.example.com"}}}"""))
		assertTrue("the node was dropped: $notes", proxy != null)
		assertEquals("hysteria2", proxy!!.optString("type"))
		assertEquals("a.example.com", proxy.optString("server"))
		assertEquals(443, proxy.optInt("server_port"))
		assertEquals("pw", proxy.optString("password"))
		// TLS is not optional for this outbound: the core answers a missing
		// block with "TLS required" and refuses the whole document.
		assertTrue(proxy.optJSONObject("tls")?.optBoolean("enabled") == true)
		assertEquals("a.example.com", proxy.optJSONObject("tls")?.optString("server_name"))
	}

	@Test
	fun `the password is found wherever the config keeps it`() {
		// Xray writes it in streamSettings; a Hysteria2-style generator writes
		// it in settings; both describe the same node.
		val native = cfg(
			"""{"protocol":"hysteria","tag":"n","settings":{"servers":[{"address":"a.example.com",
                 "port":443}]},"streamSettings":{"network":"hysteria","security":"tls",
                   "tlsSettings":{"serverName":"a.example.com"},"hysteriaSettings":{"auth":"pw"}}}""")
		val (proxy, notes) = convert(native)
		assertTrue("the node was dropped: $notes", proxy != null)
		assertEquals("hysteria2", proxy!!.optString("type"))
		assertEquals("pw", proxy.optString("password"))
	}

	@Test
	fun `rates are carried across in whole Mbps, however they were spelled`() {
		for (settings in listOf(
			"""{"servers":[{"address":"a.example.com","port":443,"password":"pw","up":"100 Mbps",
                 "down":"200 Mbps"}]}""",
			"""{"servers":[{"address":"a.example.com","port":443,"password":"pw","upMbps":100,
                 "downMbps":200}]}""",
			// The spelling the Hysteria v1 client itself writes.
			"""{"servers":[{"address":"a.example.com","port":443,"password":"pw","up_mbps":100,
                 "down_mbps":200}]}"""
		)) {
			val (proxy,
				notes) = convert(cfg(
					"""{"protocol":"hysteria2","tag":"n","settings":$settings,
                         "streamSettings":{"security":"tls",
                         "tlsSettings":{"serverName":"a.example.com"}}}"""))
			assertTrue("dropped for $settings: $notes", proxy != null)
			assertEquals("up, for $settings", 100, proxy!!.optInt("up_mbps"))
			assertEquals("down, for $settings", 200, proxy.optInt("down_mbps"))
		}
	}

	@Test
	fun `salamander obfuscation is carried in either form`() {
		for (obfs in listOf(
			""""obfs":"salamander","obfsPassword":"secret"""",
			""""obfs":{"type":"salamander","salamander":{"password":"secret"}}"""
		)) {
			val (proxy,
				_) = convert(cfg(
					"""{"protocol":"hysteria2","tag":"n",
                         "settings":{"servers":[{"address":"a.example.com","port":443,
                           "password":"pw"}],$obfs},"streamSettings":{"security":"tls",
                             "tlsSettings":{"serverName":"a.example.com"}}}"""))
			val obfsBlock = proxy?.optJSONObject("obfs")
			assertTrue("no obfs block for $obfs", obfsBlock != null)
			assertEquals("salamander", obfsBlock!!.optString("type"))
			assertEquals("secret", obfsBlock.optString("password"))
		}
	}

	@Test
	fun `gecko obfuscation and an unknown type are refused, not stripped`() {
		// gecko came in sing-box 1.14, which the 1.12 and 1.13 cores refuse a whole document over,
		// and a third type is one the server would not answer: either way the node goes, with why.
		for ((obfs, said) in listOf("gecko" to "1.14", "randomizer" to "randomizer")) {
			val body = cfg(
				"""{"protocol":"hysteria2","tag":"n","settings":{"servers":[{"address":"a.example.com",
					"port":443,"password":"pw"}],"obfs":"$obfs","obfsPassword":"s"},
					"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""
			)
			val result = SingBoxConverter.convertToOutbounds(body, "n")
			assertTrue("$result", result is SingBoxConverter.OutboundsResult.Unsupported)
			val notes = (result as SingBoxConverter.OutboundsResult.Unsupported).notes
			assertTrue("$notes", notes.any { it.startsWith("skipped: ") && it.contains(said) })
		}
	}

	@Test
	fun `port hopping becomes the range list the core takes`() {
		val (proxy,
			_) = convert(cfg(
				"""{"protocol":"hysteria2","tag":"n",
                     "settings":{"servers":[{"address":"a.example.com","port":443,
                       "ports":"443-8443,9000",
                         "password":"pw"}],"hopInterval":"30s"},"streamSettings":{"security":"tls",
                           "tlsSettings":{"serverName":"a.example.com"}}}"""))
		val ranges = proxy?.optJSONArray("server_ports")
		assertTrue("no server_ports", ranges != null)
		assertEquals(2, ranges!!.length())
		// "443-8443,9000" in the source; "start:end" in the core, and a lone
		// port spelled as a range of one.
		assertEquals("443:8443", ranges.getString(0))
		assertEquals("9000:9000", ranges.getString(1))
		assertEquals("30s", proxy!!.optString("hop_interval"))
	}

	// The v1 credential always goes out as a plain string.
	@Test
	fun `the v1 credential is taken as a plain string, whichever name held it`() {
		for (field in listOf("auth", "auth_str", "password")) {
			val (proxy,
				_) = convert(cfg(
					"""{"protocol":"hysteria","tag":"n",
                         "settings":{"servers":[{"address":"a.example.com","port":443,"$field":"pw",
                           "up_mbps":100,
                             "down_mbps":100}]},"streamSettings":{"security":"tls",
                               "tlsSettings":{"serverName":"a.example.com"}}}"""))
			assertEquals("from $field", "pw", proxy!!.optString("auth_str"))
			assertFalse("nothing may be handed over as base64: $field", proxy.has("auth"))
		}
	}

	// A rate is not always in Mbps.
	@Test
	fun `rates in other units survive rather than being dropped`() {
		val kbps = convert(cfg(
			"""{"protocol":"hysteria","tag":"n","settings":{"servers":[{"address":"a.example.com",
                 "port":443,"auth_str":"pw","up":"640 KBps",
                   "down":"640 KBps"}]},"streamSettings":{"security":"tls",
                     "tlsSettings":{"serverName":"a.example.com"}}}""")).first
		assertEquals("640 KBps", kbps!!.optString("up"))
		assertEquals("640 KBps", kbps.optString("down"))

		// Gbps lands on a whole number of Mbps, so it goes out as a number.
		val gbps = convert(cfg(
			"""{"protocol":"hysteria","tag":"n","settings":{"servers":[{"address":"a.example.com",
                 "port":443,"auth_str":"pw","up":"2 Gbps",
                   "down":"2 Gbps"}]},"streamSettings":{"security":"tls",
                     "tlsSettings":{"serverName":"a.example.com"}}}""")).first
		assertEquals(2000, gbps!!.optInt("up_mbps"))
	}

	@Test
	fun `a hysteria2 rate that is not whole Mbps takes the nearest and says so`() {
		// hysteria2 has no string form for the rate, so the nearest whole Mbps stands in for one that
		// does not land on a whole one, and the note says what it was.
		val (proxy,
			notes) = convert(cfg(
				"""{"protocol":"hysteria2","tag":"n",
                     "settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw",
                       "up":"640 KBps",
                         "down":"640 KBps"}]},"streamSettings":{"security":"tls",
                           "tlsSettings":{"serverName":"a.example.com"}}}"""))
		assertTrue("the node itself must survive", proxy != null)
		assertEquals(1, proxy!!.optInt("up_mbps"))
		assertTrue("the rounding must be reported: $notes", notes.any { it.contains("640 KBps") })
	}

	@Test
	fun `version 1 gets port hopping too`() {
		val (proxy,
			_) = convert(cfg(
				"""{"protocol":"hysteria","tag":"n",
                     "settings":{"servers":[{"address":"a.example.com","port":443,
                       "ports":"443-8443","auth_str":"pw","up_mbps":100,
                         "down_mbps":100}],"hopInterval":"30s"},"streamSettings":{"security":"tls",
                           "tlsSettings":{"serverName":"a.example.com"}}}"""))
		assertEquals("443:8443", proxy!!.getJSONArray("server_ports").getString(0))
		assertEquals("30s", proxy.optString("hop_interval"))
	}

	@Test
	fun `a hysteria v1 node keeps its own field names`() {
		val (proxy,
			notes) = convert(cfg(
				"""{"protocol":"hysteria","tag":"n",
                     "settings":{"servers":[{"address":"a.example.com","port":443,"auth":"pw",
                       "up_mbps":100,
                         "down_mbps":200}],"obfs":"xplus"},"streamSettings":{"security":"tls",
                           "tlsSettings":{"serverName":"a.example.com"}}}"""))
		assertTrue("the node was dropped: $notes", proxy != null)
		assertEquals("hysteria", proxy!!.optString("type"))
		// Version 1 authenticates with a plain string under auth_str, and its
		// obfuscator is a string rather than version 2's object.
		assertEquals("pw", proxy.optString("auth_str"))
		assertEquals("xplus", proxy.optString("obfs"))
		assertEquals(100, proxy.optInt("up_mbps"))
		assertEquals(200, proxy.optInt("down_mbps"))
	}

	@Test
	fun `hysteria v1 without rates is refused with the reason`() {
		// Both rates are mandatory in version 1; the core has nothing to pace with otherwise.
		val (proxy,
			notes) = convert(cfg(
				"""{"protocol":"hysteria","tag":"n",
                     "settings":{"servers":[{"address":"a.example.com","port":443,"auth":"pw"}]},
                       "streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}"""))
		assertNull(proxy)
		assertTrue("the reason must be given, notes were $notes",
			notes.any { it.contains("up and down rates") })
	}

	@Test
	fun `a TUIC node becomes a tuic outbound with its options`() {
		val (proxy,
			notes) = convert(cfg(
				"""{"protocol":"tuic","tag":"n","settings":{"servers":[{"address":"a.example.com",
                     "port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e",
                       "password":"pw"}],"congestion_control":"bbr","udp_relay_mode":"native",
                         "reduce_rtt":true,"heartbeat_interval":10000},
                           "streamSettings":{"security":"tls",
                             "tlsSettings":{"serverName":"a.example.com","alpn":["h3"]}}}"""))
		assertTrue("the node was dropped: $notes", proxy != null)
		assertEquals("tuic", proxy!!.optString("type"))
		assertEquals(uuid, proxy.optString("uuid"))
		assertEquals("pw", proxy.optString("password"))
		assertEquals("bbr", proxy.optString("congestion_control"))
		assertEquals("native", proxy.optString("udp_relay_mode"))
		// reduce_rtt is what the source calls it; the core calls it zero_rtt_handshake.
		assertTrue(proxy.optBoolean("zero_rtt_handshake"))
		// heartbeat_interval is in milliseconds - mihomo documents it that way and 10000 is the
		// value its own sample uses.
		assertEquals("10000ms", proxy.optString("heartbeat"))
		assertEquals(listOf("h3"), (0 until (proxy.optJSONObject("tls")!!.getJSONArray("alpn").length()))
			.map { proxy.optJSONObject("tls")!!.getJSONArray("alpn").getString(it) })
	}

	@Test
	fun `a value the core would refuse is dropped instead of taking the config down`() {
		// congestion_control is validated by the core, and an unknown name is answered by refusing
		// the whole document - one odd node would cost the subscription.
		val (proxy,
			notes) = convert(cfg(
				"""{"protocol":"tuic","tag":"n","settings":{"servers":[{"address":"a.example.com",
                     "port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e",
                       "password":"pw"}],"congestion_control":"bbr2","udp_relay_mode":"weird"},
                         "streamSettings":{"security":"tls",
                         "tlsSettings":{"serverName":"a.example.com"}}}"""))
		assertTrue("the node must survive", proxy != null)
		assertFalse(proxy!!.has("congestion_control"))
		assertFalse(proxy.has("udp_relay_mode"))
		assertTrue("both losses must be named: $notes", notes.size >= 2)
	}

	@Test
	fun `a TUIC v4 node is refused rather than emitted without a credential`() {
		// sing-box implements v5, which authenticates with a uuid. A v4 node
		// carries a token instead and has no representation here.
		val (proxy,
			notes) = convert(cfg(
				"""{"protocol":"tuic","tag":"n","settings":{"servers":[{"address":"a.example.com",
                     "port":443,
                       "token":"tok"}]},"streamSettings":{"security":"tls",
                         "tlsSettings":{"serverName":"a.example.com"}}}"""))
		assertNull(proxy)
		assertTrue("the reason must name the uuid, notes were $notes", notes.any { it.contains("uuid") })
	}

	@Test
	fun `these live alongside the older protocols in one configuration`() {
		val mixed = """{"remarks":"M","outbounds":[
            {"protocol":"vless","tag":"v","settings":{"vnext":[{"address":"b.example.com",
              "port":443,"users":[{"id":"$uuid",
                "encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls",
                  "tlsSettings":{"serverName":"b.example.com"}}},
            {"protocol":"hysteria2","tag":"h","settings":{"servers":[{"address":"a.example.com",
              "port":443,
                "password":"pw"}]},"streamSettings":{"security":"tls",
                  "tlsSettings":{"serverName":"a.example.com"}}},
            {"protocol":"tuic","tag":"t","settings":{"servers":[{"address":"c.example.com",
              "port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"}]},"streamSettings":{"security":"tls",
                "tlsSettings":{"serverName":"c.example.com"}}}]}"""
			.trimIndent().replace("\n", "")
		val result = SingBoxConverter.convert(mixed, "N")
		assertTrue("expected a converted config, got $result", result is SingBoxConverter.Result.Ok)
		val types = (result as SingBoxConverter.Result.Ok).config.getJSONArray("outbounds").let { arr ->
			(0 until arr.length()).map { arr.getJSONObject(it).optString("type") }
		}
		for (type in listOf("vless", "hysteria2", "tuic")) {
			assertTrue("$type is missing from $types", type in types)
		}
		assertTrue("nothing should have been dropped: ${result.notes}", result.notes.isEmpty())
	}

	@Test
	fun `the link form carries the credential too`() {
		// The password is read where nodes actually carry it: read from a field nothing writes,
		// every node would become "hysteria2://@host:port" - a link with no credential, which
		// connects to nothing.
		val hysteriaConfig =
			"""{"remarks":"H","outbounds":[{"protocol":"hysteria2","tag":"h",
                 "settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}],
                   "obfs":"salamander","obfsPassword":"o"},"streamSettings":{"security":"tls",
                     "tlsSettings":{"serverName":"a.example.com"}}}]}"""
		val link = SubscriptionConverter.convert(hysteriaConfig, jsonToUri = true)
		assertTrue("no password in $link", link.startsWith("hysteria2://pw@a.example.com:443"))
		assertTrue("no obfs in $link", link.contains("obfs=salamander"))
		assertTrue("no obfs password in $link", link.contains("obfs-password=o"))

		val tuic =
			"""{"remarks":"T","outbounds":[{"protocol":"tuic","tag":"t",
                 "settings":{"servers":[{"address":"a.example.com","port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e",
                   "password":"pw"}]},"streamSettings":{"security":"tls",
                     "tlsSettings":{"serverName":"a.example.com"}}}]}"""
		val tlink = SubscriptionConverter.convert(tuic, jsonToUri = true)
		val tuicStart = "tuic://9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e:pw@a.example.com:443"
		assertTrue("empty credentials in $tlink", tlink.startsWith(tuicStart))
		assertFalse("the empty form must be gone", tlink.contains("tuic://:@:0"))
	}

	// A hop interval written as a range: mihomo takes it as written, sing-box and the link keep its
	// lower bound with a note - read wherever the ports are: beside the address, in the shared
	// settings, in hysteriaSettings.udphop, in finalmask's udpHop and in its udphop mask.
	@Test
	fun `a hop interval range reaches mihomo whole and sing-box as its low end, from every place`() {
		val forms = listOf(
			"""{"protocol":"hysteria2","tag":"n","settings":{"servers":[{"address":"a.example.com",
                 "port":443,"password":"pw","ports":"20000-30000",
                   "hopInterval":"5-10"}]},"streamSettings":{"security":"tls",
                     "tlsSettings":{"serverName":"a.example.com"}}}""",
			"""{"protocol":"hysteria2","tag":"n","settings":{"servers":[{"address":"a.example.com",
                 "port":443,"password":"pw",
                   "ports":"20000-30000"}],"hopInterval":"5-10"},"streamSettings":{"security":"tls",
                     "tlsSettings":{"serverName":"a.example.com"}}}""",
			"""{"protocol":"hysteria","tag":"n","settings":{"address":"a.example.com","port":443,
                 "version":2},"streamSettings":{"network":"hysteria",
                   "hysteriaSettings":{"version":2,"auth":"pw","udphop":{"ports":"20000-30000",
                     "interval":"5-10"}},"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}""",
			"""{"protocol":"hysteria","tag":"n","settings":{"address":"a.example.com","port":443,
                 "version":2},"streamSettings":{"network":"hysteria",
                   "hysteriaSettings":{"version":2,"auth":"pw"},"security":"tls",
                     "tlsSettings":{"serverName":"a.example.com"},
                       "finalmask":{"quicParams":{"udpHop":{"ports":"20000-30000","interval":"5-10"}}}}}""",
			"""{"protocol":"hysteria","tag":"n","settings":{"address":"a.example.com","port":443,
                 "version":2},"streamSettings":{"network":"hysteria",
                   "hysteriaSettings":{"version":2,"auth":"pw"},"security":"tls",
                     "tlsSettings":{"serverName":"a.example.com"},"finalmask":{"udp":[{"type":"udphop",
                       "settings":{"mode":"intervalRemote","remotePorts":"20000-30000",
                         "interval":"5-10"}}]}}}"""
		)
		for (form in forms) {
			val (proxy, _) = convert(cfg(form))
			assertEquals(form, "5s", proxy!!.optString("hop_interval"))
			assertFalse("the 1.12 and 1.13 cores refuse this field", proxy.has("hop_interval_max"))
			val yaml = SubscriptionConverter.convert(cfg(form), jsonToUri = false, xrayToMihomo = true)
			assertTrue(form, yaml.contains("hop-interval: 5-10"))
			val link = SubscriptionConverter.convertWithStats(cfg(form), jsonToUri = true)
			assertTrue(form,
				link.text.contains("mportHopInt=5&") || link.text.contains("mportHopInt=5#") ||
					link.text.trim().endsWith("mportHopInt=5"))
			assertTrue(form, link.notes.any { it.contains("5-10") })
		}
	}
}
