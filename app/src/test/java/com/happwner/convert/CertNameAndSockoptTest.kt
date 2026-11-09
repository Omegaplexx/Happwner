package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Two things a config can say that must leave a trace: a certificate-name check mihomo can perform,
// and socket options that have to be named by both converters.
class CertNameAndSockoptTest {

	private fun mihomo(xray: String): MihomoConverter.Result.Ok {
		val result = MihomoConverter.convert(xray)
		assertTrue("expected Ok, got $result", result is MihomoConverter.Result.Ok)
		return result as MihomoConverter.Result.Ok
	}

	private fun cfg(tls: String = "", sockopt: String = "") = """
        {"remarks":"C","outbounds":[{"tag":"t","protocol":"vless",
         "settings":{"vnext":[{"address":"a.com","port":443,
           "users":[{"id":"u","encryption":"none"}]}]},
         "streamSettings":{"network":"tcp","security":"tls",
           "tlsSettings":{"serverName":"a.com"$tls}$sockopt}}]}
	""".trimIndent()

	// mihomo's name-cert-verify is exactly this check.
	@Test
	fun mihomo_carries_verify_peer_cert_in_names() {
		val yaml = mihomo(cfg(tls = ",\"verifyPeerCertInNames\":[\"real.example.com\"]")).yaml
		assertTrue("name-cert-verify missing from:\n$yaml",
			yaml.contains("name-cert-verify: real.example.com"))
	}

	// mihomo verifies against one name, so a longer list has to say what happened to the rest.
	@Test
	fun a_longer_name_list_is_reported() {
		val result = mihomo(cfg(tls = ",\"verifyPeerCertInNames\":[\"one.example.com\",\"two.example.com\"]"))
		assertTrue("name-cert-verify missing", result.yaml.contains("name-cert-verify: one.example.com"))
		assertEquals(1, result.notes.count { it.contains("verifyPeerCertByName / verifyPeerCertInNames") })
		assertEquals(1, result.notes.count { it.contains("verifyPeerCertInNames is not read by Xray 26") })
	}

	// sing-box verifies against server_name only, so it says so rather than staying silent.
	@Test
	fun singbox_reports_verify_peer_cert_in_names() {
		val notes = singBoxNotesOf(cfg(tls = ",\"verifyPeerCertInNames\":[\"real.example.com\"]"))
		assertEquals(1, notes.count { it.contains("verifyPeerCertByName / verifyPeerCertInNames") })
		assertEquals(1, notes.count { it.contains("verifyPeerCertInNames is not read by Xray 26") })
	}

	// sing-box checks the certificate against the name it sends, so the name to verify is the one sent -
	// unless nothing is checked, or the one sent is a name to verify already.
	@Test
	fun singbox_sends_the_name_to_verify() {
		fun tlsOf(extra: String): JSONObject {
			val result = SingBoxConverter.convert(cfg(tls = extra), "N") as SingBoxConverter.Result.Ok
			return result.config.getJSONArray("outbounds").getJSONObject(0).getJSONObject("tls")
		}
		val names = ",\"verifyPeerCertByName\":\"real.example.com\""
		assertEquals("real.example.com", tlsOf(names).getString("server_name"))
		assertEquals("a.com", tlsOf("$names,\"allowInsecure\":true").getString("server_name"))
		assertEquals("a.com", tlsOf(",\"verifyPeerCertByName\":\"a.com\"").getString("server_name"))
		val notes = singBoxNotesOf(cfg(tls = ",\"verifyPeerCertByName\":\"a.com\""))
		assertTrue("$notes", notes.none { "verifyPeerCertByName" in it })
		// With no name written, the address is the one sent.
		val unnamed = cfg(tls = ",\"verifyPeerCertByName\":\"a.com\"")
			.replace("\"serverName\":\"a.com\",", "")
		val kept = SingBoxConverter.convert(unnamed, "N") as SingBoxConverter.Result.Ok
		val keptTls = kept.config.getJSONArray("outbounds").getJSONObject(0).getJSONObject("tls")
		assertFalse("$keptTls", keptTls.has("server_name"))
		assertTrue("${kept.notes}", kept.notes.none { "verifyPeerCertByName" in it })
		// An httpupgrade Host stays the one Xray sends, where sing-box would send the name in its place.
		val upgrade = cfg(tls = names).replace("\"network\":\"tcp\"", "\"network\":\"httpupgrade\"")
		val upgraded = SingBoxConverter.convert(upgrade, "N") as SingBoxConverter.Result.Ok
		val node = upgraded.config.getJSONArray("outbounds").getJSONObject(0)
		assertEquals("real.example.com", node.getJSONObject("tls").getString("server_name"))
		assertEquals("a.com", node.getJSONObject("transport").getString("host"))
	}

	// A Hysteria2 node the same, and the pin its outbound has no field for named, as on any other.
	@Test
	fun singbox_hysteria2_sends_the_name_to_verify_and_names_the_pin_it_drops() {
		val tls = """{"serverName":"fake.example.org","verifyPeerCertByName":"h.example.com",""" +
			""""pinnedPeerCertSha256":"${"aa".repeat(32)}"}"""
		val stream = """{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"pw"},""" +
			""""security":"tls","tlsSettings":$tls}"""
		val body = """{"outbounds":[{"protocol":"hysteria","tag":"h","settings":{"version":2,""" +
			""""address":"h.example.com","port":443},"streamSettings":$stream}]}"""
		val result = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		val node = result.config.getJSONArray("outbounds").getJSONObject(0)
		assertEquals("h.example.com", node.getJSONObject("tls").getString("server_name"))
		assertTrue("${result.notes}", result.notes.any { SingBoxStream.UNPINNED_NOTE in it })
		assertTrue("${result.notes}", result.notes.any { "was sent as the server name" in it })
	}

	// A switched-off option is not a dropped one. Reporting it would send somebody looking for a
	// setting they deliberately turned off, and the two modes would disagree about the same config.
	@Test
	fun a_switched_off_sockopt_is_not_reported_by_either() {
		val sockopt = ",\"sockopt\":{\"tcpNoDelay\":false,\"V6Only\":false,\"penetrate\":false," +
			"\"tcpUserTimeout\":0,\"tcpMaxSeg\":0,\"customSockopt\":[]}"
		val singBoxNotes = singBoxNotesOf(cfg(sockopt = sockopt))
		val mihomoNotes = mihomo(cfg(sockopt = sockopt)).notes
		for (field in listOf("tcpNoDelay", "V6Only", "penetrate", "tcpUserTimeout", "tcpMaxSeg",
			"customSockopt")) {
			assertTrue("sing-box should say nothing about a disabled $field: $singBoxNotes",
				singBoxNotes.none { it.contains(field) })
			assertTrue("mihomo should say nothing about a disabled $field: $mihomoNotes",
				mihomoNotes.none { it.contains(field) })
		}
	}

	// The same configuration must read the same way whichever mode produced it.
	@Test
	fun both_converters_name_the_same_dropped_sockopt_options() {
		val sockopt = ",\"sockopt\":{\"tcpNoDelay\":true,\"tcpUserTimeout\":10000," +
			"\"tcpWindowClamp\":600,\"tcpMaxSeg\":1440,\"V6Only\":true,\"penetrate\":true," +
			"\"happyEyeballs\":{\"tryDelayMs\":250},\"customSockopt\":[{\"level\":\"6\"}]}"
		val singBoxNotes = singBoxNotesOf(cfg(sockopt = sockopt))
		val mihomoNotes = mihomo(cfg(sockopt = sockopt)).notes
		for (field in listOf("tcpNoDelay", "tcpUserTimeout", "tcpWindowClamp", "tcpMaxSeg",
						 "V6Only", "penetrate", "happyEyeballs", "customSockopt")) {
			assertTrue("sing-box says nothing about $field", singBoxNotes.any { it.contains(field) })
			assertTrue("mihomo says nothing about $field", mihomoNotes.any { it.contains(field) })
		}
	}
}
