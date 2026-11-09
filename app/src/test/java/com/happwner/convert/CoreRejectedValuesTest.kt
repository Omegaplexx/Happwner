package com.happwner.convert

import com.happwner.text.decodeBase64Any
import com.happwner.text.toHex
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Values a core refuses the whole document over: a field it does not know, or a value it will not take,
// is not skipped but answered by refusing everything, so one odd node costs the whole subscription.
class CoreRejectedValuesTest {

	private val uuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"
	private val wgPriv = "cKX1G0yg4Uyq6M6l7xX6h4L3s8m3Jo2eZk1v7d9n2ZA="
	private val wgPub = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="

	private fun vlessTls(tls: String) =
		"""{"remarks":"T","outbounds":[{"protocol":"vless","tag":"n","settings":{"vnext":[
           {"address":"a.example.com","port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
           "streamSettings":{"network":"tcp","security":"tls","tlsSettings":$tls}}]}"""
			.trimIndent().replace("\n", "")

	private fun wireguard(settings: String) =
		"""{"remarks":"W","outbounds":[{"protocol":"wireguard","tag":"n","settings":$settings}]}"""

	private fun sbProxy(body: String): Pair<JSONObject?, List<String>> =
		when (val result = SingBoxConverter.convert(body, "N")) {
			is SingBoxConverter.Result.Ok -> {
				val skip = setOf("direct", "block", "dns", "selector", "urltest")
				val outs = result.config.optJSONArray("outbounds")
				var found: JSONObject? = (0 until (outs?.length() ?: 0))
					.map { outs!!.getJSONObject(it) }
					.firstOrNull { it.optString("type") !in skip }
				if (found == null) {
					val eps = result.config.optJSONArray("endpoints")
					found = (0 until (eps?.length() ?: 0)).map { eps!!.getJSONObject(it) }.firstOrNull()
				}
				found to result.notes
			}
			is SingBoxConverter.Result.Unsupported -> null to result.notes
			else -> null to listOf("NotXray")
		}

	@Test
	fun `only the four TLS versions the core knows are written`() {
		// "unknown tls version: TLS1.2" refuses everything, and Xray's own
		// spellings are the four below, so anything else came from an edit.
		for (version in listOf("1.0", "1.1", "1.2", "1.3")) {
			val (proxy, _) = sbProxy(vlessTls("""{"serverName":"a.example.com","minVersion":"$version"}"""))
			assertEquals("version $version must be carried", version,
				proxy!!.optJSONObject("tls")?.optString("min_version"))
		}
		for (version in listOf("TLS1.2", "1.4", "nonsense", "1")) {
			val (proxy,
				notes) = sbProxy(vlessTls("""{"serverName":"a.example.com","minVersion":"$version"}"""))
			assertTrue("the node must survive", proxy != null)
			assertFalse("$version must not reach the core", proxy!!.optJSONObject("tls")!!.has("min_version"))
			assertTrue("the drop must be named for $version: $notes", notes.any { it.contains(version) })
		}
	}

	@Test
	fun `maxVersion is held to the same list`() {
		val (proxy, notes) = sbProxy(vlessTls("""{"serverName":"a.example.com","maxVersion":"1.4"}"""))
		assertFalse(proxy!!.optJSONObject("tls")!!.has("max_version"))
		assertTrue("$notes", notes.any { it.contains("maxVersion") })
	}

	@Test
	fun `a certificate file path is not carried into someone else's document`() {
		// The core opens the file as it loads and answers a missing one with "no such file or
		// directory", refusing everything.
		val (proxy, notes) = sbProxy(vlessTls(
			"""{"serverName":"a.example.com","certificates":[{"usage":"verify",
                 "certificateFile":"/etc/xray/ca.pem"}]}"""
		))
		assertTrue("the node must survive", proxy != null)
		assertFalse("a foreign path must not reach the core",
			proxy!!.optJSONObject("tls")!!.has("certificate_path"))
		assertTrue("the drop must be named: $notes", notes.any { it.contains("certificateFile") })
	}

	@Test
	fun `an inline certificate is still carried`() {
		// Only the path is a problem; the certificate itself travels fine.
		val pem = TEST_CERTIFICATE_JSON
		val (proxy, _) = sbProxy(vlessTls(
			"""{"serverName":"a.example.com","certificates":[{"usage":"verify","certificate":["$pem"]}]}"""
		))
		assertTrue("the inline certificate was lost", proxy!!.optJSONObject("tls")!!.has("certificate"))
	}

	@Test
	fun `a wireguard key is read whichever form Xray reads it in`() {
		// Hex, or base64 in either alphabet with or without its padding, as ParseWireGuardKey reads
		// it; both cores take only standard base64, so the key reaches them rewritten.
		val std = wgPriv
		val url = std.replace('+', '-').replace('/', '_')
		val hex = toHex(decodeBase64Any(std)!!)
		for ((label, key) in listOf("standard" to std, "url-safe" to url,
			"unpadded" to std.trimEnd('='), "url-safe unpadded" to url.trimEnd('='), "hex" to hex)) {
			val (endpoint, notes) = sbProxy(wireguard(
				"""{"secretKey":"$key","address":["10.0.0.2/32"],
                   "peers":[{"endpoint":"a.example.com:51820","publicKey":"$wgPub",
                   "allowedIPs":["0.0.0.0/0"]}]}""".trimIndent().replace("\n", "")
			))
			assertTrue("the $label key should not cost the node: $notes", endpoint != null)
			assertEquals(
				"the $label key has to reach the core in the form it decodes",
				std, endpoint!!.optString("private_key")
			)
		}
	}

	@Test
	fun `a key Xray cannot use still costs the node`() {
		// Xray reads a key as written - no spaces trimmed, one alphabet - and a short one fails
		// when it dials ("IPC error -22: failed to set private_key"): the node never carried traffic.
		val short = wgPriv.dropLast(8)
		for ((label, key) in listOf("too short" to short, "not base64" to "not-a-key-at-all",
			"nothing but dashes" to "-".repeat(42) + "=", "padded with spaces" to "  $wgPriv  ",
			"of two alphabets" to "-+" + wgPriv.drop(2))) {
			val (endpoint, notes) = sbProxy(wireguard(
				"""{"secretKey":"$key","address":["10.0.0.2/32"],
                   "peers":[{"endpoint":"a.example.com:51820","publicKey":"$wgPub",
                   "allowedIPs":["0.0.0.0/0"]}]}""".trimIndent().replace("\n", "")
			))
			assertTrue("a $label key should be refused", endpoint == null)
			assertTrue("the refusal should say why: $notes",
				notes.any { it.contains("32 bytes") })
		}
	}

	@Test
	fun `a peer's keys are read the same way`() {
		val urlPub = wgPub.replace('+', '-').replace('/', '_')
		val (endpoint, notes) = sbProxy(wireguard(
			"""{"secretKey":"$wgPriv","address":["10.0.0.2/32"],
               "peers":[{"endpoint":"a.example.com:51820","publicKey":"$urlPub",
               "preSharedKey":"${wgPub.trimEnd('=')}","allowedIPs":["0.0.0.0/0"]}]}"""
				.trimIndent().replace("\n", "")
		))
		assertTrue("the peer's key should not cost the node: $notes", endpoint != null)
		val peer = endpoint!!.getJSONArray("peers").getJSONObject(0)
		assertEquals(wgPub, peer.optString("public_key"))
		assertEquals(wgPub, peer.optString("pre_shared_key"))
	}

	@Test
	fun `wireguard reserved is carried only at the length the core wants`() {
		// "invalid reserved value, required 3 bytes, got 4" from both cores.
		val accepted = sbProxy(wireguard("""{"secretKey":"$wgPriv","address":["10.0.0.2/32"],
          "reserved":[1,2,3],
            "peers":[{"endpoint":"a.example.com:51820","publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","allowedIPs":["0.0.0.0/0"]}]}"""
			.trimIndent().replace("\n", ""))).first
		val peer = accepted!!.getJSONArray("peers").getJSONObject(0)
		assertTrue("three bytes must be carried", peer.has("reserved"))
		assertEquals(3, peer.getJSONArray("reserved").length())

		val (bad, notes) = sbProxy(wireguard("""{"secretKey":"$wgPriv","address":["10.0.0.2/32"],
          "reserved":[1,2,3,4],
            "peers":[{"endpoint":"a.example.com:51820","publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","allowedIPs":["0.0.0.0/0"]}]}"""
			.trimIndent().replace("\n", "")))
		assertFalse("four bytes must not reach the core",
			bad!!.getJSONArray("peers").getJSONObject(0).has("reserved"))
		assertTrue("the drop must be named: $notes", notes.any { it.contains("reserved") })
	}

	@Test
	fun `wireguard reserved belongs to the peer and not to the endpoint`() {
		// sing-box has no reserved on the endpoint at all: putting it there is an unknown field and
		// the document is refused.
		val endpoint = sbProxy(wireguard("""{"secretKey":"$wgPriv","address":["10.0.0.2/32"],
          "reserved":[1,2,3],
            "peers":[{"endpoint":"a.example.com:51820","publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","allowedIPs":["0.0.0.0/0"]},
                     {"endpoint":"b.example.com:51821","publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","allowedIPs":["0.0.0.0/0"]}]}"""
			.trimIndent().replace("\n", ""))).first
		assertFalse("the endpoint must not carry it", endpoint!!.has("reserved"))
		val peers = endpoint.getJSONArray("peers")
		for (i in 0 until peers.length()) {
			assertTrue("peer $i lost the reserved value", peers.getJSONObject(i).has("reserved"))
		}
	}

	private fun addressBody(address: String) = wireguard(
		"""{"secretKey":"$wgPriv","address":$address,
			"peers":[{"endpoint":"a.example.com:51820","publicKey":"$wgPub","allowedIPs":["0.0.0.0/0"]}]}"""
			.trimIndent().replace("\n", ""))

	private fun reservedBody(reserved: String) = wireguard(
		"""{"secretKey":"$wgPriv","address":["10.0.0.2/32"],"reserved":$reserved,
			"peers":[{"endpoint":"a.example.com:51820","publicKey":"$wgPub","allowedIPs":["0.0.0.0/0"]}]}"""
			.trimIndent().replace("\n", ""))

	@Test
	fun `a reserved value that is not a byte is dropped and named, not cut down to one`() {
		// Xray refuses 1.5 or 300 in a byte outright; cut down to fit, mihomo carried 1, 44 or 255 the
		// config never held, and sing-box took 1.5 as it was and refused the whole file.
		for (value in listOf("1.5", "-0.5", "300", "-1", "\"x\"")) {
			val (endpoint, notes) = sbProxy(reservedBody("[$value,2,3]"))
			val peer = endpoint!!.getJSONArray("peers").getJSONObject(0)
			assertFalse("$value reached sing-box", peer.has("reserved"))
			assertTrue("sing-box must name $value: $notes", notes.any { it.contains("not a byte") })
			val mihomo = MihomoConverter.convert(reservedBody("[$value,2,3]")) as MihomoConverter.Result.Ok
			assertFalse("$value reached mihomo: ${mihomo.yaml}", mihomo.yaml.contains("reserved:"))
			assertTrue("mihomo must name $value: ${mihomo.notes}",
				mihomo.notes.any { it.contains("not a byte") })
		}
	}

	// Xray reads "reserved" as Go reads bytes from JSON: a list of numbers or their base64 in one string.
	@Test
	fun `a reserved value written as base64 reaches both cores as its three bytes`() {
		val (endpoint, notes) = sbProxy(reservedBody("\"AQID\""))
		val peer = endpoint!!.getJSONArray("peers").getJSONObject(0)
		assertEquals("[1,2,3]", peer.getJSONArray("reserved").toString())
		assertFalse("$notes", notes.any { it.contains("reserved") })
		val mihomo = MihomoConverter.convert(reservedBody("\"AQID\"")) as MihomoConverter.Result.Ok
		assertTrue(mihomo.yaml, mihomo.yaml.contains("reserved: [1, 2, 3]"))
	}

	@Test
	fun `a reserved list of the wrong length is named for its length in both passes`() {
		val notes = sbProxy(reservedBody("[1.5,2]")).second
		assertTrue("sing-box must name the length: $notes", notes.any { it.contains("reserved is 2") })
		val mihomo = MihomoConverter.convert(reservedBody("[1.5,2]")) as MihomoConverter.Result.Ok
		assertTrue("mihomo must name the length: ${mihomo.notes}",
			mihomo.notes.any { it.contains("reserved is 2 bytes") })
		assertFalse(mihomo.yaml, mihomo.yaml.contains("reserved:"))
	}

	@Test
	fun `a whole reserved value reaches both cores as an integer`() {
		val peer = sbProxy(reservedBody("[2.0,0,255]")).first!!.getJSONArray("peers").getJSONObject(0)
		assertEquals("[2,0,255]", peer.getJSONArray("reserved").toString())
		val mihomo = MihomoConverter.convert(reservedBody("[2.0,0,255]")) as MihomoConverter.Result.Ok
		assertTrue(mihomo.yaml, mihomo.yaml.contains("reserved: [2, 0, 255]"))
	}

	@Test
	fun `an address org json cannot write back drops its configuration, not the merged document`() {
		// sing-box takes the address list over as it stands, and Android's org.json reads 1e400 in it as
		// infinity, which it then cannot write.
		val vless = vlessTls("""{"serverName":"a.example.com"}""")
		val outOfRange = addressBody("""[1e400,"10.0.0.2/32"]""")
		val singBox = ConversionFlags(false, true, false, false)
		val merged = SubscriptionConverter.convertWithStats("[$vless,$outOfRange]", singBox)
		assertTrue(merged.text, merged.text.contains("a.example.com") && merged.xraySkipped == 1)
		assertTrue(merged.notes.toString(), merged.notes.any { "out of range" in it })
	}

	@Test
	fun `a repeated wireguard address reaches sing-box once`() {
		// sing-box refuses the document over \"duplicate address\".
		val kept = sbProxy(addressBody("""["10.0.0.2/32","10.0.0.2/32"]""")).first!!.getJSONArray("address")
		assertEquals(1, kept.length())
		val spelled = sbProxy(addressBody("""["fd00::2/128","FD00:0:0:0:0:0:0:2/128","fd00::3/128"]"""))
		assertEquals(2, spelled.first!!.getJSONArray("address").length())
	}

	@Test
	fun `a null or empty wireguard address never reaches sing-box`() {
		// sing-box reads either as the zero address without complaint and then panics over it.
		val kept = sbProxy(addressBody("""[null,"","10.0.0.2/32"]""")).first!!.getJSONArray("address")
		assertEquals(1, kept.length())
		assertEquals("10.0.0.2/32", kept.getString(0))
		val (assumed, notes) = sbProxy(addressBody("[null]"))
		assertEquals("10.0.0.2/32", assumed!!.getJSONArray("address").getString(0))
		assertTrue("the assumed address must be named: $notes", notes.any { it.contains("was assumed") })
	}

	@Test
	fun `a peer's own reserved wins over the shared one`() {
		val endpoint = sbProxy(wireguard("""{"secretKey":"$wgPriv","address":["10.0.0.2/32"],
          "reserved":[1,2,3],
            "peers":[{"endpoint":"a.example.com:51820","publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
              "allowedIPs":["0.0.0.0/0"],"reserved":[9,9,9]}]}"""
			.trimIndent().replace("\n", ""))).first
		val reserved = endpoint!!.getJSONArray("peers").getJSONObject(0).getJSONArray("reserved")
		assertEquals(9, reserved.getInt(0))
	}

	@Test
	fun `an unknown shadowsocks method drops the node rather than the config`() {
		// mihomo answers "cipher: ... initialize error" and refuses the whole file, so its pass
		// keeps a list of the methods it has, as the sing-box one does.
		val body = """{"remarks":"S","outbounds":[{"protocol":"shadowsocks","tag":"n","settings":{"servers":[
            {"address":"a.example.com","port":8388,"method":"totalnonsense","password":"pw"}]}}]}"""
			.trimIndent().replace("\n", "")
		val result = MihomoConverter.convert(body)
		assertTrue("expected a drop, got $result", result is MihomoConverter.Result.Unsupported)
		assertTrue(
			"the method must be named: ${(result as MihomoConverter.Result.Unsupported).notes}",
			result.notes.any { it.contains("totalnonsense") }
		)
	}

	@Test
	fun `the methods both cores implement still convert`() {
		// Including 2022-blake3-aes-128-gcm, which looks unsupported if it is offered a 32-byte
		// key: the core refuses it on the key length, not on the name, and a list built from that
		// mistake would lose it.
		val keys = mapOf(
			"aes-256-gcm" to "pw",
			"chacha20-ietf-poly1305" to "pw",
			"2022-blake3-aes-128-gcm" to "AAAAAAAAAAAAAAAAAAAAAA==",
			"2022-blake3-aes-256-gcm" to "Kq2tGRQPDLnJXQ8DAtEyC0hMLoGRGGPHKDtu0FLmCqQ=",
			"rc4-md5" to "pw"
		)
		for ((method, password) in keys) {
			val body = """{"remarks":"S","outbounds":[{"protocol":"shadowsocks","tag":"n",
              "settings":{"servers":[
                {"address":"a.example.com","port":8388,"method":"$method","password":"$password"}]}}]}"""
				.trimIndent().replace("\n", "")
			assertTrue("$method was dropped", MihomoConverter.convert(body) is MihomoConverter.Result.Ok)
		}
	}

	@Test
	fun `plain is mapped to the name mihomo has for it`() {
		// mihomo knows "none" and not "plain", and refuses the file over the latter.
		assertEquals("none", ssCipher("plain"))
		assertEquals("none", ssCipher("none"))
		assertEquals("", ssCipher("totalnonsense"))
	}
}
