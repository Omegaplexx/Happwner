package com.happwner.convert

import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// What a configuration carries across, and what it says about the rest.
class CarriedAndReportedTest {

	private val uuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"

	private fun proxy(stream: String? = null, extra: String = ""): String {
		val streamSettings =
			stream ?: """{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}"""
		return """{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
            "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]},
            "streamSettings":$streamSettings$extra}"""
			.trimIndent().replace("\n", "")
	}

	private fun convert(body: String): JSONObject =
		JSONObject(SubscriptionConverter.convert(body, jsonToUri = false, base64Result = false,
			xrayToSingBox = true))

	private fun stats(body: String) =
		SubscriptionConverter.convertWithStats(
			body, jsonToUri = false, base64Result = false, xrayToSingBox = true
		)

	private fun outbound(cfg: JSONObject, type: String): JSONObject {
		val arr = cfg.getJSONArray("outbounds")
		for (i in 0 until arr.length()) {
			val outbound = arr.getJSONObject(i)
			if (outbound.optString("type") == type) return outbound
		}
		throw AssertionError("no $type outbound in $cfg")
	}

	// A configuration is more than its outbounds. What its other blocks asked for is named too:
	// the global transport block, which Xray itself refuses to load; a reverse tunnel neither core
	// builds; the per-level timeouts a core decides for itself.
	@Test
	fun `blocks a client document has no place for are named`() {
		val node = """{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"a.example.com",
            "port":443,"users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}"""
		val blocks = mapOf(
			""""transport":{"kcpSettings":{"mtu":1350}}""" to "global transport block",
			""""reverse":{"bridges":[{"tag":"b","domain":"r.example.com"}]}""" to "reverse builds a tunnel",
			""""policy":{"levels":{"0":{"connIdle":300}}}""" to "policy sets Xray's own timeouts"
		)
		for ((block, reason) in blocks) {
			val body = """{"remarks":"N",$block,"outbounds":[$node]}""".replace("\n", " ")
			val singBox = SubscriptionConverter.convertWithStats(
				body, jsonToUri = false, xrayToSingBox = true
			)
			assertTrue("$block sing-box: ${singBox.notes}", singBox.notes.any { reason in it })
			val mihomo = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true)
			assertTrue("$block mihomo: ${mihomo.notes}", mihomo.notes.any { reason in it })
		}
	}

	// Whatever an outbound was tuned with is either carried or named, whichever protocol it is and
	// whichever pass answers: a dialer option, a second download path, an address family, a
	// multiplexer. Silence here is a node that behaves differently and says nothing about it.
	@Test
	fun `what no form carries is named for every protocol`() {
		val settings = mapOf(
			"vless" to """{"vnext":[{"address":"a.example.com","port":443,
                "users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none"}]}]}""",
			"trojan" to """{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]}""",
			"hysteria2" to """{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]}""",
			"tuic" to """{"servers":[{"address":"a.example.com","port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"}]}"""
		)
		val extras = mapOf(
			"sockopt" to (""""sockopt":{"tcpKeepAliveIdle":30}""" to "sockopt"),
			"downloadSettings" to (""""downloadSettings":{"network":"ws"}""" to "downloadSettings"),
			"targetStrategy" to ("" to "targetStrategy")
		)
		for ((protocol, node) in settings) {
			for ((name, pair) in extras) {
				val (streamExtra, word) = pair
				val outboundExtra = if (name == "targetStrategy") ""","targetStrategy":"ForceIPv6"""" else ""
				val stream = listOfNotNull("\"network\":\"raw\"",
					streamExtra.ifEmpty { null }).joinToString(",")
				val body = """
                    {"remarks":"N","outbounds":[{"protocol":"$protocol","tag":"proxy",
                     "settings":$node$outboundExtra,"streamSettings":{$stream}}]}
				""".trimIndent().replace("\n", " ")
				for (pass in listOf("link", "sing-box", "mihomo")) {
					val result = when (pass) {
						"link" -> SubscriptionConverter.convertWithStats(body, jsonToUri = true)
						"sing-box" -> SubscriptionConverter.convertWithStats(body,
							jsonToUri = false, xrayToSingBox = true)
						else -> SubscriptionConverter.convertWithStats(body, jsonToUri = false,
							xrayToMihomo = true)
					}
					val wrote = result.text.contains("://") || result.text.contains("\"type\":") ||
						result.text.contains("proxies:")
					// sing-box carries the dialer options rather than dropping them
					val carried = pass == "sing-box" && name == "sockopt"
					if (!wrote || carried) continue
					assertTrue("$protocol/$name/$pass: ${result.notes}",
						result.notes.any { word.lowercase() in it.lowercase() })
				}
			}
		}
	}

	// Xray masks packets in its own dialer, for a Hysteria node as much as for a WireGuard one, and
	// the link forms built from a blob or an address have no field for it either. Whoever cannot
	// carry it says so, or a node tuned for a censored network fails quietly somewhere else.
	@Test
	fun `a mask is carried, named or refuses the node by the side the node sends through`() {
		fun body(protocol: String, settings: String) = """
            {"remarks":"M","outbounds":[{"protocol":"$protocol","tag":"proxy","settings":$settings,
             "streamSettings":{"network":"raw",
              "finalmask":{"udp":[{"type":"salamander","settings":{"password":"maskpw"}}]}}}]}
		""".trimIndent().replace("\n", " ")
		val nodes = listOf(
			"hysteria2" to """{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]}""",
			"tuic" to """{"servers":[{"address":"a.example.com","port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"}]}""",
			"vmess" to """{"vnext":[{"address":"a.example.com","port":443,
                "users":[{"id":"11111111-2222-3333-4444-555555555555","alterId":0}]}]}"""
		)
		// A TCP node never sends through a UDP mask, so it keeps the node with a note; hysteria2 carries
		// salamander as its own obfuscation; a QUIC node without one never connects, and goes.
		for ((protocol, settings) in nodes) {
			val source = body(protocol, settings)
			val link = SubscriptionConverter.convertWithStats(source, jsonToUri = true)
			val singBox = SubscriptionConverter.convertWithStats(
				source, jsonToUri = false, xrayToSingBox = true
			)
			val mihomo = SubscriptionConverter.convertWithStats(source, jsonToUri = false,
				xrayToMihomo = true)
			val all = link.notes + singBox.notes + mihomo.notes
			when (protocol) {
				"vmess" -> {
					assertTrue("$protocol link: ${link.text}", link.text.contains("://"))
					for (pass in listOf(link, singBox, mihomo)) {
						assertTrue("$protocol: ${pass.notes}", pass.notes.any { "finalmask.udp" in it })
					}
				}
				"hysteria2" -> {
					assertTrue(link.text, link.text.contains("obfs=salamander"))
					assertTrue(singBox.text, singBox.text.contains("\"obfs\""))
					assertFalse("$all", all.any { "finalmask.udp" in it })
				}
				else -> {
					assertFalse("$protocol link: ${link.text}", link.text.contains("://"))
					for (pass in listOf(link, singBox, mihomo)) {
						val refused = pass.notes.any { "mask \"salamander\" rewrites" in it }
						assertTrue("$protocol: ${pass.notes}", refused)
					}
				}
			}
		}
	}

	// Xray dials a WireGuard tunnel itself, reading nothing of the stream but the socket options
	// and the UDP mask - which it does apply. Neither core has a field for that mask, and a server
	// expecting masked packets answers nothing without it, so both passes say so.
	@Test
	fun `a UDP mask both ends share refuses a WireGuard node in both cores`() {
		val body = """
			{"remarks":"WG","outbounds":[{"protocol":"wireguard","tag":"proxy","settings":{
			  "secretKey":"gNUPIzY82Rx9Kl9Z0PJtRARB0NJB47pLOyOJa2gKEGE=","address":["10.0.0.2/32"],
			  "peers":[{"endpoint":"wg.example.com:51820",
			    "publicKey":"4eI0MXrujCIV73+dH2v8RlOkJCwd+xcqfuK08Atxbxc=","allowedIPs":["0.0.0.0/0"]}]},
			 "streamSettings":{"network":"raw",
			  "finalmask":{"udp":[{"type":"salamander","settings":{"password":"maskpw"}}]}}}]}
		""".trimIndent().replace("\n", " ")
		val singBox = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToSingBox = true)
		assertFalse(singBox.text, singBox.text.contains("\"type\":\"wireguard\""))
		assertTrue(singBox.notes.toString(), singBox.notes.any { "mask \"salamander\" rewrites" in it })
		val mihomo = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true)
		assertTrue(mihomo.notes.toString(), mihomo.notes.any { "mask \"salamander\" rewrites" in it })
	}

	@Test
	fun `mux is reported rather than translated into a different multiplexer`() {
		// Xray multiplexes with mux.cool, which sing-box does not implement - it offers smux, yamux
		// and h2mux. The node carries traffic with no multiplex block and none with it.
		val body = """{"outbounds":[${proxy(extra = ""","mux":{"enabled":true,"concurrency":8}""")}]}"""
		val result = stats(body)
		val cfg = JSONObject(result.text)
		assertFalse(
			"a multiplex block here breaks the connection outright",
			outbound(cfg, "vless").has("multiplex")
		)
		assertTrue("and the person should be told why: ${result.notes}",
			result.notes.any { it.contains("mux") })
	}

	@Test
	fun `mux switched off says nothing at all`() {
		val result = stats(
			"""{"outbounds":[${proxy(extra = ""","mux":{"enabled":false,"concurrency":8}""")}]}""")
		assertFalse("nothing was asked for, so there is nothing to report: ${result.notes}",
			result.notes.any { it.contains("mux") })
	}

	@Test
	fun `the TLS cipher list and curves cross over`() {
		val cfg = convert(
			"""{"outbounds":[${proxy("""{"network":"tcp","security":"tls","tlsSettings":{
               "serverName":"a.example.com","cipherSuites":"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
               "curvePreferences":["X25519","P256"]}}""".trimIndent().replace("\n", ""))}]}"""
		)
		val tls = outbound(cfg, "vless").getJSONObject("tls")
		val suites = tls.getJSONArray("cipher_suites")
		assertEquals("the colon-separated list becomes an array", 2, suites.length())
		assertEquals("TLS_AES_128_GCM_SHA256", suites.getString(0))
		// curve_preferences arrived in sing-box 1.13, so it stays out for the 1.12 cores.
		assertFalse("curve_preferences is 1.13-only", tls.has("curve_preferences"))
	}

	@Test
	fun `a certificate pin is reported rather than mapped to a different one`() {
		// The core pins the public key inside a certificate; Xray pins the certificate. Writing one
		// where the other was meant would pin the wrong value and fail every handshake.
		val result = stats(
			"""{"outbounds":[${proxy("""{"network":"tcp","security":"tls","tlsSettings":{
               "serverName":"a.example.com",
               "pinnedPeerCertSha256":"deadbeef"}}""".trimIndent().replace("\n", ""))}]}"""
		)
		val cfg = JSONObject(result.text)
		assertFalse("must not be written as a public-key pin",
			outbound(cfg, "vless").getJSONObject("tls").has("certificate_public_key_sha256"))
		assertTrue("and it must be reported: ${result.notes}",
			result.notes.any { it.contains("pinnedPeerCertSha256") })
	}

	@Test
	fun `a socks version stated in settings is carried too`() {
		val cfg = convert(
			"""{"outbounds":[{"protocol":"socks","tag":"p","settings":{"version":"4",
               "servers":[{"address":"a.example.com","port":1080}]}}]}""".trimIndent().replace("\n", "")
		)
		assertEquals("4", outbound(cfg, "socks").optString("version"))
	}

	@Test
	fun `dropped transport options are named`() {
		val result = stats(
			"""{"outbounds":[${proxy("""{"network":"ws","security":"tls",
               "tlsSettings":{"serverName":"a.example.com"},
               "wsSettings":{"path":"/w","heartbeatPeriod":30}}""".trimIndent().replace("\n", ""))}]}"""
		)
		assertTrue("the heartbeat has no equivalent and should be reported: ${result.notes}",
			result.notes.any { it.contains("heartbeatPeriod") })
	}

	@Test
	fun `a pretty-printed configuration reports what a one-line one reports`() {
		// The line walk never sees a multi-line document whole, so the body is read as one value
		// first: an unsupported document is counted and explained the same as on one line.
		val body = """{"outbounds":[${proxy("""{"network":"xhttp","security":"tls",
            "tlsSettings":{"serverName":"a.example.com"},"xhttpSettings":{"path":"/x"}}"""
			.trimIndent().replace("\n", ""))}]}"""
		val oneLine = stats(body)
		val pretty = stats(JSONObject(body).toString(2))
		assertTrue("the one-line form should explain itself", oneLine.notes.isNotEmpty())
		assertEquals("and the pretty-printed form the same way",
			oneLine.notes, pretty.notes)
		assertEquals("with the same count", oneLine.xraySkipped, pretty.xraySkipped)
	}

	// Xray reads no alterId since 1.8.3 and runs VMess AEAD alone; a core given a non-zero one sends the
	// legacy header no Xray server takes, so every pass writes 0 and says so.
	@Test
	fun `a VMess alterId is written as the 0 Xray runs, and said`() {
		val body = """{"remarks":"V","outbounds":[{"protocol":"vmess","tag":"proxy","settings":{"vnext":[
            {"address":"a.example.com","port":443,"users":[{"id":"$uuid","alterId":64}]}]},
            "streamSettings":{"network":"tcp"}}]}""".trimIndent().replace("\n", "")
		val singBox = stats(body)
		assertEquals(0, outbound(JSONObject(singBox.text), "vmess").getInt("alter_id"))
		val mihomo = SubscriptionConverter.convertWithStats(body, jsonToUri = false, xrayToMihomo = true)
		assertTrue(mihomo.text, "alterId: 0\n" in mihomo.text)
		val link = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
		val blob = JSONObject(String(Base64.getDecoder().decode(link.text.trim().removePrefix("vmess://"))))
		assertEquals("0", blob.getString("aid"))
		for (pass in listOf(singBox, mihomo, link)) {
			val said = pass.notes.any { "vmess alterId 64 asks for the legacy header" in it }
			assertTrue("${pass.notes}", said)
		}
		// A negative one the cores already read as 0: written so, with nothing to say.
		val negative = body.replace("\"alterId\":64", "\"alterId\":-1")
		assertEquals(0, outbound(JSONObject(stats(negative).text), "vmess").getInt("alter_id"))
		assertTrue("${stats(negative).notes}", stats(negative).notes.none { "alterId" in it })
	}

	// Xray splits a Client Hello in its own dialer - by a fragment mask, or a freedom outbound the node
	// dials through; sing-box splits the one its own TLS makes, so a TLS node takes that instead and a
	// REALITY one, or a range past the first packet, goes without - each said.
	@Test
	fun `an Xray fragment becomes sing-box's own where sing-box makes the Client Hello`() {
		val tls = """"security":"tls","tlsSettings":{"serverName":"a.example.com"}"""
		fun masked(settings: String) =
			"""{"network":"tcp",$tls,"finalmask":{"tcp":[{"type":"fragment","settings":$settings}]}}"""
		for ((settings, records, segments) in listOf(
			Triple("""{"packets":"tlshello","length":"100-200","delay":"10-20"}""", true, true),
			Triple("""{"packets":"tlshello","length":"100-200","delay":0}""", true, false),
			Triple("""{"packets":"1-3","length":"1-5","delay":"1-2"}""", false, true)
		)) {
			val result = stats("""{"outbounds":[${proxy(masked(settings))}]}""")
			val written = outbound(JSONObject(result.text), "vless").getJSONObject("tls")
			assertEquals(settings, records, written.optBoolean("record_fragment"))
			assertEquals(settings, segments, written.optBoolean("fragment"))
			assertTrue("${result.notes}", result.notes.any { "sing-box's own TLS fragmenting" in it })
			assertFalse("${result.notes}", result.notes.any { "finalmask.tcp is Xray's own" in it })
		}
		val later = stats("""{"outbounds":[${proxy(masked("""{"packets":"2-3","length":"1-5"}"""))}]}""")
		val unsplit = outbound(JSONObject(later.text), "vless").getJSONObject("tls")
		assertFalse("$unsplit", unsplit.has("fragment"))
		assertTrue("${later.notes}", later.notes.any { "finalmask.tcp is Xray's own" in it })
		// To an address with no server name the Client Hello has none to split at, and goes whole.
		val unnamed = masked("""{"packets":"tlshello","length":"100-200"}""")
			.replace(""""serverName":"a.example.com"""", "")
		val byAddress = stats("""{"outbounds":[${proxy(unnamed).replace("a.example.com", "192.0.2.10")}]}""")
		val whole = outbound(JSONObject(byAddress.text), "vless").getJSONObject("tls")
		assertFalse("$whole", whole.has("fragment") || whole.has("record_fragment"))
		assertTrue("${byAddress.notes}", byAddress.notes.any { "finalmask.tcp is Xray's own" in it })
		val freedom = """{"protocol":"freedom","tag":"split","settings":{"fragment":{""" +
			""""packets":"tlshello","length":"100-200","interval":"10-20"}}}"""
		val through = ""","proxySettings":{"tag":"split"}"""
		val chained = stats("""{"outbounds":[${proxy(extra = through)},$freedom]}""")
		val node = outbound(JSONObject(chained.text), "vless")
		// Straight out: sing-box dials through no direct outbound that has nothing of its own.
		assertFalse("$node", node.has("detour"))
		assertTrue("$node", node.getJSONObject("tls").optBoolean("record_fragment"))
		assertTrue("${chained.notes}", chained.notes.any { "freedom \"split\" with its fragment" in it })
		val key = "yPNRx8rTdkUp89A-J76KxmGFeexuyVG4BiVl1PJ1kCk"
		val reality = """{"network":"tcp","security":"reality","realitySettings":{""" +
			""""serverName":"r.example.com","publicKey":"$key","shortId":"ab","fingerprint":"chrome"}}"""
		val keyed = stats("""{"outbounds":[${proxy(reality, through)},$freedom]}""")
		val realityNode = outbound(JSONObject(keyed.text), "vless").getJSONObject("tls")
		assertFalse("$realityNode", realityNode.has("fragment") || realityNode.has("record_fragment"))
		assertTrue("${keyed.notes}", keyed.notes.any { "freedom \"split\" without its fragment" in it })
		val unnamedNode = proxy("""{"network":"tcp","security":"tls","tlsSettings":{}}""", through)
		val byIp = stats("""{"outbounds":[${unnamedNode.replace("a.example.com", "192.0.2.10")},$freedom]}""")
		val ipNode = outbound(JSONObject(byIp.text), "vless").getJSONObject("tls")
		assertFalse("$ipNode", ipNode.has("fragment") || ipNode.has("record_fragment"))
		val unsplitNote = "freedom \"split\" without its fragment"
		assertTrue("${byIp.notes}", byIp.notes.any { unsplitNote in it && "naming a server" in it })
		// A node over UDP alone - Hysteria 2 here - has nothing either fragment splits, in Xray as here.
		val hysteria = """{"outbounds":[{"protocol":"hysteria","tag":"h","settings":{"version":2,""" +
			""""address":"h.example.com","port":443},"streamSettings":{"network":"hysteria",""" +
			""""hysteriaSettings":{"version":2,"auth":"pw"},$tls,"finalmask":{"tcp":[{"type":"fragment",""" +
			""""settings":{"packets":"tlshello","length":"100-200"}}]}}}]}"""
		val udp = stats(hysteria)
		val quicTls = outbound(JSONObject(udp.text), "hysteria2").getJSONObject("tls")
		assertFalse("$quicTls", quicTls.has("fragment") || quicTls.has("record_fragment"))
		assertTrue("${udp.notes}", udp.notes.none { "sing-box's own TLS fragmenting" in it })
	}

	// The note on a freedom's fragment is told for each node that dials through it, in the order the nodes
	// stand, so a configuration gives the same log on every run.
	@Test
	fun `the notes on a freedom's fragment follow the order of the nodes`() {
		val freedom = """{"protocol":"freedom","tag":"split","settings":{"fragment":{""" +
			""""packets":"tlshello","length":"100-200"}}}"""
		val through = ""","proxySettings":{"tag":"split"}"""
		val nodes = (1..8).joinToString(",") {
			proxy(extra = through).replace(""""tag":"proxy"""", """"tag":"p$it"""")
		}
		val notes = stats("""{"outbounds":[$nodes,$freedom]}""").notes.filter { "freedom \"split\"" in it }
		assertEquals("$notes", (0 until 8).map { "outbounds[$it]" }, notes.map { it.substringBefore(" (") })
	}

	// Xray dials a serviceName starting with "/" as the custom path it spells. mihomo takes such a path
	// whole but for the "|" part, which Xray's multi mode alone reads; sing-box reaches only one ending
	// in "/Tun" with one service before it, and for any other the node is left out there, with the reason.
	@Test
	fun `a custom gRPC path reaches each core as Xray dials it, or the node is left out`() {
		fun body(service: String): String {
			val stream = """{"network":"grpc","security":"tls",""" +
				""""tlsSettings":{"serverName":"a.example.com"},"grpcSettings":{"serviceName":"$service"}}"""
			return """{"outbounds":[${proxy(stream)}]}"""
		}
		val transport = outbound(convert(body("/a/Tun|TunMulti")), "vless").getJSONObject("transport")
		assertEquals("a", transport.getString("service_name"))
		val single =
			SubscriptionConverter.convert(body("/a/Tun|TunMulti"), jsonToUri = false, xrayToMihomo = true)
		assertTrue(single, "grpc-service-name: /a/Tun\n" in single)
		val nested = body("/a/b/Tun")
		val refused = SingBoxConverter.convert(nested, "N")
		assertTrue("$refused", refused is SingBoxConverter.Result.Unsupported)
		assertTrue("$refused", "is a custom gRPC path" in "$refused")
		val kept = SubscriptionConverter.convert(nested, jsonToUri = false, xrayToMihomo = true)
		assertTrue(kept, "grpc-service-name: /a/b/Tun\n" in kept)
		// A plain name Xray escapes on the wire - "a/b" is /a%2Fb/Tun - goes to mihomo, which sends a name
		// as written, as that path; sing-box escapes it itself. And gunSettings is grpcSettings to Xray.
		val escaped = SubscriptionConverter.convert(body("a/b"), jsonToUri = false, xrayToMihomo = true)
		assertTrue(escaped, "grpc-service-name: /a%2Fb/Tun\n" in escaped)
		val gun = convert(body("svc").replace("grpcSettings", "gunSettings"))
		assertEquals("svc", outbound(gun, "vless").getJSONObject("transport").getString("service_name"))
		// A proxy type that carries no transport at all is left out for that, whatever path it names.
		val http = """{"outbounds":[{"protocol":"http","tag":"h","settings":{"servers":[{"address":""" +
			""""a.example.com","port":443}]},"streamSettings":{"network":"grpc",""" +
			""""grpcSettings":{"serviceName":"/a/b/Tun"}}}]}"""
		val plain = SingBoxConverter.convert(http, "N")
		assertTrue("$plain", "has no form in any core" in "$plain" && "custom gRPC path" !in "$plain")
	}
}
