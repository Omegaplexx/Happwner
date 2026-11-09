package com.happwner.convert

import android.util.Base64
import java.net.URI
import java.net.URLDecoder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Shapes taken from live subscriptions, where what matters is not what the converters compute but
// where they look.
class RealWorldShapeTest {

	private fun singBox(body: String): List<JSONObject> {
		val result = SingBoxConverter.convertToOutbounds(body.trimIndent().replace("\n", " "), "N")
		assertTrue("refused: $result", result is SingBoxConverter.OutboundsResult.Ok)
		return (result as SingBoxConverter.OutboundsResult.Ok).outbounds
	}

	private fun mihomo(body: String): String {
		val result = MihomoConverter.convert(body.trimIndent().replace("\n", " "))
		assertTrue("refused: $result", result is MihomoConverter.Result.Ok)
		return (result as MihomoConverter.Result.Ok).yaml
	}

	// Xray spells the WebSocket Host beside the headers as well as inside them. Reading only the
	// headers sends a node behind a CDN to the wrong host - it resolves, connects and fails.
	@Test
	fun `the WebSocket Host is carried however the config spells it`() {
		for (websocketSettings in listOf(
			""""wsSettings":{"path":"/wsvpn","host":"cdn.example.com","headers":{}}""",
			""""wsSettings":{"path":"/wsvpn","headers":{"Host":"cdn.example.com"}}"""
		)) {
			val body = """
                {"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
                {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
                "streamSettings":{"network":"ws","security":"tls",
                "tlsSettings":{"serverName":"a.example.com"},$websocketSettings}}]}
            """
			val transport = singBox(body).first().optJSONObject("transport")
			assertEquals(websocketSettings, "cdn.example.com",
				transport?.optJSONObject("headers")?.optString("Host"))
			assertTrue(websocketSettings, mihomo(body).contains("Host: cdn.example.com"))
			assertTrue(websocketSettings, SubscriptionConverter.convert(body.trimIndent().replace("\n", " "),
				jsonToUri = true).contains("host=cdn.example.com"))
		}
	}

	// A Hysteria node keeps its address in settings and its credentials, rates and port hopping in
	// the transport. Reading one half and not the other would refuse the node outright.
	@Test
	fun `a hysteria node written across settings and the transport converts`() {
		val body = """
            {"remarks":"N","outbounds":[{"protocol":"hysteria","tag":"proxy",
            "settings":{"address":"a.example.com","port":28190,"version":2},
            "streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"pw"},
            "security":"tls","tlsSettings":{"serverName":"a.example.com","alpn":["h3"]}}}]}
        """
		val uri = SubscriptionConverter.convert(body.trimIndent().replace("\n", " "), jsonToUri = true).trim()
		assertTrue(uri, uri.startsWith("hysteria2://pw@a.example.com:28190"))
		assertEquals("hysteria2", singBox(body).first().optString("type"))
		assertTrue(mihomo(body), mihomo(body).contains("password: pw"))
	}

	// The stated version decides. A node that says 1 is Hysteria v1, and rendering it as v2 hands
	// over a link for a protocol the server does not speak.
	@Test
	fun `a stated hysteria version is honoured wherever it is written`() {
		fun node(version: String, rates: String) = """
            {"remarks":"N","outbounds":[{"protocol":"hysteria","tag":"proxy",
            "settings":{"address":"a.example.com","port":443$version},
            "streamSettings":{"network":"hysteria","hysteriaSettings":{"auth":"pw"$rates},
            "security":"tls","tlsSettings":{"serverName":"a.example.com"}}}]}
        """
		val version1 = node(""","version":1""", ""","up_mbps":50,"down_mbps":100""")
		val uriV1 = SubscriptionConverter.convert(version1.trimIndent().replace("\n", " "),
			jsonToUri = true).trim()
		assertTrue(uriV1, uriV1.startsWith("hysteria://") && uriV1.contains("upmbps=50"))
		assertEquals("hysteria", singBox(version1).first().optString("type"))
		assertTrue(mihomo(version1), mihomo(version1).contains("type: hysteria\n"))

		// Nothing stated: a transport named hysteria is the current version.
		val bare = node("", "")
		assertTrue(SubscriptionConverter.convert(bare.trimIndent().replace("\n", " "),
			jsonToUri = true).startsWith("hysteria2://"))
	}

	// A subscription is a list somebody arranged: the first server is first for a reason, and the
	// three passes must hand it back in the order it arrived.
	@Test
	fun `the order of a subscription survives every pass`() {
		val names = listOf("A first", "B second", "C third", "D fourth", "E fifth")
		val body = names.joinToString(",", "[", "]") { name ->
			"""{"remarks":"$name","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
               {"address":"${name.first().lowercase()}.example.com","port":443,
               "users":[{"id":"u","encryption":"none"}]}]},"streamSettings":{"network":"tcp"}}]}"""
		}.replace("\n", " ")

		val uri = SubscriptionConverter.convert(body, jsonToUri = true).trim().lines()
			.map { URLDecoder.decode(it.substringAfter('#'), "UTF-8") }
		assertEquals(names, uri)

		val singBox = JSONObject(SubscriptionConverter.convert(body, jsonToUri = false,
			xrayToSingBox = true))
			.getJSONArray(
				"outbounds").let { array -> (0 until array.length()).map { array.getJSONObject(it) } }
			.filter { it.optString("type") == "vless" }.map { it.getString("tag") }
		assertEquals(names, singBox)

		val mihomo = SubscriptionConverter.convert(body, jsonToUri = false, xrayToMihomo = true).lines()
			.filter { it.startsWith("  - name:") }.map { it.removePrefix("  - name: ").trim().trim('\'') }
			.filter { it !in setOf("PROXY", "AUTO") }
		assertEquals(names, mihomo)
	}

	// The current name for the REALITY key is "password". A pass that read only the old one would
	// write an empty key, and sing-box refuses a whole document over one - so a single node written
	// the current way would take the rest of the subscription down with it.
	@Test
	fun `the REALITY key is read under both of its names`() {
		for (key in listOf("password", "publicKey")) {
			val body = """
                {"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
                {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
                "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
                "serverName":"f.example.com","$key":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw","shortId":"aabb","fingerprint":"chrome"}}}]}
            """
			val tls = singBox(body).first().optJSONObject("tls")
			assertEquals(
				key, "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw",
				tls?.optJSONObject("reality")?.optString("public_key")
			)
			assertTrue(key, mihomo(body).contains("public-key: HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw"))
			assertTrue(key, SubscriptionConverter.convert(body.trimIndent().replace("\n", " "),
				jsonToUri = true).contains("pbk=HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw"))
		}
	}

	// Early data rides inside the WebSocket path, which is the one place a link has for it and
	// where both cores read it from.
	@Test
	fun `WebSocket early data reaches the link`() {
		val body = """
            {"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
            {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
            "streamSettings":{"network":"ws","wsSettings":{"path":"/ws","maxEarlyData":2048}}}]}
        """
		val uri = SubscriptionConverter.convert(body.trimIndent().replace("\n", " "), jsonToUri = true)
		assertTrue(uri, uri.contains("path=%2Fws%3Fed%3D2048"))

		// Already in the path: left exactly as written, not doubled.
		val inPath = body.replace(""""path":"/ws","maxEarlyData":2048""", """"path":"/ws?ed=2048"""")
		val uri2 = SubscriptionConverter.convert(inPath.trimIndent().replace("\n", " "), jsonToUri = true)
		assertTrue(uri2, uri2.contains("path=%2Fws%3Fed%3D2048") && !uri2.contains("ed%3D2048%26ed"))
	}

	// Anti-censorship tuning Xray does in its own dialer. Neither core has it, and a node moved
	// without it behaves differently on the network it was tuned for - so all three say so.
	@Test
	fun `settings only Xray itself can perform are named by every pass`() {
		val body = """
			{"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
			"streamSettings":{"network":"tcp","finalmask":{"tcp":[{"type":"fragment",
			"settings":{"delay":"10-20"}}],"quicParams":{"congestion":"bbr"}}}}]}
		""".trimIndent().replace("\n", " ")

		// The link has one field for the whole block, so it travels there instead.
		assertTrue(SubscriptionConverter.convert(body, jsonToUri = true).contains("fm="))

		val singBox = SingBoxConverter.convertToOutbounds(body, "N") as SingBoxConverter.OutboundsResult.Ok
		assertTrue(singBox.notes.toString(), singBox.notes.any { it.contains("finalmask.tcp") })
		assertTrue(singBox.notes.toString(), singBox.notes.any { it.contains("finalmask.quicParams") })

		val mihomo = MihomoConverter.convert(body) as MihomoConverter.Result.Ok
		assertTrue(mihomo.notes.toString(), mihomo.notes.any { it.contains("finalmask.tcp") })
		assertTrue(mihomo.notes.toString(), mihomo.notes.any { it.contains("finalmask.quicParams") })
	}

	// A link has one field for the Host and nothing for any other header.
	@Test
	fun `headers a link cannot carry are named rather than dropped in silence`() {
		val body = """
			{"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
			"streamSettings":{"network":"ws","wsSettings":{"path":"/w",
			"headers":{"Host":"h.example.com","X-Extra":"e","X-Other":"o"}}}}]}
		""".trimIndent().replace("\n", " ")
		val stats = SubscriptionConverter.convertWithStats(body, jsonToUri = true)
		assertTrue(stats.text, stats.text.contains("host=h.example.com"))
		val notes = stats.notes.joinToString("\n")
		assertTrue(notes, notes.contains("X-Extra") && notes.contains("X-Other"))
		assertFalse(notes, notes.contains("headers.Host"))
	}

	// "ed=" can be part of a path. Only a query parameter named ed is early data already there.
	@Test
	fun `a path that merely contains the letters ed still gets its early data`() {
		fun path(websocketSettings: String): String {
			val body = """
                {"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
                {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
                "streamSettings":{"network":"ws","wsSettings":$websocketSettings}}]}
			""".trimIndent().replace("\n", " ")
			val query = SubscriptionConverter.convert(body,
				jsonToUri = true).substringAfter('?').substringBefore('#')
			return URLDecoder.decode(
				query.split("&").first { it.startsWith("path=") }.substringAfter('='), "UTF-8"
			)
		}
		assertEquals("/feed=1?ed=2048", path("""{"path":"/feed=1","maxEarlyData":2048}"""))
		assertEquals("/x?ed=100", path("""{"path":"/x?ed=100","maxEarlyData":2048}"""))
		assertEquals("/x?a=1&ed=2048", path("""{"path":"/x?a=1","maxEarlyData":2048}"""))
	}

	// finalmask masks both sides of the connection, and neither side survives the crossing.
	@Test
	fun `finalmask is named for the side it was asked for`() {
		fun notes(finalmask: String): String {
			val body = """
                {"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
                {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
                "streamSettings":{"network":"tcp","finalmask":$finalmask}}]}
			""".trimIndent().replace("\n", " ")
			val result = SingBoxConverter.convertToOutbounds(body, "N") as SingBoxConverter.OutboundsResult.Ok
			return result.notes.joinToString("\n")
		}
		assertTrue(notes("""{"udp":[{"type":"rand"}]}""").contains("finalmask.udp"))
		assertTrue(notes("""{"tcp":[{"type":"fragment"}]}""").contains("finalmask.tcp"))
		assertFalse(notes("""{"tcp":[],"udp":null}""").contains("finalmask"))
	}

	// Current Xray moved the mKCP seed and header out of kcpSettings into finalmask: the seed became the
	// password of an "mkcp-aes128gcm" mask, the header a "header-*" entry ahead of it, later both
	// "mkcp-legacy". All spellings describe the same node, and one that loses its seed connects to nothing.
	@Test
	fun `the mKCP seed and header are read under both spellings`() {
		fun node(stream: String) = """
            {"remarks":"N","outbounds":[{"protocol":"vmess","tag":"proxy","settings":{"vnext":[
            {"address":"a.example.com","port":443,"users":[{"id":"u"}]}]},"streamSettings":$stream}]}
		""".trimIndent().replace("\n", " ")

		val older = node(
			"""{"network":"kcp","kcpSettings":{"seed":"s3cret","header":{"type":"wechat-video"}}}""")
		val current = node(
			"""{"network":"kcp","finalmask":{"udp":[{"type":"header-wechat"},{"type":"mkcp-aes128gcm",
               "settings":{"password":"s3cret"}}]}}"""
		)
		val legacy = node(
			"""{"network":"kcp","finalmask":{"udp":[{"type":"mkcp-legacy","settings":{"value":"s3cret"}},
               {"type":"mkcp-legacy","settings":{"header":"wechat"}}]}}"""
		)
		for (body in listOf(older, current, legacy)) {
			val blob = JSONObject(
				String(
					Base64.decode(
						SubscriptionConverter.convert(body, jsonToUri = true).trim().removePrefix("vmess://"),
						Base64.DEFAULT
					)
				)
			)
			// The blob keeps the mKCP seed in its path field and the header in its type field.
			assertEquals("kcp", blob.optString("net"))
			assertEquals("s3cret", blob.optString("path"))
			assertEquals("wechat-video", blob.optString("type"))

			val yaml = mihomo(body)
			assertTrue(yaml, yaml.contains("seed: s3cret"))
			assertTrue(yaml, yaml.contains("header: wechat-video"))
		}
	}

	// mihomo calls this transport "mkcp"; "kcp" is Xray's name for it, and a network mihomo does
	// not know leaves the node not using mKCP at all.
	@Test
	fun `mihomo is given the transport name it uses`() {
		val body = """
			{"remarks":"N","outbounds":[{"protocol":"vmess","tag":"proxy","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"u"}]}]},
			"streamSettings":{"network":"kcp","kcpSettings":{"mtu":1350}}}]}
		""".trimIndent().replace("\n", " ")
		val yaml = mihomo(body)
		assertTrue(yaml, yaml.contains("network: mkcp"))
		assertTrue(yaml, yaml.contains("mkcp-opts:"))
	}

	// Xray masks mKCP with a DNS header as well; mihomo's list has no such value, and with no masking or
	// the wrong one the node is one the server never answers.
	@Test
	fun `a header mihomo does not have leaves the node out of its document`() {
		val body = """
			{"remarks":"N","outbounds":[{"protocol":"vmess","tag":"proxy","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"u"}]}]},
			"streamSettings":{"network":"kcp","kcpSettings":{"header":{"type":"dns",
			  "domain":"m.example.com"}}}}]}
		""".trimIndent().replace("\n", " ")
		val result = MihomoConverter.convert(body) as MihomoConverter.Result.Unsupported
		assertTrue(result.notes.toString(), result.notes.single().contains("mihomo masks with"))

		// The link has a place for both, so it keeps them.
		val uri = SubscriptionConverter.convert(body, jsonToUri = true)
		val blob = JSONObject(
			String(Base64.decode(uri.trim().removePrefix("vmess://"),
				Base64.DEFAULT))
		)
		assertEquals("dns", blob.optString("type"))
		assertEquals("m.example.com", blob.optString("host"))
	}

	// The certificate names are read under both of Xray's spellings, and each target takes what it can
	// use: a link carries them all (the core splits the commas), mihomo verifies against one.
	@Test
	fun `certificate names are read from both spellings and given as each target takes them`() {
		fun body(tls: String) = """
            {"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
            {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
            "streamSettings":{"network":"tcp","security":"tls",
            "tlsSettings":{"serverName":"s.example.com",$tls}}}]}
		""".trimIndent().replace("\n", " ")

		for (spelling in listOf(
			""""verifyPeerCertByName":"one.example.com"""",
			""""verifyPeerCertInNames":["one.example.com"]"""
		)) {
			assertTrue(spelling, mihomo(body(spelling)).contains("name-cert-verify: one.example.com"))
			assertTrue(spelling, SubscriptionConverter.convert(body(spelling),
				jsonToUri = true).contains("vcn=one.example.com"))
		}

		val several = body(""""verifyPeerCertInNames":["one.example.com","two.example.com"]""")
		val yaml = mihomo(several)
		assertTrue(yaml, yaml.contains("name-cert-verify: one.example.com"))
		assertFalse("a joined name matches no certificate: $yaml", yaml.contains("one.example.com,two"))
		// The link has room for both, and says them the way the standard reads them.
		val uri = SubscriptionConverter.convert(several, jsonToUri = true)
		assertTrue(uri, uri.contains("vcn=one.example.com%2Ctwo.example.com"))
	}

	// An address a client cannot read where a link keeps its host - or reads as something else -
	// is a node that imports and connects nowhere. It has no link form, and says so.
	@Test
	fun `an address that cannot stand in a link means no link`() {
		fun link(addr: String): String {
			val body = """
                {"remarks":"N","outbounds":[{"protocol":"trojan","tag":"proxy","settings":{"servers":[
                {"address":$addr,"port":8080,"password":"pw"}]},"streamSettings":{"network":"tcp",
                "security":"tls","tlsSettings":{"serverName":"s.example.com"}}}]}
			""".trimIndent().replace("\n", " ")
			return SubscriptionConverter.convert(body, jsonToUri = true).trim()
		}
		// A host that is not a host: an empty one, a slash that starts a path, a colon that becomes
		// a port, or a value that is not a string at all.
		for (addr in listOf("{}", "[]", "\" \"", "\"[{}]\"", "\"a/b\"", "\"a:b\"", "\"\"")) {
			assertFalse("$addr became a link: ${link(addr)}", link(addr).contains("://"))
		}
		// And every name a resolver would actually be asked for still does - the rule is what
		// breaks a link, not what a strict URI parser happens to accept. An underscore, an
		// all-digit label and a name outside ASCII are all handed out by real panels.
		for (addr in listOf(
			"a.example.com", "my_host.example.com", "example.com.", "192.168.1.1",
			"[2001:db8::1]", "2001:db8::1", "xn--e1afmkfd.xn--p1ai",
				"\u043F\u0440\u0438\u043C\u0435\u0440.\u0440\u0444",
			"1.2.3.4.5.6", "localhost", "sub.sub.sub.example.com"
		)) {
			assertTrue("$addr lost its link", link("\"$addr\"").startsWith("trojan://"))
		}
	}

	// Every link percent-encodes what it puts in the authority, this one included: a credential
	// holding a delimiter would end the authority early and name a different node.
	@Test
	fun `tuic credentials are encoded like every other link's`() {
		val body = """
			{"remarks":"N","outbounds":[{"protocol":"tuic","tag":"proxy","settings":{"servers":[
			{"address":"a.example.com","port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e",
			"password":"p@ss:word"}]},
			"streamSettings":{"security":"tls","tlsSettings":{"serverName":"s.example.com"}}}]}
		""".trimIndent().replace("\n", " ")
		val uri = SubscriptionConverter.convert(body, jsonToUri = true).trim()
		URI(uri)
		assertEquals("a.example.com", URI(uri).host)
		val tuicStart = "tuic://9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e:p%40ss%3Aword@a.example.com:443"
		assertTrue(uri, uri.startsWith(tuicStart))
	}

	// A TUIC node's tuning is written beside its address as readily as beside the protocol, and all
	// three passes have to read it the same way: a link that missed it would describe a slower node
	// than the documents do. What stands beside the address describes that address, so it wins.
	@Test
	fun `tuic tuning is read from beside the address and from the settings alike`() {
		fun body(besideAddress: String, inSettings: String) = """
            {"remarks":"N","outbounds":[{"protocol":"tuic","tag":"proxy","settings":{
              "servers":[{"address":"a.example.com","port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e",
                "password":"pw"$besideAddress}]$inSettings},
              "streamSettings":{"security":"tls","tlsSettings":{"serverName":"s.example.com"}}}]}
		""".trimIndent().replace("\n", " ")

		val cases = listOf(
			""","congestion_control":"bbr"""" to "",
			""","congestionController":"bbr"""" to "",
			"" to ""","congestion_control":"bbr"""",
			// Both: the one beside the address is about that address, so it decides.
			""","congestionController":"bbr"""" to ""","congestion_control":"cubic""""
		)
		for ((beside, shared) in cases) {
			val config = body(beside, shared)
			val where = "beside=[$beside] shared=[$shared]"
			assertTrue(where,
				SubscriptionConverter.convert(config, jsonToUri = true).contains("congestion_control=bbr"))
			assertEquals(where, "bbr", singBox(config).first().optString("congestion_control"))
			assertTrue(where, mihomo(config).contains("congestion-controller: bbr"))
		}
	}

	// The hysteria2 scheme writes an empty path segment between the port and the query, and a
	// client that reads the name of every other link reads this one's only with it there.
	@Test
	fun `a hysteria2 link is shaped like every other link`() {
		val body = """
			{"remarks":"🇩🇪 Germany","outbounds":[{"protocol":"hysteria2","tag":"proxy",
			"settings":{"servers":[{"address":"a.example.com","port":28190,"password":"pw"}]},
			"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}]}
		""".trimIndent().replace("\n", " ")
		val link = SubscriptionConverter.convert(body, jsonToUri = true).trim()

		// The scheme is "hysteria2://[auth@]hostname[:port]/?[key=value]", the form Hysteria's own
		// documentation and Happ's reference both spell out, so the separator stands before the query.
		assertTrue(link, link.startsWith("hysteria2://pw@a.example.com:28190/?"))
		// Only what the scheme defines stands between the port and the fragment. Hysteria2
		// negotiates h3 by definition, so writing it says nothing and the scheme has no field for
		// it; a client reading the query has nothing unfamiliar to stop at before the name.
		assertFalse("h3 says nothing here: $link", link.contains("alpn=h3"))
		// and it is still a URI whose fragment still holds the name
		val uri = URI(link)
		assertEquals("a.example.com", uri.host)
		assertEquals(28190, uri.port)
		assertEquals("🇩🇪 Germany", URLDecoder.decode(uri.rawFragment, "UTF-8"))
	}

	// Hysteria2 authenticates by password alone, so a link without one connects to nothing; and a
	// password holding a space has to travel as %20 - a "+" is not a space where a link keeps its
	// credential, and a client would read it as part of the password.
	@Test
	fun `a hysteria2 link needs a password and encodes it the way every link does`() {
		fun link(password: String): String {
			val body = """
                {"remarks":"N","outbounds":[{"protocol":"hysteria2","tag":"proxy",
                "settings":{"servers":[{"address":"a.example.com","port":443,"password":"$password"}]},
                "streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.com"}}}]}
			""".trimIndent().replace("\n", " ")
			return SubscriptionConverter.convert(body, jsonToUri = true).trim()
		}
		assertFalse("a link with nothing to authenticate with: " +
			"${link("")}", link("").startsWith("hysteria2://"))
		val spaced = link("my secret")
		assertTrue(spaced, spaced.startsWith("hysteria2://my%20secret@a.example.com:443"))
		assertFalse("a plus is not a space here: $spaced", spaced.contains("my+secret"))
	}

	// With both the host field and a Host header, the field wins - the header is the spelling Xray
	// deprecated. All three passes agree, or one node asks a CDN for different hosts per output.
	@Test
	fun `the websocket host field wins over the deprecated header in every pass`() {
		val body = """
			{"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
			"streamSettings":{"network":"ws","wsSettings":{"path":"/w","host":"field.example.com",
			"headers":{"Host":"header.example.com"}}}}]}
		""".trimIndent().replace("\n", " ")
		val uri = SubscriptionConverter.convert(body, jsonToUri = true)
		assertTrue(uri, uri.contains("host=field.example.com"))
		assertFalse(uri, uri.contains("header.example.com"))
		val singBoxText = singBox(body).first().toString()
		assertTrue(singBoxText,
			singBoxText.contains("field.example.com") && !singBoxText.contains("header.example.com"))
		val mihomoText = mihomo(body)
		assertTrue(mihomoText,
			mihomoText.contains("field.example.com") && !mihomoText.contains("header.example.com"))
	}

	// The same word means opposite directions: Xray's "verify" is a CA the client trusts; mihomo's
	// "certificate" with "private-key" is the client's own certificate for mutual TLS (Xray's
	// "encipherment", the default); sing-box's "certificate" is what the server is verified against.
	@Test
	fun `a certificate lands where each core means it, by what it is for`() {
		val pem = TEST_CERTIFICATE_JSON
		val key = "-----BEGIN PRIVATE KEY-----\\nBBBB\\n-----END PRIVATE KEY-----"
		fun body(certs: String) = """
            {"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
            {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
            "streamSettings":{"network":"tcp","security":"tls",
            "tlsSettings":{"serverName":"s.example.com","certificates":[$certs]}}}]}
		""".trimIndent().replace("\n", " ")

		// A CA to trust: sing-box verifies against it, and mihomo, with no per-proxy field, for the document.
		val verifyCert = body("""{"usage":"verify","certificate":["$pem"]}""")
		assertTrue(singBox(verifyCert).first().getJSONObject("tls").has("certificate"))
		val caResult = MihomoConverter.convert(verifyCert) as MihomoConverter.Result.Ok
		assertFalse("a CA presented as a client certificate: " +
			"${caResult.yaml}", caResult.yaml.contains("certificate:"))
		assertTrue(caResult.yaml, caResult.yaml.contains("custom-certifactes:"))

		// A client certificate whose key does not read is one no core can present - sing-box would refuse
		// the whole document over it, mihomo fail every handshake - and Xray presents none on an outbound.
		val client = body("""{"certificate":["$pem"],"key":["$key"]}""")
		val clientYaml = mihomo(client)
		assertFalse(clientYaml, clientYaml.contains("private-key:"))
		val clientTls = singBox(client).first().optJSONObject("tls")
		val sent = clientTls?.has("certificate") == true || clientTls?.has("client_key") == true
		assertFalse("$clientTls", sent)
	}

	// Xray's parser spells the XHTTP session settings sessionPlacement and sessionKey; the
	// sessionID* forms are the other spelling in circulation. A configuration written either way
	// keeps its session settings.
	@Test
	fun `xhttp session settings are read under both spellings`() {
		fun body(fields: String) = """
            {"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
            {"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
            "streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/x","mode":"packet-up",$fields}}}]}
		""".trimIndent().replace("\n", " ")
		for (fields in listOf(
			""""sessionPlacement":"cookie","sessionKey":"sid"""",
			""""sessionIDPlacement":"cookie","sessionIDKey":"sid""""
		)) {
			val yaml = mihomo(body(fields))
			assertTrue(yaml, yaml.contains("session-placement: cookie"))
			assertTrue(yaml, yaml.contains("session-key: sid"))
		}
	}

	// A Hysteria duration ("30s", "1m", "500ms", "2h") is written as each core reads it: whole seconds
	// for mihomo, which refuses a string where it reads an int, a unit-bearing duration for sing-box;
	// one under 5 seconds, which sing-box will not dial with, hops from 5.
	@Test
	fun `a port hopping interval is a duration, not a string with an s cut off`() {
		fun body(interval: String) = """
            {"remarks":"N","outbounds":[{"protocol":"hysteria2","tag":"proxy",
            "settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw",
              "ports":"20000-30000"}],
            "hopInterval":"$interval"},"streamSettings":{"security":"tls",
              "tlsSettings":{"serverName":"a.example.com"}}}]}
		""".trimIndent().replace("\n", " ")
		for ((interval, seconds) in listOf("30s" to 30, "1m" to 60, "500ms" to 5, "2h" to 7200, "45" to 45)) {
			val yaml = mihomo(body(interval))
			assertTrue("$interval -> $yaml",
				yaml.contains("hop-interval: $seconds\n") || yaml.contains("hop-interval: $seconds "))
			assertFalse("a quoted number for $interval: $yaml", yaml.contains("hop-interval: '"))
			assertEquals("$interval", "${seconds}s",
				singBox(body(interval)).first().optString("hop_interval"))
		}
	}

	// The TLS block is found under either of its spellings by every pass: xtlsSettings is the old
	// name of the same block, and a node written with it under security "tls" keeps its server
	// name and ALPN in all three outputs.
	@Test
	fun `the tls block is read under its old spelling by every pass`() {
		val body = """
			{"remarks":"N","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
			"streamSettings":{"network":"tcp","security":"tls",
			  "xtlsSettings":{"serverName":"s.example.com","alpn":["h2"]}}}]}
		""".trimIndent().replace("\n", " ")
		val tls = singBox(body).first().getJSONObject("tls")
		assertEquals("s.example.com", tls.optString("server_name"))
		assertTrue(SubscriptionConverter.convert(body, jsonToUri = true).contains("sni=s.example.com"))
		assertTrue(mihomo(body).contains("servername: s.example.com"))
	}

	// An h2 transport naming several hosts reaches the link with every host, comma-separated as
	// the share-link standard has it; a Host header under httpupgrade or xhttp is read where the
	// field is empty, in every pass, so the three outputs name the same host.
	@Test
	fun `h2 hosts and a Host header reach the link as the documents carry them`() {
		val http2Body = """
			{"remarks":"N","outbounds":[{"protocol":"vless","tag":"p","settings":{"vnext":[
			{"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
			"streamSettings":{"network":"h2","httpSettings":{"path":"/h",
			"host":["a.example.com","b.example.com"]}}}]}
		""".trimIndent().replace("\n", " ")
		assertEquals("a.example.com,b.example.com", queryOf(SubscriptionConverter.convert(http2Body,
			jsonToUri = true))["host"])

		val httpUpgradeBody = http2Body.replace(
			""""network":"h2","httpSettings":{"path":"/h", "host":["a.example.com","b.example.com"]}""",
			""""network":"httpupgrade",
            "httpupgradeSettings":{"path":"/u","headers":{"Host":"h.example.com"}}""")
		assertEquals("h.example.com", queryOf(SubscriptionConverter.convert(httpUpgradeBody,
			jsonToUri = true))["host"])
		assertEquals("h.example.com",
			singBox(httpUpgradeBody).first().getJSONObject("transport").optString("host"))
		assertTrue(mihomo(httpUpgradeBody).contains("Host: h.example.com"))
	}
}
