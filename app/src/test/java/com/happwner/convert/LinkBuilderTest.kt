package com.happwner.convert

import android.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Turning an Xray outbound into a share link.
class LinkBuilderTest {

	private val uuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"
	private val pbk = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw"

	private fun link(outbound: String, remarks: String = "N"): String =
		SubscriptionConverter.convert("""{"remarks":"$remarks","outbounds":[$outbound]}""",
			jsonToUri = true).trim()

	private fun vless(stream: String, user: String = """{"id":"$uuid","encryption":"none"}""") =
		"""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,
           "users":[$user]}]},"streamSettings":$stream}""".trimIndent().replace("\n", "")

	private fun trojan(stream: String) =
		"""{"protocol":"trojan","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,
           "password":"pw"}]},"streamSettings":$stream}""".trimIndent().replace("\n", "")

	private fun vmessBlob(uri: String): JSONObject {
		assertTrue("not a vmess link: $uri", uri.startsWith("vmess://"))
		val raw = uri.removePrefix("vmess://")
		val padded = raw + "=".repeat((4 - raw.length % 4) % 4)
		return JSONObject(String(Base64.decode(padded, Base64.DEFAULT)))
	}

	@Test
	fun `a websocket node carries its path and host`() {
		// Without these the link points at the right server and the wrong
		// endpoint, which fails in a way that looks like a dead node.
		val query = queryOf(link(vless(
			"""{"network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com"},
                 "wsSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}}}""")))
		assertEquals("ws", query["type"])
		assertEquals("/ws", query["path"])
		assertEquals("cdn.example.com", query["host"])
	}

	@Test
	fun `a gRPC node carries its service name`() {
		val query = queryOf(link(vless(
			"""{"network":"grpc","security":"tls","tlsSettings":{"serverName":"a.example.com"},
                 "grpcSettings":{"serviceName":"gun","multiMode":true}}""")))
		assertEquals("grpc", query["type"])
		assertEquals("gun", query["serviceName"])
		assertEquals("multi", query["mode"])
	}

	@Test
	fun `the HTTP-shaped transports are named as a link names them`() {
		// Xray spells the HTTP/2 transport three ways internally; links and
		// sing-box both call it http, and writing h2 here left clients guessing.
		val http2Query = queryOf(link(vless(
			"""{"network":"h2","security":"tls","tlsSettings":{"serverName":"a.example.com"},
                 "httpSettings":{"path":"/h2","host":["a.example.com"]}}""")))
		assertEquals("http", http2Query["type"])
		assertEquals("/h2", http2Query["path"])
		assertEquals("a.example.com", http2Query["host"])

		val httpUpgradeQuery = queryOf(link(vless(
			"""{"network":"httpupgrade","security":"tls",
                 "tlsSettings":{"serverName":"a.example.com"},"httpupgradeSettings":{"path":"/hu",
                   "host":"h.example.com"}}""")))
		assertEquals("httpupgrade", httpUpgradeQuery["type"])
		assertEquals("/hu", httpUpgradeQuery["path"])
		assertEquals("h.example.com", httpUpgradeQuery["host"])
	}

	@Test
	fun `the raw TCP masquerade is carried too`() {
		val query = queryOf(link(vless(
			"""{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"http",
                 "request":{"path":["/mask"],"headers":{"Host":["m.example.com"]}}}}}""")))
		assertEquals("tcp", query["type"])
		assertEquals("http", query["headerType"])
		assertEquals("/mask", query["path"])
		assertEquals("m.example.com", query["host"])
	}

	@Test
	fun `mKCP carries its seed`() {
		val query = queryOf(link(vless(
			"""{"network":"kcp","security":"none",
                 "kcpSettings":{"seed":"s3cr3t","header":{"type":"srtp"}}}""")))
		assertEquals("kcp", query["type"])
		assertEquals("s3cr3t", query["seed"])
		assertEquals("srtp", query["headerType"])
	}

	@Test
	fun `a plain TLS node keeps its server name`() {
		// The SNI comes from tlsSettings for a plain TLS node, not only from realitySettings.
		val query = queryOf(link(vless(
			"""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com",
                 "alpn":["h2","http/1.1"],"allowInsecure":true}}""")))
		assertEquals("tls", query["security"])
		assertEquals("a.example.com", query["sni"])
		assertEquals("h2,http/1.1", query["alpn"])
		assertEquals("1", query["allowInsecure"])
	}

	@Test
	fun `a fingerprint is written only when the source names one`() {
		// A fingerprint the source did not name would tell the client to mimic a browser the
		// configuration never asked for.
		val without = queryOf(link(vless(
			"""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}""")))
		assertFalse("a fingerprint appeared from nowhere: $without", without.containsKey("fp"))

		val with = queryOf(link(vless(
			"""{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com",
                 "fingerprint":"firefox"}}""")))
		assertEquals("firefox", with["fp"])
	}

	@Test
	fun `REALITY carries its key, short id and spider`() {
		val query = queryOf(link(vless(
			"""{"network":"tcp","security":"reality",
                 "realitySettings":{"serverName":"a.example.com","publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw",
                   "shortId":"0123456789abcdef","spiderX":"/spx","fingerprint":"chrome"}}""")))
		assertEquals("reality", query["security"])
		assertEquals(pbk, query["pbk"])
		assertEquals("0123456789abcdef", query["sid"])
		assertEquals("/spx", query["spx"])
		assertEquals("chrome", query["fp"])
		assertEquals("a.example.com", query["sni"])
	}

	@Test
	fun `an IPv6 address is bracketed`() {
		// Without the brackets the colons of the address are read as the port
		// separator and the link does not parse at all.
		val uri = link(
			"""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"2001:db8::1",
                 "port":443,"users":[{"id":"$uuid",
                   "encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls",
                     "tlsSettings":{"serverName":"a.example.com"}}}""")
		assertTrue("no brackets in $uri", uri.contains("@[2001:db8::1]:443"))
	}

	@Test
	fun `values that would break the query are escaped`() {
		val uri = link(vless(
			"""{"network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com"},
                 "wsSettings":{"path":"/a?b=c&d#e"}}"""))
		val query = queryOf(uri)
		assertEquals("the path must survive intact", "/a?b=c&d#e", query["path"])
		// And the raw characters must not appear loose in the query.
		assertFalse("a raw & leaked into the query: $uri",
			uri.substringAfter('?').substringBefore('#').contains("&d"))
	}

	@Test
	fun `nothing is written empty`() {
		// An empty parameter - flow=&pbk=&sid=&sni= - says nothing, and some parsers read it as a
		// setting rather than as its absence.
		val uri = link(vless("""{"network":"tcp","security":"none"}"""))
		for (empty in listOf("flow=&", "pbk=&", "sid=&", "sni=&", "path=&", "host=&")) {
			assertFalse("$empty in $uri", uri.contains(empty))
		}
		assertFalse("a trailing empty value in $uri", uri.substringBefore('#').endsWith("="))
	}

	@Test
	fun `the flow travels as the source wrote it`() {
		val query = queryOf(link(vless(
			"""{"network":"tcp","security":"reality",
                 "realitySettings":{"serverName":"a.example.com","publicKey":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw","shortId":"aa"}}""",
			user = """{"id":"$uuid","encryption":"none","flow":"xtls-rprx-vision-udp443"}"""
		)))
		// The link is an Xray-format one and the clients that read it act on the -udp443 part, so
		// it travels whole.
		assertEquals("xtls-rprx-vision-udp443", query["flow"])
	}

	@Test
	fun `a trojan link carries the same transport detail`() {
		val uri = link(trojan(
			"""{"network":"grpc","security":"tls","tlsSettings":{"serverName":"a.example.com"},
                 "grpcSettings":{"serviceName":"gun"}}"""))
		val query = queryOf(uri)
		assertTrue(uri.startsWith("trojan://pw@a.example.com:443"))
		assertEquals("grpc", query["type"])
		assertEquals("gun", query["serviceName"])
		assertEquals("tls", query["security"])
		assertEquals("a.example.com", query["sni"])
		// Trojan links have always repeated the SNI here and some parsers read
		// only this one.
		assertEquals("a.example.com", query["host"])
	}

	@Test
	fun `a vmess blob describes its transport and TLS`() {
		val blob = vmessBlob(link(
			"""{"protocol":"vmess","tag":"n","settings":{"vnext":[{"address":"a.example.com",
                 "port":443,"users":[{"id":"$uuid","alterId":0,
                   "security":"auto"}]}]},"streamSettings":{"network":"ws","security":"tls",
                     "tlsSettings":{"serverName":"a.example.com","alpn":["h2"],
                       "fingerprint":"chrome"},"wsSettings":{"path":"/ws",
                         "headers":{"Host":"cdn.example.com"}}}}"""))
		assertEquals("a.example.com", blob.optString("add"))
		assertEquals("443", blob.optString("port"))
		assertEquals(uuid, blob.optString("id"))
		assertEquals("ws", blob.optString("net"))
		assertEquals("/ws", blob.optString("path"))
		assertEquals("cdn.example.com", blob.optString("host"))
		assertEquals("tls", blob.optString("tls"))
		assertEquals("a.example.com", blob.optString("sni"))
		assertEquals("h2", blob.optString("alpn"))
		assertEquals("chrome", blob.optString("fp"))
		assertEquals("none", blob.optString("type"))
	}

	@Test
	fun `a socks node becomes a link instead of raw JSON`() {
		val withAuth = link(
			"""{"protocol":"socks","tag":"n","settings":{"servers":[{"address":"a.example.com",
                 "port":1080,"users":[{"user":"u","pass":"p"}]}]}}""")
		assertTrue("not a socks link: $withAuth", withAuth.startsWith("socks://"))
		assertTrue("no credentials in $withAuth", withAuth.contains("@a.example.com:1080"))

		val noAuth = link(
			"""{"protocol":"socks","tag":"n",
                 "settings":{"servers":[{"address":"a.example.com","port":1080}]}}""")
		assertTrue(noAuth.startsWith("socks://a.example.com:1080"))
	}

	@Test
	fun `an http proxy takes the scheme its TLS implies`() {
		val plain = link(
			"""{"protocol":"http","tag":"n","settings":{"servers":[{"address":"a.example.com",
                 "port":8080,"users":[{"user":"u","pass":"p"}]}]}}""")
		assertTrue("not an http link: $plain", plain.startsWith("http://u:p@a.example.com:8080"))

		val secure = link(
			"""{"protocol":"http","tag":"n","settings":{"servers":[{"address":"a.example.com",
                 "port":8080}]},"streamSettings":{"network":"tcp","security":"tls",
                   "tlsSettings":{"serverName":"a.example.com"}}}""")
		assertTrue("TLS must show in the scheme: $secure", secure.startsWith("https://a.example.com:8080"))
		assertEquals("a.example.com", queryOf(secure)["sni"])
	}

	@Test
	fun `a node with no stream settings still states what it is`() {
		val query = queryOf(link(
			"""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com",
                 "port":443,"users":[{"id":"$uuid","encryption":"none"}]}]}}"""))
		assertEquals("tcp", query["type"])
		assertEquals("none", query["security"])
		assertEquals("none", query["encryption"])
	}
}
