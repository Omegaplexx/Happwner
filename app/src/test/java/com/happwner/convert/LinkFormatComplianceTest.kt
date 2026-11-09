package com.happwner.convert

import android.util.Base64
import java.net.URLDecoder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Pins the share links to the schemes their clients actually read: a Shadowsocks 2022 node written the
// pre-2022 way does not connect, and a base64 in the wrong alphabet is refused by a strict parser.
class LinkFormatComplianceTest {

	private val uuid = "9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e"

	private fun conv(outboundJson: String): String =
		SubscriptionConverter.convert("""{"remarks":"N","outbounds":[$outboundJson]}""",
			jsonToUri = true).trim()

	@Test
	fun `a shadowsocks link uses web-safe base64 with no padding`() {
		// SIP002: userinfo = websafe-base64(method:password). A standard-alphabet
		// '+' or '/' or a trailing '=' is what a strict SIP002 parser trips on.
		val uri = conv(
			"""{"protocol":"shadowsocks","tag":"n","server":"a.example.com","server_port":8388,
                 "method":"chacha20-ietf-poly1305","password":"p@ss/w+rd??"}""")
		assertTrue("not a shadowsocks link: $uri", uri.startsWith("ss://"))
		val userInfo = userInfoOf(uri)
		assertFalse("standard-alphabet '+' in userinfo: $uri", userInfo.contains("+"))
		assertFalse("standard-alphabet '/' in userinfo: $uri", userInfo.contains("/"))
		assertFalse("padding in userinfo: $uri", userInfo.contains("="))
		// And it must round-trip back to the credential it came from.
		val decoded = String(Base64.decode(userInfo, Base64.URL_SAFE))
		assertEquals("chacha20-ietf-poly1305:p@ss/w+rd??", decoded)
	}

	@Test
	fun `a 2022 cipher is written plain, not base64`() {
		// SIP022 forbids base64 for the 2022-blake3-* ciphers: method and password go in the
		// userinfo percent-encoded, and a client that follows the spec will not base64-decode them.
		val uri = conv(
			"""{"protocol":"shadowsocks","tag":"n","server":"a.example.com","server_port":8388,
                 "method":"2022-blake3-aes-256-gcm","password":"YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI="}""")
		assertTrue("not a shadowsocks link: $uri", uri.startsWith("ss://"))
		// The method is visible in the clear (base64 would hide it).
		assertTrue("method should be plain: $uri", uri.startsWith("ss://2022-blake3-aes-256-gcm:"))
		val userInfo = userInfoOf(uri)
		val method = URLDecoder.decode(userInfo.substringBefore(":"), "UTF-8")
		val password = URLDecoder.decode(userInfo.substringAfter(":"), "UTF-8")
		assertEquals("2022-blake3-aes-256-gcm", method)
		assertEquals("YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=", password)
	}

	@Test
	fun `a tuic link carries every alpn value`() {
		// The TUIC URI takes a comma-separated ALPN list; cutting it to the first
		// entry negotiates a protocol the server may not have offered.
		val uri = conv(
			"""{"protocol":"tuic","tag":"t","settings":{"servers":[{"address":"a.example.com",
                 "port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e",
                   "password":"pw"}]},"streamSettings":{"security":"tls",
                     "tlsSettings":{"serverName":"a.example.com","alpn":["h3","spdy/3.1"]}}}""")
		assertEquals("h3,spdy/3.1", queryOf(uri)["alpn"])
	}

	@Test
	fun `hysteria2 port hopping travels as mport with a single port in the authority`() {
		// Every client can still connect on the authority port; the range rides along as mport for
		// the ones that read it, and the authority stays a single valid port so a strict URI parser
		// does not reject the link.
		val uri = conv(
			"""{"protocol":"hysteria2","tag":"h","settings":{"servers":[{"address":"a.example.com",
                 "port":443,"password":"pw",
                   "ports":"443,5000-6000"}]},"streamSettings":{"security":"tls",
                     "tlsSettings":{"serverName":"a.example.com"}}}""")
		assertTrue("authority must hold one valid port: " +
			"$uri", uri.startsWith("hysteria2://pw@a.example.com:443"))
		assertEquals("443,5000-6000", queryOf(uri)["mport"])
	}

	@Test
	fun `hysteria2 without hopping writes no mport`() {
		val uri = conv(
			"""{"protocol":"hysteria2","tag":"h","settings":{"servers":[{"address":"a.example.com",
                 "port":443,
                   "password":"pw"}]},"streamSettings":{"security":"tls",
                     "tlsSettings":{"serverName":"a.example.com"}}}""")
		assertFalse("a single-port node must not carry mport: $uri", queryOf(uri).containsKey("mport"))
	}

	@Test
	fun `an IPv6 address is bracketed in every scheme that puts it in the authority`() {
		// Without the brackets the colons of the address are read as the port separator and the
		// link does not parse.
		val ipv6 = "2001:db8::1"
		val nodes = mapOf(
			"ss" to """{"protocol":"shadowsocks","tag":"n","server":"$ipv6","server_port":8388,
              "method":"aes-256-gcm","password":"p"}""",
			"hysteria2" to """{"protocol":"hysteria2","tag":"h",
              "settings":{"servers":[{"address":"$ipv6","port":443,"password":"pw"}]}}""",
			"tuic" to """{"protocol":"tuic","tag":"t","settings":{"servers":[{"address":"$ipv6",
              "port":443,"uuid":"9b4b0b7e-5a1e-4a2b-9f2f-3a3f0a1c2d3e","password":"pw"}]}}""",
			"socks" to """{"protocol":"socks","tag":"n","settings":{"servers":[{"address":"$ipv6",
              "port":1080}]}}""",
			"trojan" to """{"protocol":"trojan","tag":"n","settings":{"servers":[{"address":"$ipv6",
              "port":443,"password":"pw"}]}}"""
		)
		for ((name, cfg) in nodes) {
			val uri = conv(cfg)
			assertTrue("$name did not bracket the IPv6 address: $uri", uri.contains("[$ipv6]"))
			assertFalse("$name left a bare IPv6 address: $uri",
				uri.contains("@$ipv6:") || uri.contains("//$ipv6:"))
		}
	}

	// The share-link proposal carries mtu and tti, and both v2rayN and v2rayNG spell the DNS
	// masquerade's domain as host.
	@Test
	fun `an mKCP node carries its seed, masquerade, mtu and interval`() {
		val uri = conv(
			"""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,
              "users":[{"id":"$uuid","encryption":"none"}]}]},
              "streamSettings":{"network":"kcp","kcpSettings":{"seed":"s3cret","mtu":1350,"tti":20,
                "header":{"type":"dns","domain":"cloud.example.com"}}}}"""
		)
		val query = queryOf(uri)
		assertEquals("kcp", query["type"])
		assertEquals("s3cret", query["seed"])
		assertEquals("dns", query["headerType"])
		assertEquals("cloud.example.com", query["host"])
		assertEquals("1350", query["mtu"])
		assertEquals("20", query["tti"])
	}

	// An absent value is not a zero: writing mtu=0 into a link would hand the next client a broken
	// transport rather than the core's own default.
	@Test
	fun `an mKCP node with nothing set carries no empty numbers`() {
		val uri = conv(
			"""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,
              "users":[{"id":"$uuid","encryption":"none"}]}]},
              "streamSettings":{"network":"kcp"}}"""
		)
		val query = queryOf(uri)
		assertFalse(uri, query.containsKey("mtu"))
		assertFalse(uri, query.containsKey("tti"))
		assertFalse(uri, query.containsKey("host"))
	}

	// The same node must not come out of the three converters with three different security layers.
	@Test
	fun `the old xtls spelling of the TLS block is still read`() {
		val uri = conv(
			"""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,
              "users":[{"id":"$uuid","encryption":"none"}]}]},
              "streamSettings":{"network":"tcp","security":"xtls",
                "xtlsSettings":{"serverName":"sni.example.com","fingerprint":"chrome"}}}"""
		)
		val query = queryOf(uri)
		assertEquals("tls", query["security"])
		assertEquals("sni.example.com", query["sni"])
		assertEquals("chrome", query["fp"])
	}

	// REALITY settings are never there by accident, so a config that names them without naming the
	// layer is still a REALITY node - which is how the sing-box and mihomo passes read it.
	@Test
	fun `a REALITY node with no security field is still REALITY`() {
		val uri = conv(
			"""{"protocol":"vless","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,
              "users":[{"id":"$uuid","encryption":"none"}]}]},
              "streamSettings":{"network":"tcp",
                "realitySettings":{"serverName":"front.example.com","password":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw","shortId":"aa"}}}"""
		)
		val query = queryOf(uri)
		assertEquals("reality", query["security"])
		assertEquals("HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw", query["pbk"])
		assertEquals("aa", query["sid"])
		assertEquals("front.example.com", query["sni"])
	}

	// The blob keeps several settings in one field, and every one of them has to match the server:
	// a node exported without its mKCP seed or QUIC key imports and then connects to nothing.
	@Test
	fun `the vmess blob carries the seed, key and security its one path field holds`() {
		fun blob(uri: String) = JSONObject(
			String(Base64.decode(uri.removePrefix("vmess://"), Base64.DEFAULT))
		)

		val kcp = blob(
			conv(
				"""{"protocol":"vmess","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,
                  "users":[{"id":"$uuid"}]}]},
                  "streamSettings":{"network":"kcp",
                  "kcpSettings":{"seed":"s3cret","header":{"type":"srtp"}}}}"""
			)
		)
		assertEquals("kcp", kcp.optString("net"))
		assertEquals("s3cret", kcp.optString("path"))
		assertEquals("srtp", kcp.optString("type"))

		val quic = blob(
			conv(
				"""{"protocol":"vmess","tag":"n","settings":{"vnext":[{"address":"a.example.com","port":443,
                  "users":[{"id":"$uuid"}]}]},
                  "streamSettings":{"network":"quic","quicSettings":{"security":"aes-128-gcm","key":"k3y",
                    "header":{"type":"wechat-video"}}}}"""
			)
		)
		assertEquals("quic", quic.optString("net"))
		assertEquals("k3y", quic.optString("path"))
		assertEquals("aes-128-gcm", quic.optString("host"))
		assertEquals("wechat-video", quic.optString("type"))
	}
}
