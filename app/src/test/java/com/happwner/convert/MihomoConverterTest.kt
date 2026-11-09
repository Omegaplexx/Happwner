package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Conversion tests for the Xray -> mihomo converter: each expectation is what mihomo reads.
class MihomoConverterTest {

	private fun convert(input: String): MihomoConverter.Result.Ok {
		val result = MihomoConverter.convert(input)
		assertTrue("expected a conversion, got $result", result is MihomoConverter.Result.Ok)
		return result as MihomoConverter.Result.Ok
	}

	private fun vlessConfig(streamSettings: String, remarks: String = "node"): String = """
        {
          "remarks": "$remarks",
          "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": { "vnext": [{
              "address": "a.example.com", "port": 443,
              "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "encryption": "none" }]
            }] }
            ${if (streamSettings.isEmpty()) "" else ", \"streamSettings\": $streamSettings"}
          }]
        }
	""".trimIndent()

	@Test
	fun `non-xray input is left alone`() {
		assertEquals(MihomoConverter.Result.NotXray, MihomoConverter.convert("vless://x@a.com:443"))
		assertEquals(MihomoConverter.Result.NotXray, MihomoConverter.convert(""))
		assertEquals(MihomoConverter.Result.NotXray, MihomoConverter.convert("{\"outbounds\":[]}"))
		// A sing-box config has "type", not "protocol", on its outbounds.
		assertEquals(
			MihomoConverter.Result.NotXray,
			MihomoConverter.convert("{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"proxy\"}]}")
		)
	}

	@Test
	fun `comments and trailing commas are tolerated`() {
		val input = """
            // a commented config
            [
              /* block */
              ${vlessConfig("")},
            ]
		""".trimIndent()
		val out = convert(input)
		assertEquals(1, out.converted)
		assertTrue(out.yaml.contains("- name: node"))
	}

	@Test
	fun `the document carries proxies, groups and rules`() {
		val yaml = convert(vlessConfig("")).yaml
		assertTrue(yaml.contains("mixed-port: 7890"))
		assertTrue(yaml.contains("proxies:"))
		assertTrue(yaml.contains("name: PROXY"))
		assertTrue(yaml.contains("name: AUTO"))
		assertTrue(yaml.contains("MATCH,PROXY"))
	}

	@Test
	fun `repeated names are made unique`() {
		val input = """
            [${vlessConfig("", "same")}, ${vlessConfig("", "same")}]
		""".trimIndent()
		val yaml = convert(input).yaml
		assertTrue(yaml.contains("- name: same\n"))
		assertTrue(yaml.contains("- name: 'same #2'"))
	}

	@Test
	fun `local outbounds are not proxies`() {
		val input = """
			{ "remarks": "n", "outbounds": [
			  { "protocol": "freedom", "tag": "direct" },
			  { "protocol": "blackhole", "tag": "block" },
			  { "protocol": "vless", "tag": "proxy", "settings": { "vnext": [{
			      "address": "a.example.com", "port": 443,
			      "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] }] } }
			] }
		""".trimIndent()
		val out = convert(input)
		assertEquals(1, out.converted)
		assertEquals(0, out.skipped)
	}

	@Test
	fun `post-quantum encryption passes through`() {
		val enc = "mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111." +
			"RvI5xPRmxvhVMSxOsCUDIF1uu4sN0-1Z9RXTVIrGYFk"
		val input = """
            { "remarks": "pq", "outbounds": [{ "protocol": "vless", "tag": "proxy",
              "settings": { "vnext": [{ "address": "a.example.com", "port": 443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "encryption": "$enc" }] }] } }] }
		""".trimIndent()
		assertTrue(convert(input).yaml.contains("encryption: $enc"))
	}

	@Test
	fun `a server-side encryption value is rejected by name`() {
		// "600s" belongs in the server's decryption field. mihomo refuses the
		// whole file over one bad value, so it must never be passed through.
		val enc = "mlkem768x25519plus.native.600s.RvI5xPRmxvhVMSxOsCUDIF1uu4sN0-1Z9RXTVIrGYFk"
		val input = """
            { "remarks": "bad", "outbounds": [{ "protocol": "vless", "tag": "proxy",
              "settings": { "vnext": [{ "address": "a.example.com", "port": 443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "encryption": "$enc" }] }] } }] }
		""".trimIndent()
		assertTrue(MihomoConverter.convert(input) is MihomoConverter.Result.Unsupported)
	}

	@Test
	fun `encryption padding and key length are validated`() {
		fun encryptionIsRejected(enc: String): Boolean {
			val input = """
                { "outbounds": [{ "protocol": "vless", "tag": "proxy",
                  "settings": { "vnext": [{ "address": "a.example.com", "port": 443,
                    "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                      "encryption": "$enc" }] }] } }] }
			""".trimIndent()
			return MihomoConverter.convert(input) is MihomoConverter.Result.Unsupported
		}
		val key = "RvI5xPRmxvhVMSxOsCUDIF1uu4sN0-1Z9RXTVIrGYFk"
		assertTrue(encryptionIsRejected("mlkem768x25519plus.native.1rtt.99-35-35.$key"))
		assertTrue(encryptionIsRejected("mlkem768x25519plus.sideways.1rtt.$key"))
		assertTrue(encryptionIsRejected("mlkem768x25519plus.native.1rtt.RvI5xPRmxvhVMSxOsCUD"))
		assertTrue(encryptionIsRejected("chacha20poly1305.native.1rtt.$key"))
		assertFalse(encryptionIsRejected("mlkem768x25519plus.xorpub.0rtt.100-35-35.$key"))
	}

	@Test
	fun `xhttp extra replaces the outer settings`() {
		// Xray applies "extra" by replacement, keeping only host/path/mode from the outer object.
		// Merging instead would carry over headers and padding that Xray itself discards.
		val stream = """
			{ "network": "xhttp", "xhttpSettings": {
			    "host": "outer.example.com", "path": "/outer", "mode": "stream-up",
			    "headers": { "X-Outer": "discarded" },
			    "xPaddingBytes": "900-1400", "noGRPCHeader": true,
			    "extra": { "headers": { "X-Inner": "kept" }, "xPaddingBytes": "100-200" } } }
		""".trimIndent()
		val yaml = convert(vlessConfig(stream)).yaml
		assertTrue(yaml.contains("X-Inner: kept"))
		assertFalse(yaml.contains("X-Outer"))
		assertTrue(yaml.contains("x-padding-bytes: 100-200"))
		assertFalse(yaml.contains("no-grpc-header"))
		// host, path and mode still come from the outer object.
		assertTrue(yaml.contains("path: /outer"))
		assertTrue(yaml.contains("host: outer.example.com"))
		assertTrue(yaml.contains("mode: stream-up"))
	}

	@Test
	fun `xmux becomes reuse-settings and zero ranges are dropped`() {
		val stream = """
			{ "network": "xhttp", "xhttpSettings": { "mode": "auto", "xmux": {
			    "maxConcurrency": "16-32", "maxConnections": 0, "hKeepAlivePeriod": 45 } } }
		""".trimIndent()
		val yaml = convert(vlessConfig(stream)).yaml
		assertTrue(yaml.contains("reuse-settings:"))
		assertTrue(yaml.contains("max-concurrency: 16-32"))
		assertTrue(yaml.contains("h-keep-alive-period: 45"))
		// Xray reads zero as "use the default", so it must not reach mihomo.
		assertFalse(yaml.contains("max-connections"))
	}

	@Test
	fun `downloadSettings keeps its own address and security`() {
		val stream = """
			{ "network": "xhttp", "xhttpSettings": { "mode": "auto", "path": "/up",
			    "downloadSettings": { "address": "dl.example.com", "port": 8443,
			      "network": "xhttp", "security": "tls",
			      "tlsSettings": { "serverName": "dl.example.com" },
			      "xhttpSettings": { "path": "/down", "mode": "auto" } } } }
		""".trimIndent()
		val yaml = convert(vlessConfig(stream)).yaml
		assertTrue(yaml.contains("download-settings:"))
		assertTrue(yaml.contains("server: dl.example.com"))
		assertTrue(yaml.contains("port: 8443"))
		assertTrue(yaml.contains("path: /down"))
		assertTrue(yaml.contains("servername: dl.example.com"))
	}

	// The download leg over REALITY dials as the node itself does: X25519MLKEM768 offered as Xray offers
	// it, and chrome where no fingerprint is named, which mihomo would otherwise refuse.
	@Test
	fun `downloadSettings over REALITY offers what the node does`() {
		val stream = """
			{ "network": "xhttp", "xhttpSettings": { "mode": "auto", "path": "/up",
			    "downloadSettings": { "address": "dl.example.com", "port": 443,
			      "network": "xhttp", "security": "reality",
			      "realitySettings": { "serverName": "dl.example.com",
			        "publicKey": "yPNRx8rTdkUp89A-J76KxmGFeexuyVG4BiVl1PJ1kCk", "shortId": "ab" },
			      "xhttpSettings": { "path": "/down", "mode": "auto" } } } }
		""".trimIndent()
		val result = convert(vlessConfig(stream))
		val download = result.yaml.substringAfter("download-settings:")
		assertTrue(download, download.contains("support-x25519mlkem768: true"))
		assertTrue(download, download.contains("client-fingerprint: chrome"))
		assertTrue("${result.notes}", result.notes.any { REALITY_MIHOMO_NOTE in it })
	}

	@Test
	fun `combinations xray itself refuses are skipped`() {
		val getOutsidePacketUp =
			"""{ "network": "xhttp", "xhttpSettings": { "mode": "stream-up", "uplinkHTTPMethod": "GET" } }"""
		assertTrue(MihomoConverter.convert(vlessConfig(
			getOutsidePacketUp)) is MihomoConverter.Result.Unsupported)
		val badPlacement =
			"""{ "network": "xhttp", "xhttpSettings": { "xPaddingPlacement": "nowhere" } }"""
		assertTrue(MihomoConverter.convert(vlessConfig(badPlacement)) is MihomoConverter.Result.Unsupported)
	}

	@Test
	fun `hysteria2 in the xray-native shape finds its password`() {
		// Xray's hysteria outbound carries only the address; the password lives
		// in streamSettings.hysteriaSettings.auth.
		val input = """
			{ "remarks": "hy2", "outbounds": [{ "protocol": "hysteria", "tag": "proxy",
			  "settings": { "address": "hy2.example.com", "port": 30443, "version": 2 },
			  "streamSettings": { "network": "hysteria",
			    "hysteriaSettings": { "version": 2, "auth": "the-password" },
			    "security": "tls", "tlsSettings": { "serverName": "hy2.example.com", "alpn": ["h3"] },
			    "finalmask": {
			      "udp": [{ "type": "salamander", "settings": { "password": "obfs-secret" } }],
			      "quicParams": { "brutalUp": "50 mbps", "brutalDown": "200 mbps",
			        "udpHop": { "ports": "20000-30000", "interval": 30 } } } } }] }
		""".trimIndent()
		val yaml = convert(input).yaml
		assertTrue(yaml.contains("type: hysteria2"))
		assertTrue(yaml.contains("password: the-password"))
		assertTrue(yaml.contains("obfs: salamander"))
		assertTrue(yaml.contains("obfs-password: obfs-secret"))
		// Xray reads "50 mbps" in binary units, 52428800 bits a second; mihomo gets exactly that, in a
		// spelling it reads (it refuses the whole document over "50 mbps").
		assertTrue(yaml, yaml.contains("up: 52428800 bps"))
		assertTrue(yaml.contains("ports: 20000-30000"))
		assertTrue(yaml.contains("hop-interval: 30"))
	}

	@Test
	fun `a salamander packet size range selects gecko`() {
		val input = """
			{ "outbounds": [{ "protocol": "hysteria", "tag": "proxy",
			  "settings": { "address": "gk.example.com", "port": 443, "version": 2 },
			  "streamSettings": { "network": "hysteria",
			    "hysteriaSettings": { "version": 2, "auth": "pw" },
			    "finalmask": { "udp": [{ "type": "salamander",
			      "settings": { "password": "o", "packetSize": "100-1200" } }] } } }] }
		""".trimIndent()
		val yaml = convert(input).yaml
		assertTrue(yaml.contains("obfs: gecko"))
		assertTrue(yaml.contains("obfs-min-packet-size: 100"))
		assertTrue(yaml.contains("obfs-max-packet-size: 1200"))
	}

	@Test
	fun `hysteria2 in the client shape accepts every spelling`() {
		val input = """
			{ "outbounds": [{ "protocol": "hysteria2", "tag": "proxy", "settings": {
			    "server": "hy.example.com:8443", "auth_str": "pw",
			    "bandwidth": { "up": "100 mbps", "down": "500 mbps" },
			    "obfs": { "type": "salamander", "salamander": { "password": "os" } },
			    "hopInterval": "45s",
			    "tls": { "sni": "sni.example.com", "insecure": true, "alpn": ["h3"] } } }] }
		""".trimIndent()
		val yaml = convert(input).yaml
		// The "host:port" address is split apart.
		assertTrue(yaml.contains("server: hy.example.com"))
		assertTrue(yaml.contains("port: 8443"))
		assertTrue(yaml.contains("password: pw"))
		assertTrue(yaml.contains("obfs-password: os"))
		assertTrue(yaml.contains("up: 100 Mbps") && yaml.contains("down: 500 Mbps"))
		assertTrue(yaml.contains("sni: sni.example.com"))
		assertTrue(yaml.contains("skip-cert-verify: true"))
		assertTrue(yaml.contains("hop-interval: 45"))
	}

	// The cores read "100 Mbps", "640 KBps" and refuse the file over anything else; Hysteria 2 reads
	// every case and "1g" as bits, and version 1 reads an uppercase B as bytes.
	@Test
	fun `a rate reaches mihomo in the one spelling it reads`() {
		fun hy2(up: String) = """
            { "outbounds": [{ "protocol": "hysteria2", "tag": "proxy",
              "settings": { "address": "h.example.com", "port": 443, "password": "pw", "up": "$up" } }] }
		""".trimIndent()
		assertTrue(convert(hy2("1g")).yaml.contains("up: 1 Gbps"))
		assertTrue(convert(hy2("512 KBPS")).yaml.contains("up: 512 Kbps"))
		assertTrue(convert(hy2("100 Mbps")).yaml.contains("up: 100 Mbps"))
		assertTrue(convert(hy2("640 KBps")).yaml.contains("up: 640 Kbps"))
		val odd = convert(hy2("fast"))
		assertFalse(odd.yaml.contains("up:"))
		assertTrue(odd.notes.toString(), odd.notes.any { it.contains("\"fast\" is not one Hysteria reads") })

		fun hy1(up: String) = """
            { "outbounds": [{ "protocol": "hysteria", "tag": "proxy", "settings": { "servers": [
              { "address": "h.example.com", "port": 443, "auth_str": "pw", "up": "$up", "down": "$up" }] },
              "streamSettings": { "security": "tls", "tlsSettings": { "serverName": "h.example.com" } } }] }
		""".trimIndent()
		assertTrue(convert(hy1("640 KBps")).yaml.contains("up: 640 KBps"))
		assertTrue(convert(hy1("1 MBps")).yaml.contains("up: 1 MBps"))
		assertTrue(convert(hy1("100 mbps")).yaml.contains("up: 100 Mbps"))
		val bad = MihomoConverter.convert(hy1("fast")) as MihomoConverter.Result.Unsupported
		assertTrue(bad.notes.toString(),
			bad.notes.any { it.contains("\"fast\" is not a rate Hysteria reads") })
	}

	@Test
	fun `a unit-less rate is emitted as Mbps`() {
		val input = """
			{ "outbounds": [{ "protocol": "hysteria2", "tag": "proxy",
			  "settings": { "address": "h.example.com", "port": 443, "password": "pw",
			    "up": "50", "down": "200" } }] }
		""".trimIndent()
		val yaml = convert(input).yaml
		assertTrue(yaml.contains("up: 50 Mbps"))
		assertTrue(yaml.contains("down: 200 Mbps"))
	}

	@Test
	fun `another protocol over the hysteria transport is refused`() {
		// mihomo cannot express VLESS inside a Hysteria tunnel, and a plain
		// hysteria2 node would not connect.
		assertTrue(MihomoConverter.convert(vlessConfig(
			"""{ "network": "hysteria" }""")) is MihomoConverter.Result.Unsupported)
	}

	@Test
	fun `websocket early data moves out of the path`() {
		val stream = """
			{ "network": "ws", "wsSettings": { "path": "/ws?a=1&ed=2048",
			    "headers": { "Host": "h.example.com" } } }
		""".trimIndent()
		val yaml = convert(vlessConfig(stream)).yaml
		assertTrue(yaml.contains("path: /ws?a=1"))
		assertTrue(yaml.contains("max-early-data: 2048"))
		assertTrue(yaml.contains("early-data-header-name: Sec-WebSocket-Protocol"))
		assertTrue(yaml.contains("Host: h.example.com"))
	}

	@Test
	fun `httpupgrade becomes websocket with a flag`() {
		val stream = """
			{ "network": "httpupgrade", "httpupgradeSettings": { "path": "/u", "host": "h.example.com" } }
		""".trimIndent()
		val yaml = convert(vlessConfig(stream)).yaml
		assertTrue(yaml.contains("network: ws"))
		assertTrue(yaml.contains("v2ray-http-upgrade: true"))
	}

	@Test
	fun `reality reads the newer password field and the array spellings`() {
		val stream = """
			{ "network": "tcp", "security": "reality", "realitySettings": {
			    "serverNames": ["r.example.com"],
			    "password": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
			    "shortIds": ["6ba85179e30d4fc2"], "fingerprint": "chrome" } }
		""".trimIndent()
		val yaml = convert(vlessConfig(stream)).yaml
		assertTrue(yaml.contains("servername: r.example.com"))
		assertTrue(yaml.contains("public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"))
		assertTrue(yaml.contains("short-id: 6ba85179e30d4fc2"))
		assertTrue(yaml.contains("client-fingerprint: chrome"))
	}

	@Test
	fun `transports mihomo lacks are skipped rather than emitted`() {
		assertTrue(MihomoConverter.convert(vlessConfig(
			"""{ "network": "quic" }""")) is MihomoConverter.Result.Unsupported)
		val trojanH2 = """
			{ "outbounds": [{ "protocol": "trojan", "tag": "proxy",
			  "settings": { "servers": [{ "address": "t.example.com", "port": 443, "password": "pw" }] },
			  "streamSettings": { "network": "h2", "security": "tls" } }] }
		""".trimIndent()
		assertTrue(MihomoConverter.convert(trojanH2) is MihomoConverter.Result.Unsupported)
	}

	@Test
	fun `a balancer becomes one group named from remarks`() {
		val input = """
			{ "remarks": "Germany", "outbounds": [
			    { "tag": "proxy-de-1", "protocol": "vless", "settings": { "vnext": [{
			        "address": "de1.example.com", "port": 443,
			        "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] }] } },
			    { "tag": "proxy-de-2", "protocol": "vless", "settings": { "vnext": [{
			        "address": "de2.example.com", "port": 443,
			        "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] }] } },
			    { "tag": "other", "protocol": "vless", "settings": { "vnext": [{
			        "address": "x.example.com", "port": 443,
			        "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] }] } }
			  ],
			  "routing": { "balancers": [{ "tag": "b", "selector": ["proxy"],
			    "strategy": { "type": "leastPing" } }],
			    "rules": [{ "balancerTag": "b" }] } }
		""".trimIndent()
		val yaml = convert(input).yaml
		assertTrue(yaml.contains("# Xray balancer \"b\", strategy leastPing"))
		assertTrue(yaml.contains("- name: Germany\n    type: url-test"))
		// The selector matches by prefix, so "other" is not a member.
		val group = yaml.substringAfter("- name: Germany").substringBefore("- name: PROXY")
		assertTrue(group.contains("proxy-de-1"))
		assertTrue(group.contains("proxy-de-2"))
		assertFalse(group.contains("Germany #other"))
		// Balanced nodes are reachable through the group, not on their own.
		val selector = yaml.substringAfter("- name: PROXY")
		assertFalse(selector.contains("- Germany #proxy-de-1"))
		assertTrue(selector.contains("- Germany\n"))
		assertTrue(selector.contains("Germany #other"))
	}

	@Test
	fun `a fallbackTag wraps the balancer in a fallback group`() {
		val input = """
			{ "remarks": "NL", "outbounds": [
			    { "tag": "nl-1", "protocol": "vless", "settings": { "vnext": [{
			        "address": "nl1.example.com", "port": 443,
			        "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] }] } },
			    { "tag": "spare", "protocol": "vless", "settings": { "vnext": [{
			        "address": "sp.example.com", "port": 443,
			        "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] }] } }
			  ],
			  "routing": { "balancers": [{ "tag": "b", "selector": ["nl-"],
			    "fallbackTag": "spare" }] } }
		""".trimIndent()
		val yaml = convert(input).yaml
		assertTrue(yaml.contains("- name: NL pool"))
		assertTrue(yaml.contains("- name: NL\n    type: fallback"))
		// Only the outer group is offered; the spare is reached through it.
		val selector = yaml.substringAfter("- name: PROXY")
		assertTrue(selector.contains("- NL\n"))
		assertFalse(selector.contains("- spare"))
		assertFalse(selector.contains("- NL pool"))
	}

	@Test
	fun `values a yaml parser would retype are quoted`() {
		assertEquals("'yes'", quoteYamlString("yes"))
		assertEquals("'true'", quoteYamlString("true"))
		assertEquals("'123'", quoteYamlString("123"))
		assertEquals("'1.5'", quoteYamlString("1.5"))
		assertEquals("'0x1f'", quoteYamlString("0x1f"))
		assertEquals("'12:34'", quoteYamlString("12:34"))
		assertEquals("''", quoteYamlString(""))
		assertEquals("'- dash'", quoteYamlString("- dash"))
		assertEquals("'a: b'", quoteYamlString("a: b"))
		assertEquals("plain", quoteYamlString("plain"))
		assertEquals("a.example.com", quoteYamlString("a.example.com"))
		assertEquals("100-200", quoteYamlString("100-200"))
	}

	@Test
	fun `a password that looks like a number stays a string`() {
		val input = """
			{ "outbounds": [{ "protocol": "trojan", "tag": "proxy", "settings": {
			    "servers": [{ "address": "t.example.com", "port": 443, "password": "12345678" }] },
			    "streamSettings": { "security": "tls" } }] }
		""".trimIndent()
		assertTrue(convert(input).yaml.contains("password: '12345678'"))
	}

	@Test
	fun `with every proxy taken by a balancer, the selector still offers its group`() {
		val node = { tag: String ->
			"""{"tag":"$tag","protocol":"vless",
				"settings":{"vnext":[{"address":"$tag.example.com","port":443,
				"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
				"streamSettings":{"network":"tcp","security":"tls",
				"tlsSettings":{"serverName":"$tag.example.com"}}}"""
		}
		val balancer = """{"tag":"bal","selector":["a","b"],"fallbackTag":"c",
			"strategy":{"type":"leastPing"}}"""
		val yaml = convert("""{"outbounds":[${node("a")},${node("b")},${node("c")}],
			"routing":{"balancers":[$balancer],
			"rules":[{"type":"field","network":"tcp,udp","balancerTag":"bal"}]},
			"observatory":{"subjectSelector":["a","b"]}}""").yaml
		val selector = yaml.substringAfter("- name: PROXY").substringBefore("- name: AUTO")
		assertTrue(selector, selector.contains("- bal\n"))
	}

	@Test
	// Xray refuses the two together ("proxySettings.tag is conflicted with sockopt.dialerProxy"); the
	// node connects through proxySettings.tag all the same, and the note says so.
	fun `with both a sockopt dialerProxy and proxySettings, the node goes through proxySettings`() {
		val node = { tag: String, sockopt: String, extra: String ->
			"""{"tag":"$tag","protocol":"vless","settings":{"vnext":[{"address":"$tag.example.com",
				"port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
				"streamSettings":{"network":"tcp","security":"tls",
				"tlsSettings":{"serverName":"$tag.example.com"}$sockopt}$extra}"""
		}
		val chained = node("z", ""","sockopt":{"dialerProxy":"x"}""", ""","proxySettings":{"tag":"y"}""")
		val result = convert("""{"outbounds":[${node("x", "", "")},${node("y", "", "")},$chained]}""")
		assertTrue(result.yaml, result.yaml.contains("- name: z"))
		assertTrue(result.yaml, Regex("dialer-proxy: '?y'?\n").containsMatchIn(result.yaml))
		assertTrue("${result.notes}", result.notes.any { "proxySettings.tag \"y\" was followed" in it })
	}

	@Test
	fun `xhttp values mihomo reads pass, and one it would take for its default refuses the node`() {
		// An unknown value is no error to mihomo: it quietly takes its default, so the node is refused.
		val fields = listOf(
			Triple("xPaddingPlacement", "header", "x-padding-placement"),
			Triple("xPaddingMethod", "tokenish", "x-padding-method"),
			Triple("sessionPlacement", "cookie", "session-placement"),
			Triple("seqPlacement", "query", "seq-placement"),
			Triple("uplinkDataPlacement", "body", "uplink-data-placement")
		)
		for ((field, good, key) in fields) {
			fun stream(value: String) = """{"network":"xhttp","security":"tls",
				"tlsSettings":{"serverName":"example.com"},
				"xhttpSettings":{"path":"/p","mode":"packet-up","$field":"$value"}}"""
			assertTrue(field, convert(vlessConfig(stream(good))).yaml.contains("$key: $good"))
			val refused = MihomoConverter.convert(vlessConfig(stream("bogus")))
			val label = if (field == "sessionPlacement") "session placement" else field
			assertTrue("$field: $refused", refused is MihomoConverter.Result.Unsupported &&
				refused.notes.any { it.contains("unsupported $label \"bogus\"") })
		}
	}
}
