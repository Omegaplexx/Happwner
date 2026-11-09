package com.happwner.convert

import com.happwner.text.splitHostPort
import org.json.JSONObject

// The per-protocol converters.

private class VlessEndpoint(
	val address: String,
	val port: Int,
	val id: String,
	var flow: String,
	var encryption: String
)

private fun vlessEndpoints(settings: JSONObject): List<VlessEndpoint> {
	val out = ArrayList<VlessEndpoint>()
	for (next in settings.xObjList("vnext")) {
		val users = next.xObjList("users")
		if (users.isEmpty()) {
			out.add(VlessEndpoint(next.xStr("address"), next.xInt("port"), "", "", ""))
			continue
		}
		for (user in users) {
			out.add(
				VlessEndpoint(
					address = next.xStr("address"),
					port = next.xInt("port"),
					id = user.xStr("id"),
					flow = user.xStr("flow"),
					encryption = user.xStr("encryption")
				)
			)
		}
	}
	if (out.isEmpty() && (settings.xStr("address").isNotEmpty() || settings.xStr("id").isNotEmpty())) {
		out.add(
			VlessEndpoint(
				address = settings.xStr("address"),
				port = settings.xInt("port"),
				id = settings.xStr("id"),
				flow = settings.xStr("flow"),
				encryption = settings.xStr("encryption")
			)
		)
	}
	// The flat "encryption"/"flow" keys act as defaults for users that do not
	// carry their own.
	for (endpoint in out) {
		if (endpoint.encryption.isEmpty()) endpoint.encryption = settings.xStr("encryption")
		if (endpoint.flow.isEmpty()) endpoint.flow = settings.xStr("flow")
	}
	return out
}

internal fun MihomoConversion.convertVless(outbound: JSONObject, preferred: String): List<YamlMap> {
	val settings = outboundSettings(outbound)
	val endpoints = vlessEndpoints(settings)
	if (endpoints.isEmpty()) throw MihomoUnsupported("the vless outbound has no server")
	if (settings.xStr("seed").isNotEmpty()) {
		warn(UNUSED_VLESS_SEED)
	}

	val streamSettings = outbound.xObj("streamSettings")
	val out = ArrayList<YamlMap>(endpoints.size)
	for (endpoint in endpoints) {
		val name = name(preferred, outbound.xStr("tag"), "vless", endpoint.address, endpoint.port)
		val proxy = base(name, "vless", endpoint.address, endpoint.port)
		if (endpoint.id.isEmpty()) throw MihomoUnsupported(missingCredentialRefusal("vless", "uuid"))
		proxy.set("uuid", endpoint.id)

		// The encryption first, as the other passes read it: whether a flow can run depends on it.
		vlessEncryptionRefusal(endpoint.encryption)?.let { throw MihomoUnsupported(it) }
		val enc = endpoint.encryption.trim()
		if (enc.isNotEmpty() && enc != "none") proxy.set("encryption", enc)

		val flow = normalizeFlow(endpoint.flow)
		if (flow.isNotEmpty()) {
			vlessFlowRefusal(endpoint.flow, endpoint.encryption,
				streamSettings)?.let { throw MihomoUnsupported(it) }
			proxy.set("flow", flow)
		}

		udpFlag(proxy)
		applyMux(proxy, outbound, "vless")
		applyTls(proxy, streamSettings, TLS_V2RAY)
		applyTransport(proxy, streamSettings, "vless")
		applyDialer(proxy, outbound)
		out.add(proxy)
	}
	return out
}

private class VmessEndpoint(
	val address: String,
	val port: Int,
	val id: String,
	val alterIdNote: String?,
	val security: String,
	val securityNote: String?,
	val experiments: String
)

private fun vmessEndpoints(settings: JSONObject): List<VmessEndpoint> {
	val out = ArrayList<VmessEndpoint>()
	for (next in settings.xObjList("vnext")) {
		for (user in next.xObjList("users")) {
			out.add(
				VmessEndpoint(
					address = next.xStr("address"),
					port = next.xInt("port"),
					id = user.xStr("id"),
					alterIdNote = vmessAlterIdNote(user),
					security = vmessSecurity(user),
					securityNote = vmessSecurityNote(user),
					experiments = user.xStr("experiments")
				)
			)
		}
	}
	if (out.isEmpty() &&
		(settings.xStrOf("address", "server").isNotEmpty() || settings.xStrOf("id", "uuid").isNotEmpty())
	) {
		out.add(
			VmessEndpoint(
				address = settings.xStrOf("address", "server"),
				port = if (settings.xInt("port") > 0) settings.xInt("port") else settings.xInt("server_port"),
				id = settings.xStrOf("id", "uuid"),
				alterIdNote = vmessAlterIdNote(settings),
				security = vmessSecurity(settings),
				securityNote = vmessSecurityNote(settings),
				experiments = settings.xStr("experiments")
			)
		)
	}
	return out
}

internal fun MihomoConversion.convertVmess(outbound: JSONObject, preferred: String): List<YamlMap> {
	val settings = outbound.xObj("settings") ?: outbound
	val endpoints = vmessEndpoints(settings)
	if (endpoints.isEmpty()) throw MihomoUnsupported("the vmess outbound has no server")

	val streamSettings = outbound.xObj("streamSettings")
	val out = ArrayList<YamlMap>(endpoints.size)
	for (endpoint in endpoints) {
		val name = name(preferred, outbound.xStr("tag"), "vmess", endpoint.address, endpoint.port)
		val proxy = base(name, "vmess", endpoint.address, endpoint.port)
		if (endpoint.id.isEmpty()) throw MihomoUnsupported(missingCredentialRefusal("vmess", "uuid"))
		proxy.set("uuid", endpoint.id)
		// mihomo requires alterId, including the modern value of 0.
		proxy.set("alterId", 0)
		endpoint.alterIdNote?.let { warn(it) }
		proxy.set("cipher", endpoint.security)
		endpoint.securityNote?.let { warn(it) }

		if (endpoint.experiments.isNotEmpty()) {
			// The experiment flags have dedicated mihomo options.
			if (endpoint.experiments.contains("AuthenticatedLength")) {
				proxy.set("authenticated-length", true)
			}
			if (endpoint.experiments.contains("NoTerminationSignal")) {
				warn("the vmess NoTerminationSignal experiment has no mihomo equivalent and was dropped")
			}
		}

		udpFlag(proxy)
		applyMux(proxy, outbound, "vmess")
		applyTls(proxy, streamSettings, TLS_V2RAY)
		applyTransport(proxy, streamSettings, "vmess")
		applyDialer(proxy, outbound)
		out.add(proxy)
	}
	return out
}

internal fun MihomoConversion.convertTrojan(outbound: JSONObject, preferred: String): List<YamlMap> {
	val settings = outboundSettings(outbound)
	val servers = xrayServers(settings, "address")
	if (servers.isEmpty()) throw MihomoUnsupported("the trojan outbound has no server")

	val streamSettings = outbound.xObj("streamSettings")
	val out = ArrayList<YamlMap>(servers.size)
	for (server in servers) {
		val address = server.xStr("address")
		val port = server.xInt("port")
		val name = name(preferred, outbound.xStr("tag"), "trojan", address, port)
		val proxy = base(name, "trojan", address, port)
		val password = server.xStrRaw("password")
		if (password.isEmpty()) throw MihomoUnsupported(missingCredentialRefusal("trojan", "password"))
		proxy.set("password", password)

		val flow = server.xStr("flow")
		if (normalizeFlow(flow).isNotEmpty()) {
			warn("trojan flow \"$flow\" has no mihomo equivalent and was dropped")
		}

		udpFlag(proxy)
		applyMux(proxy, outbound, "trojan")
		applyTls(proxy, streamSettings, TLS_TROJAN)
		applyTransport(proxy, streamSettings, "trojan")
		applyDialer(proxy, outbound)
		out.add(proxy)
	}
	return out
}

// A server's SIP003 plugin in mihomo's form, with what the plugin itself takes where mihomo would
// put its own (a "bing.com" host, a mode it insists on): obfs-local is mihomo's obfs, and
// v2ray-plugin runs over websocket alone there.
private fun MihomoConversion.setMihomoPlugin(proxy: YamlMap, plugin: TransportPlugin) {
	val options = YamlMap()
	if (plugin.name == "obfs-local") {
		proxy.set("plugin", "obfs")
		options.set("mode", plugin.options["obfs"] ?: "http")
		options.set("host", plugin.options["obfs-host"])
	} else {
		if ((plugin.options["mode"] ?: "websocket") != "websocket") {
			throw MihomoUnsupported(
				"the server's v2ray-plugin runs over quic, and mihomo runs it over websocket alone"
			)
		}
		proxy.set("plugin", "v2ray-plugin")
		options.set("mode", "websocket")
		options.set("host", plugin.options["host"])
		options.set("path", plugin.options["path"] ?: "/")
		if ("tls" in plugin.options) options.set("tls", true)
		options.set("mux", plugin.muxOn())
		if ("certRaw" in plugin.options) {
			warn("the server's plugin certRaw has no place in mihomo's v2ray-plugin, so it was dropped")
		}
	}
	proxy.set("plugin-opts", options)
}

internal fun MihomoConversion.convertShadowsocks(outbound: JSONObject, preferred: String): List<YamlMap> {
	// A node copied out of a sing-box configuration keeps its server on the outbound itself rather
	// than in a settings block. It is the same server either way, and refusing to read it would
	// leave a working node behind.
	val servers = shadowsocksServers(outbound)
	if (servers.isEmpty()) throw MihomoUnsupported(unusableServerRefusal("shadowsocks", "", 0))

	val streamSettings = outbound.xObj("streamSettings")
	val out = ArrayList<YamlMap>(servers.size)
	for (server in servers) {
		val address = server.xStrOf("address", "server")
		val port = if (server.xInt("port") > 0) server.xInt("port") else server.xInt("server_port")
		val name = name(preferred, outbound.xStr("tag"), "ss", address, port)
		val proxy = base(name, "ss", address, port)
		if (server.xStr("method").isEmpty()) throw MihomoUnsupported(MISSING_SS_METHOD_REFUSAL)
		unknownSsMethodRefusal(canonicalSsMethod(server.xStr("method")))
			?.let { throw MihomoUnsupported(it) }
		// What Xray refuses before what mihomo lacks, in the order every pass checks it.
		val password = server.xStrRaw("password")
		if (password.isEmpty()) throw MihomoUnsupported(missingCredentialRefusal("shadowsocks", "password"))
		ss2022KeyRefusal(server.xStr("method"), password)?.let { throw MihomoUnsupported(it) }
		val cipher = ssCipher(server.xStr("method"))
		if (cipher.isEmpty()) {
			throw MihomoUnsupported("unsupported shadowsocks method \"${server.xStr("method")}\"")
		}
		proxy.set("cipher", cipher)
		proxy.set("password", password)
		udpFlag(proxy)

		// A plugin the server names itself comes first, as in the sing-box pass, in mihomo's own form.
		val serverPlugin = serverPluginOf(server)
		serverPlugin.refusal?.let { throw MihomoUnsupported(it) }
		serverPlugin.plugin?.let { plugin ->
			setMihomoPlugin(proxy, plugin.withOwnDefaults())
			serverPlugin.notes.forEach { warn(it) }
		}

		// Xray wraps the outbound in its transport; the one shape a core can carry is WebSocket,
		// as the v2ray-plugin in websocket mode. Anything else is a node that would connect to
		// nothing, and is refused.
		val form = transportFormOf("shadowsocks", streamSettings)
		form.refusal?.let { throw MihomoUnsupported(it) }
		val transportPlugin = form.pluginFor(address)
		serverPlugin.plugin?.let { own -> transportPlugin?.let { warn(displacedTransportNote(own, it)) } }
		if (transportPlugin != null && !proxy.has("plugin")) {
			proxy.set("plugin", transportPlugin.name)
			val pluginOptions = YamlMap()
			pluginOptions.set("mode", "websocket")
			transportPlugin.options["host"]?.let { pluginOptions.set("host", it) }
			transportPlugin.options["path"]?.let { pluginOptions.set("path", it) }
			if (transportPlugin.options.containsKey("tls")) {
				pluginOptions.set("tls", true)
				if (transportPlugin.insecure) pluginOptions.set("skip-cert-verify", true)
			}
			proxy.set("plugin-opts", pluginOptions)
		}
		applyDialer(proxy, outbound)
		out.add(proxy)
	}
	return out
}

// The Shadowsocks methods mihomo implements, established by offering the core each name with a key of
// the right length (2022-blake3-aes-128-gcm looks unsupported until given a 16-byte key).
private val MIHOMO_SS_METHODS = setOf(
	"none",
	"aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
	"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
	"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
	"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
	"aes-128-ccm", "aes-192-ccm", "aes-256-ccm",
	"lea-128-gcm", "lea-192-gcm", "lea-256-gcm",
	"rc4-md5", "chacha20", "chacha20-ietf"
)

// The method under mihomo's spelling, or empty when it has none. An unknown name reaching the core is
// answered with "cipher: ... initialize error", which refuses the whole config file.
internal fun ssCipher(method: String): String =
	when (val name = canonicalSsMethod(method.trim().lowercase())) {
		"", "none", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305" -> name
		// AEAD, AEAD-2022 and the stream ciphers use the same names in both
		// projects - but only the ones mihomo actually has.
		else -> if (name in MIHOMO_SS_METHODS) name else ""
	}

private class ProxyEndpoint(
	val address: String,
	val port: Int,
	val user: String,
	val pass: String,
	val headers: Map<String, String>
)

private fun proxyEndpoints(settings: JSONObject): List<ProxyEndpoint> {
	val out = ArrayList<ProxyEndpoint>()
	for (server in settings.xObjList("servers")) {
		var user = ""
		var pass = ""
		val users = server.xObjList("users")
		if (users.isNotEmpty()) {
			user = users[0].xStrOf("user", "username")
			pass = users[0].xStrRawOf("pass", "password")
		}
		out.add(
			ProxyEndpoint(
				address = server.xStr("address"),
				port = server.xInt("port"),
				user = user,
				pass = pass,
				headers = settings.xHeaders("headers")
			)
		)
	}
	if (out.isEmpty() && settings.xStr("address").isNotEmpty()) {
		out.add(
			ProxyEndpoint(
				address = settings.xStr("address"),
				port = settings.xInt("port"),
				user = settings.xStr("user"),
				// Xray makes a user of these only when one is named; a lone password goes unused.
				pass = if (settings.xStr("user").isEmpty()) "" else settings.xStrRaw("pass"),
				headers = settings.xHeaders("headers")
			)
		)
	}
	return out
}

internal fun MihomoConversion.convertSocks(outbound: JSONObject, preferred: String): List<YamlMap> {
	val settings = outboundSettings(outbound)
	val endpoints = proxyEndpoints(settings)
	if (endpoints.isEmpty()) throw MihomoUnsupported("the socks outbound has no server")
	val streamSettings = outbound.xObj("streamSettings")
	// The proxy type carries no transport: a node under one would connect to nothing.
	transportFormOf("socks", streamSettings).refusal?.let { throw MihomoUnsupported(it) }

	val out = ArrayList<YamlMap>(endpoints.size)
	for (endpoint in endpoints) {
		val name = name(preferred, outbound.xStr("tag"), "socks5", endpoint.address, endpoint.port)
		val proxy = base(name, "socks5", endpoint.address, endpoint.port)
		proxy.setString("username", endpoint.user)
		proxy.setString("password", endpoint.pass)
		udpFlag(proxy)
		if (streamSettings != null && streamSecurity(streamSettings) == "tls") {
			val saidFrom = diagnostics.size
			val tls = streamTls(streamSettings)
			// mihomo's socks5 has no server name for TLS and checks the certificate against the address it
			// dials, so a certificate for another name fails every connection.
			val serverName = tls?.xStr("serverName").orEmpty()
			if (serverName.isNotEmpty() && !serverName.equals(endpoint.address, ignoreCase = true)) {
				throw MihomoUnsupported(
					"tlsSettings.serverName \"$serverName\" is not the address this node dials, " +
						"and mihomo's socks5 takes no server name for TLS, so the node would not connect"
				)
			}
			proxy.set("tls", true)
			if (tls != null && tls.xBool("allowInsecure")) {
				proxy.set("skip-cert-verify", true)
			}
			tls?.let { applyProxyTls(proxy, it, streamSettings, "socks5", saidFrom) }
		}
		applyMux(proxy, outbound, "socks")
		applyDialer(proxy, outbound)
		out.add(proxy)
	}
	return out
}

internal fun MihomoConversion.convertHttp(outbound: JSONObject, preferred: String): List<YamlMap> {
	val settings = outboundSettings(outbound)
	val endpoints = proxyEndpoints(settings)
	if (endpoints.isEmpty()) throw MihomoUnsupported("the http outbound has no server")
	val streamSettings = outbound.xObj("streamSettings")
	// The proxy type carries no transport: a node under one would connect to nothing.
	transportFormOf("http", streamSettings).refusal?.let { throw MihomoUnsupported(it) }

	val out = ArrayList<YamlMap>(endpoints.size)
	for (endpoint in endpoints) {
		val name = name(preferred, outbound.xStr("tag"), "http", endpoint.address, endpoint.port)
		val proxy = base(name, "http", endpoint.address, endpoint.port)
		proxy.setString("username", endpoint.user)
		proxy.setString("password", endpoint.pass)
		if (streamSettings != null && streamSecurity(streamSettings) == "tls") {
			val saidFrom = diagnostics.size
			proxy.set("tls", true)
			val tls = streamTls(streamSettings)
			if (tls != null) {
				proxy.setString("sni", tls.xStr("serverName"))
				if (tls.xBool("allowInsecure")) proxy.set("skip-cert-verify", true)
				applyProxyTls(proxy, tls, streamSettings, "HTTP", saidFrom)
			}
		}
		if (endpoint.headers.isNotEmpty()) {
			val headers = YamlMap()
			for (key in endpoint.headers.keys.sorted()) headers.setString(key, endpoint.headers[key])
			proxy.set("headers", headers)
		}
		applyMux(proxy, outbound, "http")
		applyDialer(proxy, outbound)
		out.add(proxy)
	}
	return out
}

internal fun MihomoConversion.convertWireGuard(outbound: JSONObject, preferred: String): List<YamlMap> {
	val settings = outboundSettings(outbound)
	wireguardRefusal(settings)?.let { throw MihomoUnsupported(it) }
	val peers = wireguardUsablePeers(settings)
	wireguardDroppedPeerNotes(settings).forEach { warn(it) }
	val secret = settings.xStr("secretKey")

	// mihomo takes the first peer's endpoint as the proxy address and carries
	// any further peers in a "peers" list.
	val primary = peers[0]
	val endpoint = splitEndpoint(primary.xStr("endpoint"))
		?: throw MihomoUnsupported("peer endpoint \"${primary.xStr("endpoint")}\" is not host:port")
	val name = name(preferred, outbound.xStr("tag"), "wireguard", endpoint.first, endpoint.second)
	val proxy = base(name, "wireguard", endpoint.first, endpoint.second)
	proxy.set("private-key", canonicalWireguardKey(secret))
	proxy.setString("public-key", canonicalWireguardKey(primary.xStr("publicKey")))
	proxy.setString("pre-shared-key", canonicalWireguardKey(primary.xStr("preSharedKey")))

	val addresses = settings.xStrList("address").map { it.trim() }.filter { it.isNotEmpty() }
		.mapNotNull { raw ->
			wireguardInterfacePrefix(raw).also { if (it == null) warn(wireguardAddressDroppedNote(raw)) }
		}
		.ifEmpty {
			// The same assumption the sing-box pass makes, said the same way: a proxy with no
			// interface address is one mihomo cannot bring up.
			warn(
				"the wireguard outbound names no address; " +
					"${WIREGUARD_ASSUMED_ADDRESS} was assumed - check it against " +
					"what the server assigned"
			)
			listOf(WIREGUARD_ASSUMED_ADDRESS)
		}
	for (raw in addresses) {
		var address = raw
		// mihomo wants the bare interface address, not a CIDR.
		val slash = address.indexOf('/')
		if (slash >= 0) address = address.substring(0, slash)
		if (address.contains(":")) {
			if (!proxy.has("ipv6")) proxy.set("ipv6", address)
		} else if (!proxy.has("ip")) {
			proxy.set("ip", address)
		}
	}

	val allowed = primary.xStrList("allowedIPs")
	if (allowed.isNotEmpty()) proxy.set("allowed-ips", toFlowSeq(allowed))
	proxy.setInt("mtu", settings.xInt("mtu"))
	proxy.setInt("persistent-keepalive", primary.xInt("keepAlive"))
	val reserved = parseReserved(settings.xOpt("reserved")) { warn(reservedNotByteNote(it)) }
	if (reserved != null && reserved.isNotEmpty()) {
		if (reserved.size == WG_RESERVED_BYTES) {
			val seq = YamlFlowSeq()
			for (byte in reserved) seq.add(byte.toInt() and 0xFF)
			proxy.set("reserved", seq)
		} else {
			// The core wants exactly three bytes and refuses the whole config file otherwise
			// ("invalid reserved value, required 3 bytes, got N"), so a hand-edited four-byte value
			// is left out and named rather than written.
			warn(
				"wireguard reserved is ${reserved.size} bytes and mihomo wants " +
					"$WG_RESERVED_BYTES, so it was dropped"
			)
		}
	}
	udpFlag(proxy)

	if (peers.size > 1) {
		val list = YamlSeq()
		for (peer in peers) {
			val peerEndpoint = splitEndpoint(peer.xStr("endpoint"))
			if (peerEndpoint == null) {
				warn("wireguard peer with endpoint \"${peer.xStr("endpoint")}\" was dropped: not host:port")
				continue
			}
			val peerMap = YamlMap()
			peerMap.set("server", peerEndpoint.first)
			peerMap.set("port", peerEndpoint.second)
			peerMap.setString("public-key", canonicalWireguardKey(peer.xStr("publicKey")))
			peerMap.setString("pre-shared-key", canonicalWireguardKey(peer.xStr("preSharedKey")))
			// Xray gives a peer without allowedIPs everything; mihomo refuses the whole file over a
			// listed peer that names none, so that default is written out.
			val pAllowed = peer.xStrList("allowedIPs").ifEmpty { listOf("0.0.0.0/0", "::/0") }
			peerMap.set("allowed-ips", toFlowSeq(pAllowed))
			list.add(peerMap)
		}
		if (list.size > 1) proxy.set("peers", list)
	}

	applyDialer(proxy, outbound)
	return listOf(proxy)
}

// Splits a "host:port" endpoint, handling a bracketed IPv6 literal.
internal fun splitEndpoint(endpoint: String): Pair<String, Int>? {
	val trimmed = endpoint.trim()
	if (trimmed.isEmpty()) return null
	val hostPort = splitHostPort(trimmed)
	val port = hostPort.port?.takeIf { it in 1..65535 } ?: return null
	return hostPort.host to port
}
