package com.happwner.convert

import com.happwner.text.firstNonEmpty
import org.json.JSONObject

// The TLS settings both hysteria versions carry beyond the name and ALPN: the certificate pin, the
// certificates and the ECH config. Kept in one place so the two versions cannot drift apart here.
private fun MihomoConversion.applyHysteriaTlsExtras(proxy: YamlMap, settings: JSONObject,
	streamSettings: JSONObject?) {
	val saidFrom = diagnostics.size
	// Hysteria spells its own pin "pinSHA256" and its own ECH "ech"; the shared tlsSettings block
	// has three spellings of the pin, which applyCertPin sorts out.
	settings.xObj("tls")?.let {
		applyCertPinValue(proxy, it.xStr("pinSHA256"), "hysteria settings tls.pinSHA256")
		applyEchValue(proxy, it.xStr("ech"), "hysteria settings tls.ech")
	}
	val tls = streamTls(streamSettings) ?: return
	applyProxyTls(proxy, tls, streamSettings, "QUIC", saidFrom)
	applyEch(proxy, tls)
}

internal fun MihomoConversion.convertHysteria2(outbound: JSONObject, preferred: String): List<YamlMap> {
	val settings = outboundSettings(outbound)
	val streamSettings = outbound.xObj("streamSettings")

	val (obfsMode, obfsPassword) = parsedObfsAnywhere(settings)
	val tls = hysteriaTls(settings, streamSettings)

	val out = ArrayList<YamlMap>()
	for (endpoint in hysteriaEndpoints(settings, streamSettings)) {
		// Anything the outbound's own settings did not supply comes from
		// streamSettings, which is where Xray itself keeps it.
		val params = HysteriaParams(
			password = endpoint.password,
			up = endpoint.up,
			down = endpoint.down,
			ports = endpoint.ports,
			hopInterval = endpoint.hopInterval.ifEmpty { hysteriaHopInterval(settings) },
			obfs = obfsMode,
			obfsPassword = obfsPassword
		)
		val streamNotes = ArrayList<String>()
		params.fromStream(streamNotes, streamSettings)
		for (note in streamNotes) warn(note)

		var port = endpoint.port
		if (port == 0 && params.ports.isNotEmpty()) {
			// Port hopping without a base port: use the low end of the range so
			// mihomo has something to dial before it starts hopping.
			firstPortOfRange(params.ports)?.let { port = it }
		}
		val name = name(preferred, outbound.xStr("tag"), "hysteria2", endpoint.address, port)
		val proxy = base(name, "hysteria2", endpoint.address, port)
		val hopping = hopPorts(params.ports)
		hopping.notes().forEach { warn(it) }
		proxy.setString("ports", hopping.joined())
		if (params.password.isEmpty()) {
			throw MihomoUnsupported(MISSING_HYSTERIA2_PASSWORD_REFUSAL)
		}
		brutalRateNotes(outbound.xObj("streamSettings")).forEach { warn(it) }
		proxy.set("password", params.password)

		when {
			params.obfs.isNotEmpty() -> {
				// The core implements salamander and gecko; a node written without the obfuscation
				// its server expects connects to nothing, so a third type is refused, not stripped.
				val type = params.obfs.lowercase()
				hysteriaObfsRefusal(type, params.obfsPassword)?.let { throw MihomoUnsupported(it) }
				if (type != "salamander" && type != "gecko") {
					throw MihomoUnsupported(
						"hysteria2 obfuscation \"${params.obfs}\" has no mihomo equivalent"
					)
				}
				proxy.set("obfs", type)
				proxy.set("obfs-password", params.obfsPassword)
				// The packet-size range is a gecko-only setting.
				if (type == "gecko") {
					proxy.setInt("obfs-min-packet-size", params.obfsMinSize)
					proxy.setInt("obfs-max-packet-size", params.obfsMaxSize)
				}
			}
			params.obfsPassword.isNotEmpty() -> {
				// A password without a type means Salamander, the only
				// obfuscator Hysteria2 shipped for a long time.
				proxy.set("obfs", "salamander")
				proxy.set("obfs-password", params.obfsPassword)
			}
		}

		for ((key, raw) in listOf("up" to params.up, "down" to params.down)) {
			val rate = coreRateString(raw, version = 2)
			if (rate == null) {
				warn("the $key rate \"$raw\" is not one Hysteria reads, so it was dropped and the " +
					"core will pace itself")
			} else {
				proxy.setString(key, rate)
			}
		}

		// mihomo hops within a range written as "low-high"; a single value is an integer of seconds,
		// never the text of one: the YAML writer quotes a numeric string to keep it a string, and
		// mihomo refuses a string where it reads an int.
		val (hop, hopNote) = dialableHopInterval(params.hopInterval)
		if (hopping.joined().isNotEmpty()) hopNote?.let { warn(it) }
		if (hop.isRange) proxy.set("hop-interval", "${hop.low}-${hop.high}")
		else hop.low.toIntOrNull()?.let { proxy.set("hop-interval", it) }
		proxy.setString("sni", tls.sni)
		if (tls.alpn.isNotEmpty()) proxy.set("alpn", toFlowSeq(tls.alpn))
		if (tls.insecure) proxy.set("skip-cert-verify", true)

		applyHysteriaTlsExtras(proxy, settings, streamSettings)
		// Hysteria2 is QUIC, so there is no TLS ClientHello for a uTLS
		// profile to shape and mihomo offers no field for one.
		quicProtocolFingerprintNote(streamTls(streamSettings))?.let { warn(it) }
		proxy.setString("bbr-profile", params.bbrProfile)
		proxy.setInt("cwnd", settings.xInt("cwnd"))
		proxy.setInt("udp-mtu", settings.xInt("udpMTU"))
		if (params.initStreamWindow > 0) proxy.set("initial-stream-receive-window", params.initStreamWindow)
		if (params.maxStreamWindow > 0) proxy.set("max-stream-receive-window", params.maxStreamWindow)
		if (params.initConnectionWindow > 0) {
			proxy.set("initial-connection-receive-window", params.initConnectionWindow)
		}
		if (params.maxConnectionWindow > 0) {
			proxy.set("max-connection-receive-window", params.maxConnectionWindow)
		}
		udpFlag(proxy)
		applyDialer(proxy, outbound)
		out.add(proxy)
	}
	return out
}

// Handles a "hysteria" outbound, which may be either version.
internal fun MihomoConversion.convertHysteria(outbound: JSONObject, preferred: String): List<YamlMap> {
	val settings = outboundSettings(outbound)
	val streamSettings = outbound.xObj("streamSettings")
	if (isHysteria2(settings, streamSettings)) return convertHysteria2(outbound, preferred)

	val (obfsMode, obfsPassword) = parsedObfsAnywhere(settings)
	val tls = hysteriaTls(settings, streamSettings)

	val out = ArrayList<YamlMap>()
	for (endpoint in hysteriaEndpoints(settings, streamSettings)) {
		val name = name(preferred, outbound.xStr("tag"), "hysteria", endpoint.address, endpoint.port)
		val proxy = base(name, "hysteria", endpoint.address, endpoint.port)
		// Hysteria v1 authenticates with a plain string.
		proxy.setString("auth-str", endpoint.password)
		// Version 1 requires both rates; mihomo refuses the node without them.
		val up = coreRateString(endpoint.up, version = 1)
		val down = coreRateString(endpoint.down, version = 1)
		if (up == null || down == null) {
			val bad = if (up == null) endpoint.up else endpoint.down
			throw MihomoUnsupported("hysteria v1 needs both up and down rates, and \"$bad\" is not a " +
				"rate Hysteria reads")
		}
		if (up.isEmpty() || down.isEmpty()) {
			throw MihomoUnsupported("hysteria v1 needs both up and down rates")
		}
		proxy.set("up", up)
		proxy.set("down", down)

		if (obfsPassword.isNotEmpty()) {
			proxy.set("obfs", obfsPassword)
		} else if (obfsMode.isNotEmpty()) {
			proxy.set("obfs", obfsMode)
		}
		proxy.setString("sni", tls.sni)
		if (tls.alpn.isNotEmpty()) proxy.set("alpn", toFlowSeq(tls.alpn))
		if (tls.insecure) proxy.set("skip-cert-verify", true)
		applyHysteriaTlsExtras(proxy, settings, streamSettings)
		quicProtocolFingerprintNote(streamTls(streamSettings))?.let { warn(it) }
		val hopping = hopPorts(endpoint.ports)
		hopping.notes().forEach { warn(it) }
		proxy.setString("ports", hopping.joined())
		udpFlag(proxy)
		applyDialer(proxy, outbound)
		out.add(proxy)
	}
	return out
}

// Handles standalone TUIC nodes.
internal fun MihomoConversion.convertTuic(outbound: JSONObject, preferred: String): List<YamlMap> {
	val settings = outbound.xObj("settings") ?: outbound
	val streamSettings = outbound.xObj("streamSettings")

	val endpoints = ArrayList<TuicEndpoint>()
	for (server in settings.xObjList("servers")) {
		endpoints.add(
			TuicEndpoint(
				address = firstNonEmpty(server.xStr("address"), server.xStr("server")),
				port = server.xInt("port"),
				uuid = server.xStr("uuid"),
				password = server.xStrRaw("password"),
				token = server.xStr("token"),
				serverEntry = server
			)
		)
	}
	if (endpoints.isEmpty()) {
		endpoints.add(
			TuicEndpoint(
				address = firstNonEmpty(settings.xStr("address"), settings.xStr("server")),
				port = if (settings.xInt("port") > 0) settings.xInt("port") else settings.xInt("server_port"),
				uuid = settings.xStr("uuid"),
				password = settings.xStrRaw("password"),
				token = settings.xStr("token")
			)
		)
	}

	val out = ArrayList<YamlMap>(endpoints.size)
	for (endpoint in endpoints) {
		val name = name(preferred, outbound.xStr("tag"), "tuic", endpoint.address, endpoint.port)
		val proxy = base(name, "tuic", endpoint.address, endpoint.port)
		val saidFrom = diagnostics.size
		quicProtocolFingerprintNote(streamTls(streamSettings))?.let { warn(it) }
		when {
			endpoint.uuid.isNotEmpty() -> {
				tuicUuidRefusal(endpoint.uuid)?.let { throw MihomoUnsupported(it) }
				proxy.set("uuid", endpoint.uuid)
				proxy.setString("password", endpoint.password)
			}
			// TUIC v4 authenticates with a token instead of a uuid/password.
			endpoint.token.isNotEmpty() -> proxy.set("token", endpoint.token)
			else -> throw MihomoUnsupported("the tuic outbound has neither a uuid nor a token")
		}

		val details = tuicTls(outbound, streamSettings)
		proxy.setString("sni", details.sni)
		if (details.alpn.isNotEmpty()) proxy.set("alpn", toFlowSeq(details.alpn))
		if (details.insecure) proxy.set("skip-cert-verify", true)
		streamTls(streamSettings)?.let { applyProxyTls(proxy, it, streamSettings, "QUIC", saidFrom) }
		proxy.setString("congestion-controller",
			tuicSetting(endpoint.serverEntry, settings, "congestion_control", "congestionController",
				"congestionControl"))
		proxy.setString("udp-relay-mode",
			tuicSetting(endpoint.serverEntry, settings, "udp_relay_mode", "udpRelayMode"))
		if (tuicFlag(endpoint.serverEntry, settings, *TUIC_ZERO_RTT_NAMES)) proxy.set("reduce-rtt", true)
		proxy.setInt("heartbeat-interval", tuicHeartbeatMs(endpoint.serverEntry, settings))
		if (tuicFlag(endpoint.serverEntry, settings, *TUIC_DISABLE_SNI_NAMES)) proxy.set("disable-sni", true)
		udpFlag(proxy)
		applyDialer(proxy, outbound)
		out.add(proxy)
	}
	return out
}
