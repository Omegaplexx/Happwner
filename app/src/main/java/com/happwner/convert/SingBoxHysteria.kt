package com.happwner.convert

import com.happwner.text.firstNonEmpty
import org.json.JSONArray
import org.json.JSONObject

// Hysteria2, Hysteria v1 and TUIC as sing-box outbounds, which panels write in Xray-shaped configs.
// TLS is never optional for any of the three: the core answers "TLS required".
internal object SingBoxHysteria {

	// What the core accepts; anything else refuses the whole document.
	private val TUIC_CONGESTION = setOf("cubic", "new_reno", "bbr")
	private val TUIC_RELAY_MODES = setOf("native", "quic")

	// Port hopping: sing-box takes "start:end" ranges where Xray writes "443-8443,9000". A range
	// of seconds ("5-10") keeps its low end - hop_interval_max came in sing-box 1.14, and the 1.12
	// and 1.13 cores refuse the whole document over a field they do not know.
	private fun applyPortHopping(
		outbound: JSONObject, ports: String, intervalText: String, notes: MutableList<String>
	) {
		notes.addAll(hopPorts(ports).notes())
		val hopRanges = portHopRanges(ports)
		if (hopRanges.isEmpty()) return
		outbound.put("server_ports", JSONArray(hopRanges))
		val (hop, hopNote) = dialableHopInterval(intervalText)
		hopNote?.let { notes.add(it) }
		val low = SingBoxUtil.toDuration(hop.low) ?: return
		outbound.put("hop_interval", low)
		if (hop.isRange) {
			notes.add(
				"the hop interval range \"$intervalText\" needs sing-box 1.14, which the 1.12 and " +
					"1.13 cores refuse the document over; it hops every $low instead"
			)
		}
	}

	// Converts a hysteria2 outbound, or a hysteria one that turns out to be v2.
	internal fun convertHysteria2(xrayOutbound: JSONObject, notes: MutableList<String>): JSONObject? {
		val settings = xrayOutbound.xObj("settings") ?: JSONObject()
		val streamSettings = xrayOutbound.xObj("streamSettings")

		// One endpoint: the converter splits an outbound naming several before it reaches here.
		val endpoint = hysteriaEndpoints(settings, streamSettings).firstOrNull() ?: return null

		val params = HysteriaParams(
			obfs = parsedObfsAnywhere(settings).first,
			obfsPassword = parsedObfsAnywhere(settings).second,
			hopInterval = endpoint.hopInterval.ifEmpty { hysteriaHopInterval(settings) }
		)
		params.fromStream(notes, streamSettings)
		params.windowsDroppedNote("sing-box")?.let { notes.add(it) }

		var port = endpoint.port
		val ports = firstNonEmpty(endpoint.ports, params.ports)
		if (port == 0) firstPortOfRange(ports)?.let { port = it }
		// Left out with the reason, the way the mihomo pass and the link builder leave it out: a
		// node dropped in silence looks like a node that was never there.
		if (!LinkParams.usableHost(endpoint.address) || port !in 1..65535) {
			notes.add(unusableServerRefusal("hysteria2", endpoint.address, port))
			return null
		}
		// Hysteria2 authenticates by password alone; without one the node connects to nothing.
		val password = firstNonEmpty(endpoint.password, params.password)
		if (password.isEmpty()) {
			notes.add(MISSING_HYSTERIA2_PASSWORD_REFUSAL)
			return null
		}
		notes.addAll(brutalRateNotes(streamSettings))

		val outbound = JSONObject()
		outbound.put("type", "hysteria2")
		outbound.put("server", endpoint.address)
		outbound.put("server_port", port)

		applyPortHopping(outbound, ports, params.hopInterval, notes)

		outbound.put("password", password)

		// The core takes plain integers in Mbps; the source may spell them "100 Mbps", "100", or
		// leave them out entirely.
		for ((key, raw) in listOf(
			"up_mbps" to firstNonEmpty(endpoint.up, params.up),
			"down_mbps" to firstNonEmpty(endpoint.down, params.down)
		)) {
			if (raw.isBlank()) continue
			// Named by direction, as the mihomo pass names it: the two rates are often the same.
			val direction = key.substringBefore('_')
			val bits = bitsPerSecond(raw)
			if (bits == null) {
				notes.add(
					"the $direction rate \"$raw\" is not one Hysteria reads, so it was dropped and " +
						"the core will pace itself"
				)
				continue
			}
			// None at all is no rate, for Xray as for the core.
			if (bits <= 0L) continue
			val mbps = mbpsNumber(raw)
			if (mbps == null) {
				notes.add(
					"the $direction rate \"$raw\" is under half a Mbps, and hysteria2 takes whole Mbps " +
						"here, so it was dropped and the core will pace itself"
				)
				continue
			}
			outbound.put(key, mbps)
			if (bits % 1_000_000L != 0L) {
				notes.add(
					"the $direction rate \"$raw\" is $bits bits a second, and hysteria2 " +
						"takes whole Mbps here, so $mbps stands in"
				)
			}
		}

		val obfsMode = params.obfs.lowercase()
		if (obfsMode.isNotEmpty()) {
			hysteriaObfsRefusal(obfsMode, params.obfsPassword)?.let {
				notes.add(it)
				return null
			}
			// A node the server would not answer without its obfuscation is refused, not stripped:
			// a third type has no sing-box form, and gecko came in 1.14, which the 1.12 and 1.13
			// cores refuse the whole document over.
			if (obfsMode == "gecko") {
				notes.add(
					"hysteria2 obfuscation \"gecko\" needs sing-box 1.14, and the 1.12 and 1.13 " +
						"cores refuse the whole document over it"
				)
				return null
			}
			if (obfsMode != "salamander") {
				notes.add(
					"hysteria2 obfuscation \"${params.obfs}\" has no sing-box equivalent"
				)
				return null
			}
			val obfsBlock = JSONObject()
			obfsBlock.put("type", obfsMode)
			obfsBlock.put("password", params.obfsPassword)
			outbound.put("obfs", obfsBlock)
		}

		outbound.put("tls", hysteriaTlsBlock(hysteriaTls(settings, streamSettings), streamSettings,
			endpoint.address, notes))
		return outbound
	}

	// Converts a Hysteria v1 outbound.
	internal fun convertHysteria(xrayOutbound: JSONObject, notes: MutableList<String>): JSONObject? {
		val settings = xrayOutbound.xObj("settings") ?: JSONObject()
		val streamSettings = xrayOutbound.xObj("streamSettings")

		// One endpoint: the converter splits an outbound naming several before it reaches here.
		val endpoint = hysteriaEndpoints(settings, streamSettings).firstOrNull() ?: return null
		if (!LinkParams.usableHost(endpoint.address) || endpoint.port !in 1..65535) {
			notes.add(unusableServerRefusal("hysteria", endpoint.address, endpoint.port))
			return null
		}

		val outbound = JSONObject()
		outbound.put("type", "hysteria")
		outbound.put("server", endpoint.address)
		outbound.put("server_port", endpoint.port)

		// auth_str rather than auth, which sing-box reads as base64.
		if (endpoint.password.isNotEmpty()) outbound.put("auth_str", endpoint.password)

		// The core takes the rate either as a number of Mbps or as a string with a unit, and its
		// unit table is wider than Mbps alone.
		val upOk = putRate(outbound, "up", "up_mbps", endpoint.up)
		val downOk = putRate(outbound, "down", "down_mbps", endpoint.down)
		if (!upOk || !downOk) {
			// Both rates are mandatory in version 1; the core answers a missing
			// one with "missing upload speed" and refuses the outbound.
			val bad = listOf(endpoint.up, endpoint.down).firstOrNull { it.isNotBlank() && v1Rate(it) == null }
			notes.add(
				if (bad == null) "hysteria v1 needs both up and down rates"
				else "hysteria v1 needs both up and down rates, and \"$bad\" is not one sing-box reads"
			)
			return null
		}

		// Port hopping is a version 1 feature too.
		applyPortHopping(outbound, endpoint.ports,
			endpoint.hopInterval.ifEmpty { hysteriaHopInterval(settings) }, notes)

		val (obfsMode, obfsPassword) = parsedObfsAnywhere(settings)
		// Version 1's obfuscator is a plain string, unlike version 2's object.
		val obfs = firstNonEmpty(obfsPassword, obfsMode)
		if (obfs.isNotEmpty()) outbound.put("obfs", obfs)

		outbound.put("tls", hysteriaTlsBlock(hysteriaTls(settings, streamSettings), streamSettings,
			endpoint.address, notes))
		return outbound
	}

	internal fun convertTuic(xrayOutbound: JSONObject, notes: MutableList<String>): JSONObject? {
		// A node copied out of a sing-box configuration keeps all of it beside the protocol, as mihomo
		// and the links read it.
		val settings = xrayOutbound.xObj("settings") ?: xrayOutbound
		val streamSettings = xrayOutbound.xObj("streamSettings")

		val servers = settings.xObjList("servers")
		val src = servers.firstOrNull() ?: settings
		if (servers.size > 1) {
			notes.add(
				"the outbound lists ${servers.size} servers and a sing-box outbound holds one, " +
					"so the first was used"
			)
		}

		val address = firstNonEmpty(src.xStr("address"), src.xStr("server"))
		val listed = servers.isNotEmpty()
		val port = if (listed || src.xInt("port") > 0) src.xInt("port") else src.xInt("server_port")
		if (!LinkParams.usableHost(address) || port !in 1..65535) {
			notes.add(unusableServerRefusal("tuic", address, port))
			return null
		}

		val uuid = firstNonEmpty(src.xStr("uuid"), settings.xStr("uuid"))
		tuicUuidRefusal(uuid)?.let { notes.add(it); return null }
		if (uuid.isEmpty()) {
			// sing-box implements TUIC v5 only, which is uuid plus password.
			notes.add("sing-box implements TUIC v5, which needs a uuid; this outbound has none")
			return null
		}

		val outbound = JSONObject()
		outbound.put("type", "tuic")
		outbound.put("server", address)
		outbound.put("server_port", port)
		outbound.put("uuid", uuid)
		val password = firstNonEmpty(src.xStrRaw("password"), settings.xStrRaw("password"))
		if (password.isNotEmpty()) outbound.put("password", password)

		// The core refuses the whole document over a value it does not know, so an unfamiliar name is
		// dropped here. Read beside the address as well as beside the protocol, like the password.
		val congestion = tuicSetting(
			src, settings, "congestion_control", "congestionController", "congestionControl"
		)
		if (congestion.isNotEmpty()) {
			if (congestion in TUIC_CONGESTION) outbound.put("congestion_control", congestion)
			else notes.add(
				"congestion control \"$congestion\" is not one sing-box implements and was dropped")
		}
		val relay = tuicSetting(src, settings, "udp_relay_mode", "udpRelayMode")
		if (relay.isNotEmpty()) {
			if (relay in TUIC_RELAY_MODES) outbound.put("udp_relay_mode", relay)
			else notes.add("udp relay mode \"$relay\" is not one sing-box implements and was dropped")
		}
		if (tuicFlag(src, settings, *TUIC_ZERO_RTT_NAMES)) {
			outbound.put("zero_rtt_handshake", true)
		}
		// heartbeat_interval is in MILLISECONDS - that is what the clients and mihomo's own
		// documentation say, and 10000 is the value they suggest.
		val heartbeatMs = tuicHeartbeatMs(src, settings)
		if (heartbeatMs > 0) outbound.put("heartbeat", "${heartbeatMs}ms")

		val tls = hysteriaTlsBlock(tuicTls(xrayOutbound, streamSettings), streamSettings, address, notes)
		if (tuicFlag(src, settings, *TUIC_DISABLE_SNI_NAMES)) tls.put("disable_sni", true)
		outbound.put("tls", tls)
		return outbound
	}

	// The TLS block these three always carry - not conditional, since the core answers a missing
	// one with "TLS required" and rejects the whole document.
	private fun hysteriaTlsBlock(
		tlsDetails: HysteriaTls, streamSettings: JSONObject?, address: String, notes: MutableList<String>
	): JSONObject {
		val tls = JSONObject()
		tls.put("enabled", true)
		if (tlsDetails.sni.isNotEmpty()) tls.put("server_name", tlsDetails.sni)
		if (tlsDetails.insecure) tls.put("insecure", true)
		if (tlsDetails.alpn.isNotEmpty()) tls.put("alpn", JSONArray(tlsDetails.alpn))
		val tlsSettings = streamTls(streamSettings)
		tlsSettings?.let { SingBoxStream.applyCertificates(it, tls, notes) }
		SingBoxStream.applyVerifyName(tlsSettings, tls, tlsDetails.sni, address, tlsDetails.insecure, notes)
		// No field takes the hash here either, and one written where nothing reads it would pin nothing.
		if (tlsDetails.pin.isNotEmpty()) notes.add(SingBoxStream.UNPINNED_NOTE)
		quicProtocolFingerprintNote(tlsSettings)?.let { notes.add(it) }
		return tls
	}

	// Turns a "443-8443,9000" port list into the "443:8443" ranges sing-box takes, the parts a core can
	// dial alone (hopPorts). A single port stays a single port, spelled as a one-wide range.
	internal fun portHopRanges(ports: String): List<String> =
		hopPorts(ports).ranges.map { "${it.first}:${it.last}" }

	// Writes a rate under whichever of the two names fits it, and reports whether anything was
	// written at all.
	private fun putRate(outbound: JSONObject, stringKey: String, numberKey: String, raw: String): Boolean {
		if (raw.isBlank()) return false
		mbpsNumber(raw, version = 1)?.let { outbound.put(numberKey, it); return true }
		outbound.put(stringKey, v1Rate(raw) ?: return false)
		return true
	}

	// A version 1 rate in the core's string form, or null: its unit table is case-sensitive and has
	// no bare bps, and "100 mbps" as written would take the whole document down.
	private fun v1Rate(raw: String): String? =
		coreRateString(raw, version = 1)?.takeUnless { it.endsWith(" bps") }
}
