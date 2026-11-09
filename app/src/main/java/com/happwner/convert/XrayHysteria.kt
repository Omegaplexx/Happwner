package com.happwner.convert

import com.happwner.text.firstNonEmpty
import com.happwner.text.parsePort
import com.happwner.text.splitHostPort
import org.json.JSONObject

// Readers of Hysteria, Hysteria2 and TUIC nodes as Xray-shaped configurations write them, shared by
// the three passes: where the servers, credentials, rates, obfuscation, port hopping, TLS details and
// the version are found, under every spelling.

// Gathers a Hysteria2 node's settings from wherever the config puts them. Values in the outbound's
// own settings win - a generator that filled those meant them.
internal class HysteriaParams(
	var password: String = "",
	var up: String = "",
	var down: String = "",
	var ports: String = "",
	var hopInterval: String = "",
	var obfs: String = "",
	var obfsPassword: String = "",
	var obfsMinSize: Int = 0,
	var obfsMaxSize: Int = 0,
	var bbrProfile: String = "",
	var initStreamWindow: Long = 0,
	var maxStreamWindow: Long = 0,
	var initConnectionWindow: Long = 0,
	var maxConnectionWindow: Long = 0
)

// The note for QUIC receive windows a writer has no field for, in the same words wherever they go.
internal fun HysteriaParams.windowsDroppedNote(holder: String): String? {
	val set = initStreamWindow > 0 || maxStreamWindow > 0 ||
		initConnectionWindow > 0 || maxConnectionWindow > 0
	if (!set) return null
	return "finalmask.quicParams receive windows have no field in $holder, so they were dropped"
}

// Reads the parts of a Hysteria2 node Xray keeps in streamSettings, where a natively written config
// puts the password. Drops go into notes so the sing-box converter can share this reader.
internal fun HysteriaParams.fromStream(notes: MutableList<String>, streamSettings: JSONObject?) {
	if (streamSettings == null) return

	// Port hopping as Xray 26.9.9 reads it - the udphop mask - comes first; quicParams, where Xray 26.7
	// reads it, and hysteriaSettings fill in only what the mask leaves unsaid.
	udpHopMask(streamSettings)?.let { hop ->
		if (hop.remotePorts.isNotEmpty()) {
			ports = firstNonEmpty(ports, hop.remotePorts)
			hopInterval = firstNonEmpty(hopInterval, hop.interval)
		}
		notes.addAll(hop.notes)
	}
	// Xray reads the bandwidth and QUIC window settings from finalmask alone, so these come next and
	// hysteriaSettings only fills in what they leave unsaid.
	val quicParams = streamQuicParams(streamSettings)
	if (quicParams != null) {
		up = firstNonEmpty(up, xrayBrutalRate(quicParams.xStr("brutalUp")))
		down = firstNonEmpty(down, xrayBrutalRate(quicParams.xStr("brutalDown")))
		bbrProfile = firstNonEmpty(bbrProfile, quicParams.xStr("bbrProfile"))
		val hop = quicParams.xObj("udpHop")
		if (hop != null) {
			ports = firstNonEmpty(ports, hop.xPortList("ports"))
			// The interval text as written ("30s", "5", "5-10"); each pass reads the range itself.
			hopInterval = firstNonEmpty(hopInterval, hop.xStr("interval"))
		}
		initStreamWindow = quicParams.xLong("initStreamReceiveWindow")
		maxStreamWindow = quicParams.xLong("maxStreamReceiveWindow")
		initConnectionWindow = quicParams.xLong("initConnectionReceiveWindow")
		maxConnectionWindow = quicParams.xLong("maxConnectionReceiveWindow")

		// Both cores use Brutal when a rate is given and BBR otherwise, which is what the
		// congestion field selects here, so it needs no mapping.
		val congestion = quicParams.xStr("congestion")
		when (congestion.lowercase()) {
			"", "bbr", "brutal" -> {}
			else -> notes.add(
				"quicParams.congestion \"$congestion\" has no field in either core or the link; " +
					"both cores use Brutal when a rate is set and BBR otherwise"
			)
		}
	}

	val hysteria = streamSettings.xObj("hysteriaSettings")
	if (hysteria != null) {
		password = firstNonEmpty(password, hysteria.xStrRaw("auth"))
		up = firstNonEmpty(up, xrayRate(hysteria.xStr("up")), mbpsString(hysteria.xInt("upMbps")),
			mbpsString(hysteria.xInt("up_mbps")))
		down = firstNonEmpty(down, xrayRate(hysteria.xStr("down")), mbpsString(hysteria.xInt("downMbps")),
			mbpsString(hysteria.xInt("down_mbps")))
		val hop = hysteria.xObj("udpHop")
		if (hop != null) {
			ports = firstNonEmpty(ports, hop.xPortList("ports"))
			// The interval text as written ("30s", "5", "5-10"); each pass reads the range itself.
			hopInterval = firstNonEmpty(hopInterval, hop.xStr("interval"))
		}
		if (hysteria.xInt("udpIdleTimeout") != 0) {
			notes.add(
				"hysteriaSettings.udpIdleTimeout has no field in either core or the link, so it was dropped"
			)
		}
	}

	// The Hysteria obfuscator is a finalmask UDP mask.
	val mask = streamUdpMask(streamSettings, "salamander")
	if (mask != null && obfs.isEmpty()) {
		val settings = mask.xObj("settings")
		obfsPassword = firstNonEmpty(obfsPassword, settings.xStrRaw("password"))
		val packetSize = settings.xRange("packetSize")
		if (packetSize.set && packetSize.to > 0) {
			// A packet size range selects the gecko variant of the obfuscator.
			obfs = "gecko"
			obfsMinSize = packetSize.from
			obfsMaxSize = packetSize.to
		} else {
			obfs = "salamander"
		}
	}
}

// A resolved Hysteria server.
internal class HysteriaEndpoint(
	val address: String,
	val port: Int,
	val ports: String,
	val password: String,
	val up: String,
	val down: String,
	// The hop interval named beside the ports, in whole seconds; empty when named elsewhere or not.
	val hopInterval: String
)

// The server list of a Hysteria settings object, or the flat form. A node written the way Xray takes
// it keeps its credentials, rates and port hopping in streamSettings.hysteriaSettings, which fills in
// whatever does not stand beside the address.
internal fun hysteriaEndpoints(settings: JSONObject,
	streamSettings: JSONObject?): List<HysteriaEndpoint> {
	val flatPassword = firstNonEmpty(
		settings.xStrRaw("password"), settings.xStrRaw("auth"), settings.xStrRaw("auth_str"),
			settings.xStrRaw("authStr")
	)
	val (flatUp, flatDown) = hysteriaBandwidth(settings)

	val out = ArrayList<HysteriaEndpoint>()
	for (server in settings.xObjList("servers")) {
		out.add(
			HysteriaEndpoint(
				address = firstNonEmpty(server.xStr("address"), server.xStr("server")),
				port = server.xInt("port"),
				ports = server.xStr("ports"),
				hopInterval = hysteriaHopInterval(server),
				password = firstNonEmpty(
					server.xStrRaw("password"), server.xStrRaw("auth"),
						server.xStrRaw("auth_str"), flatPassword
				),
				// up_mbps/down_mbps is what the Hysteria v1 client itself writes, so a node copied
				// out of one names its rates that way.
				up = firstNonEmpty(
					server.xStr("up"), mbpsString(server.xInt("upMbps")),
						mbpsString(server.xInt("up_mbps")), flatUp
				),
				down = firstNonEmpty(
					server.xStr("down"), mbpsString(server.xInt("downMbps")),
						mbpsString(server.xInt("down_mbps")), flatDown
				)
			)
		)
	}
	if (out.isEmpty()) {
		var address = firstNonEmpty(settings.xStr("address"), settings.xStr("server"))
		var port = settings.xInt("port")
		// A "host:port" address is common in Hysteria2-style configs.
		if (port == 0) {
			val hostPort = splitHostPort(address)
			val parsed = hostPort.port?.takeIf { it in 1..65535 }
			if (parsed != null) {
				address = hostPort.host
				port = parsed
			}
		}
		out.add(
			HysteriaEndpoint(
				address = address,
				port = port,
				ports = settings.xStr("ports"),
				password = flatPassword,
				up = flatUp,
				down = flatDown,
				hopInterval = hysteriaHopInterval(settings)
			)
		)
	}
	if (streamSettings == null) return out
	val fromStream = HysteriaParams()
	fromStream.fromStream(ArrayList(), streamSettings)
	return out.map {
		HysteriaEndpoint(
			address = it.address,
			port = it.port,
			ports = firstNonEmpty(it.ports, fromStream.ports),
			password = firstNonEmpty(it.password, fromStream.password),
			up = firstNonEmpty(it.up, fromStream.up),
			down = firstNonEmpty(it.down, fromStream.down),
			hopInterval = firstNonEmpty(it.hopInterval, fromStream.hopInterval)
		)
	}
}

// Resolves the up/down rates from any of the spellings the Hysteria clients accept.
internal fun hysteriaBandwidth(settings: JSONObject): Pair<String, String> {
	var up = settings.xStr("up")
	var down = settings.xStr("down")
	val bandwidth = settings.xObj("bandwidth")
	if (bandwidth != null) {
		up = firstNonEmpty(up, bandwidth.xStr("up"))
		down = firstNonEmpty(down, bandwidth.xStr("down"))
	}
	up = firstNonEmpty(up, mbpsString(settings.xInt("upMbps")), mbpsString(settings.xInt("up_mbps")))
	down = firstNonEmpty(down, mbpsString(settings.xInt("downMbps")), mbpsString(settings.xInt("down_mbps")))
	return up to down
}

// A whole number of decimal Mbps, as the cores that write one mean it, spelled so both readers below
// take it alike.
internal fun mbpsString(value: Int): String = if (value <= 0) "" else "${value * 1_000_000L} bps"

// Why a Hysteria2 node's obfuscation leaves it out, or null: salamander - gecko is salamander - with no
// password, which neither core loads (mihomo refuses the whole file over it) and no server runs.
internal fun hysteriaObfsRefusal(mode: String, password: String): String? {
	val type = mode.lowercase()
	if (type !in setOf("salamander", "gecko") || password.isNotEmpty()) return null
	return "hysteria2 obfuscation \"$type\" names no password, which neither core loads - mihomo refuses " +
		"the whole file over it - and no server runs, so the node never worked"
}

// The obfuscation of a hysteria node, wherever it was written: beside the protocol or beside the
// address. A node handed out without it is one the server will not answer.
internal fun parsedObfsAnywhere(settings: JSONObject): Pair<String, String> {
	val here = parsedObfs(settings)
	if (here.first.isNotEmpty() || here.second.isNotEmpty()) return here
	val server = settings.xObjList("servers").firstOrNull() ?: return here
	return parsedObfs(server)
}

// Reads the obfuscation of one object, accepting both the string form ("salamander") and the
// object form used by the Hysteria2 client.
internal fun parsedObfs(settings: JSONObject): Pair<String, String> {
	var password = firstNonEmpty(settings.xStr("obfsPassword"), settings.xStr("obfs-password"))
	val obfs = settings.xOpt("obfs") ?: return "" to password
	if (obfs is JSONObject) {
		val mode = obfs.xStr("type")
		val salamander = obfs.xObj("salamander")
		if (salamander != null && salamander.xStrRaw("password").isNotEmpty()) {
			password = salamander.xStrRaw("password")
		} else if (obfs.xStrRaw("password").isNotEmpty()) {
			password = obfs.xStrRaw("password")
		}
		return mode to password
	}
	return xScalarString(obfs).trim() to password
}

// Xray's hop interval, hopped at random within a range: the low bound in seconds, and the high
// bound when it is a range ("5-10"), each empty otherwise. mihomo hops within the range as "5-10";
// sing-box keeps the low end, since hop_interval_max came in 1.14.
internal class HopInterval(val low: String, val high: String) {
	val isRange: Boolean get() = high.isNotEmpty()
}

internal fun hopInterval(raw: String): HopInterval {
	val text = raw.trim()
	if (text.isEmpty()) return HopInterval("", "")
	durationInSeconds(text)?.let {
		// A duration of no time at all is unset, not the second a shorter one rounds up to.
		val none = text.none { digit -> digit in '1'..'9' }
		return HopInterval(if (none) "0" else it.toString(), "")
	}
	val range = Regex("^(\\d+)\\s*-\\s*(\\d+)$").find(text) ?: return HopInterval("", "")
	return HopInterval(range.groupValues[1], range.groupValues[2])
}

// The hop interval every pass writes, and the note when it differs: one under 5 seconds - which
// sing-box will not dial with and Xray refuses - hops from 5; 0, alone or as 0-0, is unset to Xray and
// the cores, and goes as 0.
internal fun dialableHopInterval(raw: String): Pair<HopInterval, String?> {
	val hop = hopInterval(raw)
	val low = hop.low.toIntOrNull()
	if (low == 0 && (hop.high.toIntOrNull() ?: 0) == 0) return HopInterval("0", "") to null
	if (low == null || low >= MIN_HOP_INTERVAL) return hop to null
	val high = hop.high.toIntOrNull()?.takeIf { it > MIN_HOP_INTERVAL }?.toString().orEmpty()
	return HopInterval(MIN_HOP_INTERVAL.toString(), high) to "the hop interval \"${raw.trim()}\" is under " +
		"$MIN_HOP_INTERVAL seconds, which sing-box will not dial with and Xray refuses; it hops from " +
		"$MIN_HOP_INTERVAL"
}

internal const val MIN_HOP_INTERVAL = 5

// The hop interval as written beside the address or in the shared settings ("30s", "5", "5-10");
// each pass reads the range from it.
internal fun hysteriaHopInterval(settings: JSONObject?): String {
	if (settings == null) return ""
	return settings.xStr("hopInterval").ifEmpty { settings.xStr("hop_interval") }
}

// A Hysteria duration ("30s", "1m", "500ms", "2h", or bare seconds) in whole seconds, rounded up so
// a sub-second interval is not zero. Anything else yields null: written as text it would be a string
// where mihomo reads an integer, which refuses the whole file.
internal fun durationInSeconds(raw: String): Int? {
	val text = raw.trim().lowercase()
	if (text.isEmpty()) return null
	if (text.all { it.isDigit() }) return text.toIntOrNull()
	val match = Regex("^(\\d+(?:\\.\\d+)?)(ms|s|m|h)$").find(text) ?: return null
	val number = match.groupValues[1].toDoubleOrNull() ?: return null
	val seconds = when (match.groupValues[2]) {
		"ms" -> number / 1000
		"s" -> number
		"m" -> number * 60
		else -> number * 3600
	}
	return maxOf(1, Math.ceil(seconds).toInt())
}

// What a hysteria node's TLS block says, gathered from the protocol's own spelling and from
// streamSettings. The pin and the ECH config are here because a share link carries them; the
// mihomo pass reads them from the same sources through applyHysteriaTlsExtras.
internal class HysteriaTls(
	val sni: String,
	val insecure: Boolean,
	val alpn: List<String>,
	val pin: String,
	val ech: String
)

// A TUIC setting, wherever the configuration put it. Generators write the tuning beside the address
// as readily as beside the protocol; what stands beside the address describes that address and wins,
// whichever spelling each is written in - reading only the root left nodes on the core's defaults.
internal fun tuicSetting(serverEntry: JSONObject?, settings: JSONObject, vararg names: String): String {
	for (name in names) {
		val beside = serverEntry?.xStr(name) ?: ""
		if (beside.isNotEmpty()) return beside
	}
	for (name in names) {
		val shared = settings.xStr(name)
		if (shared.isNotEmpty()) return shared
	}
	return ""
}

// A flag is on when either place turns it on: there is no nearer or further about it.
internal fun tuicFlag(serverEntry: JSONObject?, settings: JSONObject, vararg names: String): Boolean =
	names.any { (serverEntry?.xBool(it) ?: false) || settings.xBool(it) }

// The spellings of the three TUIC settings that mihomo, sing-box and the panels each name their own
// way: 0-RTT, the heartbeat, and disabling SNI.
internal val TUIC_ZERO_RTT_NAMES =
	arrayOf("reduce_rtt", "reduceRtt", "zero_rtt_handshake", "zeroRttHandshake", "zeroRTTHandshake")
internal val TUIC_DISABLE_SNI_NAMES = arrayOf("disable_sni", "disableSni", "disableSNI")

// The heartbeat in milliseconds: heartbeat_interval is written as milliseconds, "heartbeat" as a
// duration ("10s"); 0 when neither is named.
internal fun tuicHeartbeatMs(serverEntry: JSONObject?, settings: JSONObject): Int {
	val milliseconds = tuicNumber(serverEntry, settings, "heartbeat_interval")
	if (milliseconds > 0) return milliseconds
	for (name in arrayOf("heartbeatInterval", "heartbeat")) {
		val text = tuicSetting(serverEntry, settings, name)
		if (text.isEmpty()) continue
		val seconds = durationInSeconds(text)
		if (seconds != null) return seconds * 1000
		text.toIntOrNull()?.let { if (it > 0) return it }
	}
	return 0
}

internal fun tuicNumber(serverEntry: JSONObject?, settings: JSONObject, name: String): Int {
	val beside = serverEntry?.xInt(name) ?: 0
	return if (beside != 0) beside else settings.xInt(name)
}

// Resolves the TLS parameters, which may live in the settings object or in streamSettings depending
// on which tool wrote the config.
internal fun hysteriaTls(settings: JSONObject, streamSettings: JSONObject?): HysteriaTls {
	var sni = ""
	var insecure = false
	var alpn: List<String> = emptyList()
	var pin = ""
	var ech = ""

	val tls = settings.xObj("tls")
	if (tls != null) {
		sni = firstNonEmpty(tls.xStr("sni"), tls.xStr("serverName"), tls.xStr("server_name"))
		insecure = tls.xBool("insecure")
		alpn = tls.xStrList("alpn")
		pin = tls.xStrOf("pinSHA256", "pinnedPeerCertSha256")
		ech = tls.xStr("ech")
	}
	sni = firstNonEmpty(sni, settings.xStr("sni"))
	if (settings.xBool("insecure")) insecure = true
	if (alpn.isEmpty()) alpn = settings.xStrList("alpn")

	val tlsSettings = streamTls(streamSettings)
	if (tlsSettings != null) {
		sni = firstNonEmpty(sni, tlsSettings.xStr("serverName"))
		if (tlsSettings.xBool("allowInsecure")) insecure = true
		if (alpn.isEmpty()) alpn = tlsSettings.xStrList("alpn")
		pin = firstNonEmpty(pin, tlsSettings.xStr("pinnedPeerCertSha256"))
		ech = firstNonEmpty(ech, tlsSettings.xStr("echConfigList"))
	}
	return HysteriaTls(sni, insecure, alpn, pin, ech)
}

// A TUIC node's TLS, as every pass reads it: beside its settings, and in the tls block a node copied out of
// a sing-box configuration keeps beside the protocol - settings or not, filling in what they leave out.
internal fun tuicTls(outbound: JSONObject, streamSettings: JSONObject?): HysteriaTls {
	val settings = outbound.xObj("settings") ?: return hysteriaTls(outbound, streamSettings)
	val written = hysteriaTls(settings, streamSettings)
	if (outbound.xObj("tls") == null) return written
	val beside = hysteriaTls(outbound, null)
	return HysteriaTls(
		firstNonEmpty(written.sni, beside.sni), written.insecure || beside.insecure,
		written.alpn.ifEmpty { beside.alpn }, firstNonEmpty(written.pin, beside.pin),
		firstNonEmpty(written.ech, beside.ech)
	)
}

// A "443-8443,9000" hop list as a core can dial it: each part a port or a range within 1-65535, low to
// high, with a colon read as the dash, as sing-box writes it; the parts no core dials, and the ones
// read past a colon Xray refuses, kept apart for every pass to name.
internal class HopPorts(val ranges: List<IntRange>, val dropped: List<String>, val colons: List<String>) {
	// The ranges as mihomo and a link spell them: "20000-30000,443".
	fun joined(): String =
		ranges.joinToString(",") { if (it.first == it.last) "${it.first}" else "${it.first}-${it.last}" }

	// The notes on how the list was read, worded alike in every pass.
	fun notes(): List<String> = listOfNotNull(
		dropped.takeIf { it.isNotEmpty() }?.let {
			"port hopping \"${it.joinToString(",")}\" names no port range a core can dial " +
				"(1-65535, low to high), so it was dropped"
		},
		colons.takeIf { it.isNotEmpty() }?.let {
			"port hopping \"${it.joinToString(",")}\" is written with a colon, which Xray 26 refuses; " +
				"it was read as a dash, as sing-box writes it"
		}
	)
}

internal fun hopPorts(ports: String): HopPorts {
	val ranges = ArrayList<IntRange>()
	val dropped = ArrayList<String>()
	val colons = ArrayList<String>()
	for (raw in ports.split(',')) {
		val part = raw.trim()
		if (part.isEmpty()) continue
		val bounds = part.split('-', ':')
		val low = parsePort(bounds.first())
		val high = parsePort(bounds.last())
		if (bounds.size <= 2 && low != null && high != null && low <= high) {
			ranges.add(low..high)
			if (':' in part) colons.add(part)
		} else {
			dropped.add(part)
		}
	}
	return HopPorts(ranges, dropped, colons)
}

// The first port of the first range hopPorts keeps, for a node that names its server port only there.
internal fun firstPortOfRange(ports: String): Int? = hopPorts(ports).ranges.firstOrNull()?.first

// Which version a "hysteria" outbound is. A stated version decides, the outbound's own settings
// first, then the transport's: v1 and v2 are different protocols, and reading one as the other
// cannot connect. With none stated, a transport named "hysteria" is the current version.
internal fun isHysteria2(settings: JSONObject, streamSettings: JSONObject?): Boolean {
	val stated = if (settings.xInt("version") != 0) settings.xInt("version")
	else streamSettings.xObj("hysteriaSettings").xInt("version")
	if (stated != 0) return stated == 2
	return streamSettings != null && streamNetwork(streamSettings) == "hysteria"
}

internal class TuicEndpoint(
	val address: String,
	val port: Int,
	val uuid: String,
	val password: String,
	val token: String,
	// The server entry this address came from. A TUIC node's tuning is written beside the address
	// as often as beside the protocol, and tuicSetting reads it from here first.
	val serverEntry: JSONObject? = null
)

// A rate in whole Mbps, for the fields that take a number of Mbps and nothing else; null when the
// text is not a rate. Version 2 takes the nearest whole Mbps, and null below half of one.
internal fun mbpsNumber(raw: String, version: Int = 2): Int? {
	val bps = bitsPerSecond(raw, version) ?: return null
	if (bps <= 0) return null
	if (version == 1) return if (bps % 1_000_000L == 0L) (bps / 1_000_000L).toInt() else null
	val nearest = (bps + 500_000L) / 1_000_000L
	return if (nearest > 0) nearest.toInt() else null
}

// Bits per second as the Hysteria clients read a rate: an integer, an optional space, a unit. V2
// takes b/k/m/g/t alone or with "b"/"bps" in any case, all bits; v1 tells bits from bytes by the
// case of the b ("MBps" is bytes there). A bare number is megabits, as mihomo reads it.
internal fun bitsPerSecond(raw: String, version: Int = 2): Long? {
	val text = raw.trim()
	if (text.isEmpty()) return null
	val digits = text.takeWhile { it in '0'..'9' }
	if (digits.isEmpty()) return null
	val number = digits.toLongOrNull() ?: return null
	val unit = text.drop(digits.length).trim()
	val scale = when (unit.lowercase()) {
		"" -> return number * 1_000_000L
		"b", "bps" -> 1L
		"k", "kb", "kbps" -> 1_000L
		"m", "mb", "mbps" -> 1_000_000L
		"g", "gb", "gbps" -> 1_000_000_000L
		"t", "tb", "tbps" -> 1_000_000_000_000L
		else -> return null
	}
	val bytes = version == 1 && unit.contains('B')
	return number * scale * (if (bytes) 8L else 1L)
}

// Bits per second as Xray reads a rate it owns: a number, a fraction too, then b, k, m, g or t in
// any case, alone or with "b"/"bps", each 1024 times the last - a bare number is bits. Null when
// Xray refuses it.
internal fun xrayBitsPerSecond(raw: String): Long? {
	val lower = raw.trim().lowercase()
	if (lower.isEmpty()) return null
	val firstUnit = lower.indexOfFirst { (it < '0' || it > '9') && it != '.' }
	val cut = if (firstUnit < 0) lower.length else firstUnit
	val number = lower.substring(0, cut).toDoubleOrNull() ?: return null
	val scale = when (lower.substring(cut).trim()) {
		"", "b", "bps" -> 1L
		"k", "kb", "kbps" -> 1L shl 10
		"m", "mb", "mbps" -> 1L shl 20
		"g", "gb", "gbps" -> 1L shl 30
		"t", "tb", "tbps" -> 1L shl 40
		else -> return null
	}
	return (number * scale).toLong()
}

// A rate Xray owns, in the one spelling every reader below takes alike - or as written when Xray
// cannot read it either, for the reader to name.
private fun xrayRate(raw: String): String {
	val bits = xrayBitsPerSecond(raw) ?: return raw
	return if (bits <= 0) "" else "$bits bps"
}

// A brutal rate Xray takes, in the spelling every reader below takes alike; none where Xray would
// refuse the configuration over it (brutalRateNotes) or reads no rate at all.
private fun xrayBrutalRate(raw: String): String {
	val bits = xrayBitsPerSecond(raw) ?: return ""
	return if (bits / 8 < 65536) "" else "$bits bps"
}

// Xray refuses a whole configuration over a brutal rate it cannot read ("unsupported unit") or one
// under 65536 bytes a second; the cores connect without it, at a pace of their own, and say so.
internal fun brutalRateNotes(streamSettings: JSONObject?): List<String> {
	val quicParams = streamQuicParams(streamSettings) ?: return emptyList()
	val notes = ArrayList<String>()
	for (field in listOf("brutalUp", "brutalDown")) {
		val raw = quicParams.xStr(field)
		val bits = xrayBitsPerSecond(raw)
		if (raw.isEmpty() || bits == 0L || xrayBrutalRate(raw).isNotEmpty()) continue
		val why = if (bits == null) {
			"is not a rate Xray reads"
		} else {
			"is under the 65536 bytes a second Xray asks of it"
		}
		notes.add(
			"finalmask.quicParams.$field \"$raw\" $why - Xray refuses the configuration over it - so it " +
				"was dropped and the core paces itself"
		)
	}
	return notes
}

// The rate spelling every core reads: an integer, one space at most, a K/M/G/T prefix and "bps",
// the "b" in the case that says bits or bytes. Version 2 reads that "B" as bits, so its bytes
// spellings are not kept.
private val CORE_RATE = Regex("""^\d+ ?[KMGT]?[Bb]ps$""")

// A rate as the cores read one, null when it is not a rate. Version 1 keeps a spelling they read
// already; version 2 is re-spelled from Xray's reading, exact, in the decimal units they read -
// "512 Kbps", or bps under a whole Kbps - and none at all for a rate of nothing.
internal fun coreRateString(raw: String, version: Int): String? {
	val text = raw.trim()
	if (text.isEmpty()) return ""
	if (version == 1 && CORE_RATE.matches(text)) return text
	val bps = bitsPerSecond(text, version) ?: return null
	if (bps <= 0) return ""
	val units = listOf(
		1_000_000_000_000L to "Tbps", 1_000_000_000L to "Gbps", 1_000_000L to "Mbps", 1_000L to "Kbps"
	)
	for ((scale, name) in units) if (bps % scale == 0L) return "${bps / scale} $name"
	return "$bps bps"
}

// The refusal for a TUIC uuid that is not one: sing-box refuses the whole document over it
// ("invalid uuid"), and the server would not know the client anyway. Null when it is a UUID.
internal fun tuicUuidRefusal(uuid: String): String? =
	if (uuid.isEmpty() || isUsableUuid(uuid)) null
	else "the tuic uuid \"$uuid\" is not shaped like a UUID; sing-box refuses the whole document " +
		"over it, and the server would not know the client, so the node was dropped"
