package com.happwner.convert

import com.happwner.text.canonicalIp
import com.happwner.text.decodeBase64RawUrl
import com.happwner.text.firstNonEmpty
import com.happwner.text.parseInet4
import com.happwner.text.parseInet6
import java.math.BigInteger
import org.json.JSONArray
import org.json.JSONObject

// Readers of an Xray outbound's streamSettings, shared by the three passes: ranges, header maps,
// the transport and security names under every spelling, and the finalmask features. "s" is an
// outbound's settings object and "ss" its streamSettings - the pair Xray itself names.

// Xray's Int32Range: a plain number or a "from-to" string. Mihomo takes the same information as a
// string, so render gives it back in that form.
internal data class XRange(val from: Int, val to: Int, val set: Boolean) {
	// A bare number when both ends match, "from-to" otherwise, "" when unset.
	fun render(): String = when {
		!set -> ""
		from == to -> from.toString()
		else -> "$from-$to"
	}

	// Renders the range, treating an all-zero one as unset.
	fun renderNonZero(): String = if (!set || (from == 0 && to == 0)) "" else render()

	companion object {
		val UNSET = XRange(0, 0, false)
	}
}

internal fun JSONObject?.xRange(key: String): XRange {
	val raw = this.xOpt(key) ?: return XRange.UNSET
	if (raw is Number) {
		val number = raw.toInt()
		return XRange(number, number, true)
	}
	val text = xScalarString(raw).trim().trim('"')
	if (text.isEmpty()) return XRange.UNSET
	return parseRangeString(text) ?: XRange.UNSET
}

// Handles "114", "114-514" and negative bounds such as "-114-514".
internal fun parseRangeString(text: String): XRange? {
	text.toIntOrNull()?.let { return XRange(it, it, true) }
	val parts = splitFromSecondDash(text) ?: return null
	val from = parts.first.trim().toIntOrNull() ?: return null
	val to = parts.second.trim().toIntOrNull() ?: return null
	return if (from > to) XRange(to, from, true) else XRange(from, to, true)
}

// Splits "-114-514" into "-114" and "514", so a negative bound survives.
private fun splitFromSecondDash(text: String): Pair<String, String>? {
	val parts = text.split("-", limit = 3)
	return when (parts.size) {
		2 -> parts[0] to parts[1]
		3 -> if (parts[0].isEmpty()) ("-" + parts[1]) to parts[2] else parts[0] to (parts[1] + "-" + parts[2])
		else -> null
	}
}

// Reads Xray's port list in any of its spellings: a number, a "1000-2000" range, a comma-separated
// list, or a JSON array of those. The textual form is what mihomo's "ports" takes.
internal fun JSONObject?.xPortList(key: String): String {
	val raw = this.xOpt(key) ?: return ""
	if (raw is JSONArray) {
		val parts = ArrayList<String>(raw.length())
		for (i in 0 until raw.length()) {
			val item = xScalarString(if (raw.opt(i) === JSONObject.NULL) null else raw.opt(i)).trim()
			if (item.isNotEmpty()) parts.add(item)
		}
		return parts.joinToString(",")
	}
	return xScalarString(raw).trim()
}

// Reads a string map, as transport headers use.
internal fun JSONObject?.xHeaders(key: String): Map<String, String> {
	val headers = this.xObj(key) ?: return emptyMap()
	val out = LinkedHashMap<String, String>()
	for (name in headers.keys()) {
		out[name] = xScalarString(headers.xOpt(name)).trim()
	}
	return out
}

// Reads a header map whose values may be lists, as the raw HTTP masquerade uses.
internal fun JSONObject?.xHeaderLists(key: String): Map<String, List<String>> {
	val headers = this.xObj(key) ?: return emptyMap()
	val out = LinkedHashMap<String, List<String>>()
	for (name in headers.keys()) {
		out[name] = headers.xStrList(name)
	}
	return out
}

// A VLESS flow as the cores name it: "none" is no flow, and the "-udp443" variant is the same flow
// letting UDP 443 through where plain Vision blocks it - a difference neither core makes.
internal fun normalizeFlow(raw: String?): String {
	val flow = raw?.trim().orEmpty()
	if (flow.isEmpty() || flow == "none") return ""
	return flow.removeSuffix("-udp443")
}

// Why a VLESS flow keeps the node from connecting, or null. Xray runs a flow over the connection it
// dials: with VLESS encryption on, over any transport; with none, only where that connection is TLS
// or REALITY itself. Under a wrapping transport Xray refuses the config, so the node never worked.
internal fun vlessFlowRefusal(flow: String, encryption: String, streamSettings: JSONObject?): String? {
	val normalized = normalizeFlow(flow)
	if (normalized.isEmpty()) return null
	// Xray 1.8 kept Vision alone and refuses a configuration naming an older XTLS flow.
	if (normalized != "xtls-rprx-vision") {
		return "vless flow \"$flow\" is gone from Xray, which takes only xtls-rprx-vision since 1.8, " +
			"so the node never worked"
	}
	if (encryption.isNotEmpty() && encryption != "none") return null
	if (streamSecurity(streamSettings) !in setOf("tls", "reality")) {
		return "a VLESS flow needs TLS or REALITY under it; Xray refuses this configuration, so " +
			"the node never worked"
	}
	val net = streamNetwork(streamSettings)
	val headerType = streamTcp(streamSettings).xObj("header").xStr("type").lowercase()
	val bare = net == "kcp" || (net == "tcp" && (headerType.isEmpty() || headerType == "none"))
	if (bare) return null
	val under = if (net == "tcp") "raw with an HTTP masquerade" else net
	return "a VLESS flow runs only over a bare TLS or REALITY connection (raw or mKCP), and Xray " +
		"refuses it under $under, so the node never worked"
}

// Why Xray refuses a client's VLESS encryption, or null for "none" and a well-formed one:
// mlkem768x25519plus, a mode, 1rtt or 0rtt, then paddings and keys, read as Xray reads them.
internal fun vlessEncryptionRefusal(raw: String): String? {
	val enc = raw.trim()
	if (enc.isEmpty() || enc == "none") return null
	val fault = vlessEncryptionFault(enc) ?: return null
	return "vless encryption \"${shortToken(enc, 48)}\" $fault; Xray refuses it, so the node never worked"
}

private fun vlessEncryptionFault(enc: String): String? {
	val parts = enc.split(".")
	if (parts.size < 4 || parts[0] != "mlkem768x25519plus") {
		return "names no algorithm Xray has (it takes mlkem768x25519plus)"
	}
	if (parts[1] !in setOf("native", "xorpub", "random")) {
		return "has the mode \"${parts[1]}\" where Xray takes native, xorpub or random"
	}
	if (parts[2] !in setOf("1rtt", "0rtt")) {
		return "has \"${parts[2]}\" where a client takes 1rtt or 0rtt (\"600s\" belongs to the server)"
	}
	// Paddings and keys are told apart by length, as the cores tell them; Xray then cuts the paddings'
	// length from the front, so a padding written after a key takes part of that key instead.
	var keys = 0
	var paddingLength = 0
	val rest = parts.subList(3, parts.size)
	for (token in rest) {
		if (token.length < 20) {
			paddingLength += token.length + 1
			continue
		}
		val decoded = decodeBase64RawUrl(token)
			?: return "has a key \"${shortToken(token)}\" that is not raw URL-safe base64"
		// 32 bytes is an X25519 public key, 1184 an ML-KEM-768 encapsulation key.
		if (decoded.size != 32 && decoded.size != 1184) {
			return "has a key \"${shortToken(token)}\" of ${decoded.size} bytes where Xray takes 32 or 1184"
		}
		if (decoded.size == 1184 && !isMlKemKey(decoded)) {
			return "has a key \"${shortToken(token)}\" that is no ML-KEM-768 key: a coefficient reaches 3329"
		}
		keys++
	}
	if (keys == 0) return "carries no server key"
	if (paddingLength == 0) return null
	return vlessPaddingFault(rest.joinToString(".").substring(0, paddingLength - 1))
}

// The paddings as Xray's ParsePadding reads them: "a-b-c" each, the numbers as Go's Atoi reads
// them, the first at least 100-35-35, and every other one from the first a length, within 65553.
private fun vlessPaddingFault(padding: String): String? {
	if (padding.isEmpty()) return null
	var total = 0L
	for ((index, token) in padding.split(".").withIndex()) {
		val values = token.split("-").take(3).mapNotNull(::goAtoi)
		if (values.size < 3) return "has a padding \"$token\" that is not three numbers a-b-c"
		val (chance, low, high) = values
		if (index == 0 && (chance < 100 || low < 35 || high < 35)) {
			return "has a first padding \"$token\" below the 100-35-35 it must reach"
		}
		if (index % 2 == 0) total += maxOf(low, high)
	}
	return if (total > 18 + 65535) "has paddings longer than the 65553 bytes allowed together" else null
}

// Whether 1184 bytes are an ML-KEM-768 key as Go's crypto/mlkem reads one: three polynomials of
// 12-bit coefficients, two in every three bytes, each below the modulus 3329; then a 32-byte seed.
private fun isMlKemKey(key: ByteArray): Boolean {
	for (offset in 0 until 1152 step 3) {
		val word = (key[offset].toInt() and 0xFF) or ((key[offset + 1].toInt() and 0xFF) shl 8) or
			((key[offset + 2].toInt() and 0xFF) shl 16)
		if ((word and 0xFFF) >= 3329 || (word ushr 12) >= 3329) return false
	}
	return true
}

// A number as Go's strconv.Atoi reads one: a sign at most, then ASCII digits only, within 64 bits.
private fun goAtoi(text: String): Long? {
	val digits = if (text.startsWith("+") || text.startsWith("-")) text.substring(1) else text
	if (digits.isEmpty() || digits.any { it !in '0'..'9' }) return null
	return text.toLongOrNull()
}

private fun shortToken(token: String, keep: Int = 16): String =
	if (token.length <= keep) token else token.take(keep) + "..."

// A Shadowsocks method under the name every core and link reads: Xray reads the name in any case,
// takes the IETF ciphers by their short names too, and "plain" for none.
internal fun canonicalSsMethod(method: String): String = when (val name = method.trim().lowercase()) {
	"chacha20-poly1305" -> "chacha20-ietf-poly1305"
	"xchacha20-poly1305" -> "xchacha20-ietf-poly1305"
	"plain" -> "none"
	else -> name
}

// The reason a Shadowsocks method no core implements is left out, or null: Xray refuses one too,
// so the node never worked, and every pass says so in these words.
internal fun unknownSsMethodRefusal(method: String): String? =
	if (method.isEmpty() || method in SingBoxProtocols.SS_METHODS_OK || ssCipher(method).isNotEmpty()) null
	else "shadowsocks method \"$method\" is not one any core implements, so the node never worked"

// The transport a streamSettings object names, in the spelling the rest of the converters read:
// "method" where it is written - Xray lets it stand over "network" (c.Network = c.Method) - then
// "network", and a sing-box-shaped object's "type".
internal fun streamMethod(streamSettings: JSONObject): String {
	val raw = firstNonEmpty(streamSettings.xStr("method"), streamSettings.xStr("network"),
		streamSettings.xStr("type")).lowercase()
	return when (raw) {
		"websocket" -> "ws"
		"mkcp" -> "kcp"
		"gun" -> "grpc"
		else -> raw
	}
}

// The transports Xray's own dialer alone runs - XDRIVE, from 26.9.30 - which no other core and no link
// form carries; a node over one is refused by the document passes in the words below.
internal val XRAY_OWN_TRANSPORTS = setOf("xdrive")

// The transports some core runs, under the names streamNetwork gives them: every one Xray takes, and
// the HTTP/2 and QUIC ones it refuses, which a core runs with a server that has them.
private val KNOWN_TRANSPORTS =
	setOf("tcp", "ws", "grpc", "httpupgrade", "xhttp", "kcp", "hysteria", "h2", "quic") + XRAY_OWN_TRANSPORTS

// The protocols that send through their stream's transport; the rest carry their own and leave it be.
private val STREAM_PROTOCOLS = setOf("vless", "vmess", "trojan", "shadowsocks", "socks", "http")

// Why a node is refused for its transport, or null: a name no core knows leaves no way to reach the
// server - and Xray refuses the whole configuration over it - so every pass says so in these words.
internal fun transportRefusal(outbound: JSONObject): String? {
	if (outbound.xrayProtocol() !in STREAM_PROTOCOLS) return null
	val network = streamNetwork(outbound.xObj("streamSettings"))
	if (network == "masque") {
		return "transport \"masque\" is Xray's own (26.9.30) and runs under its masque outbound alone, " +
			"so Xray refuses this configuration and the node never worked"
	}
	if (network in KNOWN_TRANSPORTS) return null
	return "transport \"$network\" is not one Xray or any core knows, so the node never worked"
}

// The transport of Xray's own a node sends through, or null: refused by the document passes, kept as
// written by the link pass, each saying so in these words.
internal fun xrayOwnTransportOf(outbound: JSONObject): String? {
	if (outbound.xrayProtocol() !in STREAM_PROTOCOLS) return null
	return streamNetwork(outbound.xObj("streamSettings")).takeIf { it in XRAY_OWN_TRANSPORTS }
}

internal fun xrayOwnTransportRefusal(network: String): String =
	"transport \"$network\" is Xray's own from 26.9.30, which no other core and no link form carries"

// The MASQUE outbound (Xray 26.9.30) in the words both document passes refuse it with.
internal const val MASQUE_OUTBOUND_REFUSAL =
	"masque is an outbound of Xray's own from 26.9.30, which no other core runs"

// What a REALITY node in a core's document is told: which Xray servers turn the core's client away by
// default, and why - the node is right either way.
private const val REALITY_SERVERS = "an Xray 26.7 REALITY server lets in only Xray clients from 26.3.27 " +
	"unless its minClientVer allows others, and one from 26.9.8 only a Client Hello offering " +
	"X25519MLKEM768, which "
internal const val REALITY_SING_BOX_NOTE = REALITY_SERVERS + "sing-box leaves out of REALITY"
internal const val REALITY_MIHOMO_NOTE = REALITY_SERVERS + "mihomo sends with chrome alone - the " +
	"fingerprint this node runs"

// The uTLS profiles with no X25519 key share in their Client Hello, which REALITY derives its key from:
// Xray cannot connect over them either, so a core's REALITY node takes chrome, what Xray runs unnamed.
internal val REALITY_KEYLESS_FINGERPRINTS = setOf("android", "360")

// Why chrome stands in for the fingerprint a REALITY node names, in the words both document passes use;
// the profile is the one the core would have run for that name, null for none.
internal fun realityChromeNote(name: String, core: String, profile: String?): String = when {
	name.isEmpty() -> "REALITY needs a uTLS fingerprint and none was named; chrome was used"
	profile in REALITY_KEYLESS_FINGERPRINTS -> "uTLS fingerprint \"$name\" sends no X25519 key share, " +
		"which REALITY needs - Xray cannot connect over it either - so chrome was used"
	profile == "random" -> "uTLS fingerprint \"$name\" picks a browser at random, and only chrome sends " +
		"X25519MLKEM768 in $core's REALITY, which an Xray server from 26.9.8 asks for, so chrome was used"
	profile != null -> "uTLS fingerprint \"$name\" sends no X25519MLKEM768 in $core's REALITY, and an Xray " +
		"server from 26.9.8 turns a Client Hello without it away, so chrome was used"
	else -> "uTLS fingerprint \"$name\" is not one $core has, and REALITY needs one; chrome was used"
}

// Where the CA a stream's server is verified against stands - an inline verify certificate Xray can
// read, which the documents carry - or null. A mihomo QUIC proxy takes it as a pin at most, a share
// link as a pin or as the cert husi reads; Xray reads a named file instead, which no pass carries.
internal fun customAuthorityIndex(streamSettings: JSONObject?): Int? {
	val certs = streamTls(streamSettings)?.optJSONArray("certificates") ?: return null
	return (0 until certs.length()).firstOrNull { isInlineAuthority(certs.optJSONObject(it)) }
}

// Every such CA in PEM, as a client given CAs of its own takes them.
internal fun inlineAuthorities(streamSettings: JSONObject?): List<String> =
	streamTls(streamSettings).xObjList("certificates").filter(::isInlineAuthority)
		.mapNotNull { pemText(it.opt("certificate")) }

// A certificate Xray verifies the server against, written inline and readable as X.509.
internal fun isInlineAuthority(cert: JSONObject?): Boolean =
	cert != null && cert.optString("usage", "").lowercase() == "verify" &&
		cert.optString("certificateFile", "").isEmpty() && isReadableCertificate(cert.opt("certificate"))

// The one CA a stream's server is verified against, in PEM - "" when there is none, or several.
private fun soleAuthority(tls: JSONObject?): String =
	tls.xObjList("certificates").filter { it.xStr("usage").lowercase() == "verify" }
		.singleOrNull()?.let { pemText(it.opt("certificate")) }.orEmpty()

// That CA pinned where it is the server's own certificate for the names Xray checks it against - the
// names to verify, else the one sent - and null for any other.
internal fun ownAuthorityPin(tls: JSONObject?, sent: String): String? =
	ownCertificatePin(soleAuthority(tls), verifyPeerCertNames(tls).ifEmpty { listOf(sent) })

// Whether a client checking the CA's chain against a name gets past it, as far as the CA tells: the server's
// own certificate, where that is the CA, passes the names it covers; of any other CA nothing is known.
internal fun authorityPasses(tls: JSONObject?, sent: String, name: String): Boolean =
	ownAuthorityPin(tls, sent) == null || ownCertificatePin(soleAuthority(tls), listOf(name)) != null

// The name to send a client that checks the certificate against the name it sends: of the names to
// verify, one the server's own certificate covers, else the first - null when none is named or the
// one sent is among them.
internal fun nameToVerify(tls: JSONObject?, sent: String): String? {
	val names = verifyPeerCertNames(tls)
	val authority = soleAuthority(tls)
	val covered = names.filter { ownCertificatePin(authority, listOf(it)) != null }.ifEmpty { names }
	return if (covered.any { sameHost(it, sent) }) null else covered.firstOrNull()
}

// Two host names alike as Go matches them: case aside, and a final dot.
internal fun sameHost(name: String, other: String): Boolean =
	name.removeSuffix(".").equals(other.removeSuffix("."), ignoreCase = true)

// Two names alike as clients send them, however each was written: an internationalised name as punycode
// and an IPv6 address in one spelling, with or without brackets.
internal fun sameNameSent(name: String, other: String): Boolean {
	fun sent(text: String) = xrayAddressString(LinkParams.hostForUri(text)).removeSurrounding("[", "]")
	return sameHost(sent(name), sent(other))
}

// What every pass says when a name the certificate is checked against goes out as the server name: why
// is who checks it against the name sent instead.
internal fun verifyNameSentNote(name: String, sent: String, why: String): String =
	"tlsSettings.verifyPeerCertByName / verifyPeerCertInNames checks the certificate against \"$name\" " +
		"rather than ${if (sent.isEmpty()) "the address" else "\"$sent\""}, the name sent, and $why, so " +
		"\"$name\" was sent as the server name"

// And what it says when they stay behind - nothing checked, or the name sent among them - where is what
// has no field for them.
internal fun verifyNamesDroppedNote(where: String): String =
	"tlsSettings.verifyPeerCertByName / verifyPeerCertInNames checks the certificate against other names, " +
		"which $where has no field for, so it was dropped"

// Why a stream's security layer keeps the node from connecting anywhere, or null. Xray takes none,
// tls and reality (xtls became tls); any other name stops the configuration from loading there, so
// the node never worked and no pass writes it.
internal fun securityRefusal(streamSettings: JSONObject?): String? {
	val sec = streamSecurity(streamSettings)
	if (sec == "none") return null
	if (sec == "tls") return null
	if (sec != "reality") return "security \"$sec\" is not one Xray accepts, so the node never worked"
	// Xray has run REALITY over raw, xhttp and grpc - and h2 and domainsocket while it had them -
	// and never over anything else ("REALITY only supports ..."); a client needs the server's
	// public key ("empty password"), and a key or short id of the wrong shape it refuses too.
	val network = streamNetwork(streamSettings)
	if (network !in setOf("tcp", "xhttp", "grpc", "h2", "domainsocket")) {
		return "REALITY runs only over raw, xhttp, grpc or h2, and Xray refuses it over \"$network\", " +
			"so the node never worked"
	}
	val reality = streamSettings?.optJSONObject("realitySettings") ?: JSONObject()
	val key = realityPublicKey(reality)
	if (key.isEmpty()) {
		return "realitySettings has no public key, which Xray refuses, so the node never worked"
	}
	if (!isUsableRealityKey(key)) {
		return "realitySettings.publicKey is not a REALITY key (raw URL-safe base64 of 32 bytes), " +
			"which Xray refuses, so the node never worked"
	}
	val sid = realityShortId(reality)
	if (!isUsableShortId(sid)) {
		return "realitySettings.shortId \"$sid\" is not hexadecimal of up to eight bytes, which Xray " +
			"refuses, so the node never worked"
	}
	return null
}

// Which address types Xray asks for, in the one spelling the rest of the converters read. Xray
// reads this loosely - lower case, with "_" or "-" between the words - and treats anything it does
// not know as UseIP, so a legal spelling is not ignored here and an unknown one is not invented.
internal fun normalizeQueryStrategy(raw: String): String {
	val text = raw.trim().lowercase().replace("_", "").replace("-", "")
	if (text.isEmpty()) return ""
	return when (text) {
		"useip4", "useipv4" -> "UseIPv4"
		"useip6", "useipv6" -> "UseIPv6"
		"usesys", "usesystem" -> "UseSystem"
		else -> "UseIP"
	}
}

// The normalised transport name of a streamSettings object.
internal fun streamNetwork(streamSettings: JSONObject?): String {
	if (streamSettings == null) return "tcp"
	return when (val network = streamMethod(streamSettings)) {
		"", "tcp", "raw" -> "tcp"
		"splithttp" -> "xhttp"
		// In Xray, "http" is the HTTP/2 transport. It is not the same thing as mihomo's "http"
		// network, which is the HTTP masquerade that Xray spells as a raw-TCP header.
		"http", "h2", "h3" -> "h2"
		else -> network
	}
}

// The normalised security layer name of a streamSettings object.
internal fun streamSecurity(streamSettings: JSONObject?): String {
	if (streamSettings == null) return "none"
	return when (val sec = streamSettings.xStr("security").lowercase()) {
		"", "none", "auto" -> {
			// A config may omit "security" but still carry tlsSettings; Xray ignores that, and so
			// do we, except for REALITY which is only ever present deliberately.
			if (sec.isEmpty() && streamSettings.xObj("realitySettings") != null) "reality" else "none"
		}
		"xtls" -> "tls"
		else -> sec
	}
}

// Xray's QUIC transport always runs TLS: tlsSettings when security is tls, and otherwise its own
// self-signed name, never verified. With no ALPN named, Xray's TLS offers h2 then http/1.1.
internal const val XRAY_QUIC_OWN_SNI = "quic.internal.example.com"
internal val XRAY_DEFAULT_ALPN = listOf("h2", "http/1.1")

// Xray reads downloadSettings inside xhttpSettings alone; on streamSettings it does nothing, in Xray as
// in every pass, which each says in these words.
internal const val MISPLACED_DOWNLOAD_SETTINGS = "streamSettings.downloadSettings is not where Xray reads " +
	"it - it belongs in xhttpSettings - so it does nothing, in Xray as here"

// Xray reads dialerProxy inside sockopt alone; on streamSettings it does nothing, in Xray as in
// every pass, which each says in these words.
internal const val MISPLACED_DIALER_PROXY = "streamSettings.dialerProxy is not where Xray reads " +
	"it - it belongs in sockopt - so it does nothing, in Xray as here"

// What a configuration asks in a form Xray refuses or leaves unread, which every pass takes as meant
// so the node keeps working - each saying so in these words.
internal fun olderConfigLeniencies(outbound: JSONObject): List<String> {
	val notes = ArrayList<String>()
	val stream = outbound.xObj("streamSettings")
	val refuses = "is no name Xray 26 takes, so it would refuse the configuration"
	when (stream.xStr("security").lowercase()) {
		"auto" -> notes.add("security \"auto\" $refuses; it was read as none")
		"xtls" -> notes.add("security \"xtls\" $refuses; it was read as tls")
		"" -> if (stream.xObj("realitySettings") != null) notes.add(
			"security is not set, so Xray 26 would dial without the realitySettings beside it; " +
				"they were read as meant"
		)
	}
	val reality = stream.xObj("realitySettings")
	if (reality != null && reality.xStrList("shortIds").isNotEmpty()) {
		val taken = if (reality.xStr("shortId").isEmpty()) "its first was taken as shortId"
		else "shortId was used"
		notes.add("realitySettings.shortIds is a server's list, which Xray 26 refuses on a client; $taken")
	}
	if (outbound.xrayProtocol() == "vless" &&
		xrayEndpoints(outbound.xObj("settings")).any { it.user.xStr("encryption").isEmpty() }
	) {
		notes.add("a vless user names no encryption, which Xray 26 refuses (it wants \"none\" " +
			"written out); it was read as none")
	}
	val proto = outbound.xrayProtocol()
	if (proto == "vless" || proto == "trojan") {
		val settings = outbound.xObj("settings")
		val address = settings.xStr("address")
		val security = stream.xStr("security").lowercase()
		val secured = security in setOf("tls", "xtls", "reality") ||
			security.isEmpty() && stream.xObj("realitySettings") != null
		val encryption = settings.xStr("encryption")
		val ownEncryption = proto == "vless" && encryption.isNotEmpty() && encryption != "none"
		if (address.isNotEmpty() && !secured && !ownEncryption && !xrayPrivateAddress(address)) {
			notes.add("$proto with its server written in settings goes to a public address without TLS, " +
				"which Xray 26 refuses outside a private network; it was kept as the cores run it")
		}
	}
	val tls = stream.xObj("tlsSettings")
	val tlsSecurity = stream.xStr("security").lowercase()
	if (tlsSecurity == "tls" || tlsSecurity == "xtls") {
		if (tls.xBool("allowInsecure")) {
			notes.add("tlsSettings.allowInsecure is one Xray 26 refuses (it wants pinnedPeerCertSha256 or " +
				"verifyPeerCertByName); it was kept as the cores run it")
		}
		if (tls.xStrList("verifyPeerCertInNames").isNotEmpty()) {
			notes.add("tlsSettings.verifyPeerCertInNames is not read by Xray 26, which then verifies the " +
				"server name; the names were kept as meant")
		}
	}
	val kcp = stream.xObj("kcpSettings")
	if (streamNetwork(stream) == "kcp" && kcp != null && (kcp.has("header") || kcp.xHas("seed"))) {
		notes.add(kcpSettingsNote(stream))
	}
	if (proto == "shadowsocks") {
		val servers = shadowsocksServers(outbound)
		if (servers.any { canonicalSsMethod(it.xStr("method")) == "none" }) {
			notes.add("shadowsocks method none is one Xray 26 refuses; it was kept as the cores run it")
		}
		// Xray never read uot for the methods before 2022, so leaving it out changes nothing there.
		val uotOn2022 = servers.any {
			it.xBool("uot") && canonicalSsMethod(it.xStr("method")).startsWith("2022-blake3-")
		}
		if (uotOn2022) {
			notes.add("shadowsocks uot is not a field Xray reads (26.6.22 dropped it), so it sends UDP as " +
				"it is, and its servers take no UDP over TCP; it was dropped")
		}
	}
	if (proto == "socks" && outbound.xObj("settings").xObjList("servers").firstOrNull().xBool("uot")) {
		notes.add("socks uot is not a field Xray reads, so UDP goes as plain SOCKS, in Xray as here")
	}
	if (outbound.xObj("proxySettings").xStr("tag").isNotEmpty()) {
		notes.add("outbound proxySettings is one Xray 26.9 refuses - sockopt.dialerProxy took its place - " +
			"so its chain was followed as meant")
	}
	val hysteria = stream.xObj("hysteriaSettings")
	if (hysteria != null && HYSTERIA_QUIC_FIELDS.any { hysteria.xHas(it) }) {
		notes.add("hysteriaSettings carries rates, congestion or port hopping that Xray 26 reads in " +
			"finalmask alone; they were used only where finalmask gives none")
	}
	if (streamQuicParams(stream).xObj("udpHop") != null) {
		notes.add("finalmask.quicParams.udpHop is read by Xray from 26.3.23 to 26.9.8, not from 26.9.9, " +
			"which hops ports by the udphop mask alone; it was used only where that mask gives none")
	}
	return notes
}

// What a kcpSettings seed and header are to each Xray, and whether they were read here (kcpMask): beside the
// finalmask names of 26.1.31 to 26.5 only an Xray before finalmask loads the node, reading kcpSettings alone.
private fun kcpSettingsNote(stream: JSONObject?): String {
	val masks = stream.xObj("finalmask").xObjList("udp").map { it.xStr("type").lowercase() }
		.filter(::isKcpMask)
	val refused = "kcpSettings header and seed are what Xray from 26.1.31 to 26.9.8 refuses"
	return when {
		masks.isEmpty() -> "$refused and from 26.9.9 reads past (it masks mKCP from finalmask); they were " +
			"kept as written"
		"mkcp-legacy" in masks -> "$refused and from 26.9.9 reads past for the mkcp-legacy mask finalmask " +
			"names, which was read instead"
		else -> "$refused, and so does every Xray that knows the mKCP masks finalmask names; only one " +
			"before 26.1.13 loads the node, reading kcpSettings alone, so they were kept as written"
	}
}

// The hysteriaSettings fields Xray reads from finalmask instead, under every name written.
private val HYSTERIA_QUIC_FIELDS =
	listOf("up", "down", "upMbps", "downMbps", "up_mbps", "down_mbps", "congestion", "udpHop")

// The names under which Xray runs Go's own TLS rather than a uTLS fingerprint - what either core
// runs when no fingerprint is set.
internal val GO_TLS_FINGERPRINTS = setOf("unsafe", "golang", "hellogolang")

// Families a versioned uTLS name can be folded onto.
private val UTLS_FAMILIES = listOf("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq")

// Maps a versioned uTLS profile onto its family, which the core does resolve; the next character must
// not be a letter, so "chromium" isn't read as "chrome". Anything else falls back to plain Go TLS.
internal fun utlsFamilyOf(fingerprint: String): String? {
	// Xray's own versioned names open with "hello" ("hellochrome_120"), which neither core's names do.
	val bare = fingerprint.removePrefix("hello")
	return UTLS_FAMILIES.firstOrNull {
		bare.length > it.length && bare.startsWith(it) && !bare[it.length].isLetter()
	}
}

// What the QUIC transport leaves of the security settings, worded the same by every pass. None for
// the Go TLS names: they ask for Go's own TLS, which is what QUIC runs anyway.
internal fun quicFingerprintDropped(fingerprint: String): String? =
	if (fingerprint.isEmpty() || fingerprint.lowercase() in GO_TLS_FINGERPRINTS) null
	else "the uTLS fingerprint \"$fingerprint\" does not apply to the QUIC transport and was dropped"

// The same for a protocol that is QUIC itself - Hysteria, TUIC - in the words both document passes use.
internal fun quicProtocolFingerprintNote(tlsSettings: JSONObject?): String? =
	tlsSettings.xStr("fingerprint").takeIf { it.isNotEmpty() }
		?.let { "the uTLS fingerprint \"$it\" does not apply to a QUIC protocol and was dropped" }

// The effective TLS settings, under either spelling.
internal fun streamTls(streamSettings: JSONObject?): JSONObject? =
	streamSettings.xObj("tlsSettings") ?: streamSettings.xObj("xtlsSettings")

// The raw/tcp transport settings, under either spelling.
internal fun streamTcp(streamSettings: JSONObject?): JSONObject? =
	streamSettings.xObj("rawSettings") ?: streamSettings.xObj("tcpSettings")

// The websocket settings, under either spelling.
internal fun streamWs(streamSettings: JSONObject?): JSONObject? =
	streamSettings.xObj("wsSettings") ?: streamSettings.xObj("websocketSettings")

// The gRPC settings, under either spelling.
internal fun streamGrpc(streamSettings: JSONObject?): JSONObject? =
	streamSettings.xObj("grpcSettings") ?: streamSettings.xObj("gunSettings")

// The gRPC path a service name asks Xray for: "/<name>/Tun", or for a name starting with "/" the custom
// path it spells - the segments between the first and the last "/" the service, the last one up to its
// "|" the stream.
internal class GrpcPath(val service: String, val stream: String, val custom: Boolean)

internal fun grpcPath(serviceName: String): GrpcPath {
	if (!serviceName.startsWith("/")) return GrpcPath(serviceName, "Tun", custom = false)
	val lastSlash = serviceName.lastIndexOf('/')
	val stream = serviceName.substring(lastSlash + 1).substringBefore('|')
	return GrpcPath(serviceName.substring(1, lastSlash.coerceAtLeast(1)), stream, custom = true)
}

// The path a gRPC service name has on the wire: Xray escapes each part as Go's url.PathEscape does - all
// but letters, digits and -._~$&+:=@ as %XX of its UTF-8 bytes - and a client sending a path as written
// reaches the server only with it so.
internal fun grpcWirePath(path: GrpcPath): String {
	val service = if (path.custom) path.service.split('/').joinToString("/") { goPathEscape(it) }
	else goPathEscape(path.service)
	return "/$service/${goPathEscape(path.stream)}"
}

private fun goPathEscape(text: String): String = buildString {
	for (byte in text.toByteArray(Charsets.UTF_8)) {
		val char = (byte.toInt() and 0xFF).toChar()
		if (char in 'a'..'z' || char in 'A'..'Z' || char in '0'..'9' || char in "-._~$&+:=@") append(char)
		else append('%').append("%02X".format(byte.toInt() and 0xFF))
	}
}

// The XHTTP settings, under either spelling, with "extra" already applied.
internal fun streamXhttp(streamSettings: JSONObject?): JSONObject? {
	val cfg = streamSettings.xObj("xhttpSettings") ?: streamSettings.xObj("splithttpSettings") ?: return null
	return resolveXhttpExtra(cfg)
}

// Applies XHTTP's "extra" object the way Xray does: everything comes from "extra" except host, path and mode.
internal fun resolveXhttpExtra(cfg: JSONObject): JSONObject {
	val extra = cfg.xObj("extra") ?: return cfg
	val out = jsonCopy(extra)
	for (key in listOf("host", "path", "mode")) {
		val outer = cfg.xOpt(key)
		if (outer != null) out.put(key, outer) else out.remove(key)
	}
	out.remove("extra")
	return out
}

// The first finalmask UDP mask of the given type.
internal fun streamUdpMask(streamSettings: JSONObject?, maskType: String): JSONObject? =
	streamMask(streamSettings, "udp", maskType)

internal fun streamTcpMask(streamSettings: JSONObject?, maskType: String): JSONObject? =
	streamMask(streamSettings, "tcp", maskType)

private fun streamMask(streamSettings: JSONObject?, side: String, maskType: String): JSONObject? {
	val masks = streamSettings.xObj("finalmask").xArr(side) ?: return null
	for (i in 0 until masks.length()) {
		val mask = masks.opt(i) as? JSONObject ?: continue
		if (mask.xStr("type").equals(maskType, ignoreCase = true)) return mask
	}
	return null
}

// The finalmask QUIC parameters, if any.
internal fun streamQuicParams(streamSettings: JSONObject?): JSONObject? = streamSettings.xObj(
	"finalmask").xObj("quicParams")

// What a core carries of the udphop UDP mask, which Xray hops ports with from 26.9.9 - the server
// ports and the interval - and, for the notes, what the mask asks that no core does.
internal class UdpHop(val remotePorts: String, val interval: String, val notes: List<String>)

// The modes Xray takes in a udphop mask: it splits the mode at its commas and reads each part in any
// case but as written, so a space beside a comma makes a mode it does not know.
private val UDP_HOP_MODES = setOf("intervallocal", "intervalremote", "perconnremote")

private fun udpHopModes(settings: JSONObject?): List<String> =
	settings.xStrRaw("mode").split(',').map { it.lowercase() }

internal fun udpHopMask(streamSettings: JSONObject?): UdpHop? {
	val settings = streamUdpMask(streamSettings, "udphop")?.xObj("settings")
		?: return null
	val modes = udpHopModes(settings)
	val notes = ArrayList<String>()
	if ("intervallocal" in modes) {
		notes.add("the udphop mask's intervalLocal mode renews the client's own port, which no core " +
			"does, so that part was dropped")
	}
	if ("perconnremote" in modes && "intervalremote" !in modes) {
		notes.add("the udphop mask's perConnRemote mode picks the server port once per connection; " +
			"the cores pick it anew by the interval")
	}
	if (settings.xStrList("remoteIPs").isNotEmpty()) {
		notes.add("udphop remoteIPs hop between server addresses, which no core does, so they were dropped " +
			"and the node dials its own address")
	}
	val interval = settings.xStr("interval")
	if (interval.isNotEmpty() && hopInterval(interval).low.isEmpty()) {
		notes.add("the udphop mask's interval \"$interval\" is no number of seconds, so the cores hop by " +
			"their own default")
	}
	val remote = "intervalremote" in modes || "perconnremote" in modes
	return UdpHop(if (remote) settings.xPortList("remotePorts") else "", interval, notes)
}

// Why Xray refuses the configuration over a udphop mask - so the node never worked - or null: a mode it
// has no name for (none written is one), which tells nothing of what was meant; where Xray reads the mask
// itself, an interval it cannot read or under 5 seconds, or a remote IP that is none - cores correct those.
private fun udpHopRefusal(finalmask: JSONObject, carriedWhole: Boolean): String? {
	val mask = finalmask.xObjList("udp").firstOrNull { it.xStr("type").equals("udphop", ignoreCase = true) }
		?: return null
	val settings = mask.xObj("settings")
	val never = "which Xray refuses the configuration over, so the node never worked"
	udpHopModes(settings).firstOrNull { it !in UDP_HOP_MODES }?.let {
		val what = if (it.isEmpty()) "names no mode" else "names the mode \"$it\""
		return "finalmask.udp mask \"udphop\" $what, $never"
	}
	if (!carriedWhole) return null
	// Xray reads the interval as written: an empty one is its default, a padded one no number at all.
	val interval = settings.xStrRaw("interval")
	val range = settings.xRange("interval")
	val unreadable = interval.isNotEmpty() && (interval != interval.trim() || !range.set)
	val short = range.set && range.from < MIN_HOP_INTERVAL && !(range.from == 0 && range.to == 0)
	if (unreadable || short) {
		return "finalmask.udp mask \"udphop\" has the interval \"$interval\", not whole seconds from " +
			"$MIN_HOP_INTERVAL up, $never"
	}
	settings.xStrList("remoteIPs").firstOrNull { wireguardInterfacePrefix(it) == null }?.let {
		return "finalmask.udp mask \"udphop\" names the remote IP \"$it\", which is no address, $never"
	}
	return null
}

// What an mKCP node masks its packets with, in kcpSettings' terms - the seed, empty for the original mask,
// and the header outside it - whether it names a mask at all, keys it by an empty seed, and why its masks
// are not the one layout kcpSettings writes, a header outside a seed or original mask.
internal class KcpMask(
	val seed: String,
	val headerType: String,
	val domain: String,
	val stated: Boolean,
	val blankSeed: Boolean = false,
	val unlike: String? = null,
	val inFinalmask: Boolean = false,
	// Why Xray refuses the configuration over these masks, so the node never worked, or null.
	val refusal: String? = null,
	// More than one mkcp-legacy mask: Xray 26.6.1 wrapped them in list order, later Xray the other way.
	val severalLegacy: Boolean = false
)

// The header names finalmask gives what kcpSettings called srtp, utp, wechat-video and the rest; an
// mkcp-legacy mask names them without the prefix.
private val FINALMASK_HEADERS = mapOf(
	"header-srtp" to "srtp",
	"header-utp" to "utp",
	"header-wechat" to "wechat-video",
	"header-dtls" to "dtls",
	"header-wireguard" to "wireguard",
	"header-dns" to "dns"
)

// The masks that are an mKCP node's seed and packet header rather than an obfuscation of their own, by
// the lowercase name Xray reads.
private fun isKcpMask(type: String): Boolean =
	type == "mkcp-aes128gcm" || type == "mkcp-original" || type == "mkcp-legacy" ||
		(type.startsWith("header-") && type != "header-custom")

// The packet headers Xray read in kcpSettings before 26.1.31, refusing the configuration over any other.
private val KCP_SETTINGS_HEADERS = setOf("none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "dns")

internal fun kcpMask(streamSettings: JSONObject?): KcpMask {
	val masks = streamSettings.xObj("finalmask").xObjList("udp")
		.filter { isKcpMask(it.xStr("type").lowercase()) }
	val written = kcpSettingsMask(streamSettings.xObj("kcpSettings"))
	// Beside a kcpSettings seed or header the mask names of 26.1.31 to 26.5 load in no Xray that knows them,
	// and one before finalmask reads kcpSettings alone; mkcp-legacy loads from 26.9.9, which reads it past.
	val legacy = masks.any { it.xStr("type").lowercase() == "mkcp-legacy" }
	if (masks.isEmpty() || written.stated && !legacy) return written
	return finalmaskKcpMask(masks)
}

// Xray before 26.1.31 reads kcpSettings and keys the mask by a seed it names, even an empty one; a node
// that names neither seed nor header is masked as the server's version masks.
private fun kcpSettingsMask(kcp: JSONObject?): KcpMask {
	// Xray takes a header only as an object naming a type it has: one written as anything else, null
	// included, it refuses as it does an unknown name.
	val headed = kcp?.has("header") == true
	val header = kcp.xObj("header")
	val type = header.xStr("type")
	val seeded = kcp?.opt("seed") is String
	val seed = kcp.xStrRaw("seed")
	val named = when {
		header == null -> "an mKCP header that is no object"
		type.isEmpty() -> "an mKCP header of no type"
		else -> "the mKCP header \"$type\""
	}
	val refusal = if (!headed || type.lowercase() in KCP_SETTINGS_HEADERS) null
		else "kcpSettings names $named, which no Xray has, so the node never worked as written"
	return KcpMask(
		seed, type, header.xStr("domain"), stated = seeded || headed,
		blankSeed = seeded && seed.isEmpty(), refusal = refusal
	)
}

// The finalmask mKCP masks in kcpSettings' terms. Up to 26.6.1 Xray wraps the connection in list order,
// the first mask outermost, and from 26.6.22 in reverse; mkcp-legacy, the one name from 26.6.1 on, is read
// the 26.6.22 way.
private fun finalmaskKcpMask(masks: List<JSONObject>): KcpMask {
	val legacy = masks.count { it.xStr("type").lowercase() == "mkcp-legacy" }
	var seed = ""
	var header = ""
	var domain = ""
	var keyed = false
	var seeds = 0
	var headers = 0
	var headerInside = false
	var unknown = ""
	for ((place, mask) in (if (legacy > 0) masks.asReversed() else masks).withIndex()) {
		val type = mask.xStr("type").lowercase()
		val settings = mask.xObj("settings")
		val named = if (type != "mkcp-legacy") type.takeIf { it.startsWith("header-") }
			else settings.xStrRaw("header").lowercase().takeIf { it.isNotEmpty() }?.let { "header-$it" }
		// Where there are several, the outermost of each stands for the node, as a link names one.
		if (named == null) {
			if (seeds++ > 0) continue
			seed = when (type) {
				"mkcp-aes128gcm" -> settings.xStrRaw("password")
				"mkcp-legacy" -> settings.xStrRaw("value")
				else -> ""
			}
			keyed = type == "mkcp-aes128gcm" || seed.isNotEmpty()
			continue
		}
		if (place > 0) headerInside = true
		headers++
		val known = FINALMASK_HEADERS[named]
		if (known == null) unknown = named.removePrefix("header-")
		if (known == null || header.isNotEmpty()) continue
		header = known
		if (known == "dns") domain = settings.xStr(if (type == "mkcp-legacy") "value" else "domain")
	}
	val refusal = when {
		legacy in 1 until masks.size -> "finalmask mixes the mKCP masks of two Xray generations, and an " +
			"Xray that reads either refuses the configuration over the other, so the node never worked"
		unknown.isNotEmpty() -> "finalmask names the mKCP header \"$unknown\", which no Xray has, so it " +
			"refuses the configuration and the node never worked"
		else -> null
	}
	// Two mkcp-legacy masks read the other way round, as 26.6.1 read them, put the header outside.
	val legacyOrder = if (legacy == 0) "" else ", as Xray wraps mkcp-legacy masks from 26.6.22 (a 26.6.1 " +
		"server wraps them the other way, the header outside)"
	val unlike = when {
		seeds == 0 -> "finalmask names an mKCP header with no seed or original mask under it"
		seeds > 1 || headers > 1 -> "finalmask names more than one mKCP header, or more than one seed or " +
			"original mask"
		headerInside -> "finalmask puts the mKCP header under the seed or original mask$legacyOrder"
		else -> null
	}
	return KcpMask(
		seed, header, domain, stated = true, blankSeed = keyed && seed.isEmpty(), unlike = unlike,
		inFinalmask = true, refusal = refusal, severalLegacy = legacy > 1
	)
}

// What a finalmask block asks for that the node goes without, in words. Xray does this work in its
// own dialer, so a core that is not Xray has nowhere to put it - and a node tuned for a censored
// network behaves differently without it, which is worth saying rather than leaving to be discovered.
internal fun finalmaskFeatures(outbound: JSONObject, tlsFragment: Boolean = false): List<String> {
	val streamSettings = outbound.xObj("streamSettings")
	val finalmask = streamSettings.xObj("finalmask") ?: return emptyList()
	val out = mutableListOf<String>()
	// What the block holds is left behind, and an entry that is not an object is counted with it
	// rather than passed over; what a pass writes into the node itself is carried (maskCarried).
	for (side in listOf("tcp", "udp")) {
		val entries = finalmask.opt(side) as? JSONArray ?: continue
		val carried = finalmask.xObjList(side).count {
			maskCarried(outbound, side, it) ||
				tlsFragment && side == "tcp" && it.xStr("type").equals("fragment", ignoreCase = true)
		}
		if (entries.length() > carried) out.add("finalmask.$side")
	}
	if (streamQuicParams(streamSettings) != null && !hysteriaNode(outbound)) out.add("finalmask.quicParams")
	return out
}

// The finalmask masks that only shape how a client sends - TCP split into pieces, noise packets ahead
// of the real ones, the port hopped by udphop - which a server reads past; every other mask rewrites
// the bytes for both ends.
private val CLIENT_SIDE_MASKS = setOf("fragment", "noise", "udphop")

// The side a node's own traffic goes through: UDP for the protocols that send nothing else, for the
// mKCP and Hysteria transports and for XHTTP over HTTP/3, TCP for every other one. A mask on the
// other side never touches it.
private fun finalmaskSideUsed(outbound: JSONObject): String {
	val stream = outbound.xObj("streamSettings")
	val udpProtocol = outbound.xrayProtocol() in setOf("wireguard", "hysteria", "hysteria2", "tuic")
	val network = streamNetwork(stream)
	val udpTransport = network in setOf("kcp", "hysteria") || network == "xhttp" && xhttpOverH3(stream)
	return if (udpProtocol || udpTransport) "udp" else "tcp"
}

// Whether XHTTP runs over HTTP/3, as Xray (decideHTTPVersion) and mihomo both decide: TLS - not
// REALITY - with "h3" its one ALPN.
private fun xhttpOverH3(stream: JSONObject?): Boolean =
	stream.xStr("security").lowercase() in setOf("tls", "xtls") &&
		stream.xObj("tlsSettings").xStrList("alpn") == listOf("h3")

// A Hysteria node by its protocol or its transport, as the readers that carry its masks take it.
private fun hysteriaNode(outbound: JSONObject): Boolean =
	outbound.xrayProtocol() in setOf("hysteria", "hysteria2") ||
		streamNetwork(outbound.xObj("streamSettings")) == "hysteria"

// Whether a pass writes a mask into the node itself: an mKCP node's seed and header (kcpMask), and the
// udp masks a Hysteria node takes into fields of its own (the hysteria readers, which name what is left).
private fun maskCarried(outbound: JSONObject, side: String, mask: JSONObject): Boolean =
	streamNetwork(outbound.xObj("streamSettings")) == "kcp" && isKcpMask(mask.xStr("type").lowercase()) ||
		hysteriaNode(outbound) && side == "udp" && mask.xStr("type").lowercase() in HYSTERIA_OWN_MASKS

// Salamander - gecko with a packetSize - becomes the obfuscation, udphop's server ports the port hopping.
private val HYSTERIA_OWN_MASKS = setOf("salamander", "udphop")

// Why Xray refuses the configuration over its masks - so the node never worked - or null: an mKCP mask it
// has no such name for, and all of finalmask for a link carrying the block whole as fm, what the cores
// cannot correct for any other pass.
internal fun xrayMaskRefusal(outbound: JSONObject, carriedWhole: Boolean): String? {
	val stream = outbound.xObj("streamSettings")
	if (streamNetwork(stream) == "kcp") kcpMask(stream).refusal?.let { return it }
	val finalmask = stream.xObj("finalmask") ?: return null
	return geckoRefusal(finalmask) ?: udpHopRefusal(finalmask, carriedWhole)
}

// Why a node is refused where its finalmask cannot go: a mask both ends share, on the side the node
// sends through, rewrites every byte, so a core sending without it never connects. Null otherwise.
internal fun finalmaskRefusal(outbound: JSONObject): String? {
	xrayMaskRefusal(outbound, carriedWhole = false)?.let { return it }
	val finalmask = outbound.xObj("streamSettings").xObj("finalmask") ?: return null
	val side = finalmaskSideUsed(outbound)
	// Hopping the server port, Xray dials only the ports in remotePorts; no core hops outside Hysteria,
	// and the port the node names itself may be one the server does not listen on.
	if (side == "udp" && !hysteriaNode(outbound) &&
		udpHopMask(outbound.xObj("streamSettings"))?.remotePorts.orEmpty().isNotEmpty()
	) {
		return "finalmask.udp mask \"udphop\" sends this node to the server ports in remotePorts alone, " +
			"which no core does outside Hysteria, so without it the node dials a port Xray never does"
	}
	val shared = finalmask.xObjList(side).firstOrNull {
		it.xStr("type").lowercase() !in CLIENT_SIDE_MASKS && !maskCarried(outbound, side, it)
	} ?: return null
	return "finalmask.$side mask \"${shared.xStr("type")}\" rewrites the bytes for both ends, which " +
		"only Xray does, so the node never connects without it"
}

// The largest packet size gecko takes: Xray ("gecko: invalid min/max packet size") and mihomo ("gecko:
// invalid packet size range") both refuse one past it, or one below 1.
private const val GECKO_PACKET_SIZE_MAX = 2048

// Gecko is a salamander mask with a packetSize: Xray refuses the whole configuration over a size gecko
// does not take, and over a mask typed "gecko" ("unknown config id"), so such a node never worked.
private fun geckoRefusal(finalmask: JSONObject): String? {
	for (mask in finalmask.xObjList("udp")) {
		val type = mask.xStr("type").lowercase()
		if (type == "gecko") {
			return "finalmask.udp mask \"gecko\" is no mask type Xray has - gecko is salamander with a " +
				"packetSize - so the node never worked"
		}
		if (type != "salamander") continue
		val size = mask.xObj("settings").xRange("packetSize")
		if (!size.set || size.to <= 0 || (size.from >= 1 && size.to <= GECKO_PACKET_SIZE_MAX)) continue
		return "finalmask.udp mask \"salamander\" has packetSize \"${size.render()}\" outside the 1 to " +
			"$GECKO_PACKET_SIZE_MAX gecko takes, which Xray refuses the configuration over, so the node " +
			"never worked"
	}
	return null
}

// The REALITY server name.
internal fun realitySni(reality: JSONObject): String {
	val serverName = reality.xStr("serverName")
	if (serverName.isNotEmpty()) return serverName
	return reality.xStrList("serverNames").firstOrNull().orEmpty()
}

// The REALITY short id, under either of the two names it is written with.
internal fun realityShortId(reality: JSONObject): String {
	val shortId = reality.xStr("shortId")
	if (shortId.isNotEmpty()) return shortId
	return reality.xStrList("shortIds").firstOrNull().orEmpty()
}

// The REALITY public key. Newer Xray builds call the client-side field "password"; older ones call
// it "publicKey".
internal fun realityPublicKey(reality: JSONObject): String = reality.xStrOf("publicKey", "password")

// The names a peer certificate may be verified against instead of the server name: current Xray
// takes one comma-separated string, the list spelling is the one it removed. A link carries them
// all; mihomo verifies against one.
internal fun verifyPeerCertNames(tls: JSONObject?): List<String> =
	(tls.xStrList("verifyPeerCertByName") + tls.xStrList("verifyPeerCertInNames")).distinct()

internal data class WsPath(val path: String, val earlyData: Int?)

internal fun parseWsPath(path: Any?): WsPath {
	if (path !is String || !path.contains("?") || !path.contains("ed=")) {
		return WsPath(path as? String ?: "", null)
	}
	val qIdx = path.indexOf("?")
	val base = path.substring(0, qIdx)
	val query = path.substring(qIdx + 1)
	val kept = mutableListOf<String>()
	var edValue: Int? = null
	for (pair in query.split("&")) {
		if (pair.isEmpty()) continue
		if (pair.startsWith("ed=")) {
			val number = pair.substring(3).toIntOrNull()
			if (number != null) edValue = number else kept.add(pair)
		} else {
			kept.add(pair)
		}
	}
	val newQuery = kept.joinToString("&")
	val newPath = if (newQuery.isEmpty()) base else "$base?$newQuery"
	return WsPath(newPath, edValue)
}

internal fun headerHost(settings: JSONObject?): String? {
	val headers = settings?.optJSONObject("headers") ?: return null
	val keys = headers.keys()
	while (keys.hasNext()) {
		val key = keys.next()
		if (key.equals("Host", ignoreCase = true)) return LinkParams.firstOfList(headers.opt(key))
	}
	return null
}

// What a shadowsocks, socks or http outbound's stream settings mean where the proxy type carries
// no transport: shadowsocks over WebSocket is the v2ray-plugin in websocket mode everywhere, and
// anything else has no form. insecureLost names allowInsecure where the plugin has no switch for it.
internal class TransportPlugin(
	val name: String,
	val options: LinkedHashMap<String, String>,
	val insecure: Boolean
) {
	// The SIP003 spelling: "key=value;key=value", a bare "tls" for the flag. A backslash goes before
	// a "\\" or ";" in a value and an "=" in a key too - all a reader needs, and a value's "=" left as
	// written for the readers that split at the first one.
	fun sip003(): String =
		name + ";" + options.entries.joinToString(";") { (key, value) ->
			val written = sip003Escaped(key, "=;")
			if (value.isEmpty()) written else "$written=${sip003Escaped(value, ";")}"
		}
}

private fun sip003Escaped(text: String, special: String): String = buildString {
	for (character in text) {
		if (character == '\\' || character in special) append('\\')
		append(character)
	}
}

// A server address as Xray writes it once read (net.Address.String()): an IPv4 literal as it is, one
// mapped into IPv6 as that IPv4, any other IPv6 literal as Go compresses it - the longest run of two
// or more zero groups, the first of equal ones - in brackets, and anything else as written.
internal fun xrayAddressString(written: String): String {
	val text = written.trim().removeSurrounding("[", "]")
	if (parseInet4(text) || '%' in text || !parseInet6(text)) return text
	val groups = canonicalIp(text)?.split(':')?.map { it.toInt() } ?: return text
	if (groups.subList(0, 5).all { it == 0 } && groups[5] == 0xffff) {
		val (high, low) = groups[6] to groups[7]
		return listOf(high shr 8, high and 0xff, low shr 8, low and 0xff).joinToString(".")
	}
	var runStart = -1
	var runLength = 1
	var i = 0
	while (i < groups.size) {
		var end = i
		while (end < groups.size && groups[end] == 0) end++
		if (end - i > runLength) {
			runStart = i
			runLength = end - i
		}
		i = maxOf(end, i + 1)
	}
	val hex = groups.map { it.toString(16) }
	if (runStart < 0) return "[${hex.joinToString(":")}]"
	val left = hex.subList(0, runStart).joinToString(":")
	val right = hex.subList(runStart + runLength, hex.size).joinToString(":")
	return "[$left::$right]"
}

// Whether Xray takes an address as private, as its geodata lists have it: an IP in one of its private
// ranges - an IPv4 mapped into IPv6 as that IPv4 - or a name in one of its private zones or with no dot.
internal fun xrayPrivateAddress(written: String): Boolean {
	val text = written.trim().removeSurrounding("[", "]")
	ipValue(text)?.let { (value, width) -> return PRIVATE_RANGES.any { inRange(value, width, it) } }
	val name = text.lowercase().removeSuffix(".")
	return PRIVATE_ZONES.any { name == it || name.endsWith(".$it") } || DOTLESS_NAME.matches(name)
}

private val PRIVATE_RANGES = listOf(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/3", "::/127", "fc00::/7", "fe80::/10", "ff00::/8"
)
private val PRIVATE_ZONES =
	listOf("lan", "localdomain", "example", "invalid", "localhost", "test", "local", "home.arpa", "internal")
private val DOTLESS_NAME = Regex("^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")

// An IP literal as a number and its width in bits, an IPv4 mapped into IPv6 as that IPv4; null for
// anything else.
private fun ipValue(text: String): Pair<BigInteger, Int>? {
	if (parseInet4(text)) {
		val hex = text.split('.').joinToString("") { it.toInt().toString(16).padStart(2, '0') }
		return BigInteger(hex, 16) to 32
	}
	if ('%' in text || !parseInet6(text)) return null
	val groups = canonicalIp(text)?.split(':')?.map { it.toInt() } ?: return null
	if (groups.subList(0, 5).all { it == 0 } && groups[5] == 0xffff) {
		return BigInteger.valueOf((groups[6].toLong() shl 16) or groups[7].toLong()) to 32
	}
	return BigInteger(groups.joinToString("") { it.toString(16).padStart(4, '0') }, 16) to 128
}

private fun inRange(value: BigInteger, width: Int, cidr: String): Boolean {
	val (base, baseWidth) = ipValue(cidr.substringBefore('/')) ?: return false
	if (baseWidth != width) return false
	val shift = width - cidr.substringAfter('/').toInt()
	return value.shiftRight(shift) == base.shiftRight(shift)
}

// SIP003 options as v2ray-plugin and sing-box read them: "key=value" pairs split by ";", a key alone
// meaning "1", a backslash keeping the character after it, and the first of a repeated key read.
// Null where they refuse the text outright - an empty key, or a backslash with nothing after it.
internal fun sip003Options(text: String): LinkedHashMap<String, String>? {
	val out = LinkedHashMap<String, String>()
	var i = 0
	fun readUntil(stops: String): String? {
		val part = StringBuilder()
		while (i < text.length && text[i] !in stops) {
			if (text[i] == '\\' && ++i >= text.length) return null
			part.append(text[i++])
		}
		return part.toString()
	}
	while (i < text.length) {
		val key = readUntil("=;") ?: return null
		if (key.isEmpty()) return null
		val value = if (i < text.length && text[i] == '=') {
			i++
			readUntil(";") ?: return null
		} else "1"
		if (key !in out) out[key] = value
		i++
	}
	return out
}

// A SIP003 plugin a Shadowsocks server names itself, beside its address: Xray runs no such plugin
// and never reads it, and the passes carry it to the cores - under the name both cores know, or not
// at all where a core would refuse the whole configuration over it.
internal class ServerPlugin(val plugin: TransportPlugin?, val refusal: String?, val notes: List<String>)

// The note for a WebSocket transport the server's own plugin takes the place of, alike in every pass.
internal fun displacedTransportNote(own: TransportPlugin, transport: TransportPlugin): String {
	val tls = if ("tls" in transport.options) " over tls" else ""
	return "the server's own plugin \"${own.name}\" takes the place of the ws transport$tls under the " +
		"outbound, so that was dropped"
}

internal fun serverPluginOf(server: JSONObject): ServerPlugin {
	val stated = server.xStr("plugin")
	if (stated.isEmpty()) return ServerPlugin(null, null, emptyList())
	fun refused(why: String): ServerPlugin {
		val reason = "the server's plugin \"$stated\" $why, so the node never connects there"
		return ServerPlugin(null, reason, emptyList())
	}
	val name = when (stated) {
		"obfs-local", "simple-obfs", "obfs" -> "obfs-local"
		"v2ray-plugin" -> "v2ray-plugin"
		else -> return refused("is neither obfs-local nor v2ray-plugin, the only plugins both cores run")
	}
	val raw = server.opt("plugin_opts")?.takeIf { it != JSONObject.NULL } ?: server.opt("pluginOpts")
	val options = when (raw) {
		null, JSONObject.NULL -> LinkedHashMap()
		is String -> sip003Options(raw) ?: return refused("takes options \"$raw\" that do not read as SIP003")
		is JSONObject -> jsonPluginOptions(raw)
		else -> return refused("takes options that are neither SIP003 text nor an object")
	}
	if (stated == "obfs") {
		// mihomo's name for the plugin, written with mihomo's names for its two options.
		options.remove("mode")?.let { if ("obfs" !in options) options["obfs"] = it }
		options.remove("host")?.let { if ("obfs-host" !in options) options["obfs-host"] = it }
	}
	val notes = ArrayList<String>()
	if (name == "obfs-local") {
		val mode = options["obfs"] ?: "http"
		if (mode != "http" && mode != "tls") return refused("asks for obfs \"$mode\", neither http nor tls")
	} else {
		val mode = options["mode"] ?: "websocket"
		if (mode != "websocket" && mode != "quic") {
			return refused("asks for mode \"$mode\", neither websocket nor quic")
		}
		if (mode == "quic" && "tls" !in options) return refused("runs quic without tls, which quic cannot do")
		val mux = options["mux"]
		if (mode == "websocket" && mux != null && goAtoi(mux) == null) {
			return refused("takes mux \"$mux\", not a number")
		}
		if ("tls" in options && options.remove("cert") != null) {
			notes.add(
				"the server's plugin names a cert file on the machine that wrote the configuration, " +
					"so it was dropped"
			)
		}
		val embedded = options["certRaw"]
		if ("tls" in options && embedded != null &&
			!isReadableCertificate("-----BEGIN CERTIFICATE-----\n$embedded\n-----END CERTIFICATE-----")
		) {
			options.remove("certRaw")
			notes.add("the server's plugin certRaw does not read as a certificate, so it was dropped")
		}
	}
	notes.add("the server names the SIP003 plugin \"$stated\", which Xray never reads; it was carried " +
		"for the core")
	return ServerPlugin(TransportPlugin(name, options, insecure = false), null, notes)
}

// Plugin options written as an object, read for what each value says rather than through a SIP003
// text: tls is on by its mere presence, so a false one is left out where "tls=0" would turn TLS on,
// and any other false reads as 0 - mux off.
private fun jsonPluginOptions(raw: JSONObject): LinkedHashMap<String, String> {
	val out = LinkedHashMap<String, String>()
	for (key in raw.keys()) {
		when (val value = raw.opt(key)) {
			null, JSONObject.NULL -> Unit
			false -> if (key != "tls") out[key] = "0"
			true -> out[key] = "1"
			else -> out[key] = value.toString()
		}
	}
	return out
}

// The plugin with the host it takes when none is written, written out for the cores and the links:
// sing-box would send none from obfs-local and take no TLS name from v2ray-plugin's, mihomo its own
// "bing.com" - and from a link, an empty one.
internal fun TransportPlugin.withOwnDefaults(): TransportPlugin {
	val key = if (name == "obfs-local") "obfs-host" else "host"
	if (key in options) return this
	val filled = LinkedHashMap(options)
	filled[key] = if (name == "obfs-local") "cloudfront.net" else "cloudfront.com"
	return TransportPlugin(name, filled, insecure)
}

// As a link carries it: its mode written out as well - mihomo refuses a proxy whose link leaves it out, and
// the whole subscription with it, and obfs-local itself does not start without one.
internal fun TransportPlugin.forLink(): TransportPlugin {
	val own = withOwnDefaults()
	val key = if (name == "obfs-local") "obfs" else "mode"
	if (key in own.options) return own
	val filled = LinkedHashMap<String, String>()
	filled[key] = if (name == "obfs-local") "http" else "websocket"
	filled.putAll(own.options)
	return TransportPlugin(name, filled, insecure)
}

// Whether the v2ray-plugin multiplexes: its mux option, 1 when left out, and off at 0.
internal fun TransportPlugin.muxOn(): Boolean = options["mux"]?.let { goAtoi(it) != 0L } ?: true

internal class TransportForm(private val plugin: TransportPlugin?, val refusal: String?) {
	// The plugin, with the Host header Xray sends where the transport names none - host, then the
	// Host header, then the TLS server name, then the server's address as Xray writes it - which then
	// names the TLS server too.
	fun pluginFor(address: String): TransportPlugin? {
		val found = plugin ?: return null
		if ("host" in found.options) return found
		val options = LinkedHashMap<String, String>()
		options["mode"] = found.options["mode"] ?: "websocket"
		options["host"] = xrayAddressString(address)
		for ((key, value) in found.options) if (key !in options) options[key] = value
		return TransportPlugin(found.name, options, found.insecure)
	}

	// The loss to name when the plugin's options cannot carry allowInsecure.
	val insecureLost: String?
		get() = if (plugin?.insecure == true) "tlsSettings.allowInsecure has no place in the " +
			"v2ray-plugin options here, so the plugin verifies the certificate" else null
}

internal fun transportFormOf(proto: String, streamSettings: JSONObject?): TransportForm {
	if (streamSettings == null) return TransportForm(null, null)
	// The normalised name: "raw" is what Xray writes for tcp now, and a plain node under either
	// spelling has nothing to carry. An HTTP masquerade on it is a transport the server expects.
	val net = streamNetwork(streamSettings)
	val sec = streamSecurity(streamSettings)
	val headerType = streamTcp(streamSettings).xObj("header").xStr("type").lowercase()
	val masquerade = headerType.isNotEmpty() && headerType != "none"
	if (net == "tcp" && masquerade) {
		return TransportForm(
			null,
			"$proto over raw with an HTTP masquerade has no form in any core: the proxy type " +
				"carries no transport, and a node written without the masquerade connects to nothing"
		)
	}
	if (net == "tcp" && sec == "none") return TransportForm(null, null)
	if (net == "tcp" && sec == "tls") {
		// socks and http carry TLS as a flag of their own where a core has one; shadowsocks over
		// bare TLS has no plugin form.
		if (proto != "shadowsocks") return TransportForm(null, null)
		return TransportForm(null, "shadowsocks over TLS without WebSocket has no plugin form in any core")
	}
	if (proto == "shadowsocks" && net == "ws" && sec in setOf("none", "tls")) {
		val websocket = streamWs(streamSettings)
		val tls = streamTls(streamSettings)
		val options = LinkedHashMap<String, String>()
		options["mode"] = "websocket"
		val host = websocket.xStr("host").ifEmpty { headerHost(
			websocket).orEmpty() }.ifEmpty { tls.xStr("serverName") }
		if (host.isNotEmpty()) options["host"] = host
		// Xray sends a path written without its leading slash with one (GetNormalizedPath).
		val path = websocket.xStr("path")
		if (path.isNotEmpty()) options["path"] = if (path.startsWith("/")) path else "/$path"
		if (sec == "tls") options["tls"] = ""
		val insecure = sec == "tls" && tls.xBool("allowInsecure")
		return TransportForm(TransportPlugin("v2ray-plugin", options, insecure), null)
	}
	val what = if (sec == "reality") "$net over REALITY" else if (sec != "none") "$net over $sec" else net
	return TransportForm(
		null,
		"$proto over $what has no form in any core: the proxy type carries no transport, " +
			"and a node written without one connects to nothing"
	)
}
