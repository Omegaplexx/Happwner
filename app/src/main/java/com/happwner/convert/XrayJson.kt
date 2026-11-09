package com.happwner.convert

import com.happwner.text.decodeBase64Any
import com.happwner.text.isIpLiteral
import java.net.InetAddress
import java.util.Collections
import java.util.IdentityHashMap
import org.json.JSONArray
import org.json.JSONObject

// Lenient accessors for reading Xray JSON. Xray configs in the wild are loosely typed: ports as
// `"443"`, booleans as `"true"`, single-element lists as bare strings, absent fields as JSON null.

// Reads key, mapping both a missing field and JSON null to null.
internal fun JSONObject?.xOpt(key: String): Any? {
	val value = this?.opt(key) ?: return null
	if (value === JSONObject.NULL) return null
	return value
}

// Reads key as an object, or null when it is missing or another type.
internal fun JSONObject?.xObj(key: String): JSONObject? = this.xOpt(key) as? JSONObject

// Reads key as an array, or null when it is missing or another type.
internal fun JSONObject?.xArr(key: String): JSONArray? = this.xOpt(key) as? JSONArray

// Coerces a scalar to a string, so a number or boolean reads as text.
internal fun xScalarString(value: Any?): String = when (value) {
	null -> ""
	is String -> value
	is JSONObject, is JSONArray -> ""
	else -> value.toString()
}

// Reads key as a trimmed string, accepting numbers and booleans.
internal fun JSONObject?.xStr(key: String): String = xScalarString(this.xOpt(key)).trim()

// Reads the first of keys that holds a non-empty string.
internal fun JSONObject?.xStrOf(vararg keys: String): String {
	for (key in keys) {
		val value = this.xStr(key)
		if (value.isNotEmpty()) return value
	}
	return ""
}

// Like xStr but without the trim, for values a person chose rather than a generator emitted -
// passwords and auth strings, where a leading or trailing space can be part of the secret.
internal fun JSONObject?.xStrRaw(key: String): String = xScalarString(this.xOpt(key))

// xStrOf without the trim - same reasoning as xStrRaw.
internal fun JSONObject?.xStrRawOf(vararg keys: String): String {
	for (key in keys) {
		val value = this.xStrRaw(key)
		if (value.isNotEmpty()) return value
	}
	return ""
}

// Reads key as an integer, accepting a quoted number or a float.
internal fun JSONObject?.xInt(key: String): Int {
	val value = this.xOpt(key) ?: return 0
	if (value is Boolean) return 0
	// A whole number, whether written as one, as "443", or as 443.0; a fraction is not an integer
	// and Xray refuses it, so it reads as nothing here rather than as its truncation.
	val decimal = when (value) {
		is Number -> value.toDouble()
		else -> value.toString().trim().trim('"').ifEmpty { return 0 }.toDoubleOrNull() ?: return 0
	}
	if (decimal != Math.floor(decimal) || decimal > Int.MAX_VALUE || decimal < Int.MIN_VALUE) return 0
	return decimal.toInt()
}

// Reads key as a 64-bit integer, for values such as QUIC window sizes.
internal fun JSONObject?.xLong(key: String): Long {
	val value = this.xOpt(key) ?: return 0L
	if (value is Number) return value.toLong()
	if (value is Boolean) return 0L
	val text = value.toString().trim().trim('"')
	if (text.isEmpty()) return 0L
	text.toLongOrNull()?.let { return it }
	text.toDoubleOrNull()?.let { return it.toLong() }
	return 0L
}

// Reads key as a boolean, accepting "true"/"false" strings and 0/1.
internal fun JSONObject?.xBool(key: String): Boolean {
	val value = this.xOpt(key) ?: return false
	if (value is Boolean) return value
	if (value is Number) return value.toDouble() != 0.0
	return when (value.toString().trim().trim('"').lowercase()) {
		"true", "1", "yes", "on" -> true
		else -> false
	}
}

// True when key is present and not JSON null.
internal fun JSONObject?.xHas(key: String): Boolean = this.xOpt(key) != null

// True when sendThrough names a real local address to bind to. Xray's own default is "0.0.0.0",
// and "::" is the same thing for IPv6; neither binds anything, so neither is worth reporting.
internal fun JSONObject?.xBindsLocalAddress(): Boolean {
	val address = this.xStr("sendThrough")
	return address.isNotEmpty() && address != "0.0.0.0" && address != "::"
}

// True when a sockopt asks for a TCP keepalive of its own. Zero and absent both leave Xray's own
// 45s default alone; a positive value overrides it and a negative one switches it off.
internal fun JSONObject?.xAsksForKeepAlive(): Boolean =
	this.xInt("tcpKeepAliveIdle") != 0 || this.xInt("tcpKeepAliveInterval") != 0

// Reads a string list, accepting either a JSON array or a single comma-separated string, matching
// Xray's own StringList type. Empty entries are dropped.
internal fun JSONObject?.xStrList(key: String): List<String> {
	val value = this.xOpt(key) ?: return emptyList()
	if (value is JSONArray) {
		val out = ArrayList<String>(value.length())
		for (i in 0 until value.length()) {
			val raw = value.opt(i)
			val item = xScalarString(if (raw === JSONObject.NULL) null else raw).trim()
			if (item.isNotEmpty()) out.add(item)
		}
		return out
	}
	return xScalarString(value).split(",").map { it.trim() }.filter { it.isNotEmpty() }
}

// Reads the objects of an array field, skipping nulls and non-objects.
internal fun JSONObject?.xObjList(key: String): List<JSONObject> {
	val entries = this.xArr(key) ?: return emptyList()
	val out = ArrayList<JSONObject>(entries.length())
	for (i in 0 until entries.length()) {
		(entries.opt(i) as? JSONObject)?.let { out.add(it) }
	}
	return out
}

// The outbound's protocol as Xray reads it: lowercased, since Xray lowercases the name before
// matching it, and a configuration written "VLESS" runs there.
internal fun JSONObject?.xrayProtocol(): String = xStr("protocol").lowercase()

// A server as a VLESS/VMess outbound gives it. Current Xray writes the fields straight into
// settings, where the settings object is the user as well; generators still write the vnext/users
// pair, and one vnext with several users is several servers.
internal class XrayEndpoint(val address: String, val port: Int, val user: JSONObject)

// The reason a node with no server a client could reach is left out, worded alike in every pass.
internal fun unusableServerRefusal(proto: String, address: String, port: Int): String =
	"the $proto outbound has no usable server address (\"$address\", port $port)"

// The reason a node with nothing to authenticate with is left out, worded alike in every pass.
internal fun missingCredentialRefusal(proto: String, credential: String): String =
	"the $proto outbound has no $credential"

// The EDNS client subnet Xray sends for a clientIp, masked as it masks one - /24 for IPv4, /96 for
// IPv6 - or null for anything but an address, which Xray does not take there.
internal fun xrayClientSubnet(raw: String): String? {
	val text = raw.trim()
	if (!isIpLiteral(text)) return null
	val bytes = InetAddress.getByName(text).address
	val bits = if (bytes.size == 4) 24 else 96
	for (i in bits / 8 until bytes.size) bytes[i] = 0
	val masked = InetAddress.getByAddress(bytes).hostAddress ?: return null
	return "$masked/$bits"
}

// One of WireGuard's reserved bytes as Xray reads it - a whole number from 0 to 255 - or null:
// cutting 1.5 down to 1, or 300 to 44, would carry a byte the config never held.
internal fun xrayReservedByte(value: Any?): Int? {
	val number = (value as? Number)?.toDouble() ?: return null
	if (number % 1.0 != 0.0 || number < 0 || number > 255) return null
	return number.toInt()
}

// The note for a reserved value that is not a byte, worded alike in every pass.
internal fun reservedNotByteNote(value: Any?): String {
	val held = if (value is Number) "$value, which is" else "something that is"
	return "wireguard reserved holds $held not a byte, so it was dropped"
}

// WireGuard's reserved field is three bytes; both cores refuse any other length.
internal const val WG_RESERVED_BYTES = 3

// Accepts the reserved bytes as a JSON array or a base64 string; anything else drops the lot, named
// through notByte rather than cut down to a byte the config never held.
internal fun parseReserved(raw: Any?, notByte: (Any?) -> Unit): ByteArray? {
	if (raw == null) return null
	if (raw is JSONArray) {
		val out = ByteArray(raw.length())
		// A list of another length is named for its length by the caller, so only one the cores could
		// take has its values read.
		if (raw.length() != WG_RESERVED_BYTES) return out
		for (i in 0 until raw.length()) {
			val value = raw.opt(i)
			out[i] = (xrayReservedByte(value) ?: run { notByte(value); return null }).toByte()
		}
		return out
	}
	val text = xScalarString(raw).trim()
	if (text.isEmpty()) return null
	return decodeBase64Any(text) ?: run { notByte(raw); null }
}

// A server's expected answers as Xray reads them: expectedIPs, or expectIPs when that is empty, in
// either of StringList's forms - both passes read them here, so they cannot disagree.
internal fun JSONObject?.xExpectedIps(): List<String> =
	xStrList("expectedIPs").ifEmpty { xStrList("expectIPs") }

// Whether Xray asks its first server alone about a name no domains match: with disableFallback, or
// when every server keeps out of the order, its list of the rest is empty.
internal fun xrayAsksFirstAlone(dns: JSONObject?): Boolean {
	if (dns.xBool("disableFallback")) return true
	val servers = dns.xArr("servers") ?: return false
	return servers.length() > 0 && (0 until servers.length()).all { i ->
		(servers.opt(i) as? JSONObject).xBool("skipFallback")
	}
}

// Xray's first server, as written: the address of an object entry or the entry itself.
internal fun xrayFirstServer(dns: JSONObject?): String {
	val first = dns.xArr("servers")?.opt(0)
	return ((first as? JSONObject)?.xStr("address") ?: first as? String).orEmpty().trim()
}

// Why that first server cannot answer those names here, worded alike in every pass.
internal fun firstServerNotDefault(raw: String): String =
	"dns server \"$raw\" is the only one Xray asks about a name no domains match, and it cannot be the " +
		"default here, so the default is chosen as when Xray moves on"

// Why the answer filter of a server with finalQuery is dropped, worded alike in every pass.
internal const val FINAL_QUERY_FILTER_REASON = "with finalQuery Xray asks no server after this one, so a " +
	"failed answer returns nothing, which has no form here, and the answer is taken as it comes"

// Why an answer filter is dropped when Xray asks its first server alone, worded alike in every pass:
// it then moves on from no answer to another server.
internal fun firstAloneFilterReason(first: Boolean): String = if (first) {
	"Xray asks this server alone about a name no domains match and returns nothing for an answer that " +
		"fails it, which has no form here, so the answer is taken as it comes"
} else {
	"Xray asks only its first server about a name no domains match, so it never decides"
}

// The reason a clientIp that is not an address is left out, worded alike in every pass.
internal fun unreadableClientIp(field: String, raw: String): String =
	"$field \"$raw\" is not an address - Xray sends only an address as the client subnet - so it was dropped"

// A Hysteria2 node's password, said with where Xray keeps it, since a node written the way Xray
// takes it has it in the transport rather than beside the address.
internal val MISSING_HYSTERIA2_PASSWORD_REFUSAL = missingCredentialRefusal("hysteria2", "password") +
	" (Xray keeps it in streamSettings.hysteriaSettings.auth)"

// Xray has no default Shadowsocks method: its parser answers an empty one with "unknown cipher
// method" and refuses the configuration, so a node without one never worked.
internal const val MISSING_SS_METHOD_REFUSAL = "shadowsocks method is empty, and Xray has no default for it"

// The tag an outbound dials through: proxySettings.tag, else sockopt.dialerProxy - with both, which
// Xray refuses, the first (chainConflictNote). streamSettings has no dialerProxy of its own in Xray.
internal fun xrayChainTag(outbound: JSONObject): String {
	outbound.xObj("proxySettings").xStr("tag").takeIf { it.isNotEmpty() }?.let { return it }
	return outbound.xObj("streamSettings").xObj("sockopt").xStr("dialerProxy")
}

// Xray refuses an outbound naming its chain both ways (xray.go: "proxySettings.tag is conflicted with
// sockopt.dialerProxy"); every pass follows proxySettings.tag instead, so the node connects all the same.
internal fun chainConflictNote(outbound: JSONObject): String? {
	val byTag = outbound.xObj("proxySettings").xStr("tag")
	val bySockopt = outbound.xObj("streamSettings").xObj("sockopt").xStr("dialerProxy")
	if (byTag.isEmpty() || bySockopt.isEmpty()) return null
	return "proxySettings.tag and sockopt.dialerProxy both name a chain - Xray refuses the " +
		"configuration over it - so proxySettings.tag \"$byTag\" was followed"
}

// Why Xray never connects an outbound through its chain, or null: it runs on through proxies and through
// a freedom that dials through another, and a freedom that dials straight out ends it; a tag no outbound
// has, blackhole, dns, loopback, a proxy refused itself or a circle back to one passed ends it unconnected.
internal fun deadChainReason(outbound: JSONObject, outbounds: List<JSONObject>): String? {
	val byTag = outbounds.filter { it.xStr("tag").isNotEmpty() }.associateBy { it.xStr("tag") }
	val first = xrayChainTag(outbound).takeIf { it.isNotEmpty() } ?: return null
	val passed = Collections.newSetFromMap(IdentityHashMap<JSONObject, Boolean>()).apply { add(outbound) }
	val never = "its chain through \"$first\" never connects in Xray:"
	var via = first
	while (true) {
		val next = byTag[via] ?: return "$never \"$via\" is no outbound here"
		val proto = next.xrayProtocol()
		if (proto != "freedom" && proto !in SingBoxProtocols.XRAY_PROTOCOLS_PROXY) {
			return "$never \"$via\" is a $proto outbound"
		}
		if (proto != "freedom" && securityRefusal(next.xObj("streamSettings")) != null) {
			return "$never \"$via\" is refused itself"
		}
		if (!passed.add(next)) return "$never it comes back round"
		via = xrayChainTag(next).takeIf { it.isNotEmpty() } ?: return null
	}
}

// Xray reads a VLESS "seed" beside the server and then leaves it unused - the line that would hand
// it on is commented out - so it does nothing, in Xray as in every pass, and each says so.
internal const val UNUSED_VLESS_SEED = "vless settings.seed is read by Xray but never used, so it " +
	"does nothing, in Xray as here"

// The first server of a socks or http outbound with the name and password of its first user - the
// four things every writer of one reads. Written without a server list, as Xray reads one too, it is
// the address beside the rest, with a user only when one is named: Xray drops a lone password.
internal data class CredentialedServer(val address: String, val port: Int, val username: String,
	val password: String, val hasUser: Boolean)

internal fun credentialedServer(settings: JSONObject?): CredentialedServer? {
	if (settings == null) return null
	val server = settings.optJSONArray("servers")?.optJSONObject(0)
	if (server == null) {
		if (settings.xStr("address").isEmpty()) return null
		val user = settings.optString("user", "")
		return CredentialedServer(
			settings.optString("address", ""), settings.optInt("port", 0),
			user, if (user.isEmpty()) "" else settings.optString("pass", ""), user.isNotEmpty()
		)
	}
	val user = server.optJSONArray("users")?.optJSONObject(0)
	return CredentialedServer(
		server.optString("address", ""), server.optInt("port", 0),
		user?.optString("user", "") ?: "", user?.optString("pass", "") ?: "",
		(server.optJSONArray("users")?.length() ?: 0) > 0
	)
}

// The server list each protocol keeps beside a written-out address.
private val FLAT_LISTS = mapOf(
	"vless" to "vnext", "vmess" to "vnext",
	"trojan" to "servers", "shadowsocks" to "servers", "http" to "servers", "socks" to "servers"
)

// What a dns outbound sets that no core carries - each answers DNS with its own module, so the
// outbound's server, rewrites and rules are lost - in the same words in both passes; null for none.
internal fun dnsOutboundSettingsNote(outbound: JSONObject): String? {
	val settings = outbound.xObj("settings") ?: return null
	val keys = settings.keys().asSequence().filter { it != "userLevel" }.sorted().toList()
	if (keys.isEmpty()) return null
	return "${keys.joinToString(", ")} of the dns outbound have no form in the core's own DNS handling, " +
		"so they were dropped"
}

// The outbound as Xray reads it, before any reader here sees it: an address written into the settings
// drops the server list beside it ("if c.Address != nil"), and streamSettings.method stands for its
// network ("c.Network = c.Method"). The same object when none applies.
internal fun xrayAsRead(outbound: JSONObject): JSONObject {
	// A node copied out of a sing-box configuration is first the outbound it stands for.
	val written = singBoxShapedAsXray(outbound)
	var read = written
	val list = FLAT_LISTS[written.xrayProtocol()]
	val settings = written.optJSONObject("settings")
	if (list != null && settings != null && settings.xStr("address").isNotEmpty() && settings.has(list)) {
		read = jsonCopy(written)
		read.getJSONObject("settings").remove(list)
	}
	val method = written.optJSONObject("streamSettings")?.xStr("method").orEmpty()
	if (method.isNotEmpty()) {
		if (read === written) read = jsonCopy(written)
		read.getJSONObject("streamSettings").put("network", method).remove("method")
	}
	return read
}

// A VLESS, Trojan or Hysteria2 node copied out of a sing-box configuration - its server, port and
// credential beside the protocol; the Shadowsocks, VMess and TUIC readers take that form themselves.
internal fun singBoxShaped(outbound: JSONObject): Boolean =
	outbound.xObj("settings") == null && outbound.xStr("server").isNotEmpty() &&
		outbound.xrayProtocol() in setOf("vless", "trojan", "hysteria2")

// A node singBoxShaped as the outbound every reader takes; one whose stream stands in a block no pass reads
// stays as written, for every pass to leave out. Any other outbound comes back as the same object.
private fun singBoxShapedAsXray(outbound: JSONObject): JSONObject {
	if (!singBoxShaped(outbound) || singBoxStreamBlock(outbound, outbound.xrayProtocol()) != null) {
		return outbound
	}
	val read = jsonCopy(outbound)
	val server = JSONObject().put("address", read.remove("server")).put("port", read.remove("server_port"))
	val settings = when (outbound.xrayProtocol()) {
		"vless" -> {
			val user = JSONObject().put("id", read.remove("uuid")).put("flow", read.remove("flow"))
				.put("encryption", read.remove("encryption") ?: "none")
			JSONObject().put("vnext", JSONArray().put(server.put("users", JSONArray().put(user))))
		}
		"trojan" -> {
			JSONObject().put("servers", JSONArray().put(server.put("password", read.remove("password"))))
		}
		else -> {
			for (field in HYSTERIA2_FIELDS) server.put(field, read.remove(field))
			// sing-box writes a hop range with a colon, which Xray refuses: the same range with a dash.
			val hops = when (val ports = read.remove("server_ports")) {
				null, JSONObject.NULL -> ""
				is JSONArray -> (0 until ports.length()).joinToString(",") { ports.optString(it) }
				else -> ports.toString()
			}
			if (hops.isNotEmpty()) server.put("ports", hops.replace(':', '-'))
			// sing-box 1.14 hops at random up to hop_interval_max, which Xray writes as a range of seconds.
			val low = durationInSeconds(server.xStr("hop_interval"))
			val high = durationInSeconds(read.xStr("hop_interval_max"))
			if (low != null && high != null && high > low) server.put("hop_interval", "$low-$high")
			server
		}
	}
	return read.put("settings", settings)
}

// The fields a sing-box Hysteria2 node keeps beside its server, which the Hysteria readers take in settings.
private val HYSTERIA2_FIELDS = listOf("password", "up_mbps", "down_mbps", "obfs", "tls", "hop_interval")

// Why a node keeps what it connects by in a block written as sing-box writes it, which no pass reads - a
// VMess, VLESS or Trojan node's TLS or transport, a Hysteria2 node's CA or pin - or null: it would dial as
// it never does, so the documents leave it out and a link keeps it as written.
internal fun singBoxBlockOf(outbound: JSONObject): String? {
	// The links read a node keyed by type, as sing-box keys it, as the protocol it names.
	val proto = outbound.xrayProtocol().ifEmpty { outbound.xStr("type").lowercase() }
	if (proto == "hysteria2") {
		val settings = outbound.xObj("settings") ?: return null
		val block = settings.xObj("tls")
		val trusted = block.xStrList("certificate").isNotEmpty() ||
			block.xStr("certificate_path").isNotEmpty() ||
			block.xStrList("certificate_sha256").isNotEmpty() ||
			block.xStrList("certificate_public_key_sha256").isNotEmpty()
		val tls = hysteriaTls(settings, outbound.xObj("streamSettings"))
		if (!trusted || tls.insecure || tls.pin.isNotEmpty()) return null
		return "its tls block names a CA or pin of its own as sing-box writes it, which no mode translates " +
			"for hysteria2, and without it the server would be checked against the system's roots"
	}
	// A node Xray has whole in its settings it reads past a block it does not know. Any other one a reader
	// may take from the fields beside the protocol, or by sing-box's type key, where the block counts.
	if (xrayWhole(outbound)) return null
	return singBoxStreamBlock(outbound, proto)
}

// Whether Xray reads a VMess, VLESS or Trojan node whole from settings: a server, a port and a credential.
private fun xrayWhole(outbound: JSONObject): Boolean {
	val settings = outbound.xObj("settings") ?: return false
	// An address written at all is the server Xray reads, the list beside it dropped, even a blank one.
	if (settings.xHas("address") && settings.xStr("address").isEmpty()) return false
	val whole = { address: String, port: Int, credential: String ->
		address.isNotEmpty() && port in 1..65535 && credential.isNotEmpty()
	}
	return when (outbound.xrayProtocol()) {
		"vmess", "vless" -> xrayEndpoints(settings).firstOrNull()
			?.let { whole(it.address, it.port, it.user.xStr("id")) } == true
		"trojan" -> xrayServers(settings, "address").firstOrNull()
			?.let { whole(it.xStr("address"), it.xInt("port"), it.xStrRaw("password")) } == true
		else -> false
	}
}

// Why a VMess, VLESS or Trojan node keeps its TLS or transport in a block as sing-box writes it, beside a
// streamSettings naming none, or null.
private fun singBoxStreamBlock(outbound: JSONObject, proto: String): String? {
	if (proto !in setOf("vmess", "vless", "trojan")) return null
	// What streamSettings secures or carries decides; naming no TLS, or raw TCP, it leaves that to the block.
	val stream = outbound.xObj("streamSettings")
	if (outbound.xObj("tls")?.xBool("enabled") == true && streamSecurity(stream) == "none") {
		return "its TLS is in a tls block as sing-box writes it, which no mode translates for $proto, and " +
			"without it the node would connect without TLS"
	}
	// Raw TCP, by either of Xray's names, is what a node with no transport dials anyway.
	val transport = outbound.xObj("transport").xStr("type")
		.takeUnless { it.lowercase() in setOf("tcp", "raw") }
	if (!transport.isNullOrEmpty() && streamNetwork(stream) == "tcp") {
		return "its transport is in a transport block as sing-box writes it, which no mode translates, and " +
			"without it the node would connect over raw TCP rather than $transport"
	}
	return null
}

// What every pass says, in these words, of a server list Xray did not read; null when there is none.
internal fun ignoredServerListNote(outbound: JSONObject): String? {
	val list = FLAT_LISTS[outbound.xrayProtocol()] ?: return null
	val settings = outbound.optJSONObject("settings") ?: return null
	if (settings.xStr("address").isEmpty() || settings.xObjList(list).isEmpty()) return null
	return "settings.$list is not read by Xray when an address is written beside it, so that address was used"
}

// One outbound per server it names: every server-and-user combination of an Xray outbound is a node
// somebody can connect to. Each copy names one server, so a builder reading the first reads the
// only one; a single-server outbound is returned untouched.
internal fun expandOutboundEndpoints(original: JSONObject): List<JSONObject> {
	val outbound = xrayAsRead(original)
	val settings = outbound.optJSONObject("settings") ?: return listOf(outbound)

	fun copyWith(newSettings: JSONObject): JSONObject {
		val copy = jsonCopy(outbound)
		copy.put("settings", newSettings)
		return copy
	}

	// VLESS and VMess: a server list, each entry holding the credentials that server accepts.
	val vnext = settings.optJSONArray("vnext")
	if (vnext != null && vnext.length() > 0) {
		val out = ArrayList<JSONObject>()
		for (i in 0 until vnext.length()) {
			val entry = vnext.optJSONObject(i) ?: continue
			val users = entry.optJSONArray("users")
			val count = if (users == null || users.length() == 0) 1 else users.length()
			for (j in 0 until count) {
				val oneEntry = jsonCopy(entry)
				if (users != null && users.length() > 0) {
					oneEntry.put("users", JSONArray().put(users.optJSONObject(j) ?: JSONObject()))
				}
				val oneSettings = jsonCopy(settings)
				oneSettings.put("vnext", JSONArray().put(oneEntry))
				out.add(copyWith(oneSettings))
			}
		}
		return if (out.size <= 1) listOf(outbound) else out
	}

	// Everything else that lists servers: one node each.
	val servers = settings.optJSONArray("servers")
	if (servers != null && servers.length() > 1) {
		val out = ArrayList<JSONObject>()
		for (i in 0 until servers.length()) {
			val one = servers.optJSONObject(i) ?: continue
			val oneSettings = jsonCopy(settings)
			oneSettings.put("servers", JSONArray().put(one))
			out.add(copyWith(oneSettings))
		}
		return if (out.size <= 1) listOf(outbound) else out
	}

	return listOf(outbound)
}

// Every name Xray gives a domain strategy - the routing and sockopt ones, freedom's UseIP and
// ForceIP families - as the strategy sing-box reads. The name spaces do not overlap, so one table
// serves every reader; a name it does not hold maps to nothing.
internal val XRAY_DOMAIN_STRATEGY = mapOf(
		"AsIs" to "",
		"UseIP" to "prefer_ipv4",
		"UseIPv4" to "ipv4_only",
		"UseIPv4v6" to "prefer_ipv4",
		"UseIPv6" to "ipv6_only",
		"UseIPv6v4" to "prefer_ipv6",
		"ForceIP" to "prefer_ipv4",
		"ForceIPv4" to "ipv4_only",
		"ForceIPv4v6" to "prefer_ipv4",
		"ForceIPv6" to "ipv6_only",
		"ForceIPv6v4" to "prefer_ipv6",
	"IPIfNonMatch" to "prefer_ipv4",
	"IPOnDemand" to "prefer_ipv4"
)

// A domain strategy under the name the table above holds, found as Xray finds it - lowercased one
// character at a time, as Go does, with no round trip through capitals - or the name as written.
internal fun xrayDomainStrategyName(name: String): String {
	val trimmed = name.trim()
	val lower = buildString { for (c in trimmed) append(c.lowercaseChar()) }
	return XRAY_DOMAIN_STRATEGY.keys.firstOrNull { it.lowercase() == lower } ?: trimmed
}

// Whether Xray's routing resolves a domain for its address rules: IPIfNonMatch and IPOnDemand, in
// any case; it reads every other name as AsIs, which does not.
internal fun xrayRoutingResolves(domainStrategy: String): Boolean =
	xrayDomainStrategyName(domainStrategy) in setOf("IPIfNonMatch", "IPOnDemand")

// What a core whose group picks the fastest node makes of a balancer's strategy, worded alike in every
// pass, or null for leastPing, which that is. Xray takes no strategy for random and refuses a name it
// does not know, so such a balancer never ran; the strategy is named as the configuration spells it.
internal fun balancerStrategyNote(balancer: JSONObject, core: String, group: String): String? {
	val named = balancer.xObj("strategy").xStr("type")
	val fastest = "it became a $group group that picks the fastest node"
	return when (named.lowercase()) {
		"" -> "names no strategy, so it ran Xray's default, random, which spreads traffic; $fastest"
		"random", "roundrobin" -> "uses the $named strategy, which spreads traffic; $fastest"
		"leastload" -> "picks by load, which $core does not measure; it became a $group group that " +
			"picks by latency instead"
		"leastping" -> null
		else -> "names the strategy \"$named\", which Xray does not have - it refuses such a " +
			"configuration - so the balancer never ran; $fastest"
	}
}

// The URL and interval a configuration probes its outbounds with, from either shape Xray writes:
// observatory keeps them as probeURL and probeInterval, burstObservatory inside pingConfig as
// destination and interval. The interval is whole seconds, or null when none is named.
internal class XrayProbe(val url: String, val intervalSeconds: Int?)

// The interface address assumed for a WireGuard node that names none, in both passes.
internal const val WIREGUARD_ASSUMED_ADDRESS = "10.0.0.2/32"

internal fun xrayProbe(xray: JSONObject): XrayProbe {
	val burst = xray.xObj("burstObservatory")?.xObj("pingConfig")
	if (burst != null) {
		return XrayProbe(burst.xStr("destination"), durationInSeconds(burst.xStr("interval")))
	}
	val plain = xray.xObj("observatory") ?: return XrayProbe("", null)
	// Panels write probeUrl; Go reads it for Xray's probeURL, and XrayKeys brings it to that here.
	val url = plain.xStr("probeURL")
	return XrayProbe(url, durationInSeconds(plain.xStr("probeInterval")))
}

// The security Xray runs a VMess user with: one of its three, matched regardless of case and with
// nothing trimmed; any other value, an empty one included, it reads as "auto" - none and zero too,
// which Xray's own server refuses from a client.
internal fun vmessSecurity(holder: JSONObject?): String {
	val raw = (holder?.opt("security") as? String).orEmpty().lowercase()
	return if (raw in VMESS_SECURITIES) raw else "auto"
}

private val VMESS_SECURITIES = setOf("aes-128-gcm", "chacha20-poly1305", "auto")

// What every pass says, in these words, of a security written that the user does not run with.
internal fun vmessSecurityNote(holder: JSONObject?): String? {
	val written = (holder?.opt("security") as? String).orEmpty().trim()
	if (written.isEmpty() || written.lowercase() == vmessSecurity(holder)) return null
	val why = if (written.lowercase() in setOf("none", "zero")) {
		"an up-to-date Xray server refuses it from a client"
	} else {
		"Xray knows no such security"
	}
	return "vmess security \"$written\" runs as auto: $why"
}

// Xray reads no alterId since 1.8.3 and runs VMess AEAD alone, the only kind its server takes; a core given
// one above 0 falls back to the legacy header, so every pass writes 0 and says so here - a negative one the
// cores read as 0 already.
internal fun vmessAlterIdNote(holder: JSONObject?): String? {
	val written = holder.xInt("alterId").takeIf { it != 0 } ?: holder.xInt("alter_id")
	if (written <= 0) return null
	return "vmess alterId $written asks for the legacy header, which Xray dropped in 1.8.3 for AEAD alone, " +
		"on its server as on its client; 0 was written"
}

// The servers a Trojan or Shadowsocks outbound names, as every pass reads them: settings.servers, or
// the settings themselves when they name a server, in the flat form - addressKeys are the fields
// that name one.
internal fun xrayServers(settings: JSONObject, vararg addressKeys: String): List<JSONObject> {
	val servers = settings.xObjList("servers")
	if (servers.isNotEmpty()) return servers
	val named = settings.xStrOf(*addressKeys).isNotEmpty() || settings.xStr("password").isNotEmpty()
	return if (named) listOf(settings) else emptyList()
}

// A Shadowsocks outbound's servers: as xrayServers reads them, or the outbound itself when it was
// copied out of a sing-box configuration and keeps its server there.
internal fun shadowsocksServers(outbound: JSONObject): List<JSONObject> =
	xrayServers(outbound.xObj("settings") ?: outbound, "address", "server")
		.ifEmpty { listOfNotNull(outbound.takeIf { it.has("server") }) }

// A configuration with its one outbound under "outbound" rather than in the "outbounds" list, read as
// the list every pass reads; any other configuration comes back as the same object.
internal fun xrayWithOutbounds(config: JSONObject): JSONObject {
	if (config.xArr("outbounds") != null) return config
	val single = config.xObj("outbound") ?: return config
	return jsonCopy(config).apply {
		remove("outbound")
		put("outbounds", JSONArray().put(single))
	}
}

internal fun xrayEndpoints(settings: JSONObject?): List<XrayEndpoint> {
	val out = ArrayList<XrayEndpoint>()
	for (next in settings.xObjList("vnext")) {
		val users = next.xObjList("users")
		if (users.isEmpty()) out.add(XrayEndpoint(next.xStr("address"), next.xInt("port"), JSONObject()))
		for (user in users) out.add(XrayEndpoint(next.xStr("address"), next.xInt("port"), user))
	}
	if (out.isEmpty() && settings != null &&
		(settings.xStr("address").isNotEmpty() || settings.xStr("id").isNotEmpty())
	) {
		out.add(XrayEndpoint(settings.xStr("address"), settings.xInt("port"), settings))
	}
	return out
}

internal fun isTruthy(value: Any?): Boolean {
	if (value == null || value === JSONObject.NULL) return false
	return when (value) {
		is Boolean -> value
		is Number -> value.toDouble() != 0.0
		is String -> value.isNotEmpty()
		is JSONArray -> value.length() > 0
		is JSONObject -> value.length() > 0
		else -> true
	}
}
