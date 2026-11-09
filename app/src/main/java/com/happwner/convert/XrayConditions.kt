package com.happwner.convert

import com.happwner.text.canonicalIp
import com.happwner.text.decodeBase64
import com.happwner.text.decodeBase64Any
import com.happwner.text.encodeBase64Std
import com.happwner.text.fromHex
import com.happwner.text.isIpLiteral
import com.happwner.text.parseInet4
import com.happwner.text.parseInet6
import com.happwner.text.splitHostPort
import com.happwner.text.toHex
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import org.json.JSONArray
import org.json.JSONObject

// What an entry of an Xray routing condition means.
internal object XrayConditions {

	// A name condition, already stripped of its prefix.
	internal sealed class Name {
		data class Exact(val value: String) : Name()
		data class Suffix(val value: String) : Name()
		data class Keyword(val value: String) : Name()
		data class Pattern(val value: String) : Name()
		data class Geosite(val value: String) : Name()
		// Names a file that ships with Xray, which neither core reads.
		object External : Name()
		// Empty, malformed, or a pattern that will not compile.
		object Unusable : Name()
	}

	// An address condition, already normalised.
	internal sealed class Address {
		data class Cidr(val value: String) : Address()
		data class Country(val code: String) : Address()
		data class NotCountry(val code: String) : Address()
		object Private : Address()
		// "geoip:!private": both cores answer "private" from their own tables, so its negation
		// needs no country data.
		object NotPrivate : Address()
		object External : Address()
		object Unusable : Address()
	}

	internal fun name(raw: String): Name {
		val entry = raw.trim()
		if (entry.isEmpty()) return Name.Unusable
		// A leading "!" is no prefix Xray reads for a name - it would look for those characters
		// themselves - so the entry is dropped rather than read as an exclusion it is not.
		if (entry.startsWith("!")) return Name.Unusable
		fun value(prefix: String) = entry.removePrefix(prefix).trim()
		return when {
			entry.startsWith("full:") -> value("full:").ifEmpty { null }?.let { Name.Exact(
				it) } ?: Name.Unusable
			entry.startsWith("domain:") -> value("domain:").ifEmpty { null }?.let { Name.Suffix(
				it) } ?: Name.Unusable
			entry.startsWith("keyword:") -> value("keyword:").ifEmpty { null }?.let { Name.Keyword(
				it) } ?: Name.Unusable
			entry.startsWith("geosite:") -> value("geosite:").ifEmpty { null }?.let { Name.Geosite(
				it) } ?: Name.Unusable
			entry.startsWith("regexp:") -> {
				val pattern = value("regexp:")
				if (XrayConditions.isUsableRegex(pattern)) Name.Pattern(pattern) else Name.Unusable
			}
			listOf("ext:", "ext-domain:", "ext-site:").any { entry.startsWith(it) } -> Name.External
			else -> Name.Keyword(entry)
		}
	}

	internal fun address(raw: String): Address {
		var entry = raw.trim()
		if (entry.isEmpty()) return Address.Unusable
		// Xray turns the match over for every leading "!", and for every one after "geoip:" too; what
		// stays turned over and is no country - a range, an external list - no core mirrors.
		var reverse = false
		while (entry.startsWith("!")) {
			entry = entry.substring(1)
			reverse = !reverse
		}
		if (entry.startsWith("geoip:")) {
			var code = entry.removePrefix("geoip:")
			while (code.startsWith("!")) {
				code = code.substring(1)
				reverse = !reverse
			}
			entry = "geoip:" + (if (reverse) "!" else "") + code
			reverse = false
		}
		if (reverse) return Address.Unusable
		return when {
			entry == "geoip:private" -> Address.Private
			entry == "geoip:!private" -> Address.NotPrivate
			entry.startsWith("geoip:!") ->
				entry.removePrefix("geoip:!").trim().ifEmpty { null }?.let { Address.NotCountry(it) }
					?: Address.Unusable
			entry.startsWith("geoip:") ->
				entry.removePrefix("geoip:").trim().ifEmpty { null }?.let { Address.Country(it) }
					?: Address.Unusable
			entry.startsWith("ext:") || entry.startsWith("ext-ip:") -> Address.External
			else -> XrayConditions.normalizedCidr(entry)?.let { Address.Cidr(it) } ?: Address.Unusable
		}
	}

	// The ports of a routing rule as Xray reads them - "80,443,1000-2000", one string or an array -
	// with 0 legal in a rule ("0-65535" is a common catch-all) though not for a server, and ranges
	// ordered low to high. Anything else would cost both cores the whole file: dropped, by name.
	internal class RulePorts(val singles: List<Int>, val ranges: List<Pair<Int, Int>>,
		val dropped: List<String>)

	internal fun rulePorts(value: Any?): RulePorts {
		val singles = mutableListOf<Int>()
		val ranges = mutableListOf<Pair<Int, Int>>()
		val dropped = mutableListOf<String>()
		val items = when (value) {
			null, JSONObject.NULL -> emptyList()
			is JSONArray -> (0 until value.length()).map { value.opt(it).toString() }
			else -> listOf(value.toString())
		}
		for (tok in items.flatMap { it.split(",") }.map { it.trim() }.filter { it.isNotEmpty() }) {
			val bounds = tok.split("-").map { it.trim().toIntOrNull()?.takeIf { port -> port in 0..65535 } }
			val low = bounds.getOrNull(0)
			val high = bounds.getOrNull(1)
			when {
				bounds.size == 1 && low != null -> singles.add(low)
				bounds.size == 2 && low != null && high != null && low <= high -> ranges.add(low to high)
				else -> dropped.add(tok)
			}
		}
		return RulePorts(singles, ranges, dropped)
	}

	// A routing address in the form both cores accept - a bare address gains its prefix length - or
	// null when it is not one.
	internal fun normalizedCidr(raw: String): String? {
		val value = raw.trim()
		val slash = value.lastIndexOf('/')
		val addr = if (slash < 0) value else value.substring(0, slash)
		val maskText = if (slash < 0) null else value.substring(slash + 1)
		val isIpv6 = addr.contains(':')
		if (isIpv6) {
			// A bare colon-form address, checked loosely: the core does the
			// strict reading, this only keeps out what is plainly not one.
			if (!addr.all { it.isLetterOrDigit() || it == ':' || it == '.' }) return null
			if (!addr.contains("::") && addr.count { it == ':' } != 7) return null
		} else {
			val parts = addr.split('.')
			if (parts.size != 4) return null
			for (part in parts) {
				if (part.isEmpty() || part.length > 3 || !part.all { it in '0'..'9' }) return null
				if (part.toInt() > 255) return null
			}
		}
		val maxMask = if (isIpv6) 128 else 32
		if (maskText == null) return "$addr/$maxMask"
		val mask = maskText.toIntOrNull() ?: return null
		if (mask < 0 || mask > maxMask) return null
		return "$addr/$mask"
	}

	// What Go's RE2 does not have, and Java's engine does: a pattern using any of these compiles
	// here and is refused by both cores - with the whole file. Lookahead and lookbehind, atomic
	// groups, conditionals, backreferences, possessive quantifiers, and the \\G and \\Z anchors.
	private val NOT_IN_RE2 = Regex(
		"""\(\?[=!<>]|\(\?<[=!]|\(\?\(|(?<!\\)\\[1-9]|(?<!\\)\\k<|[*+?}]\+(?![?*+])|(?<!\\)\\[GZ]"""
	)

	// True when the pattern compiles and stays within what both cores' engine reads. The cores
	// run Go's RE2, not Java's regex, so compiling here is necessary and not sufficient.
	internal fun isUsableRegex(raw: String): Boolean = try {
		// Go names a group "(?P<name>...)"; Java only reads "(?<name>...)", and they mean the same.
		Regex(raw.replace("(?P<", "(?<"))
		raw.isNotEmpty() && !NOT_IN_RE2.containsMatchIn(raw)
	} catch (_: Exception) {
		false
	}
}

// Whether a value is shaped the way the cores insist on. Absence is refused elsewhere; these catch a
// value that is present and wrong, which would be written out and cost the whole document at load.
// Each check is the core's own rule, taken from what it does with the value, not guessed.

// A REALITY short id is read as hexadecimal, up to eight bytes.
internal fun isUsableShortId(v: String): Boolean {
	if (v.isEmpty()) return true          // absent is legal: the server may not use one
	if (v.length > 16 || v.length % 2 != 0) return false
	return v.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
}

// A REALITY public key is Go's raw URL-safe base64 of 32 bytes - 43 characters of A-Z, a-z, 0-9,
// '-' and '_', no padding - the one form Xray and both cores decode it in.
internal fun isUsableRealityKey(v: String): Boolean =
	v.length == 43 && v.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }

// A PEM block written inline: its lines in an array, as Xray reads it, or as one string; null for
// anything else.
internal fun pemText(value: Any?): String? = when (value) {
	is JSONArray -> (0 until value.length()).joinToString("\n") { value.optString(it) }
	is String -> value
	else -> null
}

// Whether an inline certificate reads as X.509: its PEM lines as an array or as one string, and
// nothing else - a number, or no text at all, is no certificate.
internal fun isReadableCertificate(value: Any?): Boolean {
	val pem = pemText(value)?.trim() ?: return false
	if (pem.isEmpty()) return false
	return try {
		CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(pem.toByteArray()))
		true
	} catch (_: Exception) {
		false
	}
}

// The SHA-256 of an inline certificate in hex when it reads as the server's own, the one CA a pin can
// stand in for: a single certificate naming one of the hosts as Go matches names, not marked to sign
// others as the CAs an Xray server issues from are. Null for anything else.
internal fun ownCertificatePin(pem: String, hosts: List<String>): String? = try {
	val certificates = CertificateFactory.getInstance("X.509")
		.generateCertificates(ByteArrayInputStream(pem.toByteArray()))
	val certificate = certificates.singleOrNull() as? X509Certificate
	val names = certificate?.subjectAlternativeNames.orEmpty()
	when {
		certificate == null || certificate.keyUsage?.getOrNull(KEY_CERT_SIGN) == true -> null
		hosts.none { host -> names.any { coversHost(it, host) } } -> null
		else -> toHex(MessageDigest.getInstance("SHA-256").digest(certificate.encoded))
	}
} catch (_: Exception) {
	null
}

// Whether a subject alternative name covers a host as Go checks it: an address only by an address, a
// name case-blind, with "*." standing for its first label.
private fun coversHost(name: List<*>, host: String): Boolean {
	val value = name.getOrNull(1) as? String ?: return false
	canonicalIp(host.removePrefix("[").removeSuffix("]"))?.let {
		return name[0] == SAN_IP_ADDRESS && canonicalIp(value) == it
	}
	if (name[0] != SAN_DNS_NAME) return false
	val wanted = host.removeSuffix(".").lowercase()
	val pattern = value.lowercase()
	val label = wanted.substringBefore('.')
	return pattern == wanted || pattern.startsWith("*.") && label.isNotEmpty() && label != wanted &&
		wanted.substring(label.length + 1) == pattern.substring(2)
}

// Where java.security.cert puts keyCertSign among the key usages, and its numbers for the two kinds of
// alternative name a host is matched against.
private const val KEY_CERT_SIGN = 5
private const val SAN_DNS_NAME = 2
private const val SAN_IP_ADDRESS = 7

// The note for a certificate that signs others, worded alike in both passes.
internal const val ISSUE_CERTIFICATE_NOTE = "tlsSettings.certificates with usage \"issue\" signs other " +
	"certificates, which is a server's job, so it was dropped"

// A client certificate with its key as a core loads them: the certificate X.509, the key PKCS#8 or the
// SEC1 or PKCS#1 form its algorithm names, the two one pair - proved by a signature, since sing-box
// refuses the whole document over a key that is not the certificate's own.
internal fun isClientKeyPair(certificatePem: String, keyPem: String): Boolean {
	return try {
		val certificate = CertificateFactory.getInstance("X.509")
			.generateCertificate(ByteArrayInputStream(certificatePem.toByteArray()))
		val publicKey = certificate.publicKey
		val privateKey = pemPrivateKey(keyPem, publicKey) ?: return false
		val algorithm = when (publicKey.algorithm) {
			"EC" -> "SHA256withECDSA"
			"RSA" -> "SHA256withRSA"
			else -> return false
		}
		val probe = "client key pair".toByteArray()
		val signature = Signature.getInstance(algorithm).run { initSign(privateKey); update(probe); sign() }
		Signature.getInstance(algorithm).run { initVerify(publicKey); update(probe); verify(signature) }
	} catch (_: Exception) {
		false
	}
}

// A PEM private key read as PKCS#8: as written, or a SEC1 or PKCS#1 body wrapped under the algorithm
// the certificate's public key names - the identifier its own encoding opens with.
private fun pemPrivateKey(pem: String, publicKey: PublicKey): PrivateKey? {
	val label = Regex("-----BEGIN ([A-Z ]+)-----").find(pem)?.groupValues?.get(1) ?: return null
	val body = pem.substringAfter("-----BEGIN $label-----").substringBefore("-----END $label-----")
	val der = decodeBase64Any(body.filterNot { it.isWhitespace() }) ?: return null
	val pkcs8 = when (label) {
		"PRIVATE KEY" -> der
		"EC PRIVATE KEY", "RSA PRIVATE KEY" -> {
			val algorithm = firstDerElement(publicKey.encoded) ?: return null
			derElement(0x30, byteArrayOf(2, 1, 0) + algorithm + derElement(0x04, der))
		}
		else -> return null
	}
	return KeyFactory.getInstance(publicKey.algorithm).generatePrivate(PKCS8EncodedKeySpec(pkcs8))
}

// One DER element: its tag, its length in the short or the long form, its content.
private fun derElement(tag: Int, content: ByteArray): ByteArray {
	val size = content.size
	val length = when {
		size < 0x80 -> byteArrayOf(size.toByte())
		size < 0x100 -> byteArrayOf(0x81.toByte(), size.toByte())
		else -> byteArrayOf(0x82.toByte(), (size shr 8).toByte(), size.toByte())
	}
	return byteArrayOf(tag.toByte()) + length + content
}

// The first element inside a DER sequence, whole - in a public key's encoding, its algorithm identifier.
private fun firstDerElement(sequence: ByteArray): ByteArray? {
	// The content length at a length byte, and the length's own size.
	fun lengthAt(at: Int): Pair<Int, Int>? {
		val first = sequence.getOrNull(at)?.toInt()?.and(0xff) ?: return null
		if (first < 0x80) return first to 1
		val count = first and 0x7f
		if (count !in 1..2) return null
		var value = 0
		for (k in 1..count) {
			val byte = sequence.getOrNull(at + k)?.toInt()?.and(0xff) ?: return null
			value = (value shl 8) or byte
		}
		return value to 1 + count
	}
	val outer = lengthAt(1) ?: return null
	val start = 1 + outer.second
	val inner = lengthAt(start + 1) ?: return null
	val end = start + 1 + inner.second + inner.first
	return if (end <= sequence.size) sequence.copyOfRange(start, end) else null
}

// The 32 bytes a WireGuard key stands for, read as Xray's ParseWireGuardKey reads it - hex, or
// base64 in the alphabet its + and / point to, one "=" optional - or null when it names no key.
internal fun wireguardKeyBytes(v: String): ByteArray? {
	if (v.length == 64) fromHex(v)?.let { return it }
	val text = v.removeSuffix("=")
	if (text.isEmpty() || text.any { it.isWhitespace() }) return null
	val bytes = decodeBase64(text, urlSafe = '+' !in text && '/' !in text, padded = false) ?: return null
	return bytes.takeIf { it.size == WIREGUARD_KEY_BYTES }
}

// A WireGuard key in the form both target cores decode, or the text unchanged when it is not a
// key - the refusal that names it comes from wireguardKeyRefusal, not from here.
internal fun canonicalWireguardKey(v: String): String =
	wireguardKeyBytes(v)?.let { encodeBase64Std(it) } ?: v

private const val WIREGUARD_KEY_BYTES = 32

// The refusal for a WireGuard key that names no 32 bytes, or null: Xray cannot load or dial with
// it. Checked, once wireguardRefusal has found a secret key, for it, every peer's public key and any
// preshared key.
internal fun wireguardKeyRefusal(settings: JSONObject): String? {
	val secret = settings.optString("secretKey", "")
	if (wireguardKeyBytes(secret) == null) {
		return "the wireguard secretKey is not a key of 32 bytes in hex or base64, so the node never worked"
	}
	val peers = settings.optJSONArray("peers") ?: return null
	for (i in 0 until peers.length()) {
		val peer = peers.optJSONObject(i) ?: continue
		for (field in listOf("publicKey", "preSharedKey")) {
			val key = peer.optString(field, "")
			if (key.isNotEmpty() && wireguardKeyBytes(key) == null) {
				return "a WireGuard peer's $field is not a key of 32 bytes in hex or base64, so the node " +
					"never worked"
			}
		}
	}
	return null
}

// Why a WireGuard node can never connect, or null - every pass leaves it out in these words: Xray
// refuses one without a secretKey it can decode ("key must not be empty"), and a tunnel with no peer
// it can reach has no one to hand-shake with. One with some keeps those (wireguardDroppedPeerNotes).
internal fun wireguardRefusal(settings: JSONObject?): String? {
	if (settings == null || settings.optString("secretKey", "").isEmpty()) {
		return "the wireguard outbound has no secretKey, which Xray refuses, so the node never worked"
	}
	if (wireguardKeyBytes(settings.optString("secretKey", "")) == null) return wireguardKeyRefusal(settings)
	val peers = settings.optJSONArray("peers")
	if (peers == null || peers.length() == 0) {
		return "the wireguard outbound has no peer, so the tunnel has no one to reach"
	}
	if (wireguardUsablePeers(settings).isNotEmpty()) return null
	return wireguardPeerTrouble(settings)
}

// The first trouble among a tunnel's peers, in the order Xray meets it and in the words every pass
// refuses with: Xray fails the whole tunnel over any, so a pass that hands the node on to Xray as
// written leaves it out over one; null when every peer can be reached.
internal fun wireguardPeerTrouble(settings: JSONObject): String? {
	wireguardKeyRefusal(settings)?.let { return it }
	val peers = settings.optJSONArray("peers") ?: return null
	for (i in 0 until peers.length()) {
		val peer = peers.optJSONObject(i)
		if (peer?.optString("publicKey", "").isNullOrEmpty()) {
			return "a WireGuard peer has no publicKey, so the tunnel has no one to reach"
		}
		// Xray refuses a peer without an endpoint ("peer without endpoint"), and one it cannot split
		// into host and port fails the whole tunnel, not just that peer.
		val endpoint = peer?.opt("endpoint")?.takeIf { it != JSONObject.NULL }
		if (endpoint == null || endpoint == "") {
			return "a WireGuard peer has no endpoint, which Xray refuses, so the node never worked"
		}
		if (!isHostPort(endpoint)) {
			return "a WireGuard peer's endpoint \"$endpoint\" is not host:port, which fails Xray's whole " +
				"tunnel, so the node never worked"
		}
	}
	return null
}

// Whether an endpoint names a host and a port as Xray reads one: a port past 65535 fails its whole
// tunnel ("invalid port") as a split that fails does.
private fun isHostPort(endpoint: Any?): Boolean =
	endpoint is String && splitHostPort(endpoint).port?.let { it <= 65535 } == true

// What keeps one WireGuard peer from being reached, or null when it can be: a key naming no 32 bytes,
// no public key, no endpoint, or one that is not host:port - Xray refuses the whole tunnel over any.
internal fun wireguardPeerProblem(peer: JSONObject): String? {
	for (field in listOf("publicKey", "preSharedKey")) {
		val key = peer.optString(field, "")
		if (key.isNotEmpty() && wireguardKeyBytes(key) == null) return "its $field is not a key of 32 bytes"
	}
	if (peer.optString("publicKey", "").isEmpty()) return "it has no publicKey"
	val endpoint = peer.opt("endpoint")?.takeIf { it != JSONObject.NULL }
	if (endpoint == null || endpoint == "") return "it has no endpoint"
	if (!isHostPort(endpoint)) return "its endpoint \"$endpoint\" is not host:port"
	return null
}

// The peers of a tunnel a core can reach, in their written order.
internal fun wireguardUsablePeers(settings: JSONObject): List<JSONObject> =
	settings.xObjList("peers").filter { wireguardPeerProblem(it) == null }

// Each peer left out of a tunnel that keeps others, worded alike in both passes: Xray refuses the whole
// tunnel over it, so a core runs the rest - and what that peer alone routed then goes nowhere.
internal fun wireguardDroppedPeerNotes(settings: JSONObject): List<String> {
	val peers = settings.optJSONArray("peers") ?: return emptyList()
	if (wireguardUsablePeers(settings).isEmpty()) return emptyList()
	val notes = ArrayList<String>()
	for (i in 0 until peers.length()) {
		val peer = peers.optJSONObject(i)
		val problem = if (peer == null) "it is not an object" else wireguardPeerProblem(peer) ?: continue
		val routed = peer?.xStrList("allowedIPs").orEmpty().ifEmpty { listOf("0.0.0.0/0", "::/0") }
		notes.add("WireGuard peer ${i + 1} was dropped because $problem, over which Xray refuses the whole " +
			"tunnel; the node keeps its other peers, and ${routed.joinToString(", ")} reaches none unless " +
			"one of theirs covers it")
	}
	return notes
}

// The length of a fake-IP pool in netip.ParsePrefix's spelling, which both cores read it in - no zone
// and no leading zero in the length - or null for one written otherwise.
internal fun fakeIpPoolBits(pool: String, ipv6: Boolean): Int? {
	val address = pool.substringBefore('/', "")
	val bits = pool.substringAfter('/', "")
	if (bits.isEmpty() || bits.length > 3 || bits.any { it !in '0'..'9' }) return null
	if (bits.length > 1 && bits[0] == '0') return null
	val readable = if (ipv6) '%' !in address && parseInet6(address) else parseInet4(address)
	return bits.toInt().takeIf { readable && it <= (if (ipv6) 128 else 32) }
}

// The note for a fake-IP pool left out, worded alike in both passes: a core refuses the whole document
// over one it does not take.
internal fun fakeIpPoolDroppedNote(pool: String): String =
	"fakedns ipPool \"$pool\" is no fake-IP range the core takes, so it was dropped"

// One WireGuard interface address as a prefix every core reads - an IP with its length, /32 or /128
// where none is written, the same one address - or null where it names no address at all.
internal fun wireguardInterfacePrefix(entry: Any?): String? {
	val text = (entry as? String)?.trim()?.takeIf { it.isNotEmpty() } ?: return null
	val ip = text.substringBefore('/')
	if ('%' in ip || !isIpLiteral(ip)) return null
	val width = if (parseInet4(ip)) 32 else 128
	val bits = if ('/' in text) text.substringAfter('/').toIntOrNull() ?: return null else width
	return if (bits in 0..width) "$ip/$bits" else null
}

// The note for an interface address left out, worded alike in both passes.
internal fun wireguardAddressDroppedNote(entry: Any?): String =
	"wireguard address \"$entry\" is no interface address (an IP, with or without its length), " +
		"so it was dropped"

// A UUID as every core parses it: eight-four-four-four-twelve hexadecimal digits.
internal fun isUsableUuid(v: String): Boolean {
	val parts = v.split('-')
	if (parts.size != 5) return false
	val lengths = listOf(8, 4, 4, 4, 12)
	return parts.zip(lengths).all { (part, want) ->
		part.length == want && part.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
	}
}

// A 2022-blake3 key is base64 of exactly the cipher's key length - 16 bytes for the 128-bit
// method, 32 for the others - and both cores refuse the whole document over one of the wrong
// size. A multi-user key is "iPSK:uPSK", each part of that length.
internal fun isUsable2022Key(method: String, key: String): Boolean {
	if (!method.startsWith("2022-blake3")) return true
	val want = if (method.contains("aes-128")) 16 else 32
	val expected = ((want + 2) / 3) * 4
	val parts = key.trim().split(':')
	if (parts.isEmpty() || parts.any { it.isEmpty() }) return false
	return parts.all { part ->
		part.length == expected && part.all {
			it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' || it == '-' || it == '_'
		}
	}
}

// The refusal for a 2022-blake3 key of the wrong length, or null: both cores refuse the whole
// document over it, so the node is not handed over, in any pass.
internal fun ss2022KeyRefusal(method: String, key: String): String? =
	if (isUsable2022Key(method, key)) null
	else "the $method key is not the length that method needs (16 bytes for aes-128, 32 otherwise); " +
		"both cores refuse the whole document over it, so the node was dropped"

// Whether Xray counts a rule condition as written: localPort and vlessRoute whenever they are there
// and not null - an empty one then matches nothing - and the rest when they list anything.
internal fun xrayConditionStated(field: String, value: Any?): Boolean = when {
	value == null || value === JSONObject.NULL -> false
	field == "localPort" || field == "vlessRoute" -> true
	value is JSONArray -> value.length() > 0
	else -> true
}

// Whether Xray calls a rule's webhook: only one with an address.
internal fun xrayWebhookStated(rule: JSONObject): Boolean =
	(rule.optJSONObject("webhook")?.opt("url") as? String).orEmpty().isNotEmpty()
