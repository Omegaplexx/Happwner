package com.happwner.convert

import com.happwner.text.fromHex
import org.json.JSONObject

// The clients a link is made for, as the URI mode's drop boxes name them: a box ticked for sing-box or
// mihomo is a person importing the links into that core's clients, which then connect from the link
// alone. With neither, a link is written as Xray reads it, and nothing in it is given up for another.
internal class LinkClients(val singBox: Boolean, val mihomo: Boolean) {
	companion object {
		val ANY = LinkClients(singBox = false, mihomo = false)
	}
}

// What a link scheme carries towards checking the server, as each kind of client reads it there: Xray's
// clients, mihomo, and the sing-box clients such as husi - a pin, the names to verify, the CA whole, the
// switch that skips the check, REALITY; a Shadowsocks plugin sends its host, which is the Host header too.
internal enum class LinkScheme(
	val label: String,
	val pin: Boolean,
	val mihomoPin: Boolean,
	val verifyNames: Boolean,
	val authority: Boolean,
	val mihomoInsecure: Boolean,
	val singBoxInsecure: Boolean,
	val mihomoChecks: Boolean = true,
	val sendsName: Boolean = true,
	val mihomoReality: Boolean = false
) {
	VLESS("vless", pin = true, mihomoPin = true, verifyNames = true, authority = true,
		mihomoInsecure = false, singBoxInsecure = false, mihomoReality = true),
	TROJAN("trojan", pin = true, mihomoPin = true, verifyNames = true, authority = true,
		mihomoInsecure = true, singBoxInsecure = true),
	VMESS("vmess", pin = true, mihomoPin = false, verifyNames = true, authority = false,
		mihomoInsecure = false, singBoxInsecure = true),
	HYSTERIA2("hysteria2", pin = true, mihomoPin = true, verifyNames = false, authority = false,
		mihomoInsecure = true, singBoxInsecure = true),
	HYSTERIA("hysteria", pin = false, mihomoPin = false, verifyNames = false, authority = false,
		mihomoInsecure = true, singBoxInsecure = true),
	TUIC("tuic", pin = false, mihomoPin = false, verifyNames = false, authority = false,
		mihomoInsecure = false, singBoxInsecure = true),
	HTTPS("https", pin = false, mihomoPin = false, verifyNames = false, authority = false,
		mihomoInsecure = false, singBoxInsecure = false, mihomoChecks = false),
	SHADOWSOCKS("shadowsocks", pin = false, mihomoPin = false, verifyNames = false, authority = false,
		mihomoInsecure = false, singBoxInsecure = false, sendsName = false)
}

// Why no link is made: refused, its reason the last note, where the box's client could not connect
// from it - or, not refused, no link form at all, where no client could.
internal class LinkStop(val reason: String, val refused: Boolean)

// A link's TLS once its clients are weighed: the name it sends, the pin and the CA it carries, and
// whether the CA is covered - carried, or what became of it said - or why there is no link.
internal class LinkTls(
	val sni: String,
	val pin: String,
	val authority: String,
	val authorityCovered: Boolean,
	val stop: LinkStop?
)

// The TLS a link writes for its clients, from what its scheme reads of the node: the name sent, the
// check skipped, the pins. A CA the server is verified against is pinned where it is the server's own
// certificate and goes whole as cert; a name to verify is sent where the clients check no other.
internal fun linkTls(
	streamSettings: JSONObject?, sent: String, insecure: Boolean, pins: List<String>, address: String,
	scheme: LinkScheme, clients: LinkClients, notes: MutableList<String>
): LinkTls {
	val tls = streamTls(streamSettings)
	val index = customAuthorityIndex(streamSettings)
	val dialed = sent.ifEmpty { address }
	// Who checks the server against the CA: not a client that reads the link's switch to skip the check,
	// nor mihomo dialing an https server, which it never checks.
	val xrayChecks = index != null && !insecure
	val mihomoChecks = index != null && scheme.mihomoChecks && !(insecure && scheme.mihomoInsecure)
	val singBoxChecks = index != null && !(insecure && scheme.singBoxInsecure)
	val pinRead = xrayChecks || mihomoChecks && scheme.mihomoPin
	val own = if (pins.isNotEmpty() || !scheme.pin || !pinRead) null else ownAuthorityPin(tls, dialed)
	val pin = linkPin(pins, own, scheme, clients, notes)
	val authority = if (!scheme.authority || index == null) "" else {
		inlineAuthorities(streamSettings).joinToString("\n")
	}
	val renamed = nameInPlace(tls, insecure, dialed, own != null, scheme, clients)
	val sni = renamed?.name ?: sent
	// Who connects from the link: a client that reads the pin - mihomo one in hex alone - or takes the CA
	// and sends a name it covers, or checks nothing.
	val xrayConnects = !xrayChecks || scheme.pin && pin.isNotEmpty()
	val mihomoConnects = !mihomoChecks || scheme.mihomoPin && fromHex(pin.replace(":", ""))?.size == 32
	val singBoxTakes = !singBoxChecks || scheme.authority
	val singBoxNamed = !singBoxChecks || authorityPasses(tls, dialed, sni.ifEmpty { address })
	authorityStop(index, scheme, clients, xrayConnects, mihomoConnects, singBoxTakes && singBoxNamed)?.let {
		return LinkTls(sent, pin, authority, authorityCovered = false, it)
	}
	val anyChecks = xrayChecks || mihomoChecks || singBoxChecks
	if (anyChecks) {
		val pinned = pins.isNotEmpty() && scheme.pin
		notes.add(authorityNote(index, own != null, authority.isNotEmpty(), pinned, insecure, scheme))
	}
	val missing = listOfNotNull("Xray".takeUnless { xrayConnects }, "mihomo".takeUnless { mihomoConnects },
		"sing-box".takeUnless { singBoxTakes })
	if (missing.isNotEmpty()) {
		notes.add("${missing.joinToString(" and ")} clients take this CA from ${scheme.label} links " +
			"neither whole nor as a pin they can read, so they will not connect")
	}
	if (singBoxTakes && !singBoxNamed) {
		notes.add("sing-box clients check this CA against \"${sni.ifEmpty { address }}\", the name sent, " +
			"which it does not cover, so they will not connect")
	}
	when {
		renamed != null -> notes.add(verifyNameSentNote(renamed.name, sent, renamed.why))
		!scheme.verifyNames && verifyPeerCertNames(tls).any { insecure || !sameHost(it, dialed) } ->
			notes.add(verifyNamesDroppedNote("the ${scheme.label} link form"))
	}
	return LinkTls(sni, pin, authority, authorityCovered = anyChecks || authority.isNotEmpty(), stop = null)
}

// Why a link is not made over the CA its server is verified against: the box's client could not take it
// from the link, or no client could.
private fun authorityStop(
	index: Int?, scheme: LinkScheme, clients: LinkClients, xrayConnects: Boolean, mihomoConnects: Boolean,
	singBoxConnects: Boolean
): LinkStop? {
	val verified = "tlsSettings.certificates[$index] is a CA the server is verified against, which"
	val links = "${scheme.label} links"
	return when {
		clients.singBox && !singBoxConnects -> LinkStop("$verified a sing-box client takes from $links " +
			"neither whole nor as a pin, so it would not connect", refused = true)
		clients.mihomo && !mihomoConnects -> LinkStop("$verified a mihomo client takes from $links neither " +
			"whole nor as a pin it reads, so it would not connect", refused = true)
		!xrayConnects && !mihomoConnects && !singBoxConnects -> LinkStop("$verified no client takes from " +
			"$links, whole or as a pin", refused = false)
		else -> null
	}
}

// The pin a link writes: the node's own as written, else its CA's. A mihomo client takes one, in hex - over
// a list a VLESS or Trojan proxy never connects, and a Hysteria2 one costs the whole subscription - so for
// one there is the first.
private fun linkPin(
	pins: List<String>, own: String?, scheme: LinkScheme, clients: LinkClients, notes: MutableList<String>
): String {
	if (pins.isEmpty()) return own.orEmpty()
	if (!clients.mihomo || !scheme.mihomoPin) return pins.joinToString(",")
	val field = "tlsSettings.pinnedPeerCertSha256"
	if (pins.size > 1) notes.add("$field lists ${pins.size} pins; mihomo takes one, so the first was used")
	return mihomoPin(pins.first()) ?: "".also { notes.add(undecodedPinNote(field)) }
}

// What became of a CA the server is checked against, in a link some client connects from: the server's
// own certificate pinned, the CA carried whole for the clients that read it, the node's pin in its place,
// or the check skipped by the clients that read the link's switch for it.
private fun authorityNote(
	index: Int?, own: Boolean, whole: Boolean, pinned: Boolean, insecure: Boolean, scheme: LinkScheme
): String {
	val head = "tlsSettings.certificates[$index] is the CA the server is verified against"
	val none = "${scheme.label} links have no field for a CA"
	return when {
		own && whole -> "$head and the server's own certificate: the link pins it, and carries it whole " +
			"as cert, which sing-box clients such as husi read in place of a pin"
		own -> "$head and the server's own certificate; $none, so this one pins that certificate"
		whole -> "$head; the link carries it whole as cert, which sing-box clients such as husi read"
		pinned -> "$head; $none, and the node's own pin stands in for it"
		insecure -> "$head; $none, and the clients that take the link's allowInsecure skip the check"
		else -> "$head; ${scheme.label} links have no field for it, and mihomo checks no certificate there"
	}
}

// A name to verify sent in place of the one Xray sends, and why.
private class SentName(val name: String, val why: String)

// That name, where a client the link is made for checks the certificate against the name it sends - not one
// that skips the check by the link's switch, pins the server's own certificate or checks nothing - and, on a
// link with no field for the names, for any client.
private fun nameInPlace(
	tls: JSONObject?, insecure: Boolean, dialed: String, ownPinned: Boolean, scheme: LinkScheme,
	clients: LinkClients
): SentName? {
	if (!scheme.sendsName) return null
	val name = nameToVerify(tls, dialed) ?: return null
	val who = listOfNotNull(
		"sing-box".takeIf { clients.singBox && !(insecure && scheme.singBoxInsecure) },
		"mihomo".takeIf {
			clients.mihomo && scheme.mihomoChecks && !ownPinned && !(insecure && scheme.mihomoInsecure)
		}
	)
	return when {
		scheme.verifyNames && who.isNotEmpty() ->
			SentName(name, "${who.joinToString(" and ")} clients check it against the name they send")
		!scheme.verifyNames && (who.isNotEmpty() || !ownPinned && !insecure) ->
			SentName(name, "${scheme.label} links have no field for the names")
		else -> null
	}
}

// The uTLS fingerprint a REALITY link writes, or why there is no link.
internal class LinkReality(val fingerprint: String, val stop: LinkStop?)

// A REALITY link for its clients: mihomo offers X25519MLKEM768, which an Xray server from 26.9.8 asks
// for, with chrome alone and when told, and reads REALITY from a VLESS link only - so for a mihomo
// client a VLESS link says chrome and a Trojan one goes.
internal fun linkReality(
	fingerprint: String, scheme: LinkScheme, clients: LinkClients, notes: MutableList<String>
): LinkReality {
	if (clients.mihomo && !scheme.mihomoReality) {
		val reason = "a mihomo client reads no REALITY from ${scheme.label} links and would dial plain " +
			"TLS, which a REALITY server does not answer as itself"
		return LinkReality(fingerprint, LinkStop(reason, refused = true))
	}
	if (clients.singBox) notes.add(REALITY_SING_BOX_NOTE)
	if (!clients.mihomo) return LinkReality(fingerprint, stop = null)
	mihomoRealityChromeNote(fingerprint)?.let { notes.add(it) }
	notes.add(REALITY_MIHOMO_NOTE)
	return LinkReality("chrome", stop = null)
}
