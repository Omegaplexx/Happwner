package com.happwner.convert

import java.net.IDN
import java.net.URLEncoder
import org.json.JSONArray
import org.json.JSONObject

// Turns an Xray `streamSettings` block into the query a share link carries. One place for it so the
// per-protocol builders can't disagree about what a link needs.
internal object LinkParams {

	// The transport name a share link uses. Xray spells the HTTP/2 transport three ways; links and
	// sing-box both call it `http`. `raw` is Xray's newer name for plain TCP.
	internal fun linkNetwork(raw: String): String = when (raw.trim().lowercase()) {
		"", "tcp", "raw" -> "tcp"
		"h2", "http", "h3" -> "http"
		"ws", "websocket" -> "ws"
		"httpupgrade" -> "httpupgrade"
		"splithttp", "xhttp" -> "xhttp"
		"kcp", "mkcp" -> "kcp"
		"quic" -> "quic"
		"grpc", "gun" -> "grpc"
		else -> raw.trim().lowercase()
	}

	// Collects every query parameter the stream settings imply for a link of this scheme to this server,
	// as its clients take them - or says why there is no such link.
	internal fun streamParams(
		streamSettings: JSONObject?,
		params: MutableMap<String, String>,
		mirrorSniToHost: Boolean = false,
		notes: MutableList<String>,
		scheme: LinkScheme,
		address: String,
		clients: LinkClients
	): LinkStop? {
		// mihomo speaks TLS to every trojan server, as in its documents, so a plaintext one would be handed a
		// handshake it does not answer; QUIC is never plaintext.
		val plaintext = streamSecurity(streamSettings) == "none" &&
			(streamSettings == null || linkNetwork(streamMethod(streamSettings)) != "quic")
		if (clients.mihomo && scheme == LinkScheme.TROJAN && plaintext) {
			return LinkStop(MIHOMO_PLAINTEXT_REFUSAL, refused = true)
		}
		// A node with no stream settings is plain TCP with no TLS.
		if (streamSettings == null) {
			params["type"] = "tcp"
			params["security"] = "none"
			return null
		}
		val net = linkNetwork(streamMethod(streamSettings))
		params["type"] = net
		// No client built on sing-box runs mKCP, so under its box the link would dial without it.
		if (clients.singBox && net == "kcp") {
			return LinkStop("a sing-box client runs no mKCP and would dial without it, which the server " +
				"does not answer", refused = true)
		}
		mihomoTransportStop(net, streamSettings, scheme, clients, notes)?.let { return it }
		kcpLinkStop(net, streamSettings, scheme)?.let { return it }
		// Read the way the other two converters read it, or the same node would leave here with a different
		// security layer: xtlsSettings is the old spelling, and a REALITY node may name only its settings.
		val security = streamSecurity(streamSettings)
		val tls = streamTls(streamSettings)
		val reality = streamSettings.optJSONObject("realitySettings")
		val checked = if (security != "tls") null else linkTls(
			streamSettings, tlsServerName(tls), tls?.optBoolean("allowInsecure", false) == true,
			tls.xStrList("pinnedPeerCertSha256"), address, scheme, clients, notes
		)
		checked?.stop?.let { return it }
		// The Host header Xray sends where a transport names none - the TLS server name, else the address -
		// written out where a client would send another: the address in place of the name, the name sent in
		// its place, or - mihomo, to a VLESS server without TLS - a name of its own making.
		val original = if (security == "tls") tlsServerName(tls) else ""
		val renamed = checked != null && checked.sni != original
		val addressHost = xrayAddressString(address)
		val madeUp = clients.mihomo && scheme == LinkScheme.VLESS && security == "none"
		val hostSent = original.ifEmpty { addressHost }.takeIf { renamed || madeUp || it != addressHost }
		if (net == "quic") quicTlsParams(security, tls, checked, params, mirrorSniToHost, notes)
		else when (security) {
			"tls" -> {
				params["security"] = "tls"
				applyTlsParams(tls, checked, params, mirrorSniToHost, notes, hostSent)
			}
			"reality" -> {
				params["security"] = "reality"
				val keyed = linkReality(reality.xStr("fingerprint"), scheme, clients, notes)
				keyed.stop?.let { return it }
				applyTlsParams(reality, null, params, mirrorSniToHost, notes)
				putIfNotEmpty(params, "fp", keyed.fingerprint)
				// Read the way the other two passes read it: "password" is the current name for
				// the key the older configs call publicKey.
				putIfNotEmpty(params, "pbk", reality?.let { realityPublicKey(it) })
				putIfNotEmpty(params, "sid", reality?.let { realityShortId(it) })
				putIfNotEmpty(params, "spx", reality?.optString("spiderX"))
				putIfNotEmpty(params, "pqv", reality?.optString("mldsa65Verify"))
				// mihomo offers the key share an Xray server from 26.9.8 asks for only when told, and no
				// other client reads the switch.
				if (scheme.mihomoReality) params["support-x25519mlkem768"] = "true"
			}
			"none", "" -> {
				// Some clients want to be told rather than left to assume.
				params["security"] = "none"
			}
			else -> params["security"] = security
		}

		transportParams(net, streamSettings, params, notes)

		val carriesHost = net == "ws" || net == "httpupgrade" || renamed && net == "xhttp"
		if (hostSent != null && carriesHost && "host" !in params) params["host"] = hostSent
		// husi takes a link's Host - the whole of a list - for the TLS server name where none is named, and
		// mihomo does over ws: the address goes as the server name, as Xray sends it, or they would send and
		// check the Host.
		val namedHost = params["host"]
		if (security == "tls" && "sni" !in params && namedHost != null && !sameNameSent(namedHost, address)) {
			params["sni"] = linkHost(address)
		}
		mihomoTrojanHostStop(streamSettings, params, original, address, scheme, clients, notes)
			?.let { return it }
		grpcAuthorityNote(params, address, scheme, clients)?.let { notes.add(it) }

		// Carried whole: finalmask is a block of its own and the link has one name for all of it.
		putIfNotEmpty(params, "fm",
			streamSettings.optJSONObject("finalmask")?.takeIf { it.length() > 0 }?.let { jsonText(it) })
		return null
	}

	// The transport's own parameters - path, host, service name and the rest - as a link names them.
	private fun transportParams(
		net: String, streamSettings: JSONObject, params: MutableMap<String, String>,
		notes: MutableList<String>
	) {
		when (net) {
			"ws" -> {
				val websocket = streamSettings.optJSONObject("wsSettings")
				putIfNotEmpty(params, "path", wsPathWithEarlyData(websocket))
				// The host field is the current spelling and wins; a Host header is the one Xray
				// deprecated, and it fills the field only when the field is empty - which is how
				// Xray itself and the mihomo pass read the pair.
				putIfNotEmpty(params, "host",
					websocket?.optString("host")?.takeIf { it.isNotEmpty() } ?: headerHost(websocket))
				reportExtraHeaders(websocket, "wsSettings", notes)
			}
			"httpupgrade" -> {
				val httpUpgrade = streamSettings.optJSONObject("httpupgradeSettings")
				putIfNotEmpty(params, "path", httpUpgrade?.optString("path"))
				putIfNotEmpty(
					params, "host",
						httpUpgrade?.optString("host")?.takeIf { it.isNotEmpty() } ?: headerHost(httpUpgrade)
				)
				reportExtraHeaders(httpUpgrade, "httpupgradeSettings", notes)
			}
			"xhttp" -> {
				val xhttp = streamSettings.optJSONObject(
					"xhttpSettings") ?: streamSettings.optJSONObject("splithttpSettings")
				putIfNotEmpty(params, "path", xhttp?.optString("path"))
				putIfNotEmpty(
					params, "host", xhttp?.optString("host")?.takeIf { it.isNotEmpty() } ?: headerHost(xhttp)
				)
				putIfNotEmpty(params, "mode", xhttp?.optString("mode"))
				// Everything else an XHTTP node carries travels as one JSON value, which is the
				// shape the link format gives it.
				val extra = xhttp?.optJSONObject("extra")?.takeIf { it.length() > 0 }
				putIfNotEmpty(params, "extra", extra?.let { jsonText(it) })
			}
			"http" -> {
				val http = streamSettings.optJSONObject("httpSettings")
				putIfNotEmpty(params, "path", http?.optString("path"))
				// The standard carries every host, comma-separated; the first alone would lose the
				// others the server is reached by.
				putIfNotEmpty(params, "host",
					joinList(http?.opt("host")).ifEmpty { headerHost(http).orEmpty() })
			}
			"grpc" -> {
				val grpc = streamSettings.optJSONObject("grpcSettings")
				putIfNotEmpty(params, "serviceName", grpc?.optString("serviceName"))
				if (grpc?.optBoolean("multiMode") == true) params["mode"] = "multi"
				putIfNotEmpty(params, "authority", grpc?.optString("authority"))
			}
			"kcp" -> {
				val kcp = streamSettings.optJSONObject("kcpSettings")
				val mask = kcpMask(streamSettings)
				putIfNotEmpty(params, "seed", mask.seed)
				putIfNotEmpty(params, "headerType", mask.headerType)
				putIfNotEmpty(params, "host", mask.domain)
				putIfNotEmpty(params, "mtu", kcp.xInt("mtu").takeIf { it > 0 }?.toString())
				putIfNotEmpty(params, "tti", kcp.xInt("tti").takeIf { it > 0 }?.toString())
			}
			"quic" -> {
				val quic = streamSettings.optJSONObject("quicSettings")
				putIfNotEmpty(params, "quicSecurity", quic?.optString("security"))
				putIfNotEmpty(params, "key", quic?.optString("key"))
				putIfNotEmpty(params, "headerType", quic?.optJSONObject("header")?.optString("type"))
			}
			"tcp" -> {
				// The raw transport carries an HTTP masquerade, and its host and
				// path belong in the link the same as any other transport's.
				val tcp = streamSettings.optJSONObject(
					"tcpSettings") ?: streamSettings.optJSONObject("rawSettings")
				val header = tcp?.optJSONObject("header")
				val type = header?.optString("type", "") ?: ""
				if (type.isNotEmpty() && type != "none" && header != null) {
					params["headerType"] = type
					val req = header.optJSONObject("request")
					putIfNotEmpty(params, "path", joinList(req?.opt("path")))
					val hdrHost = req?.optJSONObject("headers")?.opt("Host")
					putIfNotEmpty(params, "host", joinList(hdrHost))
				}
			}
		}
	}

	// Why a mihomo client could not send the Host a Trojan ws node sends, or null: it reads no Host from a
	// trojan link and sends the server name the link names. A Host of the node's own, apart from the name
	// Xray sends anyway, leaves the link out; a name to verify sent in its place is named as the Host.
	private fun mihomoTrojanHostStop(
		streamSettings: JSONObject, params: Map<String, String>, original: String, address: String,
		scheme: LinkScheme, clients: LinkClients, notes: MutableList<String>
	): LinkStop? {
		if (!clients.mihomo || scheme != LinkScheme.TROJAN || params["type"] != "ws") return null
		val websocket = streamSettings.optJSONObject("wsSettings")
		val written = websocket?.optString("host")?.takeIf { it.isNotEmpty() }
			?: headerHost(websocket).orEmpty()
		val ownName = original.ifEmpty { xrayAddressString(address) }
		val xrayHost = written.ifEmpty { ownName }
		val sent = params["sni"] ?: linkHost(address)
		// An Xray server compares the Host without its port.
		if (sameNameSent(withoutPort(xrayHost), sent)) return null
		if (!sameNameSent(withoutPort(xrayHost), ownName)) {
			return LinkStop("a mihomo client reads no Host from trojan links and would send the server " +
				"name, \"$sent\", in place of the Host the node names, \"$written\"", refused = true)
		}
		notes.add("a mihomo client sends the server name of a trojan ws link as its Host, \"$sent\" " +
			"where Xray sends \"$xrayHost\"")
		return null
	}

	// The box's clients read no authority from a gRPC link and make their own of the server name, as the
	// cores do from their own documents, which have no field for it either. A VMess link carries none for
	// any client, and its note says so.
	private fun grpcAuthorityNote(
		params: Map<String, String>, address: String, scheme: LinkScheme, clients: LinkClients
	): String? {
		if (scheme == LinkScheme.VMESS) return null
		val grpcAuthority = params["authority"] ?: return null
		val sent = params["sni"] ?: linkHost(address)
		val readers = listOfNotNull("sing-box".takeIf { clients.singBox }, "mihomo".takeIf { clients.mihomo })
		if (readers.isEmpty() || sameNameSent(withoutPort(grpcAuthority), sent)) return null
		return "${readers.joinToString(" and ")} clients read no authority from gRPC links and send one " +
			"made of the server name, \"$sent\", where Xray sends \"$grpcAuthority\""
	}

	// A name written with or without a port, as name alone.
	private fun withoutPort(name: String): String = when {
		name.startsWith("[") -> name.substringBefore("]") + "]"
		name.count { it == ':' } == 1 -> name.substringBefore(':')
		else -> name
	}

	// Why a mihomo client could not dial a transport from a link of this scheme, or null: httpupgrade and
	// QUIC, which it reads as transports none of its proxies runs, and mKCP, which it runs under VMess alone
	// and there without the seed or header that masks it, judged otherwise as its documents are.
	private fun mihomoTransportStop(
		net: String, streamSettings: JSONObject, scheme: LinkScheme, clients: LinkClients,
		notes: MutableList<String>
	): LinkStop? {
		if (!clients.mihomo) return null
		val unread = when (net) {
			"httpupgrade" -> "runs no httpupgrade read from ${scheme.label} links and would dial without it"
			"quic" -> "runs no QUIC transport read from ${scheme.label} links and would dial without it"
			"kcp" -> if (scheme != LinkScheme.VMESS) {
				"runs mKCP under vmess alone and would dial ${scheme.label} without it"
			} else {
				val mask = kcpMask(streamSettings)
				val header = mask.headerType.lowercase()
				if (mask.seed.isEmpty() && (header.isEmpty() || header == "none")) {
					mihomoKcpRefusal(mask)?.let { return LinkStop(it, refused = true) }
					if (!mask.stated) notes.add(MIHOMO_KCP_UNSTATED_NOTE)
					return null
				}
				"reads no mKCP seed or header from ${scheme.label} links and would dial without them"
			}
			else -> return null
		}
		return LinkStop("a mihomo client $unread, which the server does not answer", refused = true)
	}

	// A link names an mKCP mask as kcpSettings did - a header outside a seed or original mask, no empty
	// seed - and a vless-shaped one carries finalmask whole besides: what neither says no reader sends, and
	// the node goes as written (under a box its client was answered for above).
	private fun kcpLinkStop(net: String, streamSettings: JSONObject, scheme: LinkScheme): LinkStop? {
		if (net != "kcp") return null
		val mask = kcpMask(streamSettings)
		if (mask.inFinalmask && scheme != LinkScheme.VMESS) return null
		val unsaid = when {
			mask.unlike != null -> mask.unlike
			mask.blankSeed -> "the mKCP mask is keyed by an empty seed"
			else -> return null
		}
		return LinkStop("$unsaid, which no ${scheme.label} link carries", refused = false)
	}

	// TLS settings that have no name in a share link. Every one of them is a deliberate choice
	// somebody made, so it is reported rather than dropped in silence.
	private val TLS_NO_LINK_FORM = listOf(
		"certificates", "disableSystemRoot", "minVersion", "maxVersion", "cipherSuites",
		"curvePreferences", "masterKeyLog", "echSockopt", "enableSessionResumption"
	)

	// The TLS Xray's QUIC transport runs, spelled out: tlsSettings for tls, its own unverified name
	// otherwise, Xray's default ALPN and no fingerprint - a client that is not Xray would otherwise
	// offer h3 alone, dial with uTLS that QUIC cannot carry, or have no TLS at all.
	private fun quicTlsParams(
		security: String,
		tls: JSONObject?,
		checked: LinkTls?,
		params: MutableMap<String, String>,
		mirrorSniToHost: Boolean,
		notes: MutableList<String>
	) {
		params["security"] = "tls"
		if (security == "tls") {
			applyTlsParams(tls, checked, params, mirrorSniToHost, notes)
			params.remove("fp")?.let { fp -> quicFingerprintDropped(fp)?.let { notes.add(it) } }
		} else {
			params["sni"] = XRAY_QUIC_OWN_SNI
			if (mirrorSniToHost && !params.containsKey("host")) params["host"] = XRAY_QUIC_OWN_SNI
			params["allowInsecure"] = "1"
		}
		params.getOrPut("alpn") { XRAY_DEFAULT_ALPN.joinToString(",") }
	}

	// The name a link sends, as Xray reads it: serverName, or the first of a REALITY server's names.
	private fun tlsServerName(tls: JSONObject?): String =
		firstNonEmptyOf(tls?.optString("serverName"), firstOfList(tls?.opt("serverNames")))

	// The TLS fields of a link; checked, for TLS, is what its clients take of them - the name sent, the pin
	// and the CA - and hostSent the Host header where the name sent is not the server name.
	private fun applyTlsParams(
		tls: JSONObject?,
		checked: LinkTls?,
		params: MutableMap<String, String>,
		mirrorSniToHost: Boolean,
		notes: MutableList<String>,
		hostSent: String? = null
	) {
		if (tls == null) return
		val sni = checked?.sni ?: tlsServerName(tls)
		if (sni.isNotEmpty()) {
			params["sni"] = sni
			// Trojan links have always repeated it here and some parsers read
			// only this one.
			if (mirrorSniToHost && !params.containsKey("host")) params["host"] = hostSent ?: sni
		}
		val alpn = joinList(tls.opt("alpn"))
		if (alpn.isNotEmpty()) params["alpn"] = alpn
		// Only when the source asked for one. A fingerprint invented here would
		// tell the client to mimic a browser the configuration never named.
		putIfNotEmpty(params, "fp", tls.optString("fingerprint"))
		if (tls.optBoolean("allowInsecure", false)) params["allowInsecure"] = "1"
		// Certificate pinning, name-based verification and ECH: dropping any of them either weakens
		// the connection the config asked for or stops it from being made at all. A hash list is
		// comma-joined, which is how the field itself spells "any of these".
		putIfNotEmpty(params, "pcs", checked?.pin ?: joinList(tls.opt("pinnedPeerCertSha256")))
		putIfNotEmpty(params, "vcn", verifyPeerCertNames(tls).joinToString(","))
		putIfNotEmpty(params, "cert", checked?.authority)
		putIfNotEmpty(params, "ech", xScalarString(tls.opt("echConfigList")))
		reportTlsDrops(tls, checked?.authorityCovered == true, notes)
	}

	// What a link drops of the TLS settings, each named - beside a CA covered already, only the certificates
	// that are not one, by their places.
	private fun reportTlsDrops(tls: JSONObject, authorityCovered: Boolean, notes: MutableList<String>) {
		// Removed from Xray in favour of pinnedPeerCertSha256, and not the same value: these hash
		// the certificate chain and the peer's public key, where a link's pcs is the hash of the
		// certificate itself. Copying one across would pin something no peer can match.
		for (key in listOf("pinnedPeerCertificateChainSha256", "pinnedPeerCertificatePublicKeySha256")) {
			if (tls.xHas(key)) {
				notes.add(
					"tlsSettings.$key hashes something other than the certificate, so it is not the " +
						"value a link's pcs carries and it was dropped"
				)
			}
		}
		// ech is one config rather than a comma-separated list, so half of one carries nothing.
		val ech = tls.xOpt("echConfigList")
		if (ech is JSONArray || ech is JSONObject) {
			notes.add(
				"tlsSettings.echConfigList is a list here and a link carries one config, so it was dropped")
		}
		val certificates = tls.optJSONArray("certificates")
		for (key in TLS_NO_LINK_FORM) {
			if (!tls.xHas(key)) continue
			if (key != "certificates" || !authorityCovered || certificates == null) {
				notes.add("tlsSettings.$key has no link form and was dropped")
				continue
			}
			for (i in 0 until certificates.length()) {
				if (isInlineAuthority(certificates.optJSONObject(i))) continue
				notes.add("tlsSettings.certificates[$i] has no link form and was dropped")
			}
		}
	}

	// Whether an address can stand where a link keeps its host. An empty host, a slash or a colon there
	// is a node that imports and connects nowhere. The rule is what breaks a link, not what java.net.URI
	// accepts: an underscore or an all-digit label is read by every resolver and handed out by panels.
	internal fun usableHost(address: String): Boolean {
		val host = hostForUri(address.trim())
		if (host.isEmpty()) return false
		if (host.startsWith("[")) {
			// An IPv6 literal: the brackets close around hex groups, the dots of an embedded IPv4
			// address, and the % of a zone identifier - and nothing else.
			if (!host.endsWith("]") || host.length <= 2) return false
			val inside = host.substring(1, host.length - 1)
			return inside.all { it.isDigit() || it in "abcdefABCDEF" || it in ":.%" }
		}
		// A name, said the way names are said: letters of any script, digits, and the three marks
		// that appear inside real host names. Anything else either ends the host early - a colon
		// read as a port, a slash as a path - or is not a name a resolver would be asked for.
		return host.all { it.isLetterOrDigit() || it in "-._" }
	}

	private fun wsPathWithEarlyData(websocket: JSONObject?): String {
		if (websocket == null) return ""
		val path = websocket.optString("path", "")
		if (parseWsPath(path).earlyData != null) return path
		val maxEarlyData = websocket.xInt("maxEarlyData")
		if (maxEarlyData <= 0) return path
		val base = path.ifEmpty { "/" }
		return base + (if (base.contains('?')) "&" else "?") + "ed=" + maxEarlyData
	}

	// A link has one field for the Host and nothing for any other header, so the rest are named
	// rather than dropped in silence: a server that expects one will not answer without it.
	private fun reportExtraHeaders(transport: JSONObject?, block: String, notes: MutableList<String>) {
		val headers = transport?.optJSONObject("headers") ?: return
		val extra = headers.keys().asSequence().filterNot { it.equals("Host", true) }.sorted().toList()
		if (extra.isEmpty()) return
		notes.add(
			"a link carries no header but the Host, so $block.headers.${extra.joinToString(", ")} " +
				"was dropped"
		)
	}

	// A string, or the first entry of an array of them.
	internal fun firstOfList(value: Any?): String? = when (value) {
		null, JSONObject.NULL -> null
		is String -> value.ifEmpty { null }
		is JSONArray -> (0 until value.length()).asSequence()
			.mapNotNull { value.opt(it) as? String }
			.firstOrNull { it.isNotEmpty() }
		else -> value.toString().ifEmpty { null }
	}

	// Comma-separated, which is how a link carries a list.
	internal fun joinList(value: Any?): String = when (value) {
		null, JSONObject.NULL -> ""
		is String -> value
		is JSONArray -> (0 until value.length()).mapNotNull { value.opt(it) as? String }
			.filter { it.isNotEmpty() }.joinToString(",")
		else -> value.toString()
	}

	private fun firstNonEmptyOf(vararg values: String?): String {
		for (value in values) if (!value.isNullOrEmpty()) return value
		return ""
	}

	private fun putIfNotEmpty(params: MutableMap<String, String>, key: String, value: String?) {
		if (!value.isNullOrEmpty()) params[key] = value
	}

	// The server's host as clients read it from a link: punycode, and an IPv6 address unbracketed.
	internal fun linkHost(address: String): String = hostForUri(address).removeSurrounding("[", "]")

	// The host as a link may hold it: an IPv6 literal must be bracketed, or its colons read as the
	// port separator and the link won't parse.
	internal fun hostForUri(host: String): String {
		val trimmedHost = host.trim()
		if (trimmedHost.startsWith("[")) return trimmedHost
		if (trimmedHost.count { it == ':' } >= 2) return "[$trimmedHost]"
		// A URI authority is ASCII, so an internationalised name travels as punycode. A name IDN
		// refuses is left as it was written rather than replaced with nothing.
		if (trimmedHost.all { it.code < 0x80 }) return trimmedHost
		return try {
			IDN.toASCII(trimmedHost)
		} catch (_: IllegalArgumentException) {
			trimmedHost
		}
	}

	// The query string, sorted so the same input always produces the same link.
	internal fun queryString(params: Map<String, String>): String {
		if (params.isEmpty()) return ""
		return "?" + params.entries.sortedBy { it.key }.joinToString("&") {
			"${it.key}=${enc(it.value)}"
		}
	}

	internal fun enc(text: String): String = URLEncoder.encode(text, "UTF-8").replace("+", "%20")
}
