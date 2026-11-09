package com.happwner.convert

import com.happwner.text.canonicalIp
import com.happwner.text.parseInet4
import com.happwner.text.parseInet6
import com.happwner.text.splitHostPort
import org.json.JSONArray
import org.json.JSONObject

// The proxy protocols, plus the auxiliary freedom/blackhole/dns outbounds; the QUIC-based three are
// built in SingBoxHysteria.
internal object SingBoxProtocols {

	internal val XRAY_PROTOCOLS_PROXY = setOf(
		"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard",
		// Panels and generators write these three in Xray-shaped configurations - Xray itself has
		// only "hysteria", which carries version 2 as well - and sing-box implements all of them natively.
		"hysteria2", "hysteria", "tuic"
	)

	// The three handled by SingBoxHysteria rather than by the mapping below.
	private val QUIC_PROTOCOLS = setOf("hysteria2", "hysteria", "tuic")

	internal val XRAY_PROTOCOLS_AUX = setOf("freedom", "blackhole", "dns", "loopback")

	internal val SS_METHODS_OK = setOf(
		"none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
		"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
		"2022-blake3-chacha20-poly1305",
		"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
		"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
		"rc4-md5", "chacha20-ietf", "xchacha20"
	)

	// Why an outbound cannot be carried - what Xray itself refuses (security, server, credential, flow)
	// and a mask only Xray applies before anything else sing-box lacks - or null when it can.
	internal fun unsupportedReason(xrayOutbound: JSONObject): String? {
		val proto = xrayOutbound.xrayProtocol()
		if (proto !in XRAY_PROTOCOLS_PROXY && proto !in XRAY_PROTOCOLS_AUX) {
			return when {
				proto.isEmpty() -> "no protocol specified"
				proto == "masque" -> MASQUE_OUTBOUND_REFUSAL
				else -> "unknown or unimplemented protocol \"$proto\""
			}
		}
		if (proto in XRAY_PROTOCOLS_AUX) return null
		val stream = xrayOutbound.optJSONObject("streamSettings") ?: JSONObject()
		// A stream in a block sing-box writes is no stream to judge, and the node no node to read.
		singBoxBlockOf(xrayOutbound)?.let { return it }
		// Then what Xray itself refuses, ahead of the rest, in the words and the order every pass uses - the
		// security layer, the server, the credential, then what the protocol asks of them - with a mask
		// only Xray applies right after the security layer: a node that never worked is that first.
		securityRefusal(stream)?.let { return it }
		finalmaskRefusal(xrayOutbound)?.let { return it }
		serverRefusal(proto, xrayOutbound)?.let { return it }
		if (proto == "vless") {
			val user = firstUser(xrayOutbound)
			val enc = user.xStr("encryption")
			vlessEncryptionRefusal(enc)?.let { return it }
			vlessFlowRefusal(user.xStr("flow"), enc, stream)?.let { return it }
		}
		if (proto == "wireguard") return wireguardRefusal(xrayOutbound.xObj("settings"))
		// The QUIC-based three carry their own parameters, and their
		// streamSettings hold TLS and nothing the transport check applies to.
		if (proto in QUIC_PROTOCOLS) return null
		transportRefusal(xrayOutbound)?.let { return it }
		xrayOwnTransportOf(xrayOutbound)?.let { return xrayOwnTransportRefusal(it) }
		val net = streamMethod(stream).ifEmpty { "tcp" }
		if (net !in SingBoxStream.XRAY_TRANSPORTS_OK) return "transport \"$net\" has no sing-box equivalent"
		if (net == "tcp" || net == "raw") {
			val tcpSettings = stream.optJSONObject("tcpSettings") ?: stream.optJSONObject("rawSettings")
			val hdrType = tcpSettings.xObj("header").xStr("type").ifEmpty { "none" }
			if (hdrType != "none" && hdrType != "http") {
				return "tcp header type \"$hdrType\" is not supported (only the http masquerade is)"
			}
		}
		if (net == "quic") {
			val quicSettings = stream.optJSONObject("quicSettings") ?: JSONObject()
			val qsec = quicSettings.xStr("security").lowercase().ifEmpty { "none" }
			if (qsec != "none" && qsec != "") return "quic transport security \"$qsec\" is not supported"
			val qhdr = quicSettings.xObj("header").xStr("type").lowercase().ifEmpty { "none" }
			if (qhdr != "none" && qhdr != "") return "quic transport header \"$qhdr\" is not supported"
		}
		val sec = streamSecurity(stream)
		if (proto == "vless") {
			val enc = firstUser(xrayOutbound).xStr("encryption")
			if (enc.isNotEmpty() &&
				enc != "none") return "vless encryption \"$enc\" is not supported (only \"none\" is)"
		}
		if (proto in setOf("shadowsocks", "socks", "http")) {
			transportFormOf(proto, stream).refusal?.let { return it }
			if (proto == "socks" && sec == "tls") {
				return "sing-box's socks outbound has no TLS, and a node written without it " +
					"connects to nothing"
			}
		}
		if (proto == "shadowsocks") {
			val srv = shadowsocksServer(xrayOutbound)
			// Refused above when empty or known to no core: supplying one would be inventing a
			// cipher the server may not speak.
			val rawMethod = srv.xStr("method")
			val method = canonicalSsMethod(rawMethod)
			if (method !in SS_METHODS_OK) {
				return "shadowsocks method \"$rawMethod\" has no sing-box equivalent"
			}
			srv?.let { serverPluginOf(it).refusal }?.let { return it }
		}
		if (net == "grpc") SingBoxStream.grpcPathRefusal(stream)?.let { return it }
		return null
	}

	internal fun isOutboundSupported(xrayOutbound: JSONObject): Boolean = unsupportedReason(
		xrayOutbound) == null

	internal fun firstUser(xrayOutbound: JSONObject): JSONObject? =
		xrayEndpoints(xrayOutbound.optJSONObject("settings")).firstOrNull()?.user

	// A node's server and credential, read the way this pass's builders read them, and refused in
	// the order every pass refuses them: no server a client could reach, then nothing to
	// authenticate with - for Shadowsocks the method first, known to some core, then the password.
	private fun serverRefusal(proto: String, xrayOutbound: JSONObject): String? {
		val settings = xrayOutbound.optJSONObject("settings") ?: JSONObject()
		val endpoint = proxyEndpoint(proto, xrayOutbound)
		val trojan = trojanServer(xrayOutbound)
		val shadowsocks = shadowsocksServer(xrayOutbound)
		val credentialed = credentialedServer(settings)
		val (address, port) = when (proto) {
			"vless", "vmess" -> endpoint?.address.orEmpty() to (endpoint?.port ?: 0)
			"trojan" -> trojan.xStr("address") to trojan.xInt("port")
			"shadowsocks" -> shadowsocks.xStrOf("address", "server") to
				(shadowsocks.xInt("port").takeIf { it > 0 } ?: shadowsocks.xInt("server_port"))
			"socks", "http" -> credentialed?.address.orEmpty() to (credentialed?.port ?: 0)
			else -> return null
		}
		if (!LinkParams.usableHost(address) || port !in 1..65535) {
			return unusableServerRefusal(proto, address, port)
		}
		when (proto) {
			"vless", "vmess" -> {
				if (endpoint?.user.xStr("id").isEmpty()) return missingCredentialRefusal(proto, "uuid")
			}
			"trojan" -> if (trojan.xStrRaw("password").isEmpty()) {
				return missingCredentialRefusal(proto, "password")
			}
			"shadowsocks" -> {
				val method = canonicalSsMethod(shadowsocks.xStr("method"))
				if (method.isEmpty()) return MISSING_SS_METHOD_REFUSAL
				unknownSsMethodRefusal(method)?.let { return it }
				val password = shadowsocks.xStrRaw("password")
				if (password.isEmpty()) return missingCredentialRefusal(proto, "password")
				ss2022KeyRefusal(method, password)?.let { return it }
			}
		}
		return null
	}

	// The server a VLESS or VMess outbound names, from its settings or - a VMess node copied out of a
	// sing-box configuration - beside the protocol, where mihomo and the links read it too.
	private fun proxyEndpoint(proto: String, xrayOutbound: JSONObject): XrayEndpoint? {
		xrayEndpoints(xrayOutbound.optJSONObject("settings")).firstOrNull()?.let { return it }
		val server = xrayOutbound.xStr("server")
		if (proto != "vmess" || server.isEmpty()) return null
		val user = jsonCopy(xrayOutbound).put("id", xrayOutbound.xStr("uuid"))
		return XrayEndpoint(server, xrayOutbound.xInt("server_port"), user)
	}

	// One interface address as sing-box compares them: the address it stands for and its length.
	private fun prefixKey(entry: String): String? =
		canonicalIp(entry.substringBefore('/'))?.let { it + "/" + entry.substringAfter('/', "") }

	// The Trojan server, read as every pass reads it.
	private fun trojanServer(xrayOutbound: JSONObject): JSONObject? =
		xrayOutbound.xObj("settings")?.let { xrayServers(it, "address").firstOrNull() }

	// The Shadowsocks server, read as every pass reads it.
	private fun shadowsocksServer(xrayOutbound: JSONObject): JSONObject? =
		shadowsocksServers(xrayOutbound).firstOrNull()

	// The encoding a v2fly-style "packetEncoding" asks for, where an Xray server carries it: Xray reads
	// no such field, and its servers answer packetaddr with no UDP at all, so that one is not written.
	internal fun packetEncodingOf(xrayOutbound: JSONObject, proto: String): String? {
		val settings = xrayOutbound.optJSONObject("settings") ?: JSONObject()
		var raw: Any? = settings.opt("packetEncoding")
		if (raw == null || raw === JSONObject.NULL) {
			val vnext = settings.optJSONArray("vnext")?.optJSONObject(0)
			val user = vnext?.optJSONArray("users")?.optJSONObject(0)
			raw = user?.opt("packetEncoding")
		}
		if (raw == null || raw === JSONObject.NULL) return null
		val text = raw.toString().lowercase()
		return when (text) {
			"xudp" -> if (proto == "vless") null else "xudp"
			"none", "" -> if (proto == "vless") "" else null
			else -> null
		}
	}

	// A socks or http outbound: the server, the port, and the first user's name and password when
	// there is one, read the way every writer of one reads them.
	private fun credentialedOutbound(type: String, tag: String, settings: JSONObject): JSONObject {
		val outbound = JSONObject()
		outbound.put("type", type)
		outbound.put("tag", tag)
		val server = credentialedServer(settings)
		outbound.put("server", server?.address ?: "")
		outbound.put("server_port", server?.port ?: 0)
		if (server?.hasUser == true) {
			outbound.put("username", server?.username ?: "")
			outbound.put("password", server?.password ?: "")
		}
		return outbound
	}

	internal fun applyProxySettings(outbound: JSONObject, xrayOutbound: JSONObject) {
		val chainTag = xrayChainTag(xrayOutbound)
		if (chainTag.isNotEmpty()) outbound.put("detour", chainTag)
	}

	// Maps Xray's sockopt onto the dial fields. dnsResolverTag names a DNS server the finished
	// document is known to carry.
	internal fun applySockopt(
		outbound: JSONObject,
		stream: JSONObject?,
		dnsResolverTag: String?,
		notes: MutableList<String>
	) {
		val sock = stream?.optJSONObject("sockopt") ?: return
		val domainStrategy = xrayDomainStrategyName(sock.optString("domainStrategy", ""))
		val resolverStrategy = XRAY_DOMAIN_STRATEGY[domainStrategy] ?: ""
		if (resolverStrategy.isNotEmpty() && !outbound.has("domain_resolver") && dnsResolverTag != null) {
			val resolver = JSONObject()
			resolver.put("server", dnsResolverTag)
			resolver.put("strategy", resolverStrategy)
			outbound.put("domain_resolver", resolver)
		}
		val tfo = sock.opt("tcpFastOpen")
		if (tfo is Boolean) outbound.put("tcp_fast_open", tfo)
		// sing-box has tcp_keep_alive and its two companions only since 1.13.0, and an unknown
		// field stops a configuration loading, so writing them would break every 1.12 core.
		if (sock.xAsksForKeepAlive()) {
			notes.add(
				"sockopt.tcpKeepAliveIdle / tcpKeepAliveInterval were dropped: sing-box has " +
					"these fields only since 1.13, and writing them would stop a 1.12 core loading " +
					"the configuration"
			)
		}

		// SO_MARK, SO_BINDTODEVICE and MPTCP are kernel-side options neither end negotiates, so they carry
		// over safely. routing_mark refuses a negative and tcp_multi_path a non-boolean.
		val markRaw = sock.opt("mark")
		if (markRaw is Number) {
			val mark = markRaw.toLong()
			if (mark > 0L && mark <= 0xFFFFFFFFL) outbound.put("routing_mark", mark)
		}

		val iface = sock.optString("interface", "").trim()
		if (iface.isNotEmpty()) outbound.put("bind_interface", iface)

		val mptcp = sock.opt("tcpMptcp")
		if (mptcp is Boolean && mptcp) outbound.put("tcp_multi_path", true)

		// The rest of sockopt has nowhere to go.
		for ((key, why) in SOCKOPT_WITHOUT_EQUIVALENT) {
			if (isTruthy(sock.opt(key))) notes.add("sockopt.$key $why")
		}
	}

	// What an outbound asked for that no sing-box field holds. Every protocol goes through here,
	// whichever branch built it, or a node would arrive quietly missing what it was tuned with.
	internal fun reportOutboundExtras(
		xrayOutbound: JSONObject,
		stream: JSONObject?,
		notes: MutableList<String>,
		tlsFragment: Boolean = false
	) {
		finalmaskFeatures(xrayOutbound, tlsFragment).forEach {
			notes.add("$it is Xray's own and has no sing-box equivalent, so it was dropped")
		}
		if (xrayOutbound.xStr("targetStrategy").isNotEmpty()) {
			notes.add(
				"targetStrategy picks the address family this outbound dials with, which sing-box " +
					"decides for the whole route, so it was dropped"
			)
		}
		if (stream.xHas("downloadSettings")) notes.add(MISPLACED_DOWNLOAD_SETTINGS)
		if (stream.xHas("dialerProxy")) notes.add(MISPLACED_DIALER_PROXY)
		notes.addAll(olderConfigLeniencies(xrayOutbound))
		chainConflictNote(xrayOutbound)?.let { notes.add(it) }
	}

	// The tail every proxy outbound shares: options that hang off the outbound rather than the protocol.
	private fun finishProxy(
		outbound: JSONObject,
		xrayOutbound: JSONObject,
		stream: JSONObject?,
		dnsResolverTag: String?,
		notes: MutableList<String>
	): OutboundResult {
		// A node whose server or port could not be read converts into something that looks complete
		// and connects nowhere. Saying so is the only useful answer.
		val server = outbound.xStr("server")
		val port = outbound.xInt("server_port")
		if (!LinkParams.usableHost(server) || port !in 1..65535) {
			notes.add(unusableServerRefusal(outbound.xStr("type"), server, port))
			return OutboundResult(null, null, notes)
		}
		// The same for the credential: a node with nothing to authenticate with imports and connects
		// nowhere, and an empty uuid is one sing-box refuses the whole document over.
		val credential = when (outbound.xStr("type")) {
			"vless", "vmess" -> "uuid"
			"trojan", "shadowsocks" -> "password"
			else -> null
		}
		if (credential != null && outbound.xStr(credential).isEmpty()) {
			notes.add(missingCredentialRefusal(outbound.xStr("type"), credential))
			return OutboundResult(null, null, notes)
		}
		applyProxySettings(outbound, xrayOutbound)
		applySockopt(outbound, stream, dnsResolverTag, notes)
		reportMux(xrayOutbound, notes)
		applySendThrough(outbound, xrayOutbound, notes)
		val tlsFragment =
			SingBoxStream.applyTlsFragment(outbound, streamTcpMask(stream, "fragment")?.xObj("settings"))
		if (tlsFragment) notes.add("finalmask.tcp mask \"fragment\": ${SingBoxStream.TLS_FRAGMENT_NOTE}")
		reportOutboundExtras(xrayOutbound, stream, notes, tlsFragment)
		return OutboundResult(outbound, "proxy", notes)
	}

	// Reports Xray's mux rather than translating it: mux.cool and smux/yamux/h2mux are different
	// protocols, and the node carries traffic without the block and none with it.
	internal fun reportMux(xrayOutbound: JSONObject, notes: MutableList<String>) {
		val mux = xrayOutbound.optJSONObject("mux") ?: return
		if (!isTruthy(mux.opt("enabled"))) return
		notes.add(
			"mux is Xray's own multiplexer (mux.cool) and sing-box implements a different one, " +
				"so it was dropped; the node connects without multiplexing"
		)
	}

	// Xray's sendThrough is the local address an outbound leaves from, which sing-box spells
	// inet4_bind_address or inet6_bind_address in its dial fields, one per address family.
	internal fun applySendThrough(outbound: JSONObject, xrayOutbound: JSONObject,
		notes: MutableList<String>) {
		if (!xrayOutbound.xBindsLocalAddress()) return
		val addr = xrayOutbound.xStr("sendThrough")
		when {
			parseInet4(addr) -> outbound.put("inet4_bind_address", addr)
			parseInet6(addr) -> outbound.put("inet6_bind_address", addr)
			// Xray resolves a name here; sing-box takes an address, and guessing which one it
			// would have picked is not something this can do for somebody else's machine.
			else -> notes.add(
				"sendThrough \"$addr\" is not an IP address, and sing-box binds to an address " +
					"rather than a name, so it was dropped"
			)
		}
	}

	// sockopt options sing-box has no field for, and why. Each of these names is answered by the core
	// with `unknown field`.
	private val SOCKOPT_WITHOUT_EQUIVALENT = listOf(
		"tproxy" to "is an inbound-side option and was dropped",
		"tcpNoDelay" to "has no sing-box equivalent and was dropped",
		"tcpUserTimeout" to "has no sing-box equivalent and was dropped",
		"tcpWindowClamp" to "has no sing-box equivalent and was dropped",
		"tcpcongestion" to "has no sing-box equivalent and was dropped",
		"V6Only" to "has no sing-box equivalent and was dropped",
		"tcpMaxSeg" to "has no sing-box equivalent and was dropped",
		"penetrate" to "has no sing-box equivalent and was dropped",
		"addressPortStrategy" to "has no sing-box equivalent and was dropped",
		"happyEyeballs" to "tunes Happy Eyeballs per outbound, which sing-box sets for the " +
			"whole dialer, so it was dropped",
		"customSockopt" to "sets raw socket options, which sing-box cannot express",
		// sing-box answers a per-outbound domain strategy with "legacy domain strategy options is
		// deprecated": the choice lives in the route's default_domain_resolver, which the DNS
		// builder sets for the whole document.
		"domainStrategy" to "is set for the whole route rather than per outbound, " +
			"so the route's resolver strategy decides instead"
	)

	// notes carries what the conversion had to drop, for the caller to report alongside the ones it
	// produces itself.
	internal data class OutboundResult(
		val outbound: JSONObject?,
		val kind: String?,
		val notes: List<String>
	)

	// The one part of a blackhole outbound that gets lost, worded alike wherever sing-box outbounds are
	// built: it can answer with a canned HTTP response, where sing-box only closes the connection.
	internal fun blackholeResponseNote(outbound: JSONObject, index: Int): String? {
		val response = outbound.optJSONObject("settings")?.optJSONObject("response")
		if (response?.optString("type", "") != "http") return null
		return "outbounds[$index] (blackhole): the canned HTTP response has no sing-box equivalent; " +
			"the connection is closed instead"
	}

	// One Xray outbound to one sing-box outbound
	internal fun buildOutbound(xrayOutbound: JSONObject, dnsResolverTag: String? = null): OutboundResult {
		val proto = xrayOutbound.xrayProtocol()
		val tag = xrayOutbound.optString("tag", proto)
		// One list for the whole conversion: applySockopt and the QUIC branch both add to it, and
		// every exit hands it back so nothing is lost in silence.
		val notes = ArrayList<String>()

		// freedom -> direct
		if (proto == "freedom") {
			val outbound = JSONObject()
			outbound.put("type", "direct")
			outbound.put("tag", tag)
			val settings = xrayOutbound.optJSONObject("settings") ?: JSONObject()
			// Same replacement as in applySockopt: the outbound-level domain_strategy is refused by
			// sing-box 1.12 and later, and the resolver it gives way to has to name a server that exists.
			val domainStrategy = xrayDomainStrategyName(settings.optString("domainStrategy", ""))
			val resolverStrategy = XRAY_DOMAIN_STRATEGY[domainStrategy] ?: ""
			if (resolverStrategy.isNotEmpty() && dnsResolverTag != null) {
				val resolver = JSONObject()
				resolver.put("server", dnsResolverTag)
				resolver.put("strategy", resolverStrategy)
				outbound.put("domain_resolver", resolver)
			}
			if (settings.xHas("fragment")) {
				notes.add(
					"freedom.fragment splits packets on the way out and sing-box has no such " +
						"option on a direct outbound, so it was dropped"
				)
			}
			if (settings.optString("redirect", "").isNotEmpty()) {
				notes.add(
					"freedom.redirect rewrites the destination and sing-box removed that option, " +
						"so it was dropped"
				)
			}
			if (settings.xHas("noises")) {
				notes.add("freedom.noises has no sing-box equivalent and was dropped")
			}
			applyProxySettings(outbound, xrayOutbound)
			return OutboundResult(outbound, "aux", notes)
		}

		val stream = xrayOutbound.optJSONObject("streamSettings") ?: JSONObject()
		val settings = xrayOutbound.optJSONObject("settings") ?: JSONObject()

		if (proto == "wireguard") {
			return OutboundResult(buildWireguard(xrayOutbound, settings, tag, dnsResolverTag,
				notes), "wireguard", notes)
		}

		if (proto in QUIC_PROTOCOLS) {
			val outbound = when (proto) {
				"hysteria2" -> SingBoxHysteria.convertHysteria2(xrayOutbound, notes)
				// A node written as v1 may describe v2; the same test the
				// mihomo side uses decides which.
				"hysteria" ->
					if (isHysteria2(settings, xrayOutbound.xObj("streamSettings"))) {
						SingBoxHysteria.convertHysteria2(xrayOutbound, notes)
					} else {
						SingBoxHysteria.convertHysteria(xrayOutbound, notes)
					}
				else -> SingBoxHysteria.convertTuic(xrayOutbound, notes)
			}
			if (outbound != null) {
				outbound.put("tag", tag)
				applySockopt(outbound, stream, dnsResolverTag, notes)
				applySendThrough(outbound, xrayOutbound, notes)
				reportOutboundExtras(xrayOutbound, stream, notes)
			}
			return OutboundResult(outbound, proto, notes)
		}

		val source = Source(xrayOutbound, settings, stream, tag, dnsResolverTag, notes)
		return when (proto) {
			"vless", "vmess" -> source.buildVlessOrVmess(proto)
			"trojan" -> source.buildTrojan()
			"shadowsocks" -> source.buildShadowsocks()
			"socks" -> source.buildSocks()
			"http" -> source.buildHttp()
			else -> OutboundResult(null, null, notes)
		}
	}

	// What the per-protocol builders below read from one Xray outbound.
	private class Source(
		val xrayOutbound: JSONObject,
		val settings: JSONObject,
		val stream: JSONObject,
		val tag: String,
		val dnsResolverTag: String?,
		val notes: ArrayList<String>
	)

	// The TLS layer and the transport the stream settings describe.
	private fun Source.putTlsAndTransport(outbound: JSONObject) {
		val address = outbound.optString("server")
		val tls = SingBoxStream.buildTls(stream, address, notes)
		if (tls != null) outbound.put("tls", tls)
		SingBoxStream.buildTransport(stream, notes)?.let {
			SingBoxStream.keepXrayHost(stream, tls, it, address)
			outbound.put("transport", it)
		}
	}

	// VLESS / VMess: server/uuid + flow or vmess security, tls, transport
	private fun Source.buildVlessOrVmess(proto: String): OutboundResult {
		// One endpoint: the converter splits an outbound naming several before it reaches here.
		val endpoint = proxyEndpoint(proto, xrayOutbound)
		val user = endpoint?.user ?: JSONObject()
		if (proto == "vless" && settings.xStr("seed").isNotEmpty()) notes.add(UNUSED_VLESS_SEED)
		val outbound = JSONObject()
		outbound.put("type", proto)
		outbound.put("tag", tag)
		outbound.put("server", endpoint?.address ?: "")
		outbound.put("server_port", endpoint?.port ?: 0)
		outbound.put("uuid", user.xStr("id"))
		if (proto == "vless") {
			val flowRaw = user.xStr("flow")
			val flow = normalizeFlow(flowRaw)
			if (flow.isNotEmpty()) outbound.put("flow", flow)
		} else {
			outbound.put("security", vmessSecurity(user))
			vmessSecurityNote(user)?.let { notes.add(it) }
			outbound.put("alter_id", 0)
			vmessAlterIdNote(user)?.let { notes.add(it) }
			var globalPadding: Any? = user.opt("global_padding")
			if (globalPadding == null ||
				globalPadding === JSONObject.NULL) globalPadding = user.opt("globalPadding")
			if (globalPadding == null || globalPadding === JSONObject.NULL) {
				outbound.put("global_padding", true)
			} else if (globalPadding is Boolean) {
				outbound.put("global_padding", globalPadding)
			} else {
				outbound.put("global_padding", globalPadding.toString().lowercase() == "true")
			}
			// Xray reads both from the user's experiments, each as a plain substring.
			val experiments = user.xStr("experiments")
			if (experiments.contains("AuthenticatedLength")) outbound.put("authenticated_length", true)
			if (experiments.contains("NoTerminationSignal")) {
				notes.add(
					"the vmess NoTerminationSignal experiment has no sing-box equivalent and was dropped"
				)
			}
		}
		val packetEncoding = packetEncodingOf(xrayOutbound, proto)
		if (packetEncoding != null) outbound.put("packet_encoding", packetEncoding)
		putTlsAndTransport(outbound)
		// sing-box runs a VMess "auto" under TLS as zero, which Xray servers refuse from 26.7.11; Xray's
		// own auto is a cipher.
		if (proto == "vmess" && outbound.optString("security") == "auto" && outbound.has("tls")) {
			outbound.put("security", "aes-128-gcm")
			notes.add(VMESS_AUTO_UNDER_TLS_NOTE)
		}
		return finishProxy(outbound, xrayOutbound, stream, dnsResolverTag, notes)
	}

	private const val VMESS_AUTO_UNDER_TLS_NOTE = "vmess security auto is zero under TLS in sing-box, " +
		"which an Xray server refuses from 26.7.11, so aes-128-gcm - Xray's auto on a device with AES " +
		"hardware - was written"

	private fun Source.buildTrojan(): OutboundResult {
		val srv = trojanServer(xrayOutbound) ?: JSONObject()
		val outbound = JSONObject()
		outbound.put("type", "trojan")
		outbound.put("tag", tag)
		outbound.put("server", srv.xStr("address"))
		outbound.put("server_port", srv.xInt("port"))
		outbound.put("password", srv.xStrRaw("password"))
		putTlsAndTransport(outbound)
		return finishProxy(outbound, xrayOutbound, stream, dnsResolverTag, notes)
	}

	// Shadowsocks (+ plugin)
	private fun Source.buildShadowsocks(): OutboundResult {
		val srv = shadowsocksServer(xrayOutbound) ?: JSONObject()
		// Same read as unsupportedReason above, so the check and the conversion can't disagree.
		// The pre-check has already refused a node without a method; what reaches here has one.
		val rawMethod = srv.xStr("method")
		val method = canonicalSsMethod(rawMethod)
		val outbound = JSONObject()
		outbound.put("type", "shadowsocks")
		outbound.put("tag", tag)
		outbound.put("server", srv.xStrOf("address", "server"))
		outbound.put("server_port", srv.xInt("port").takeIf { it > 0 } ?: srv.xInt("server_port"))
		outbound.put("method", method)
		val ssPassword = srv.xStrRaw("password")
		outbound.put("password", ssPassword)
		// A plugin the server names itself stands; otherwise a transport under the outbound is the
		// v2ray-plugin in websocket mode, the same wire format.
		val serverPlugin = serverPluginOf(srv)
		val form = transportFormOf("shadowsocks", stream)
		val transportPlugin = form.pluginFor(srv.xStrOf("address", "server"))
		serverPlugin.plugin?.withOwnDefaults()?.let { own ->
			outbound.put("plugin", own.name)
			val options = own.sip003().substringAfter(';')
			if (options.isNotEmpty()) outbound.put("plugin_opts", options)
			notes.addAll(serverPlugin.notes)
			transportPlugin?.let { notes.add(displacedTransportNote(own, it)) }
		}
		if (serverPlugin.plugin == null) {
			transportPlugin?.let {
				outbound.put("plugin", it.name)
				outbound.put("plugin_opts", it.sip003().substringAfter(';'))
			}
			form.insecureLost?.let { notes.add(it) }
		}
		return finishProxy(outbound, xrayOutbound, stream, dnsResolverTag, notes)
	}

	private fun Source.buildSocks(): OutboundResult {
		val srv = settings.optJSONArray("servers")?.optJSONObject(0) ?: JSONObject()
		val outbound = credentialedOutbound("socks", tag, settings)
		val ver = srv.opt("version") ?: settings.opt("version")
		if (ver != null && ver !== JSONObject.NULL) {
			val versionText = ver.toString().replace("socks", "")
			if (versionText == "4" || versionText == "4a" ||
				versionText == "5") outbound.put("version", versionText)
		}
		return finishProxy(outbound, xrayOutbound, stream, dnsResolverTag, notes)
	}

	private fun Source.buildHttp(): OutboundResult {
		val outbound = credentialedOutbound("http", tag, settings)
		// Xray sends these with every CONNECT, from settings in either form.
		val headers = settings.xHeaders("headers")
		if (headers.isNotEmpty()) {
			val map = JSONObject()
			for ((name, value) in headers) map.put(name, value)
			outbound.put("headers", map)
		}
		val tls = SingBoxStream.buildTls(stream, outbound.optString("server"), notes)
		if (tls != null) outbound.put("tls", tls)
		return finishProxy(outbound, xrayOutbound, stream, dnsResolverTag, notes)
	}

	// WireGuard's reserved field, read in both forms Xray takes - a list of bytes or their base64 - and
	// carried only at the three bytes both cores insist on: any other length is answered with "invalid
	// reserved value" and refuses the whole document. Rebuilt from the bytes, so a 2.0 reaches it as 2.
	private fun reservedThreeBytes(raw: Any?, notes: MutableList<String>): JSONArray? {
		if (!isTruthy(raw)) return null
		val bytes = parseReserved(raw) { notes.add(reservedNotByteNote(it)) } ?: return null
		if (bytes.size != WG_RESERVED_BYTES) {
			notes.add("wireguard reserved is ${bytes.size} bytes where sing-box wants three, so it was " +
				"dropped")
			return null
		}
		return JSONArray().also { array -> bytes.forEach { array.put(it.toInt() and 0xFF) } }
	}

	// WireGuard to a sing-box endpoint
	internal fun buildWireguard(
		xrayOutbound: JSONObject,
		settings: JSONObject,
		tag: String,
		dnsResolverTag: String?,
		notes: MutableList<String>
	): JSONObject {
		val addressesAny = settings.opt("address")
		val addresses = JSONArray()
		when (addressesAny) {
			// A null or empty entry reaches sing-box as the zero address, which it takes without
			// complaint and then panics over; a repeated one, in whatever spelling, it refuses as a
			// duplicate address.
			is JSONArray -> {
				val seen = HashSet<Any>()
				for (i in 0 until addressesAny.length()) {
					val entry = addressesAny.opt(i)
					if (entry == null || entry == JSONObject.NULL || entry == "") continue
					val prefix = wireguardInterfacePrefix(entry)
					if (prefix == null) notes.add(wireguardAddressDroppedNote(entry))
					else if (seen.add(prefixKey(prefix) ?: prefix)) addresses.put(prefix)
				}
			}
			is String -> if (addressesAny.isNotEmpty()) {
				val prefix = wireguardInterfacePrefix(addressesAny)
				if (prefix == null) {
					notes.add(wireguardAddressDroppedNote(addressesAny))
				} else {
					addresses.put(prefix)
				}
			}
		}
		val endpointOutbound = JSONObject()
		endpointOutbound.put("type", "wireguard")
		endpointOutbound.put("tag", tag)
		if (addresses.length() > 0) {
			endpointOutbound.put("address", addresses)
		} else {
			// The interface address is what the server assigned this peer, and the configuration did not say.
			// The usual client address is assumed and said, as the mihomo pass assumes it: a wrong one is a
			// tunnel that comes up and routes nothing.
			val fallback = JSONArray()
			fallback.put(WIREGUARD_ASSUMED_ADDRESS)
			endpointOutbound.put("address", fallback)
			notes.add(
				"the wireguard outbound names no address; $WIREGUARD_ASSUMED_ADDRESS was assumed " +
					"- check it against what the server assigned"
			)
		}
		endpointOutbound.put("private_key", canonicalWireguardKey(settings.optString("secretKey", "")))
		val mtuVal = settings.opt("mtu")
		if (isTruthy(mtuVal)) {
			val mtu = when (mtuVal) {
				is Number -> mtuVal.toInt()
				is String -> mtuVal.toIntOrNull()
				else -> null
			}
			if (mtu != null) endpointOutbound.put("mtu", mtu)
		}
		val workersVal = settings.opt("workers")
		if (isTruthy(workersVal)) {
			val workers = when (workersVal) {
				is Number -> workersVal.toInt()
				is String -> workersVal.toIntOrNull()
				else -> null
			}
			if (workers != null) endpointOutbound.put("workers", workers)
		}
		// Xray keeps one reserved value for the whole outbound; sing-box has it on each peer and
		// nowhere else - on the endpoint it is an unknown field, which refuses the whole document.
		val sharedReserved = reservedThreeBytes(settings.opt("reserved"), notes)
		// Map each peer (endpoint, keys, allowed-ips, keepalive)
		val peers = JSONArray()
		val peerArr = settings.optJSONArray("peers")
		if (peerArr != null) {
			for (peerEntry in wireguardUsablePeers(settings)) {
				val endpoint = peerEntry.xStrRaw("endpoint")
				val hostPort = splitHostPort(endpoint)
				val peer = JSONObject()
				peer.put("address", hostPort.host)
				peer.put("port", hostPort.port ?: 0)
				peer.put("public_key", canonicalWireguardKey(peerEntry.optString("publicKey", "")))
				val allowed = peerEntry.optJSONArray("allowedIPs")
				if (allowed != null && allowed.length() > 0) {
					peer.put("allowed_ips", allowed)
				} else {
					val def = JSONArray()
					def.put("0.0.0.0/0")
					def.put("::/0")
					peer.put("allowed_ips", def)
				}
				val psk = peerEntry.optString("preSharedKey", "")
				if (psk.isNotEmpty()) peer.put("pre_shared_key", canonicalWireguardKey(psk))
				val keepAlive = peerEntry.opt("keepAlive")
				if (isTruthy(keepAlive)) {
					val seconds = when (keepAlive) {
						is Number -> keepAlive.toInt()
						is String -> keepAlive.toIntOrNull()
						else -> null
					}
					if (seconds != null) peer.put("persistent_keepalive_interval", seconds)
				}
				val ownReserved = reservedThreeBytes(peerEntry.opt("reserved"), notes) ?: sharedReserved
				ownReserved?.let { peer.put("reserved", it) }
				peers.put(peer)
			}
		}
		notes.addAll(wireguardDroppedPeerNotes(settings))
		if (peers.length() > 0) endpointOutbound.put("peers", peers)
		applyProxySettings(endpointOutbound, xrayOutbound)
		applySockopt(endpointOutbound, xrayOutbound.optJSONObject("streamSettings"), dnsResolverTag, notes)
		applySendThrough(endpointOutbound, xrayOutbound, notes)
		// Xray dials a WireGuard tunnel itself and reads nothing of the stream but the socket
		// options and the UDP mask - which it does apply here, and which sing-box has no field for.
		// Said out loud, because a masked server answers nothing to an endpoint without the mask.
		reportOutboundExtras(xrayOutbound, xrayOutbound.optJSONObject("streamSettings"), notes)
		return endpointOutbound
	}
}
