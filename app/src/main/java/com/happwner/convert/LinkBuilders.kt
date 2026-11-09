package com.happwner.convert

import android.util.Base64
import com.happwner.text.firstNonEmpty
import org.json.JSONObject

// One share link per protocol. Each builder reads a node written elsewhere and answers REFUSED, its
// reason noted, for one no client can use - no server to reach, nothing to authenticate with - or
// null for one that works but has no link form, which stays as it was written.
internal object LinkBuilders {

	// What a builder answers for a node it refuses - one that never worked, whose reason it has
	// noted - as against null, a node with no link form, which stays as it was written.
	internal const val REFUSED = "\u0000refused"

	// TLS details the QUIC schemes and an https proxy have no field for. Hysteria2's own scheme defines
	// pinSHA256 and ech, so only the fingerprint is left behind there; the rest define none of the three.
	private val UNCARRIED_TLS = listOf("fingerprint", "pinnedPeerCertSha256", "echConfigList")
	private val HYSTERIA2_TLS_DROPS = listOf("fingerprint")

	// The node's own label, then whatever the caller resolved, then last what the node is - never
	// empty, since an unnamed link reaches the client as a bare address.
	private fun linkName(outbound: JSONObject, rem: String, proto: String, host: String, port: Int): String =
		SubscriptionConverter.labelOf(outbound, false)
			.ifEmpty { rem }
			.ifEmpty { addressName(proto, host, port) }

	// The vless-shaped links carry Xray's own dialer masking as "fm"; the ones built here can't,
	// and a node tuned for a censored network behaves differently without it.
	private fun reportFinalmaskNotCarried(outbound: JSONObject, notes: MutableList<String>) {
		finalmaskFeatures(outbound).forEach {
			notes.add("$it is Xray's own and this link form has no field for it, so it was dropped")
		}
	}

	// What an outbound asked for that no link form holds, whichever protocol built it.
	internal fun reportOutboundExtrasNotCarried(outbound: JSONObject, notes: MutableList<String>) {
		if (outbound.xStr("targetStrategy").isNotEmpty()) {
			notes.add(
				"targetStrategy picks the address family this outbound dials with, which a link " +
					"has no field for, so it was dropped"
			)
		}
		val streamSettings = outbound.xObj("streamSettings")
		if (streamSettings.xHas("sockopt")) {
			notes.add(
				"sockopt sets up the dialer of this client and no link form carries it, so it was dropped"
			)
		}
		if (streamSettings.xHas("downloadSettings")) notes.add(MISPLACED_DOWNLOAD_SETTINGS)
		if (streamSettings.xHas("dialerProxy")) notes.add(MISPLACED_DIALER_PROXY)
		notes.addAll(olderConfigLeniencies(outbound))
	}

	// Naming what the stream settings asked for is the only honest way to hand over a link that's
	// just an address and credentials.
	private fun reportStreamIgnored(
		scheme: String,
		outbound: JSONObject,
		tlsCarried: Boolean,
		notes: MutableList<String>
	) {
		val streamSettings = outbound.xObj("streamSettings") ?: return
		val left = mutableListOf<String>()
		val net = streamMethod(streamSettings)
		if (net.isNotEmpty() && net != "tcp" && net != "raw") left.add("the $net transport")
		val security = streamSecurity(streamSettings)
		if (!tlsCarried && security != "none") left.add("$security security")
		// Dialer options and the download path are named for every protocol by
		// reportOutboundExtrasNotCarried already, so not repeated here.
		if (left.isEmpty()) return
		val what = if (left.size == 1) left[0] else left.dropLast(1).joinToString(", ") +
			" and " + left.last()
		notes.add("the $scheme link form has no place for $what, so it was dropped")
	}

	// TLS details a scheme has no query parameter of its own for.
	private fun reportTlsExtrasDropped(
		scheme: String,
		outbound: JSONObject,
		keys: List<String>,
		notes: MutableList<String>
	) {
		val tls = streamTls(outbound.xObj("streamSettings")) ?: return
		for (key in keys) {
			if (tls.xHas(key)) {
				notes.add("the $scheme link form has no field for tlsSettings.$key, so it was dropped")
			}
		}
	}

	// A link its clients could not connect from: left out with its reason or, where no client could,
	// kept as it was written - which loses nothing a link would, so only why there is no link is said.
	private fun stopped(notes: MutableList<String>, stop: LinkStop): String? {
		if (!stop.refused) notes.clear()
		notes.add(stop.reason)
		return if (stop.refused) REFUSED else null
	}

	// The pins a QUIC protocol's TLS names, one string as its scheme spells them.
	private fun pinList(pin: String): List<String> =
		pin.split(",").map { it.trim() }.filter { it.isNotEmpty() }

	// Hysteria v1 as a link, in the scheme the v1 client documents: credential in `auth`, rates in
	// `upmbps`/`downmbps`, SNI in `peer`, obfuscator `xplus` with its password in `obfsParam`.
	internal fun buildHysteria(
		outbound: JSONObject, rem: String, notes: MutableList<String>, clients: LinkClients
	): String? {
		return try {
			val settings = outbound.optJSONObject("settings") ?: JSONObject()
			val streamSettings = outbound.optJSONObject("streamSettings")

			val endpoint = hysteriaEndpoints(settings, streamSettings).firstOrNull()
				?: return refuse(notes, unusableServerRefusal("hysteria", "", 0))
			val address = endpoint.address
			var port = endpoint.port
			if (port == 0) firstPortOfRange(endpoint.ports)?.let { port = it }
			if (!LinkParams.usableHost(address) || port !in 1..65535) {
				return refuse(notes, unusableServerRefusal("hysteria", address, port))
			}

			// upmbps/downmbps take whole megabits; a rate that is not one has no place in the link.
			val up = mbpsNumber(endpoint.up, version = 1)
			val down = mbpsNumber(endpoint.down, version = 1)
			if (up == null || down == null) {
				val bad = if (up == null) endpoint.up else endpoint.down
				// A rate the client cannot read at all is a node that never connects anywhere; one it
				// reads that is not whole Mbps works, and only has no link form.
				if (bitsPerSecond(bad, version = 1) == null) {
					return refuse(
						notes,
						if (bad.isBlank()) "hysteria v1 needs both up and down rates"
						else "hysteria v1 needs both up and down rates, and \"$bad\" is not a rate " +
							"Hysteria reads"
					)
				}
				notes.add(
					if (bad.isBlank()) "the hysteria link needs both rates in upmbps/downmbps, and " +
						"the node names no rate, so it has no link form"
					else "the hysteria link takes whole Mbps in upmbps/downmbps, and the rate " +
						"\"$bad\" is not one, so the node has no link form"
				)
				return null
			}

			finalmaskRefusal(outbound)?.let { return refuse(notes, it) }
			val tls = hysteriaTls(settings, streamSettings)
			val checked = linkTls(streamSettings, tls.sni, tls.insecure, pinList(tls.pin), address,
				LinkScheme.HYSTERIA, clients, notes)
			checked.stop?.let { return stopped(notes, it) }
			// Read beside the address as well as beside the protocol - both shapes are in use.
			val (obfsMode, obfsPassword) = parsedObfsAnywhere(settings)
			// v1's obfuscation secret is a single string; when present the mode is xplus, its only one.
			val obfsSecret = firstNonEmpty(obfsPassword, obfsMode)

			val params = linkedMapOf<String, String>()
			params["protocol"] = "udp"
			if (endpoint.password.isNotEmpty()) params["auth"] = endpoint.password
			if (checked.sni.isNotEmpty()) params["peer"] = checked.sni
			if (tls.insecure) params["insecure"] = "1"
			params["upmbps"] = up.toString()
			params["downmbps"] = down.toString()
			if (tls.alpn.isNotEmpty()) params["alpn"] = tls.alpn.joinToString(",")
			if (obfsSecret.isNotEmpty()) {
				// mihomo reads the secret itself from obfs, where the scheme names the mode xplus; the
				// sing-box clients read it from obfsParam, as the scheme writes it.
				params["obfs"] = if (clients.mihomo) obfsSecret else "xplus"
				params["obfsParam"] = obfsSecret
			}

			reportTlsExtrasDropped("hysteria v1", outbound, UNCARRIED_TLS, notes)

			val host = LinkParams.hostForUri(address)
			reportFinalmaskNotCarried(outbound, notes)
			val fragment = LinkParams.enc(linkName(outbound, rem, "hysteria", address, port))
			"hysteria://$host:$port${LinkParams.queryString(params)}#$fragment"
		} catch (_: Exception) { null }
	}

	internal fun isShadowsocks(obj: JSONObject): Boolean {
		if (obj.has("server") && obj.has("server_port") && obj.has("password") &&
			obj.has("method")) return true
		val settings = obj.optJSONObject("settings")
		if (settings != null) {
			val servers = settings.optJSONArray("servers")
			if (servers != null && servers.length() > 0) {
				val server = servers.getJSONObject(0)
				if (server.has("address") && server.has("port") && server.has("password") &&
					server.has("method")) return true
			}
		}
		return false
	}

	// Renders a VLESS node as a link: vnext/users plus the REALITY and stream parameters.
	internal fun buildVless(
		outbound: JSONObject, rem: String, notes: MutableList<String>, clients: LinkClients
	): String? {
		return try {
			val endpoint = xrayEndpoints(outbound.optJSONObject("settings") ?: JSONObject()).firstOrNull()
				?: return refuse(notes, unusableServerRefusal("vless", "", 0))
			if (outbound.optJSONObject("settings").xStr("seed").isNotEmpty()) notes.add(UNUSED_VLESS_SEED)

			val id = endpoint.user.xStrRaw("id")
			val address = endpoint.address
			val port = endpoint.port
			if (!LinkParams.usableHost(address) || port !in 1..65535) {
				return refuse(notes, unusableServerRefusal("vless", address, port))
			}
			if (id.isEmpty()) return refuse(notes, missingCredentialRefusal("vless", "uuid"))

			val params = linkedMapOf<String, String>()
			params["encryption"] = endpoint.user.xStr("encryption").ifEmpty { "none" }
			vlessEncryptionRefusal(endpoint.user.xStr("encryption"))?.let {
				notes.add(it)
				return REFUSED
			}
			// Verbatim, not through the sing-box mapping: Xray-family clients take
			// "xtls-rprx-vision-udp443" and act on the -udp443 part.
			val flow = endpoint.user.xStr("flow")
			if (flow.isNotEmpty() && flow != "none") {
				vlessFlowRefusal(flow, endpoint.user.xStr("encryption"),
					outbound.optJSONObject("streamSettings"))?.let {
					notes.add(it)
					return REFUSED
				}
				params["flow"] = flow
			}
			xrayMaskRefusal(outbound, carriedWhole = true)?.let { return refuse(notes, it) }

			LinkParams.streamParams(
				outbound.optJSONObject("streamSettings"), params, notes = notes,
				scheme = LinkScheme.VLESS, address = address, clients = clients
			)?.let { return stopped(notes, it) }

			val host = LinkParams.hostForUri(address)
			val fragment = LinkParams.enc(linkName(outbound, rem, "vless", address, port))
			"vless://${LinkParams.enc(id)}@$host:$port${LinkParams.queryString(params)}#$fragment"
		} catch (_: Exception) { null }
	}

	// One blob field often stands for several: "path" carries the WS/HTTP path, the gRPC service
	// name, the QUIC key and the mKCP seed; "host" carries the QUIC security beside transport host.
	private val VMESS_BLOB_FIELDS = setOf(
		"type", "security", "headerType", "host", "path", "serviceName", "sni", "alpn", "fp",
		"allowInsecure", "pcs", "vcn", "key", "seed", "quicSecurity", "mode"
	)

	// Renders a VMess node as a link: the legacy JSON blob, base64-encoded.
	internal fun buildVmess(
		outbound: JSONObject, rem: String, notes: MutableList<String>, clients: LinkClients
	): String? {
		return try {
			val settings = outbound.optJSONObject("settings")
			val endpoint = xrayEndpoints(settings).firstOrNull()
			val user = endpoint?.user

			val addr = firstNonEmpty(endpoint?.address ?: "", outbound.optString("server"))
			val port = endpoint?.port?.takeIf { it > 0 } ?: outbound.optInt("server_port", 0)
			val uuid = firstNonEmpty(user.xStrRaw("id"), outbound.optString("uuid"))
			if (!LinkParams.usableHost(addr) || port !in 1..65535) {
				return refuse(notes, unusableServerRefusal("vmess", addr, port))
			}
			if (uuid.isEmpty()) return refuse(notes, missingCredentialRefusal("vmess", "uuid"))

			// The blob has TLS fields but none for REALITY, so such a node would go out as a
			// complete-looking plain-TLS link and get refused. Null here means a working fallback.
			val streamSettings = outbound.optJSONObject("streamSettings")
			if (streamSettings != null && streamSecurity(streamSettings) == "reality") return null

			finalmaskRefusal(outbound)?.let { return refuse(notes, it) }
			val params = linkedMapOf<String, String>()
			LinkParams.streamParams(streamSettings, params, notes = notes, scheme = LinkScheme.VMESS,
				address = addr, clients = clients)?.let { return stopped(notes, it) }

			val linkJson = JSONObject()
			linkJson.put("v", "2")
			linkJson.put("add", addr)
			linkJson.put("port", port.toString())
			linkJson.put("id", uuid)
			// alterId is a number in the blob and every current node is zero.
			linkJson.put("aid", "0")
			vmessAlterIdNote(user)?.let { notes.add(it) }
			linkJson.put("scy", vmessSecurity(user))
			vmessSecurityNote(user)?.let { notes.add(it) }
			linkJson.put("net", params["type"] ?: "tcp")
			// The blob's "type" is the masquerade header for tcp/kcp/quic ("none" rather than
			// absent), and the mode for gRPC ("gun"/"multi", how v2rayNG reads it).
			val blobType = if (params["type"] == "grpc") (if (params["mode"] == "multi") "multi" else "gun")
				else params["headerType"] ?: "none"
			linkJson.put("type", blobType)
			linkJson.put("host", params["host"] ?: params["quicSecurity"] ?: "")
			linkJson.put("path", firstNonEmpty(
				params["path"] ?: "", params["serviceName"] ?: "",
				params["key"] ?: "", params["seed"] ?: ""
			))
			linkJson.put("tls", if (params["security"] == "tls") "tls" else "")
			linkJson.put("sni", params["sni"] ?: "")
			// Present but empty isn't absent: clients read "alpn" as comma-separated, so an empty
			// string offers one empty protocol name and the handshake finds no match.
			params["alpn"]?.takeIf { it.isNotEmpty() }?.let { linkJson.put("alpn", it) }
			linkJson.put("fp", params["fp"] ?: "")
			// Written only when set: every existing link is read as secure without them.
			if (params["allowInsecure"] == "1") linkJson.put("insecure", "1")
			params["pcs"]?.let { linkJson.put("pcs", it) }
			params["vcn"]?.let { linkJson.put("vcn", it) }
			linkJson.put("ps", linkName(outbound, rem, "vmess", addr, port))
			reportFinalmaskNotCarried(outbound, notes)

			// The blob has a field for each of these and no room for the rest - but a finalmask of mKCP masks
			// alone, which ride in its type and path, is not lost.
			val carried = params["type"] == "kcp" && finalmaskFeatures(outbound).isEmpty()
			val dropped = params.keys.filterNot { it in VMESS_BLOB_FIELDS || it == "fm" && carried }.sorted()
			if (dropped.isNotEmpty()) {
				notes.add("the vmess link form has no field for ${dropped.joinToString(", ")}, " +
					"so it was dropped")
			}

			val base64 = Base64.encodeToString(
				jsonText(linkJson).toByteArray(), Base64.NO_WRAP
			)
			"vmess://$base64"
		} catch (_: Exception) { null }
	}

	// The socks/http server a link can be built for: one that names a usable host and port.
	private fun linkableServer(
		outbound: JSONObject, proto: String, notes: MutableList<String>
	): CredentialedServer? {
		val server = credentialedServer(outbound.optJSONObject("settings"))
		if (server != null && LinkParams.usableHost(server.address) && server.port in 1..65535) return server
		notes.add(unusableServerRefusal(proto, server?.address.orEmpty(), server?.port ?: 0))
		return null
	}

	// A node no client could use is left out with its reason, as the other passes leave it out:
	// handed back as written it would be a configuration that connects nowhere either.
	private fun refuse(notes: MutableList<String>, reason: String): String {
		notes.add(reason)
		return REFUSED
	}

	// Credentials base64-encoded in the userinfo, the form clients read - plain where a sing-box client
	// would split them wrong.
	internal fun buildSocks(
		outbound: JSONObject, rem: String, notes: MutableList<String>, clients: LinkClients
	): String? {
		return try {
			val (address, port, name, pass) = linkableServer(outbound, "socks", notes) ?: return REFUSED
			finalmaskRefusal(outbound)?.let { return refuse(notes, it) }
			reportFinalmaskNotCarried(outbound, notes)
			// No place for a transport or TLS - a link without them would connect to nothing.
			transportFormOf("socks",
				outbound.xObj("streamSettings")).refusal?.let { notes.add(it); return null }
			if (streamSecurity(outbound.xObj("streamSettings")) == "tls") {
				notes.add("the socks link form has no TLS, and a link written without it connects to nothing")
				return null
			}
			val userInfo = if (name.isEmpty() && pass.isEmpty()) "" else {
				val raw = "$name:$pass"
				val encoded = Base64.encodeToString(
					raw.toByteArray(), Base64.NO_WRAP or Base64.NO_PADDING
				)
				mihomoSocksRefusal(name, pass, encoded, clients)?.let { return refuse(notes, it) }
				// A sing-box client splits the base64 at its first ":", so for it a name holding one
				// goes plain, escaped, which it reads too; a "/" of base64 would end the address.
				if (clients.singBox && ':' in name) "${LinkParams.enc(name)}:${LinkParams.enc(pass)}@"
				else encoded.replace("/", "%2F") + "@"
			}
			reportStreamIgnored("socks", outbound, tlsCarried = false, notes = notes)
			val host = LinkParams.hostForUri(address)
			"socks://$userInfo$host:$port#${LinkParams.enc(linkName(outbound, rem, "socks", address, port))}"
		} catch (_: Exception) { null }
	}

	// Why a mihomo client could not take a socks link's name and password, or null: it splits them at every
	// ":", and reads a "/" of their base64 - which only a "?", DEL or a character past ASCII puts there -
	// back escaped.
	private fun mihomoSocksRefusal(
		name: String, pass: String, encoded: String, clients: LinkClients
	): String? = when {
		!clients.mihomo -> null
		':' in name + pass -> "the name or password holds a \":\", at which a mihomo client splits those " +
			"of a socks link, so it would not connect"
		'/' in encoded -> "the base64 of the name and password holds a \"/\", which a mihomo client reads " +
			"from a socks link in its escaped form, so it would not connect"
		else -> null
	}

	// The scheme follows the TLS layer - an HTTP proxy over TLS is https://.
	internal fun buildHttpProxy(
		outbound: JSONObject, rem: String, notes: MutableList<String>, clients: LinkClients
	): String? {
		return try {
			val (address, port, name, pass) = linkableServer(outbound, "http", notes) ?: return REFUSED
			finalmaskRefusal(outbound)?.let { return refuse(notes, it) }
			reportFinalmaskNotCarried(outbound, notes)
			val userInfo = if (name.isEmpty() && pass.isEmpty()) ""
			else "${LinkParams.enc(name)}:${LinkParams.enc(pass)}@"

			val streamSettings = outbound.optJSONObject("streamSettings")
			val secure = streamSecurity(streamSettings) == "tls"
			val scheme = if (secure) "https" else "http"
			// sni/alpn/allowInsecure travel with the scheme itself; a transport has no place, and
			// a link without one would connect to nothing.
			transportFormOf("http",
				outbound.xObj("streamSettings")).refusal?.let { notes.add(it); return null }
			if (clients.mihomo && !(name + pass).all(::keptInUserPart)) {
				return refuse(notes, "the name or password holds characters a mihomo client reads from an " +
					"$scheme link in their escaped form, so it would not connect")
			}
			val params = linkedMapOf<String, String>()
			if (secure) {
				val tls = streamTls(streamSettings)
				val insecure = tls?.optBoolean("allowInsecure", false) == true
				val checked = linkTls(streamSettings, tls?.optString("serverName", "").orEmpty(), insecure,
					tls.xStrList("pinnedPeerCertSha256"), address, LinkScheme.HTTPS, clients, notes)
				checked.stop?.let { return stopped(notes, it) }
				if (checked.sni.isNotEmpty()) params["sni"] = checked.sni
				if (clients.mihomo && checked.sni.isNotEmpty() && !sameNameSent(checked.sni, address)) {
					notes.add("a mihomo client reads no server name from https links: it names the server " +
						"by its address, \"${LinkParams.linkHost(address)}\", rather than \"${checked.sni}\"")
				}
				val alpn = LinkParams.joinList(tls?.opt("alpn"))
				if (alpn.isNotEmpty()) params["alpn"] = alpn
				if (insecure) params["allowInsecure"] = "1"
				reportTlsExtrasDropped(scheme, outbound, UNCARRIED_TLS, notes)
			}
			reportStreamIgnored(scheme, outbound, tlsCarried = true, notes = notes)
			val host = LinkParams.hostForUri(address)
			val fragment = LinkParams.enc(linkName(outbound, rem, "http", address, port))
			"$scheme://$userInfo$host:$port${LinkParams.queryString(params)}#$fragment"
		} catch (_: Exception) { null }
	}

	// Shadowsocks: base64(method:password)@host:port
	internal fun buildShadowsocks(
		outbound: JSONObject, rem: String, notes: MutableList<String>, clients: LinkClients
	): String? {
		return try {
			val server = shadowsocksServers(outbound).firstOrNull()
				?: return refuse(notes, unusableServerRefusal("shadowsocks", "", 0))
			val address = server.xStrOf("address", "server")
			val port = server.xInt("port").takeIf { it > 0 } ?: server.xInt("server_port")
			val method = canonicalSsMethod(server.optString("method", ""))
			val password = server.optString("password", "")
			if (!LinkParams.usableHost(address) || port !in 1..65535) {
				return refuse(notes, unusableServerRefusal("shadowsocks", address, port))
			}
			finalmaskRefusal(outbound)?.let { return refuse(notes, it) }
			reportFinalmaskNotCarried(outbound, notes)
			// Both halves of the userinfo authenticate the connection, and a node missing either is
			// one no server will answer.
			if (method.isEmpty()) return refuse(notes, MISSING_SS_METHOD_REFUSAL)
			unknownSsMethodRefusal(method)?.let { return refuse(notes, it) }
			if (password.isEmpty()) return refuse(notes, missingCredentialRefusal("shadowsocks", "password"))
			ss2022KeyRefusal(method, password)?.let { notes.add(it); return REFUSED }
			val serverPlugin = serverPluginOf(server)
			serverPlugin.refusal?.let { return refuse(notes, it) }
			// SIP002 carries the userinfo as web-safe base64 of "method:password".
			val userInfo = if (method.startsWith("2022-")) {
				"${LinkParams.enc(method)}:${LinkParams.enc(password)}"
			} else {
				Base64.encodeToString(
					"$method:$password".toByteArray(),
					Base64.NO_WRAP or Base64.NO_PADDING or
						Base64.URL_SAFE
				)
			}
			// A transport is the v2ray-plugin in websocket mode, carried like any plugin; anything
			// else has no link form, and the node stays as it was written.
			val form = transportFormOf("shadowsocks", outbound.xObj("streamSettings"))
			form.refusal?.let { notes.add(it); return null }
			val transportPlugin = form.pluginFor(address)
			// Over TLS that plugin checks the certificate against its host and the system store, and takes
			// no CA, no pin and no allowInsecure.
			if (serverPlugin.plugin == null && transportPlugin?.options?.containsKey("tls") == true) {
				val stream = outbound.xObj("streamSettings")
				linkTls(stream, transportPlugin.options["host"].orEmpty(), insecure = false,
					streamTls(stream).xStrList("pinnedPeerCertSha256"), address, LinkScheme.SHADOWSOCKS,
					clients, notes).stop?.let { return stopped(notes, it) }
			}
			if (serverPlugin.plugin == null) form.insecureLost?.let { notes.add(it) }
			val encRem = LinkParams.enc(linkName(outbound, rem, "ss", address, port))
			// A link without the plugin's obfuscation points at a server that won't answer;
			// SIP002 carries it as one "name;options" value.
			// The server's own plugin comes before one read from the transport, as in both cores.
			val carried = serverPlugin.plugin?.forLink() ?: transportPlugin
			mihomoPluginRefusal(carried, clients)?.let { return refuse(notes, it) }
			// A transport the plugin carries is in the link; only one the server's own plugin takes the
			// place of is left behind, and that one is named.
			serverPlugin.plugin?.let { own ->
				notes.addAll(serverPlugin.notes)
				transportPlugin?.let { notes.add(displacedTransportNote(own, it)) }
			}
			val query = if (carried == null) "" else {
				"/?plugin=" + LinkParams.enc(carried.sip003().removeSuffix(";"))
			}
			"ss://$userInfo@${LinkParams.hostForUri(address)}:$port$query#$encRem"
		} catch (_: Exception) { null }
	}

	// Why a mihomo client could not take the plugin from the link, or null: it runs a v2ray-plugin over
	// websocket alone, refusing one over quic and the whole file with it, and turns its TLS on wherever
	// the text holds "tls" - a host or a path will do.
	private fun mihomoPluginRefusal(carried: TransportPlugin?, clients: LinkClients): String? {
		if (!clients.mihomo || carried == null || carried.name != "v2ray-plugin") return null
		return when {
			carried.options["mode"] == "quic" ->
				"the v2ray-plugin runs over quic, which a mihomo client refuses from a link, and the whole " +
					"file with it"
			"tls" !in carried.options && "tls" in carried.sip003() ->
				"the v2ray-plugin runs without TLS while its options hold \"tls\", from which a mihomo " +
					"client reads TLS into the link, so it would not connect"
			else -> null
		}
	}

	// Renders a Trojan node as a link: password@host:port with the tls/ws query.
	internal fun buildTrojan(
		outbound: JSONObject, rem: String, notes: MutableList<String>, clients: LinkClients
	): String? {
		return try {
			val server = outbound.xObj("settings")?.let { xrayServers(it, "address").firstOrNull() }
				?: return refuse(notes, unusableServerRefusal("trojan", "", 0))
			val address = server.xStr("address")
			val port = server.xInt("port")
			val password = server.optString("password", "")
			if (!LinkParams.usableHost(address) || port !in 1..65535) {
				return refuse(notes, unusableServerRefusal("trojan", address, port))
			}
			// Trojan authenticates by password alone; without one there is nothing to connect with.
			if (password.isEmpty()) return refuse(notes, missingCredentialRefusal("trojan", "password"))
			xrayMaskRefusal(outbound, carriedWhole = true)?.let { return refuse(notes, it) }

			val params = linkedMapOf<String, String>()
			LinkParams.streamParams(
				outbound.optJSONObject("streamSettings"), params, mirrorSniToHost = true, notes = notes,
				scheme = LinkScheme.TROJAN, address = address, clients = clients
			)?.let { return stopped(notes, it) }

			val host = LinkParams.hostForUri(address)
			val fragment = LinkParams.enc(linkName(outbound, rem, "trojan", address, port))
			"trojan://${LinkParams.enc(password)}@$host:$port${LinkParams.queryString(params)}#$fragment"
		} catch (_: Exception) { null }
	}

	// Renders a Hysteria2 node as a link, read through the shared parsers: password@host:port with
	// the obfs/sni query.
	internal fun buildHysteria2(
		outbound: JSONObject, rem: String, notes: MutableList<String>, clients: LinkClients
	): String? {
		return try {
			val settings = outbound.optJSONObject("settings") ?: JSONObject()
			val streamSettings = outbound.optJSONObject("streamSettings")

			val endpoint = hysteriaEndpoints(settings, streamSettings).firstOrNull()
				?: return refuse(notes, unusableServerRefusal("hysteria2", "", 0))
			val params = HysteriaParams()
			params.fromStream(notes, streamSettings)
			params.windowsDroppedNote("this link form")?.let { notes.add(it) }

			val address = endpoint.address
			var port = endpoint.port
			if (port == 0) firstPortOfRange(firstNonEmpty(endpoint.ports, params.ports))?.let { port = it }
			if (!LinkParams.usableHost(address) || port !in 1..65535) {
				return refuse(notes, unusableServerRefusal("hysteria2", address, port))
			}

			val password = firstNonEmpty(endpoint.password, params.password)
			// Hysteria2 authenticates by password alone - a node without one connects to nothing.
			if (password.isEmpty()) return refuse(notes, MISSING_HYSTERIA2_PASSWORD_REFUSAL)
			if (clients.mihomo && !password.all(::keptInUserPart)) {
				return refuse(notes, "the password holds characters a mihomo client reads from a hysteria2 " +
					"link in their escaped form, so it would not connect")
			}
			notes.addAll(brutalRateNotes(outbound.optJSONObject("streamSettings")))
			// Obfuscation can sit beside the address or the protocol; read from both, or the
			// server won't answer.
			val (obfsFromSettings, obfsPwFromSettings) = parsedObfsAnywhere(settings)
			val obfsType = firstNonEmpty(obfsFromSettings, params.obfs)
			val obfsPassword = firstNonEmpty(obfsPwFromSettings, params.obfsPassword)
			// A server answers only the obfuscation it runs, salamander or gecko; a node written
			// with a third type connects to nothing, as the other passes also refuse it.
			if (obfsType.isNotEmpty() && obfsType.lowercase() !in setOf("salamander", "gecko")) {
				notes.add("hysteria2 obfuscation \"$obfsType\" is neither salamander nor gecko")
				return REFUSED
			}
			hysteriaObfsRefusal(obfsType, obfsPassword)?.let { return refuse(notes, it) }
			finalmaskRefusal(outbound)?.let { return refuse(notes, it) }
			val tls = hysteriaTls(settings, streamSettings)
			val checked = linkTls(streamSettings, tls.sni, tls.insecure, pinList(tls.pin), address,
				LinkScheme.HYSTERIA2, clients, notes)
			checked.stop?.let { return stopped(notes, it) }

			val query = StringBuilder()
			if (obfsType.isNotEmpty()) query.append("&obfs=").append(LinkParams.enc(obfsType))
			if (obfsPassword.isNotEmpty()) {
				query.append("&obfs-password=").append(LinkParams.enc(obfsPassword))
			}
			if (checked.sni.isNotEmpty()) query.append("&sni=").append(LinkParams.enc(checked.sni))
			if (tls.insecure) query.append("&insecure=1")
			// No alpn parameter in the scheme, and Hysteria2 negotiates "h3" by definition - writing
			// it says nothing. Anything else is a real difference and is kept.
			if (tls.alpn.isNotEmpty() && tls.alpn != listOf("h3")) {
				query.append("&alpn=").append(LinkParams.enc(tls.alpn.joinToString(",")))
			}
			if (checked.pin.isNotEmpty()) query.append("&pinSHA256=").append(LinkParams.enc(checked.pin))
			if (tls.ech.isNotEmpty()) query.append("&ech=").append(LinkParams.enc(tls.ech))
			// The primary port stays in the authority so every client connects; the range
			// travels as mport.
			val hop = hopPorts(firstNonEmpty(endpoint.ports, params.ports))
			notes.addAll(hop.notes())
			if (hop.ranges.size > 1 || hop.ranges.any { it.first < it.last }) {
				query.append("&mport=").append(LinkParams.enc(hop.joined()))
				// Clients read mportHopInt as one integer of seconds - a range hops at random
				// within its bounds, so the link carries the lower one and says so.
				val (hop, hopNote) = dialableHopInterval(
					firstNonEmpty(endpoint.hopInterval, params.hopInterval, hysteriaHopInterval(settings))
				)
				hopNote?.let { notes.add(it) }
				if (hop.low.isNotEmpty()) query.append("&mportHopInt=").append(LinkParams.enc(hop.low))
				if (hop.isRange) {
					notes.add(
						"the hop interval \"${hop.low}-${hop.high}\" is a range, and the link form " +
							"takes one number; ${hop.low} was written"
					)
				}
			}

			reportTlsExtrasDropped("hysteria2", outbound, HYSTERIA2_TLS_DROPS, notes)

			val queryString = if (query.isNotEmpty()) "?" + query.toString().substring(1) else ""
			reportFinalmaskNotCarried(outbound, notes)
			val encRem = LinkParams.enc(linkName(outbound, rem, "hysteria2", address, port))
			val userInfo = LinkParams.enc(password) + "@"

			// The path separator belongs to the scheme as Hysteria documents it, and Happ's own
			// reference spells it the same way - written whether or not a query follows.
			"hysteria2://$userInfo${LinkParams.hostForUri(address)}:$port/$queryString#$encRem"
		} catch (_: Exception) { null }
	}

	// What Go writes back unescaped in a URL's user part, which is how a mihomo client takes a Hysteria2
	// password, and an http name and password, from a link: any other character reaches it escaped.
	private fun keptInUserPart(c: Char): Boolean =
		c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c in "-_.~$&+,;="

	// Renders a TUIC node as a link, in either shape it arrives in: uuid:password@host:port with the
	// congestion/tls query.
	internal fun buildTuic(
		outbound: JSONObject, rem: String, notes: MutableList<String>, clients: LinkClients
	): String? {
		return try {
			val xraySettings = outbound.optJSONObject("settings")
			val xraySrv = xraySettings?.optJSONArray("servers")?.optJSONObject(0) ?: xraySettings

			val address = firstNonEmpty(
				xraySrv?.optString("address") ?: "", xraySrv?.optString("server") ?: "",
				outbound.optString("server")
			)
			val port = xraySrv?.optInt("port")?.takeIf { it > 0 } ?: outbound.optInt("server_port")
			val uuid = firstNonEmpty(xraySrv?.optString("uuid") ?: "", outbound.optString("uuid"))
			val password = firstNonEmpty(xraySrv?.optString("password") ?: "", outbound.optString("password"))
			if (!LinkParams.usableHost(address) || port !in 1..65535) {
				return refuse(notes, unusableServerRefusal("tuic", address, port))
			}
			// tuic:// is TUIC v5, whose userinfo is the uuid and its password - a v4 node
			// authenticates with a token instead and has no link form at all.
			if (uuid.isEmpty()) return null
			tuicUuidRefusal(uuid)?.let { notes.add(it); return REFUSED }

			val query = mutableMapOf<String, String>()
			// Read in the same order both converters do: address first, then shared settings,
			// then the sing-box-shaped outbound.
			val shared = xraySettings ?: JSONObject()
			val congestion = firstNonEmpty(
				tuicSetting(xraySrv, shared, "congestion_control", "congestionController",
					"congestionControl"),
				outbound.optString("congestion_control")
			)
			if (congestion.isNotEmpty()) query["congestion_control"] = congestion

			val mode = firstNonEmpty(
				tuicSetting(xraySrv, shared, "udp_relay_mode", "udpRelayMode"),
				outbound.optString("udp_relay_mode")
			)
			if (mode.isNotEmpty()) query["udp_relay_mode"] = mode
			// 0-RTT and the heartbeat have no parameter in the tuic scheme, so named rather than
			// lost in silence.
			if (tuicFlag(xraySrv, shared, *TUIC_DISABLE_SNI_NAMES)) query["disable_sni"] = "1"
			val leftBehind = mutableListOf<String>()
			if (tuicFlag(xraySrv, shared, *TUIC_ZERO_RTT_NAMES)) leftBehind.add("0-RTT (reduce_rtt)")
			if (tuicHeartbeatMs(xraySrv, shared) > 0) leftBehind.add("the heartbeat interval")
			if (leftBehind.isNotEmpty()) {
				notes.add(
					"the tuic link form has no parameter for ${leftBehind.joinToString(" and ")}, " +
						"so it was dropped"
				)
			}

			finalmaskRefusal(outbound)?.let { return refuse(notes, it) }
			val streamSettings = outbound.optJSONObject("streamSettings")
			val tls = tuicTls(outbound, streamSettings)
			val checked = linkTls(streamSettings, tls.sni, tls.insecure, pinList(tls.pin), address,
				LinkScheme.TUIC, clients, notes)
			checked.stop?.let { return stopped(notes, it) }
			if (checked.sni.isNotEmpty()) query["sni"] = checked.sni
			if (tls.alpn.isNotEmpty()) query["alpn"] = tls.alpn.joinToString(",")
			if (tls.insecure) query["allow_insecure"] = "1"

			val queryStr = query.toList().sortedBy { it.first }.joinToString("&") {
				"${it.first}=${LinkParams.enc(it.second)}"
			}
			val queryString = if (queryStr.isNotEmpty()) "?$queryStr" else ""

			reportTlsExtrasDropped("tuic", outbound, UNCARRIED_TLS, notes)
			reportFinalmaskNotCarried(outbound, notes)
			val encRem = LinkParams.enc(linkName(outbound, rem, "tuic", address, port))

			// Percent-encoded like every other link's - a credential holding a delimiter would
			// otherwise end the authority early.
			"tuic://${LinkParams.enc(uuid)}:${LinkParams.enc(password)}@" +
				"${LinkParams.hostForUri(address)}:$port$queryString#$encRem"
		} catch (_: Exception) { null }
	}
}
