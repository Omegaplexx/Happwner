package com.happwner.convert

import com.happwner.text.decodeBase64
import com.happwner.text.decodeBase64Any
import com.happwner.text.encodeBase64Std
import com.happwner.text.fromHex
import com.happwner.text.stripBrackets
import com.happwner.text.toHex
import org.json.JSONObject

// The security layer and transport of an outbound: TLS, REALITY, ECH, and the
// websocket/gRPC/HTTP/2/mKCP/XHTTP transports.

// Describes how a protocol spells its TLS fields, which differs between the V2Ray-family protocols
// and the rest.
internal class TlsTarget(
	// "servername" for vless/vmess, "sni" for everything else.
	val sniKey: String,
	// True when the protocol needs "tls: true" to enable TLS. Trojan, Hysteria2 and TUIC are always
	// TLS and have no such field.
	val explicitTls: Boolean
)

// No flag for REALITY or ECH: the core parses both under every protocol that takes TLS.
internal val TLS_V2RAY = TlsTarget("servername", explicitTls = true)
internal val TLS_TROJAN = TlsTarget("sni", explicitTls = false)

// A node with no TLS of a protocol mihomo speaks over TLS alone, in the words document and link refuse it.
internal const val MIHOMO_PLAINTEXT_REFUSAL = "the source has no TLS layer, and mihomo always uses TLS for " +
	"this protocol, so a node written here would connect to nothing"

// Maps the stream's security layer onto the proxy entry.
internal fun MihomoConversion.applyTls(proxy: YamlMap, streamSettings: JSONObject?, target: TlsTarget) {
	securityRefusal(streamSettings)?.let { throw MihomoUnsupported(it) }
	val security = streamSecurity(streamSettings)
	val tlsCfg = streamTls(streamSettings)

	if (security == "none") {
		// Nothing to do for a protocol that defaults to plaintext.
		if (target.explicitTls) return
		// QUIC carries TLS of its own: what mihomo lacks there is the transport, which applyTransport names.
		if (streamNetwork(streamSettings) == "quic") return
		// mihomo's trojan always speaks TLS, so a node whose server takes plaintext would be handed
		// a handshake it does not answer: refused, not written with TLS switched on.
		throw MihomoUnsupported(MIHOMO_PLAINTEXT_REFUSAL)
	}
	// REALITY is a TLS variant, so both switch the same field on.
	if (target.explicitTls) proxy.set("tls", true)

	if (security == "reality") {
		applyReality(proxy, streamSettings, target)
		return
	}
	if (tlsCfg == null) return

	// The SNI is kept even when it repeats the server address: it is what the
	// source asked for, and it keeps the output easy to compare with it.
	proxy.setString(target.sniKey, tlsCfg.xStr("serverName"))

	val alpn = tlsCfg.xStrList("alpn")
	if (alpn.isNotEmpty()) proxy.set("alpn", toFlowSeq(alpn))
	if (tlsCfg.xBool("allowInsecure")) proxy.set("skip-cert-verify", true)
	applyNameCertVerify(proxy, tlsCfg)
	applyClientFingerprint(proxy, tlsCfg.xStr("fingerprint"))
	applyCertPin(proxy, tlsCfg)
	applyCertificates(proxy, tlsCfg)
	applyEch(proxy, tlsCfg)

	if (tlsCfg.xStr("minVersion").isNotEmpty()) {
		warn("tlsSettings.minVersion is not configurable per proxy in mihomo and was dropped")
	}
	if (tlsCfg.xStrList("curvePreferences").isNotEmpty()) {
		warn("tlsSettings.curvePreferences has no mihomo equivalent and was dropped")
	}
	if (tlsCfg.xStr("cipherSuites").isNotEmpty()) {
		warn("tlsSettings.cipherSuites has no mihomo equivalent and was dropped")
	}
	if (tlsCfg.xBool("disableSystemRoot")) {
		warn("tlsSettings.disableSystemRoot has no mihomo equivalent; the system roots stay in use")
	}
	if (tlsCfg.xStr("masterKeyLog").isNotEmpty()) {
		warn("tlsSettings.masterKeyLog has no mihomo equivalent and was dropped")
	}
	if (tlsCfg.xStr("maxVersion").isNotEmpty()) {
		warn("tlsSettings.maxVersion is not configurable per proxy in mihomo and was dropped")
	}
	if (tlsCfg.xHas("enableSessionResumption")) {
		warn("tlsSettings.enableSessionResumption has no mihomo equivalent and was dropped")
	}
}

// Maps realitySettings onto mihomo's reality-opts.
private fun MihomoConversion.applyReality(proxy: YamlMap, streamSettings: JSONObject?, target: TlsTarget) {
	// The shared security check has already refused a REALITY node without its settings or key.
	val reality = streamSettings.xObj("realitySettings") ?: return

	val sni = realitySni(reality)
	if (sni.isNotEmpty()) proxy.set(target.sniKey, sni)
	applyRealityFingerprint(proxy, reality.xStr("fingerprint"))
	proxy.set("reality-opts", realityOptions(reality))
	warn(REALITY_MIHOMO_NOTE)

	if (reality.xStr("spiderX").isNotEmpty()) {
		warn("realitySettings.spiderX has no mihomo equivalent and was dropped")
	}
	if (reality.xStr("mldsa65Verify").isNotEmpty()) {
		warn(
			"realitySettings.mldsa65Verify (post-quantum certificate verification) " +
				"is not supported by mihomo and was dropped"
		)
	}
	val alpn = streamTls(streamSettings).xStrList("alpn")
	if (alpn.isNotEmpty()) proxy.set("alpn", toFlowSeq(alpn))
}

// The key and short id, and X25519MLKEM768 offered as Xray's client offers it: mihomo leaves it out
// unless told, and a REALITY server of Xray from 26.9.8 turns a Client Hello without it away.
private fun realityOptions(reality: JSONObject): YamlMap = YamlMap()
	.setString("public-key", realityPublicKey(reality))
	.setString("short-id", realityShortId(reality))
	.set("support-x25519mlkem768", true)

// The uTLS profiles mihomo resolves to a real ClientHello. The core accepts any string and silently
// falls back to Go's own crypto/tls for one it does not know, which is trivially fingerprintable.
private val UTLS_FINGERPRINTS = setOf(
	"chrome", "firefox", "safari", "ios", "android", "edge",
	"360", "qq", "random", "randomized",
	"chrome120", "firefox120"
)

// Names with an exact counterpart under a different spelling.
private val UTLS_ALIASES = mapOf(
	"randomizedalpn" to "randomized",
	"randomizednoalpn" to "randomized"
)

// The profile mihomo runs for a uTLS name, or null for none, and what is said about the name.
private fun clientFingerprintOf(raw: String): Pair<String?, String?> {
	val fingerprint = raw.trim().lowercase()
	if (fingerprint.isEmpty()) return null to null
	if (fingerprint in UTLS_FINGERPRINTS) return fingerprint to null

	// The core's lookup is exact and case-sensitive: "chrome_120", "chrome-120" and "Chrome120" all
	// fall through to a plain Go handshake.
	val bare = fingerprint.removePrefix("hello")
	val compact = bare.filterNot { it == '_' || it == '-' || it == '.' || it == ' ' }
	if (compact != fingerprint && compact in UTLS_FINGERPRINTS) {
		return compact to "uTLS fingerprint \"$fingerprint\" is spelled \"$compact\" in mihomo; used that"
	}

	UTLS_ALIASES[bare]?.let {
		return it to "uTLS fingerprint \"$fingerprint\" is not one mihomo resolves; used \"$it\""
	}
	utlsFamilyOf(fingerprint)?.let {
		// Not "unknown to mihomo": the core takes the name without complaint and then quietly sends
		// a plain Go ClientHello.
		return it to "uTLS fingerprint \"$fingerprint\" is not one mihomo resolves; it would have " +
			"silently disabled uTLS, so \"$it\" was used instead"
	}
	return null to when (fingerprint) {
		in GO_TLS_FINGERPRINTS ->
			"uTLS fingerprint \"$fingerprint\" is Go's own TLS with no fingerprint; no uTLS was set"
		else ->
			"unknown uTLS fingerprint \"$fingerprint\" was dropped; mihomo will use a plain Go TLS handshake"
	}
}

internal fun MihomoConversion.applyClientFingerprint(proxy: YamlMap, raw: String) {
	val (name, note) = clientFingerprintOf(raw)
	if (name != null) proxy.set("client-fingerprint", name)
	note?.let { warn(it) }
}

// Chrome for every REALITY node: mihomo offers X25519MLKEM768 there with chrome alone, which an Xray
// server from 26.9.8 asks for, and chrome is what Xray runs where none is named.
private fun MihomoConversion.applyRealityFingerprint(proxy: YamlMap, raw: String) {
	proxy.set("client-fingerprint", "chrome")
	mihomoRealityChromeNote(raw)?.let { warn(it) }
}

// What is said of a REALITY node's fingerprint when chrome stands in for it in mihomo; null for chrome.
internal fun mihomoRealityChromeNote(raw: String): String? {
	val name = raw.trim()
	val profile = clientFingerprintOf(name).first
	return if (profile == "chrome") null else realityChromeNote(name, "mihomo", profile)
}

// Carries Xray's certificate pin to mihomo's "fingerprint", reading both spellings. The public-key
// variant is deliberately not mapped: it hashes a different preimage, so the pin could never match.
internal fun MihomoConversion.applyCertPin(proxy: YamlMap, tlsCfg: JSONObject) {
	if (tlsCfg.xStrList("pinnedPeerCertificatePublicKeySha256").isNotEmpty()) {
		warn(
			"tlsSettings.pinnedPeerCertificatePublicKeySha256 pins the public key, " +
				"which mihomo cannot express - its \"fingerprint\" pins the certificate - so it was dropped"
		)
	}

	if (tlsCfg.xStrList("pinnedPeerCertificateChainSha256").isNotEmpty()) {
		warn(
			"tlsSettings.pinnedPeerCertificateChainSha256 hashes the whole certificate chain, " +
				"which is not the value mihomo's \"fingerprint\" compares against, so it was dropped"
		)
	}

	val field = "pinnedPeerCertSha256"
	val pins = tlsCfg.xStrList(field)
	if (pins.isEmpty()) return

	if (pins.size > 1) {
		warn("tlsSettings.$field lists ${pins.size} pins; mihomo takes one, so the first was used")
	}
	applyCertPinValue(proxy, pins.first(), "tlsSettings.$field")
}

// Emits one SHA-256 certificate pin, accepting Xray's base64 form or a hex one. field names the
// source for the diagnostic, since the same value arrives under several spellings.
internal fun MihomoConversion.applyCertPinValue(proxy: YamlMap, raw: String, field: String) {
	if (raw.isBlank()) return
	val pin = mihomoPin(raw)
	if (pin != null) proxy.set("fingerprint", pin) else warn(undecodedPinNote(field))
}

// One SHA-256 pin in the hex mihomo's fingerprint takes, from base64 or from hex - colons and all - or
// null for neither: mihomo refuses the proxy over anything else, and a provider over one such proxy.
internal fun mihomoPin(raw: String): String? {
	val pin = raw.trim()
	val decoded = decodeBase64Any(pin)
	if (decoded != null && decoded.size == 32) return toHex(decoded)
	// It may already be hex, in which case mihomo takes it as-is.
	val clean = pin.replace(":", "")
	return clean.lowercase().takeIf { fromHex(clean)?.size == 32 }
}

internal fun undecodedPinNote(field: String): String =
	"could not decode $field as a SHA-256 value; it was dropped"

// The TLS of a socks5, HTTP or QUIC proxy, which mihomo builds before it reads the document's list of CAs:
// the name and the pin Xray checks the server by, and a CA only as the server's own certificate. A node left
// out over its CA says that alone - the notes said of it since saidFrom go.
internal fun MihomoConversion.applyProxyTls(proxy: YamlMap, tls: JSONObject, streamSettings: JSONObject?,
	kind: String, saidFrom: Int) {
	applyNameCertVerify(proxy, tls)
	applyCertPin(proxy, tls)
	applyServerAuthority(proxy, streamSettings, kind, saidFrom)
	applyCertificates(proxy, tls, documentList = false)
}

// The CA a server is verified against, which such a proxy takes none of - a fingerprint at most: moot
// beside a pin or a skipped check, pinned when it is the server's own certificate alone, and the node left
// out over any other.
private fun MihomoConversion.applyServerAuthority(proxy: YamlMap, streamSettings: JSONObject?,
	kind: String, saidFrom: Int) {
	val index = customAuthorityIndex(streamSettings) ?: return
	if (proxy.has("fingerprint") || proxy.get("skip-cert-verify") == true) return
	val host = proxy.get("sni") ?: proxy.get("server")
	val pin = ownAuthorityPin(streamTls(streamSettings), "$host")
	if (pin == null) {
		diagnostics.subList(saidFrom, diagnostics.size).clear()
		throw MihomoUnsupported(
			"tlsSettings.certificates[$index] is a CA the server is verified against, which a mihomo " +
				"$kind proxy cannot be given, so the node would not connect"
		)
	}
	proxy.set("fingerprint", pin)
	warn(
		"tlsSettings.certificates[$index] is the CA the server is verified against and the server's own " +
			"certificate; a mihomo $kind proxy cannot be given a CA, so the node pins that certificate"
	)
}

// A CA the server is verified against, which mihomo reads only for the whole document - as
// tls.custom-certifactes, its own spelling - and never per proxy. One Xray cannot read leaves the server to
// the system store there, and here.
private fun MihomoConversion.trustAuthority(pem: String, file: String, documentList: Boolean) {
	when {
		file.isNotEmpty() -> warn(
			"tlsSettings.certificates certificateFile points at \"$file\" on the machine that wrote the " +
				"configuration, so it was dropped; inline certificates are carried"
		)
		pem.isBlank() -> warn(
			"tlsSettings.certificates certificate holds no certificate, so this node verifies the server " +
				"against the system store"
		)
		!isReadableCertificate(pem) -> warn(
			"tlsSettings.certificates certificate does not read as a certificate; Xray then verifies the " +
				"server against the system store, and so does this node"
		)
		documentList -> trustedCertificates.add(pem)
	}
}

// Certificates by what each is for. The same word means opposite directions: Xray's "verify" is a CA
// this client trusts, mihomo's "certificate" with "private-key" is the one this client presents for
// mutual TLS - Xray's "encipherment", the default usage.
internal fun MihomoConversion.applyCertificates(proxy: YamlMap, tlsCfg: JSONObject,
	documentList: Boolean = true) {
	for (cert in tlsCfg.xObjList("certificates")) {
		val usage = cert.xStr("usage").lowercase().ifEmpty { "encipherment" }
		val file = cert.xStr("certificateFile")
		when (usage) {
			"verify" -> trustAuthority(cert.xStrList("certificate").joinToString("\n"), file, documentList)
			"encipherment" -> {
				val pem = cert.xStrList("certificate").joinToString("\n")
				val key = cert.xStrList("key").joinToString("\n")
				when {
					// A client certificate that does not read as one no core can present; with it the node
					// would fail every handshake the server asks a certificate in.
					pem.isNotEmpty() && key.isNotEmpty() && !isReadableCertificate(pem) ->
						warn(
							"tlsSettings.certificates holds a client certificate that does not read " +
								"as one, which no core can present, so it was dropped"
						)
					// A key that is not the certificate's own fails every handshake the server asks
					// a certificate in.
					pem.isNotEmpty() && key.isNotEmpty() && !isClientKeyPair(pem, key) ->
						warn(
							"tlsSettings.certificates holds a client certificate and key that make " +
								"no pair, which no core can present, so it was dropped"
						)
					pem.isNotEmpty() && key.isNotEmpty() -> {
						proxy.set("certificate", pem)
						proxy.set("private-key", key)
					}
					file.isNotEmpty() ->
						warn(
							"tlsSettings.certificates references the file \"$file\"; copy it and " +
								"its key next to the mihomo config and set \"certificate\" and " +
								"\"private-key\" by hand"
						)
					pem.isNotEmpty() || key.isNotEmpty() ->
						warn(
							"tlsSettings.certificates names a client certificate without its key, " +
								"or the key without the certificate; mihomo needs both, so it was dropped"
						)
				}
			}
			"issue" -> warn(ISSUE_CERTIFICATE_NOTE)
		}
	}
}

// Xray checks the peer certificate against these names instead of the SNI, which is what mihomo's
// name-cert-verify does. mihomo verifies against one name, so the first is used - joining them
// would produce a name no certificate can match.
internal fun MihomoConversion.applyNameCertVerify(proxy: YamlMap, tlsCfg: JSONObject) {
	val names = verifyPeerCertNames(tlsCfg)
	if (names.isEmpty()) return
	proxy.setString("name-cert-verify", names.first())
	if (names.size > 1) {
		warn(
			"tlsSettings.verifyPeerCertByName / verifyPeerCertInNames name ${names.size} " +
				"certificates to verify against; mihomo verifies against one, so the first was used"
		)
	}
}

// Maps Xray's ECH configuration list onto mihomo's ech-opts.
internal fun MihomoConversion.applyEch(proxy: YamlMap, tlsCfg: JSONObject) =
	applyEchValue(proxy, tlsCfg.xStr("echConfigList"), "tlsSettings.echConfigList")

// Emits one ECH configuration; field says where the value came from, since the same setting
// arrives under more than one spelling and a diagnostic has to name the one it read.
internal fun MihomoConversion.applyEchValue(proxy: YamlMap, raw: String, field: String) {
	val list = raw.trim()
	if (list.isEmpty()) return
	val optionsMap = YamlMap()
	optionsMap.set("enable", true)
	val std = decodeBase64(list, urlSafe = false, padded = true)
	val any = if (std == null) decodeBase64Any(list) else null
	when {
		list.startsWith("http://") || list.startsWith("https://") ->
			// Xray can fetch the list over DoH; mihomo instead queries the
			// HTTPS record itself when no literal config is given.
			warn("$field points at a URL; mihomo will look the ECH config up in DNS instead")
		std != null -> optionsMap.set("config", list)
		any != null -> optionsMap.set("config", encodeBase64Std(any))
		else -> warn("could not decode $field; only ECH itself was enabled")
	}
	proxy.set("ech-opts", optionsMap)
}

// The transports mihomo implements per protocol.
private val NETWORK_SUPPORT = mapOf(
	"vless" to setOf("tcp", "ws", "h2", "grpc", "xhttp", "httpupgrade"),
	"vmess" to setOf("tcp", "ws", "h2", "grpc", "kcp", "httpupgrade"),
	"trojan" to setOf("tcp", "ws", "grpc", "httpupgrade")
)

// Maps streamSettings onto mihomo's network and *-opts fields.
internal fun MihomoConversion.applyTransport(proxy: YamlMap, streamSettings: JSONObject?, proto: String) {
	val network = streamNetwork(streamSettings)

	// Transports mihomo does not implement for any protocol get a specific
	// explanation, since the generic message would not say why.
	when (network) {
		"quic" -> throw MihomoUnsupported("mihomo has no QUIC transport for the V2Ray-family protocols")
		"hysteria" -> throw MihomoUnsupported(
			"the Xray Hysteria transport carries $proto inside a Hysteria tunnel, which mihomo " +
				"cannot express; use a standalone hysteria2 outbound instead"
		)
	}

	val supported = NETWORK_SUPPORT[proto]
	if (supported != null && network !in supported) {
		throw MihomoUnsupported("mihomo does not support the $network transport for $proto")
	}

	when (network) {
		"tcp" -> applyTcp(proxy, streamSettings, proto)
		"ws" -> applyWebsocket(proxy, streamSettings, httpUpgrade = false)
		"httpupgrade" -> applyWebsocket(proxy, streamSettings, httpUpgrade = true)
		"h2" -> applyH2(proxy, streamSettings)
		"grpc" -> applyGrpc(proxy, streamSettings)
		"xhttp" -> applyXhttp(proxy, streamSettings)
		"kcp" -> applyKcp(proxy, streamSettings)
		else -> throw MihomoUnsupported("unsupported transport \"$network\"")
	}
}

// Handles the raw transport, including its HTTP masquerade, which mihomo exposes as network "http".
private fun MihomoConversion.applyTcp(proxy: YamlMap, streamSettings: JSONObject?, proto: String) {
	val header = streamTcp(streamSettings).xObj("header") ?: return // plain TCP is mihomo's default
	when (val headerType = header.xStr("type").lowercase()) {
		"", "none" -> return
		"http" -> {
			if (proto == "trojan") {
				throw MihomoUnsupported(
					"mihomo does not support the HTTP masquerade over raw TCP for trojan"
				)
			}
			proxy.set("network", "http")
			val optionsMap = YamlMap()
			val req = header.xObj("request")
			if (req != null) {
				optionsMap.setString("method", req.xStr("method"))
				val path = req.xStrList("path")
				if (path.isNotEmpty()) optionsMap.set("path", toFlowSeq(path))
				val headers = req.xHeaderLists("headers")
				if (headers.isNotEmpty()) {
					val hdr = YamlMap()
					for (key in headers.keys.sorted()) hdr.set(key, toFlowSeq(headers[key].orEmpty()))
					optionsMap.set("headers", hdr)
				}
			}
			proxy.set("http-opts", optionsMap)
		}
		else -> throw MihomoUnsupported("unsupported raw header type \"$headerType\"")
	}
}

// Handles both the websocket transport and HTTPUpgrade, which mihomo models as websocket with a flag.
private fun MihomoConversion.applyWebsocket(proxy: YamlMap, streamSettings: JSONObject?,
	httpUpgrade: Boolean) {
	proxy.set("network", "ws")
	// Xray keeps a websocket alive with a periodic ping and mihomo has no setting for one, so a
	// node on a network that drops idle connections would drop them again unexplained.
	if (streamWs(streamSettings).xInt("heartbeatPeriod") > 0) {
		warn("wsSettings.heartbeatPeriod has no mihomo equivalent and was dropped")
	}
	val optionsMap = YamlMap()

	var path = ""
	var host = ""
	var headers: Map<String, String> = emptyMap()
	var maxEd = 0
	var edName = ""

	if (httpUpgrade) {
		val httpUpgrade = streamSettings.xObj("httpupgradeSettings")
		if (httpUpgrade != null) {
			path = httpUpgrade.xStr("path")
			host = httpUpgrade.xStr("host").ifEmpty { headerHost(httpUpgrade).orEmpty() }
			headers = httpUpgrade.xHeaders("headers")
		}
	} else {
		val websocket = streamWs(streamSettings)
		if (websocket != null) {
			path = websocket.xStr("path")
			host = websocket.xStr("host")
			headers = websocket.xHeaders("headers")
			maxEd = websocket.xInt("maxEarlyData")
			edName = websocket.xStr("earlyDataHeaderName")
			if (websocket.xBool("useBrowserForwarding")) {
				warn("wsSettings.useBrowserForwarding has no mihomo equivalent and was dropped")
			}
		}
	}

	// Xray encodes WebSocket early data as an "ed" query parameter on the path;
	// mihomo takes it as a separate option.
	val split = splitEarlyData(path)
	if (split.second > 0) {
		maxEd = split.second
		if (edName.isEmpty()) edName = "Sec-WebSocket-Protocol"
	}
	optionsMap.setString("path", split.first)

	val hdr = YamlMap()
	for (key in headers.keys.sorted()) {
		val value = headers[key].orEmpty().trim()
		if (key.equals("host", ignoreCase = true)) {
			// Xray moves a Host header into the dedicated host field.
			if (host.isEmpty()) host = value
			continue
		}
		hdr.setString(key, value)
	}
	host = host.trim()
	// Where none is written Xray sends the TLS server name as the Host, else the address: mihomo would send
	// the address in place of the name, and to a VLESS server without TLS a name of its own making.
	val security = streamSecurity(streamSettings)
	if (host.isEmpty() && security == "tls") {
		host = streamTls(streamSettings).xStr("serverName").takeIf { it != proxy.get("server") }.orEmpty()
	} else if (host.isEmpty() && security == "none" && proxy.get("type") == "vless") {
		host = xrayAddressString(proxy.get("server").toString())
	}
	// mihomo reads the SNI/Host override from the Host header.
	if (host.isNotEmpty()) hdr.set("Host", host)
	optionsMap.set("headers", hdr)
	// mihomo takes the Host of a VLESS or VMess node for the TLS server name where none is named: the
	// address goes, as Xray sends it, where the two differ.
	val server = proxy.get("server").toString()
	val unnamed = proxy.get("type") in setOf("vless", "vmess") &&
		streamTls(streamSettings).xStr("serverName").isEmpty()
	if (security == "tls" && unnamed && host.isNotEmpty() && !sameNameSent(host, server)) {
		proxy.setString("servername", server)
	}

	if (maxEd > 0) {
		optionsMap.set("max-early-data", maxEd)
		if (edName.isEmpty()) edName = "Sec-WebSocket-Protocol"
		optionsMap.set("early-data-header-name", edName)
	}
	if (httpUpgrade) optionsMap.set("v2ray-http-upgrade", true)
	proxy.set("ws-opts", optionsMap)
}

// Handles the HTTP/2 transport.
private fun MihomoConversion.applyH2(proxy: YamlMap, streamSettings: JSONObject?) {
	proxy.set("network", "h2")
	val optionsMap = YamlMap()
	val http = streamSettings.xObj("httpSettings")
	if (http != null) {
		val host = http.xStrList("host")
		if (host.isNotEmpty()) optionsMap.set("host", toFlowSeq(host))
		optionsMap.setString("path", http.xStr("path"))
		val method = http.xStr("method")
		if (method.isNotEmpty() && !method.equals("PUT", ignoreCase = true)) {
			warn("httpSettings.method \"$method\" is not configurable in mihomo's h2-opts and was dropped")
		}
		if (http.xHeaders("headers").isNotEmpty()) {
			warn("httpSettings.headers has no mihomo equivalent for the h2 transport and was dropped")
		}
	}
	proxy.set("h2-opts", optionsMap)
	if (streamSecurity(streamSettings) == "none") {
		warn("the h2 transport without TLS is unusual; mihomo requires TLS for h2")
	}
}

// Handles the gRPC transport.
private fun MihomoConversion.applyGrpc(proxy: YamlMap, streamSettings: JSONObject?) {
	proxy.set("network", "grpc")
	val optionsMap = YamlMap()
	val grpc = streamGrpc(streamSettings)
	if (grpc != null) {
		// mihomo sends a custom path, and a name inside "/<name>/Tun", as written, where Xray escapes each
		// part and runs no "|" part - its multi mode's stream: such a name goes as the path Xray asks for.
		val name = grpc.xStrRaw("serviceName")
		val path = grpcPath(name)
		val wire = grpcWirePath(path)
		optionsMap.setString("grpc-service-name", if (!path.custom && wire == "/$name/Tun") name else wire)
		optionsMap.setString("grpc-user-agent", grpc.xStr("user_agent"))
		if (grpc.xBool("multiMode")) {
			warn(
				"the node still uses gRPC, but grpcSettings.multiMode has no mihomo equivalent; the " +
					"node will use single mode"
			)
		}
		if (grpc.xStr("authority").isNotEmpty()) {
			warn(
				"the node still uses gRPC, but grpcSettings.authority has no mihomo equivalent and " +
					"was dropped"
			)
		}
		if (grpc.xInt("initial_windows_size") > 0) {
			warn(
				"the node still uses gRPC, but grpcSettings.initial_windows_size has no " +
					"mihomo equivalent and was dropped"
			)
		}
	}
	proxy.set("grpc-opts", optionsMap)
}

// The packet headers mihomo masks mKCP with. Xray has one more - the DNS header - and mihomo cannot send
// a node masked by it.
private val MIHOMO_KCP_HEADERS = listOf("srtp", "utp", "wechat-video", "dtls", "wireguard")

// Why mihomo, which masks mKCP as Xray did before 26.1.31 - a header outside a seed or original mask -
// cannot send what this node's masks do, or null.
internal fun mihomoKcpRefusal(mask: KcpMask): String? {
	val header = mask.headerType.lowercase()
	return when {
		mask.unlike != null -> "${mask.unlike}, where mihomo sends a header outside a seed or original mask"
		mask.blankSeed -> "the mKCP mask is keyed by an empty seed, which mihomo takes for none"
		header.isNotEmpty() && header != "none" && header !in MIHOMO_KCP_HEADERS ->
			"the mKCP header \"$header\" is not one mihomo masks with " +
				"(${MIHOMO_KCP_HEADERS.joinToString("/")})"
		else -> null
	}
}

// What a node that names no mKCP mask is told: only an Xray server before 26.1.31, or a later one under the
// original mask, masks as mihomo does.
internal const val MIHOMO_KCP_UNSTATED_NOTE = "the node names no mKCP mask, and mihomo masks it as Xray " +
	"did before 26.1.31: an Xray server from 26.1.31 on answers mihomo only under the original mask " +
	"(mkcp-original, or mkcp-legacy with no value), and one that names no mask sends mKCP unmasked"

// What a node with more than one mkcp-legacy mask is told: they are read as later Xray wraps them.
internal const val MIHOMO_KCP_LEGACY_ORDER_NOTE = "the node's mkcp-legacy masks are read as Xray wraps " +
	"them from 26.6.22, the last outermost; a 26.6.1 server wraps them the other way, the header inside, " +
	"and does not answer mihomo"

// Handles the mKCP transport, which mihomo supports for vmess only.
private fun MihomoConversion.applyKcp(proxy: YamlMap, streamSettings: JSONObject?) {
	// The masking is a property of the node rather than of kcpSettings: current Xray writes it in
	// finalmask and leaves that block out entirely.
	val mask = kcpMask(streamSettings)
	mihomoKcpRefusal(mask)?.let { throw MihomoUnsupported(it) }
	if (!mask.stated) warn(MIHOMO_KCP_UNSTATED_NOTE)
	if (mask.severalLegacy) warn(MIHOMO_KCP_LEGACY_ORDER_NOTE)
	proxy.set("network", "mkcp")
	val optionsMap = YamlMap()
	val kcp = streamSettings.xObj("kcpSettings")
	if (kcp != null) {
		optionsMap.setInt("mtu", kcp.xInt("mtu"))
		optionsMap.setInt("tti", kcp.xInt("tti"))
		optionsMap.setInt("uplink-capacity", kcp.xInt("uplinkCapacity"))
		optionsMap.setInt("downlink-capacity", kcp.xInt("downlinkCapacity"))
		optionsMap.setBoolTrue("congestion", kcp.xBool("congestion"))
		// Xray counts these buffers in megabytes and mihomo in bytes, which is a conversion rather
		// than a missing feature: mihomo's own 2097152 default is Xray's 2 MB written out.
		kcpBufferBytes(kcp, "readBufferSize")?.let { optionsMap.set("read-buffer", it) }
		kcpBufferBytes(kcp, "writeBufferSize")?.let { optionsMap.set("write-buffer", it) }
	}
	optionsMap.setString("seed", mask.seed)
	val headerType = mask.headerType.lowercase()
	if (headerType.isNotEmpty() && headerType != "none") optionsMap.set("header", headerType)
	proxy.set("mkcp-opts", optionsMap)
}

// One mKCP buffer in the bytes mihomo counts, or null when the source did not set it. Read as a
// Long because a large megabyte figure would overflow an Int once multiplied out.
private fun kcpBufferBytes(kcp: JSONObject, field: String): Long? {
	val megabytes = kcp.xLong(field)
	if (megabytes <= 0L || megabytes > MAX_KCP_BUFFER_MB) return null
	return megabytes * 1024L * 1024L
}

// Well past any real buffer, and far enough below the point where the multiplication above would
// wrap into a negative size - which mihomo would take as a setting rather than as nonsense.
private const val MAX_KCP_BUFFER_MB = 64L * 1024L

// Maps Xray's XHTTP transport, including the "extra" object, xmux and downloadSettings, onto
// mihomo's xhttp-opts.
private fun MihomoConversion.applyXhttp(proxy: YamlMap, streamSettings: JSONObject?) {
	proxy.set("network", "xhttp")
	val cfg = streamXhttp(streamSettings)
	if (cfg == null) {
		proxy.set("xhttp-opts", YamlMap().set("mode", "auto"))
		return
	}
	proxy.set("xhttp-opts", buildXhttpOptions(cfg))
}

// The transfer modes Xray accepts.
private val XHTTP_MODES = setOf("auto", "packet-up", "stream-up", "stream-one")

internal fun MihomoConversion.buildXhttpOptions(cfg: JSONObject): YamlMap {
	val optionsMap = YamlMap()

	optionsMap.setString("path", cfg.xStr("path"))
	optionsMap.setString("host", cfg.xStr("host"))

	var mode = cfg.xStr("mode").lowercase()
	if (mode.isEmpty()) mode = "auto"
	if (mode !in XHTTP_MODES) throw MihomoUnsupported("unsupported xhttp mode \"$mode\"")
	optionsMap.set("mode", mode)

	val headers = cfg.xHeaders("headers")
	if (headers.isNotEmpty()) {
		val hdr = YamlMap()
		for (key in headers.keys.sorted()) {
			if (key.equals("host", ignoreCase = true)) {
				// Xray rejects a Host header here; fold it into "host".
				if (!optionsMap.has("host")) optionsMap.setString("host", headers[key].orEmpty().trim())
				continue
			}
			hdr.setString(key, headers[key].orEmpty().trim())
		}
		optionsMap.set("headers", hdr)
	}

	optionsMap.setBoolTrue("no-grpc-header", cfg.xBool("noGRPCHeader"))

	// Padding controls.
	optionsMap.setRange("x-padding-bytes", cfg.xRange("xPaddingBytes").render())
	optionsMap.setBoolTrue("x-padding-obfs-mode", cfg.xBool("xPaddingObfsMode"))
	optionsMap.setString("x-padding-key", cfg.xStr("xPaddingKey"))
	optionsMap.setString("x-padding-header", cfg.xStr("xPaddingHeader"))
	val placement = cfg.xStr("xPaddingPlacement")
	if (placement.isNotEmpty()) {
		if (placement !in setOf("cookie", "header", "query", "queryInHeader")) {
			throw MihomoUnsupported("unsupported xPaddingPlacement \"$placement\"")
		}
		optionsMap.set("x-padding-placement", placement)
	}
	val padMethod = cfg.xStr("xPaddingMethod")
	if (padMethod.isNotEmpty()) {
		if (padMethod !in setOf("repeat-x", "tokenish")) {
			throw MihomoUnsupported("unsupported xPaddingMethod \"$padMethod\"")
		}
		optionsMap.set("x-padding-method", padMethod)
	}

	// Uplink and session controls.
	val uplinkMethod = cfg.xStr("uplinkHTTPMethod")
	if (uplinkMethod.isNotEmpty()) {
		val upper = uplinkMethod.uppercase()
		if (upper == "GET" && mode != "packet-up") {
			throw MihomoUnsupported("uplinkHTTPMethod GET is only valid in packet-up mode")
		}
		optionsMap.set("uplink-http-method", upper)
	}
	// Xray reads these as sessionIDPlacement and sessionIDKey; the sessionPlacement and sessionKey
	// spellings stand in only where the sessionID* ones are absent.
	val sessionPlacement = cfg.xStrOf("sessionIDPlacement", "sessionPlacement")
	if (sessionPlacement.isNotEmpty()) {
		if (sessionPlacement !in setOf("path", "cookie", "header", "query")) {
			throw MihomoUnsupported("unsupported session placement \"$sessionPlacement\"")
		}
		optionsMap.set("session-placement", sessionPlacement)
	}
	optionsMap.setString("session-key", cfg.xStrOf("sessionIDKey", "sessionKey"))
	optionsMap.setString("session-table", cfg.xStr("sessionIDTable"))
	optionsMap.setString("session-length", cfg.xRange("sessionIDLength").render())

	val seqPlacement = cfg.xStr("seqPlacement")
	if (seqPlacement.isNotEmpty()) {
		if (seqPlacement !in setOf("path", "cookie", "header", "query")) {
			throw MihomoUnsupported("unsupported seqPlacement \"$seqPlacement\"")
		}
		optionsMap.set("seq-placement", seqPlacement)
	}
	optionsMap.setString("seq-key", cfg.xStr("seqKey"))

	val uplinkData = cfg.xStr("uplinkDataPlacement")
	if (uplinkData.isNotEmpty()) {
		if (uplinkData !in setOf("auto", "body", "cookie", "header")) {
			throw MihomoUnsupported("unsupported uplinkDataPlacement \"$uplinkData\"")
		}
		if ((uplinkData == "cookie" || uplinkData == "header") && mode != "packet-up") {
			throw MihomoUnsupported("uplinkDataPlacement \"$uplinkData\" is only valid in packet-up mode")
		}
		optionsMap.set("uplink-data-placement", uplinkData)
	}
	optionsMap.setString("uplink-data-key", cfg.xStr("uplinkDataKey"))
	optionsMap.setString("uplink-chunk-size", cfg.xRange("uplinkChunkSize").render())

	optionsMap.setRange("sc-max-each-post-bytes", cfg.xRange("scMaxEachPostBytes").render())
	optionsMap.setRange("sc-min-posts-interval-ms", cfg.xRange("scMinPostsIntervalMs").render())

	// Settings that only exist on the Xray side.
	if (cfg.xBool("noSSEHeader")) {
		warn("xhttp noSSEHeader has no mihomo equivalent and was dropped")
	}
	if (cfg.xInt("scMaxBufferedPosts") != 0) {
		warn("xhttp scMaxBufferedPosts is a server-side option and was dropped")
	}
	if (cfg.xRange("scStreamUpServerSecs").set) {
		warn("xhttp scStreamUpServerSecs is a server-side option and was dropped")
	}

	// XMUX, which mihomo calls reuse-settings.
	val xmux = cfg.xObj("xmux")
	if (xmux != null && !xmuxIsZero(xmux)) {
		val reuse = YamlMap()
		reuse.setRange("max-concurrency", xmux.xRange("maxConcurrency").renderNonZero())
		reuse.setRange("max-connections", xmux.xRange("maxConnections").renderNonZero())
		reuse.setRange("c-max-reuse-times", xmux.xRange("cMaxReuseTimes").renderNonZero())
		reuse.setRange("h-max-request-times", xmux.xRange("hMaxRequestTimes").renderNonZero())
		reuse.setRange("h-max-reusable-secs", xmux.xRange("hMaxReusableSecs").renderNonZero())
		reuse.setInt("h-keep-alive-period", xmux.xInt("hKeepAlivePeriod"))
		if (xmux.xRange("cMaxLifetimeMs").set) {
			warn("xmux cMaxLifetimeMs has no mihomo equivalent and was dropped")
		}
		if (reuse.size > 0) optionsMap.set("reuse-settings", reuse)
	}

	// downloadSettings splits the download half onto a separate endpoint.
	val download = cfg.xObj("downloadSettings")
	if (download != null) {
		val downloadMap = buildXhttpDownload(download)
		if (downloadMap.size > 0) optionsMap.set("download-settings", downloadMap)
	}
	return optionsMap
}

// True when no xmux field was set, so the block says nothing.
private fun xmuxIsZero(xmux: JSONObject): Boolean =
	!xmux.xRange("maxConcurrency").set && !xmux.xRange("maxConnections").set &&
		!xmux.xRange("cMaxReuseTimes").set && !xmux.xRange("cMaxLifetimeMs").set &&
		!xmux.xRange("hMaxRequestTimes").set && !xmux.xRange("hMaxReusableSecs").set &&
		xmux.xInt("hKeepAlivePeriod") == 0

// Maps an XHTTP downloadSettings block, which is a full stream configuration plus its own address.
private fun MihomoConversion.buildXhttpDownload(download: JSONObject): YamlMap {
	val out = YamlMap()

	val addr = download.xStr("address")
	if (addr.isNotEmpty()) out.set("server", stripBrackets(addr))
	val port = download.xInt("port")
	if (port > 0) out.set("port", port)

	val net = streamNetwork(download)
	if (net != "xhttp" && net != "tcp") {
		warn("downloadSettings uses the $net transport, which mihomo only supports as xhttp here")
	}
	val cfg = streamXhttp(download)
	if (cfg != null) {
		val optionsMap = buildXhttpOptions(cfg)
		// The download half reuses the upload settings for anything it does not
		// override; mihomo only accepts this subset.
		for (key in listOf("path", "host", "headers", "reuse-settings")) {
			optionsMap.get(key)?.let { out.set(key, it) }
		}
	}

	// The download endpoint carries its own security layer.
	when (streamSecurity(download)) {
		"tls" -> {
			out.set("tls", true)
			val tls = streamTls(download)
			if (tls != null) {
				out.setString("servername", tls.xStr("serverName"))
				val alpn = tls.xStrList("alpn")
				if (alpn.isNotEmpty()) out.set("alpn", toFlowSeq(alpn))
				if (tls.xBool("allowInsecure")) out.set("skip-cert-verify", true)
				applyNameCertVerify(out, tls)
				applyClientFingerprint(out, tls.xStr("fingerprint"))
			}
		}
		"reality" -> {
			out.set("tls", true)
			val realitySettings = download.xObj("realitySettings")
			if (realitySettings != null) {
				out.setString("servername", realitySni(realitySettings))
				// The same refusal as on the node itself: mihomo refuses the whole file over an
				// empty REALITY key, wherever the key sits.
				if (realityPublicKey(realitySettings).isEmpty()) throw MihomoUnsupported("downloadSettings " +
					"has REALITY with no publicKey, which mihomo refuses")
				out.set("reality-opts", realityOptions(realitySettings))
				warn(REALITY_MIHOMO_NOTE)
				applyRealityFingerprint(out, realitySettings.xStr("fingerprint"))
			}
		}
	}
	return out
}

// Pulls Xray's "ed" query parameter out of a transport path, returning the path without it and the
// early-data size. Remaining parameters keep their original text and order.
internal fun splitEarlyData(path: String): Pair<String, Int> {
	if (path.isEmpty() || !path.contains("ed=")) return path to 0
	val queryStart = path.indexOf('?')
	if (queryStart < 0) return path to 0
	val base = path.substring(0, queryStart)
	val query = path.substring(queryStart + 1)

	var earlyData = 0
	val kept = ArrayList<String>()
	for (pair in query.split("&")) {
		if (pair.isEmpty()) continue
		if (pair.startsWith("ed=") && earlyData == 0) {
			val number = pair.substring(3).toIntOrNull()
			if (number != null && number > 0) {
				earlyData = number
				continue
			}
		}
		kept.add(pair)
	}
	if (earlyData == 0) return path to 0
	val rest = kept.joinToString("&")
	return (if (rest.isEmpty()) base else "$base?$rest") to earlyData
}
