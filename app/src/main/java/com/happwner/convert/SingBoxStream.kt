package com.happwner.convert

import com.happwner.text.decodeBase64Any
import com.happwner.text.encodeBase64Std
import com.happwner.text.isIpLiteral
import org.json.JSONArray
import org.json.JSONObject

// The stream layer shared by every proxy protocol: TLS, REALITY, uTLS and the transports. UTLS_FP is
// a sing-box vocabulary; the mihomo converter has its own, longer list - do not merge the two.
internal object SingBoxStream {
	private val UTLS_FP = setOf(
		"chrome", "firefox", "edge", "safari", "360", "qq",
		"ios", "android", "random", "randomized"
	)

	// The suites sing-box 1.12 to 1.14 accept by name - Go's tls.CipherSuites(), checked against each core.
	private val CIPHER_SUITES = setOf(
		"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	)

	internal val XRAY_TRANSPORTS_OK = setOf(
		"tcp", "raw", "", "ws", "grpc", "http", "h2", "httpupgrade", "quic"
	)

	// The uTLS fingerprint sing-box will run, or null for none: a name it has, in any case, one of Xray's
	// others as its family ("hellochrome_120" chrome), no uTLS for Go's names or an unknown one; REALITY
	// needs one it can key, so a missing, unknown or keyless name is chrome there - said.
	internal fun utlsFingerprint(raw: Any?, forReality: Boolean, notes: MutableList<String>): String? {
		val name = (raw as? String).orEmpty().trim()
		val known = name.lowercase()
		val bare = known.removePrefix("hello")
		val profile = when {
			known in UTLS_FP -> known
			bare in UTLS_FP -> bare
			bare.startsWith("randomized") -> "randomized"
			else -> utlsFamilyOf(known)
		}
		if (profile != null && !(forReality && profile in REALITY_KEYLESS_FINGERPRINTS)) {
			if (profile != known) {
				notes.add("uTLS fingerprint \"$name\" is not one sing-box has; \"$profile\" was used")
			}
			return profile
		}
		if (!forReality) {
			if (known in GO_TLS_FINGERPRINTS) {
				notes.add("uTLS fingerprint \"$name\" is Go's own TLS with no fingerprint; no uTLS was set")
			} else if (name.isNotEmpty()) {
				notes.add("uTLS fingerprint \"$name\" is not one sing-box has, so no uTLS was set")
			}
			return null
		}
		notes.add(realityChromeNote(name, "sing-box", profile))
		return "chrome"
	}

	internal fun normalizeHeadersV2Ray(headers: JSONObject?, singleValue: Boolean): JSONObject {
		val out = JSONObject()
		if (headers == null) return out
		val keys = headers.keys()
		while (keys.hasNext()) {
			val key = keys.next()
			val value = headers.opt(key)
			if (value === JSONObject.NULL) continue
			if (singleValue) {
				if (value is JSONArray) {
					if (value.length() > 0) out.put(key, value.opt(0)?.toString() ?: "") else out.put(key, "")
				} else {
					out.put(key, "$value")
				}
			} else {
				if (value is JSONArray) {
					out.put(key, value)
				} else {
					out.put(key, JSONArray().put("$value"))
				}
			}
		}
		return out
	}

	private fun getTcpHttpRequest(stream: JSONObject): JSONObject? {
		val tcpSettings = stream.optJSONObject("tcpSettings")
			?: stream.optJSONObject("rawSettings")
			?: return null
		val hdr = tcpSettings.optJSONObject("header") ?: return null
		if (hdr.xStr("type").ifEmpty { "none" } != "http") return null
		return hdr.optJSONObject("request") ?: JSONObject()
	}

	// The TLS versions the core accepts; anything else refuses the document.
	private val TLS_VERSIONS = setOf("1.0", "1.1", "1.2", "1.3")

	// The tls block of an outbound to this address - TLS, REALITY, uTLS and ECH - or null for a plain
	// stream. The security layer is read through the shared reader, as the other two passes read it.
	internal fun buildTls(stream: JSONObject, address: String, notes: MutableList<String>): JSONObject? {
		val sec = streamSecurity(stream)
		val quic = streamNetwork(stream) == "quic"
		if (quic && sec != "tls") return quicOwnTls()
		if (sec != "tls" && sec != "reality") return null
		val tls = JSONObject()
		tls.put("enabled", true)

		if (sec == "reality") {
			applyReality(stream, tls, notes)
			notes.add(REALITY_SING_BOX_NOTE)
			return tls
		}
		// Through the shared reader, so the block is found under either of its spellings, as the
		// other two passes find it.
		val tlsSettings = streamTls(stream) ?: JSONObject()
		applyTlsFields(tlsSettings, tls, address, notes)
		reportTlsDrops(tlsSettings, tls, notes)
		// quic-go dials with Go's own TLS, so QUIC takes no uTLS; and sing-box would offer h3 alone
		// where Xray, with no ALPN named, offers its default.
		if (quic) {
			quicFingerprintDropped(tlsSettings.optString("fingerprint"))?.let { notes.add(it) }
			if (!tls.has("alpn")) tls.put("alpn", JSONArray(XRAY_DEFAULT_ALPN))
		} else {
			applyUtls(tlsSettings, tls, notes)
		}
		applyCertificates(tlsSettings, tls, notes)
		applyEch(tlsSettings, tls, notes)
		return tls
	}

	// The TLS Xray's QUIC transport falls back on without a tls block: its own name, unverified.
	private fun quicOwnTls(): JSONObject {
		return JSONObject().put("enabled", true).put("server_name", XRAY_QUIC_OWN_SNI)
			.put("insecure", true).put("alpn", JSONArray(XRAY_DEFAULT_ALPN))
	}

	// REALITY: the uTLS fingerprint, public key and short id.
	private fun applyReality(stream: JSONObject, tls: JSONObject, notes: MutableList<String>) {
		val realitySettings = stream.optJSONObject("realitySettings") ?: JSONObject()
		// Through the same readers the mihomo pass uses, so both spellings of each are read.
		val serverName = realitySni(realitySettings)
		if (serverName.isNotEmpty()) tls.put("server_name", serverName)
		val utls = JSONObject()
		utls.put("enabled", true)
		utls.put("fingerprint", utlsFingerprint(realitySettings.opt("fingerprint"),
			forReality = true, notes = notes))
		tls.put("utls", utls)
		val reality = JSONObject()
		reality.put("enabled", true)
		val realityKey = realityPublicKey(realitySettings)
		val realitySid = realityShortId(realitySettings)
		reality.put("public_key", realityKey)
		reality.put("short_id", realitySid)
		// spiderX is Xray's own probing path and sing-box has nothing to put it in - small, but
		// nobody can act on a setting that vanishes without being named.
		if (realitySettings.optString("spiderX", "").isNotEmpty()) {
			notes.add("realitySettings.spiderX has no sing-box equivalent and was dropped")
		}
		tls.put("reality", reality)
	}

	// The TLS fields: server name, insecure, ALPN, cipher suites, and what has no field here.
	private fun applyTlsFields(
		tlsSettings: JSONObject, tls: JSONObject, address: String, notes: MutableList<String>
	) {
		val serverName = tlsSettings.optString("serverName", "")
		if (serverName.isNotEmpty()) tls.put("server_name", serverName)
		if (tlsSettings.xBool("allowInsecure")) tls.put("insecure", true)
		val alpn = tlsSettings.opt("alpn")
		if (alpn != null && alpn !== JSONObject.NULL) {
			if (alpn is JSONArray) {
				if (alpn.length() > 0) tls.put("alpn", alpn)
			} else {
				tls.put("alpn", JSONArray().put(alpn.toString()))
			}
		}
		// The core takes Go's own suite names and refuses the whole document over any other
		// ("unknown cipher_suite"), the insecure ones Xray also allows among them.
		val suites = tlsSettings.optString("cipherSuites", "").split(":").map { it.trim() }
			.filter { it.isNotEmpty() }
		val (known, unknown) = suites.partition { it in CIPHER_SUITES }
		if (known.isNotEmpty()) tls.put("cipher_suites", JSONArray(known))
		if (unknown.isNotEmpty()) {
			notes.add(
				"tlsSettings.cipherSuites ${unknown.joinToString()} is not a suite sing-box takes " +
					"and was dropped"
			)
		}
		// curve_preferences is a sing-box 1.13.0 field, and an unknown field stops a configuration
		// loading, so it stays out for the sake of the 1.12 cores still in use.
		if (tlsSettings.xStrList("curvePreferences").isNotEmpty()) {
			notes.add(
				"tlsSettings.curvePreferences was dropped: sing-box has curve_preferences only " +
					"since 1.13, and writing it would stop a 1.12 core loading the configuration"
			)
		}
		applyVerifyName(tlsSettings, tls, serverName, address, tls.optBoolean("insecure"), notes)
	}

	// sing-box checks the certificate against the name it sends - the address where none is named - with
	// no other name for the check, so a name Xray checks it against instead goes out as the one sent,
	// which the network then sees; names it has no use for are dropped.
	internal fun applyVerifyName(
		tlsSettings: JSONObject?, tls: JSONObject, sent: String, address: String, insecure: Boolean,
		notes: MutableList<String>
	) {
		val dialed = sent.ifEmpty { address }
		val names = verifyPeerCertNames(tlsSettings)
		val verified = if (insecure) null else nameToVerify(tlsSettings, dialed)
		if (verified != null) {
			tls.put("server_name", verified)
			notes.add(verifyNameSentNote(verified, sent, "sing-box checks it against the name it sends"))
		} else if (names.any { insecure || !sameHost(it, dialed) }) {
			notes.add(verifyNamesDroppedNote("sing-box"))
		}
	}

	// The Host Xray sends where a transport names none - the TLS server name, else the address - written
	// out where sing-box would send another: the address over ws, and over httpupgrade the server name
	// sent, where a name to verify took its place.
	internal fun keepXrayHost(stream: JSONObject, tls: JSONObject?, transport: JSONObject, address: String) {
		if (tls == null || streamSecurity(stream) != "tls") return
		val written = streamTls(stream)?.optString("serverName", "").orEmpty()
		val addressHost = xrayAddressString(address)
		val sent = written.ifEmpty { addressHost }
		when (transport.optString("type")) {
			"ws" -> {
				val headers = transport.optJSONObject("headers") ?: JSONObject()
				if (sent == addressHost || headers.keys().asSequence().any { it.equals("Host", true) }) return
				transport.put("headers", headers.put("Host", sent))
			}
			"httpupgrade" -> {
				if (transport.has("host") || tls.optString("server_name") == written) return
				transport.put("host", sent)
			}
		}
	}

	internal const val UNPINNED_NOTE = "tlsSettings.pinnedPeerCertSha256 pins the certificate by its " +
		"hash, which a sing-box outbound has no field for, so it was dropped"

	// The settings this pass has no field for, each named once.
	private fun reportTlsDrops(tlsSettings: JSONObject, tls: JSONObject, notes: MutableList<String>) {
		// Named rather than mapped: a sing-box outbound has no field that takes a certificate
		// hash, and writing the hash somewhere it is not read would pin nothing.
		if (tlsSettings.optString("pinnedPeerCertSha256", "").isNotEmpty()) notes.add(UNPINNED_NOTE)
		if (tlsSettings.xBool("disableSystemRoot")) {
			notes.add(
				"tlsSettings.disableSystemRoot has no sing-box equivalent; " +
					"the system trust store stays in use"
			)
		}
		if (tlsSettings.optString("masterKeyLog", "").isNotEmpty()) {
			notes.add("tlsSettings.masterKeyLog has no sing-box equivalent and was dropped")
		}
		if (tlsSettings.has("enableSessionResumption") &&
			!tlsSettings.isNull("enableSessionResumption")) {
			notes.add("tlsSettings.enableSessionResumption has no sing-box equivalent and was dropped")
		}

		// The core knows four version names and refuses the whole document on anything else
		// ("unknown tls version"), so a hand-edited typo would cost the subscription.
		for ((from, to) in listOf("minVersion" to "min_version", "maxVersion" to "max_version")) {
			if (!tlsSettings.has(from) || tlsSettings.isNull(from)) continue
			val value = tlsSettings.optString(from, "").trim()
			if (value.isEmpty()) continue
			if (value in TLS_VERSIONS) tls.put(to, value)
			else notes.add(
				"tlsSettings.$from \"$value\" is not a TLS version sing-box knows and was dropped")
		}
	}

	private fun applyUtls(tlsSettings: JSONObject, tls: JSONObject, notes: MutableList<String>) {
		val fingerprint = utlsFingerprint(tlsSettings.optString("fingerprint", ""),
			forReality = false, notes = notes) ?: return
		val utls = JSONObject()
		utls.put("enabled", true)
		utls.put("fingerprint", fingerprint)
		tls.put("utls", utls)
	}

	// Each certificate by what it is for: Xray's "verify", a CA the server is checked against, is sing-box's
	// "certificate"; one this client presents, Xray's "encipherment", its client_certificate.
	internal fun applyCertificates(tlsSettings: JSONObject, tls: JSONObject, notes: MutableList<String>) {
		val certs = tlsSettings.optJSONArray("certificates") ?: return
		val authorities = ArrayList<String>()
		for (i in 0 until certs.length()) {
			val cert = certs.optJSONObject(i) ?: continue
			val usage = cert.optString("usage", "").lowercase().ifEmpty { "encipherment" }
			if (usage == "issue") {
				notes.add(ISSUE_CERTIFICATE_NOTE)
			} else if (usage != "verify") {
				applyClientCertificate(cert, i, tls, notes)
			} else if (cert.optString("certificateFile", "").isNotEmpty()) {
				// Deliberately not carried: the core opens the file at load and refuses everything
				// if it is missing, and an Xray path names a file on the machine that ran Xray -
				// one failed node beats a dead config.
				val certFile = cert.optString("certificateFile")
				notes.add(
					"tlsSettings.certificates[$i].certificateFile points at \"$certFile\" on the " +
						"machine that wrote the configuration, so it was dropped; inline " +
						"certificates are carried"
				)
			} else {
				// Xray only logs one it cannot read and verifies against the system store, as this
				// outbound then does; sing-box would refuse the whole document over it, as over any
				// text that is no certificate at all.
				val text = pemText(cert.opt("certificate"))
				if (text.isNullOrBlank()) {
					notes.add(
						"tlsSettings.certificates[$i].certificate holds no certificate, so this node " +
							"verifies the server against the system store"
					)
				} else if (!isReadableCertificate(text)) {
					notes.add(
						"tlsSettings.certificates[$i].certificate does not read as a certificate; " +
							"Xray then verifies the server against the system store, and so does this node"
					)
				} else {
					authorities.add(text)
				}
			}
		}
		if (authorities.size == 1) tls.put("certificate", authorities[0])
		if (authorities.size > 1) tls.put("certificate", JSONArray(authorities))
	}

	// The certificate this client presents when the server asks for one - Xray presents none on an
	// outbound - carried only as a pair a core loads, since sing-box refuses the whole document over another.
	private fun applyClientCertificate(
		cert: JSONObject, index: Int, tls: JSONObject, notes: MutableList<String>
	) {
		val pem = pemText(cert.opt("certificate")).orEmpty()
		val key = pemText(cert.opt("key")).orEmpty()
		val file = cert.optString("certificateFile", "").ifEmpty { cert.optString("keyFile", "") }
		val where = "tlsSettings.certificates[$index]"
		when {
			pem.isNotEmpty() && key.isNotEmpty() && isClientKeyPair(pem, key) -> {
				tls.put("client_certificate", pem)
				tls.put("client_key", key)
			}
			pem.isNotEmpty() && key.isNotEmpty() -> notes.add(
				"$where holds a client certificate and key that make no pair, which no core can present, " +
					"so it was dropped"
			)
			file.isNotEmpty() -> notes.add(
				"$where references the file \"$file\"; copy it and its key next to the sing-box config " +
					"and set \"client_certificate_path\" and \"client_key_path\" by hand"
			)
			pem.isNotEmpty() || key.isNotEmpty() -> notes.add(
				"$where names a client certificate without its key, or the key without the certificate; " +
					"sing-box needs both, so it was dropped"
			)
		}
	}

	// ECH, from the config list or a URL the core queries itself.
	private fun applyEch(tlsSettings: JSONObject, tls: JSONObject, notes: MutableList<String>) {
		var ech: Any? = tlsSettings.opt("echConfigList")
		if (ech == null || ech === JSONObject.NULL ||
			(ech is JSONArray && ech.length() == 0) ||
			(ech is String && ech.isEmpty())) {
			ech = tlsSettings.opt("ech")
		}
		if (ech != null && ech !== JSONObject.NULL &&
			!(ech is JSONArray && ech.length() == 0) &&
			!(ech is String && ech.isEmpty())) {
			val echObj = JSONObject()
			echObj.put("enabled", true)
			// The core reads the client-side list as PEM, inline in "config" or from "config_path".
			val lines = when (ech) {
				is JSONArray -> (0 until ech.length()).map { ech.optString(it).trim() }
				else -> ech.toString().trim().lines().map { it.trim() }
			}.filter { it.isNotEmpty() }
			val value = lines.joinToString("")
			when {
				// Xray can fetch the list over DoH.
				value.startsWith("http://") || value.startsWith("https://") ->
					notes.add(
						"tlsSettings.echConfigList points at a resolver; " +
							"sing-box looks the ECH config up in DNS instead"
					)
				else -> echPem(lines)?.let { echObj.put("config", it) } ?: notes.add(
					"could not read tlsSettings.echConfigList; only ECH itself was enabled"
				)
			}
			tls.put("ech", echObj)
		}
	}

	// The ECH config list in the PEM envelope the core parses, or null when its bytes are not one -
	// a two-byte length, then configs of a version and a two-byte length each - which the core
	// refuses the whole document over ("invalid ECH configs pem").
	private fun echPem(lines: List<String>): JSONArray? {
		val body = lines.filter { !it.startsWith("-----") }.joinToString("")
		val bytes = decodeBase64Any(body) ?: return null
		fun u16(at: Int) = ((bytes[at].toInt() and 0xff) shl 8) or (bytes[at + 1].toInt() and 0xff)
		if (bytes.size < 2 || u16(0) != bytes.size - 2) return null
		var at = 2
		while (at < bytes.size) {
			if (at + 4 > bytes.size) return null
			at += 4 + u16(at + 2)
		}
		if (at != bytes.size || bytes.size == 2) return null
		return JSONArray().put("-----BEGIN ECH CONFIGS-----").put(encodeBase64Std(bytes))
			.put("-----END ECH CONFIGS-----")
	}

	// streamSettings to the transport block (ws/grpc/http/httpupgrade/quic/tcp-http)
	internal fun buildTransport(stream: JSONObject, notes: MutableList<String>): JSONObject? {
		var net = streamMethod(stream).ifEmpty { "tcp" }
		if (net == "raw") net = "tcp"

		return when (net) {
			"tcp" -> buildTcpHttpTransport(stream)
			"ws" -> buildWsTransport(stream, notes)
			"grpc" -> buildGrpcTransport(stream, notes)
			"http", "h2" -> buildHttpTransport(stream)
			"httpupgrade" -> buildHttpUpgradeTransport(stream)
			"quic" -> JSONObject().put("type", "quic")
			else -> null
		}
	}

	// tcp + http header -> http transport
	private fun buildTcpHttpTransport(stream: JSONObject): JSONObject? {
		val req = getTcpHttpRequest(stream) ?: return null
		val transport = JSONObject()
		transport.put("type", "http")
		val pathRaw = req.opt("path")
		when (pathRaw) {
			is JSONArray -> if (pathRaw.length() > 0) transport.put("path", pathRaw.opt(0))
			is String -> if (pathRaw.isNotEmpty()) transport.put("path", pathRaw)
		}
		val method = req.optString("method", "")
		if (method.isNotEmpty()) transport.put("method", method)
		val headersIn = req.optJSONObject("headers")
		val workingHeaders = if (headersIn != null) {
			val copy = JSONObject()
			val keys = headersIn.keys()
			while (keys.hasNext()) {
				val key = keys.next()
				copy.put(key, headersIn.opt(key))
			}
			copy
		} else null
		var hostVals: Any? = null
		if (workingHeaders != null) {
			for (spelling in listOf("Host", "host")) {
				if (!workingHeaders.has(spelling)) continue
				hostVals = workingHeaders.opt(spelling)
				workingHeaders.remove(spelling)
				break
			}
		}
		if (hostVals != null && hostVals !== JSONObject.NULL) {
			if (hostVals is JSONArray) {
				transport.put("host", hostVals)
			} else {
				transport.put("host", JSONArray().put(hostVals.toString()))
			}
		}
		if (workingHeaders != null && workingHeaders.length() > 0) {
			transport.put("headers", normalizeHeadersV2Ray(workingHeaders, singleValue = false))
		}
		return transport
	}

	// WebSocket: path, headers, early-data
	private fun buildWsTransport(stream: JSONObject, notes: MutableList<String>): JSONObject? {
		val websocket = stream.optJSONObject("wsSettings") ?: JSONObject()
		val transport = JSONObject()
		transport.put("type", "ws")
		if (websocket.xInt("heartbeatPeriod") > 0) {
			notes.add("wsSettings.heartbeatPeriod has no sing-box equivalent and was dropped")
		}
		val rawPath = websocket.optString("path", "")
		val parsed = parseWsPath(rawPath)
		if (parsed.path.isNotEmpty()) transport.put("path", parsed.path)
		val headers = normalizeHeadersV2Ray(websocket.optJSONObject("headers"), singleValue = true)
		// Xray spells the Host beside the headers as well as inside them. Reading only the
		// headers leaves a node behind a CDN asking for the wrong host, which is a connection
		// that resolves and then fails - so both are read, as the other two passes read them.
		val wsHost = websocket.optString("host", "").trim()
		if (wsHost.isNotEmpty()) {
			// The field is the current spelling and wins over a Host header, which is the one
			// Xray deprecated - the same order Xray and the other two passes use.
			val hostKeys = headers.keys().asSequence().filter { it.equals("Host", true) }.toList()
			for (key in hostKeys) headers.remove(key)
			headers.put("Host", wsHost)
		}
		if (headers.length() > 0) transport.put("headers", headers)
		var earlyData = parsed.earlyData
		if (earlyData == null && websocket.has("maxEarlyData") && !websocket.isNull("maxEarlyData")) {
			val maxEarlyData = websocket.opt("maxEarlyData")
			earlyData = when (maxEarlyData) {
				is Number -> maxEarlyData.toInt()
				is String -> maxEarlyData.toIntOrNull()
				else -> null
			}
		}
		if (earlyData != null && earlyData != 0) {
			transport.put("max_early_data", earlyData)
			transport.put(
				"early_data_header_name",
				websocket.optString("earlyDataHeaderName", "").ifEmpty { "Sec-WebSocket-Protocol" }
			)
		} else {
			val edh = websocket.optString("earlyDataHeaderName", "")
			if (edh.isNotEmpty()) transport.put("early_data_header_name", edh)
		}
		return transport
	}

	// Gives an outbound's TLS sing-box's fragmenting for an Xray fragment and says whether it could: sing-box
	// splits only the Client Hello of its own TLS, never REALITY's - into records for "tlshello", sent apart
	// where Xray sends them apart, else into TCP segments - and no packet after the first.
	internal fun applyTlsFragment(outbound: JSONObject, fragment: JSONObject?): Boolean {
		if (fragment == null || sendsOverUdp(outbound)) return false
		val tls = outbound.optJSONObject("tls") ?: return false
		val reality = tls.optJSONObject("reality")?.optBoolean("enabled") == true
		if (!tls.optBoolean("enabled") || reality) return false
		// sing-box splits the Client Hello at its server name, so one sent to an address without a name it
		// leaves whole.
		if (tls.optString("server_name").isEmpty() && isIpLiteral(outbound.optString("server"))) return false
		val packets = fragment.xStr("packets").lowercase()
		val records = packets == "tlshello"
		if (!records && packets.isNotEmpty() && !Regex("^1(-\\d+)?$").matches(packets)) return false
		if (!records || helloDelayed(fragment)) tls.put("fragment", true)
		if (records) tls.put("record_fragment", true)
		return true
	}

	// Whether Xray parts the records of a split Client Hello by a delay - freedom's interval, a mask's
	// delay or delays - rather than sending them in the one write sing-box's records alone make.
	private fun helloDelayed(fragment: JSONObject): Boolean {
		val delays = fragment.optJSONArray("delays")
		if (delays == null || delays.length() == 0) {
			return fragment.xRange("interval").to > 0 || fragment.xRange("delay").to > 0
		}
		val longest = parseRangeString(xScalarString(delays.opt(0)).trim())?.to ?: 0
		return delays.length() > 1 || longest > 0
	}

	// What a node is told when its TLS takes sing-box's fragmenting for Xray's.
	internal const val TLS_FRAGMENT_NOTE = "sing-box's own TLS fragmenting does it - on the Client Hello " +
		"alone, split at its server name rather than by Xray's lengths and delays"

	// Whether an outbound sends over UDP alone - a QUIC protocol or transport, WireGuard - which neither
	// Xray's fragment nor sing-box's ever splits.
	internal fun sendsOverUdp(outbound: JSONObject): Boolean =
		outbound.optString("type") in UDP_OUTBOUNDS ||
			outbound.optJSONObject("transport")?.optString("type") == "quic"

	private val UDP_OUTBOUNDS = setOf("hysteria", "hysteria2", "tuic", "wireguard")

	// sing-box asks for "/<service>/Tun" and escapes a "/" inside the service, so of Xray's custom gRPC
	// paths it reaches the ones ending in "/Tun" with no "/" between the first and that one.
	internal fun grpcPathRefusal(stream: JSONObject?): String? {
		val name = streamGrpc(stream).xStrRaw("serviceName")
		val path = grpcPath(name)
		if (!path.custom || path.stream == "Tun" && '/' !in path.service) return null
		return "grpcSettings.serviceName \"$name\" is a custom gRPC path, and sing-box asks for " +
			"/<service>/Tun with no \"/\" inside the service, so the node would not connect"
	}

	// gRPC: service name and timeouts
	private fun buildGrpcTransport(stream: JSONObject, notes: MutableList<String>): JSONObject? {
		val grpc = streamGrpc(stream) ?: JSONObject()
		val serviceName = grpcPath(grpc.optString("serviceName", "")).service
		val transport = JSONObject()
		transport.put("type", "grpc")
		// The transport crosses over; these settings of it do not. Said plainly, because a line
		// naming grpcSettings reads as though the gRPC node itself had been dropped.
		if (grpc.optString("authority", "").isNotEmpty()) {
			notes.add(
				"the node still uses gRPC, but grpcSettings.authority has no " +
					"sing-box equivalent and was dropped"
			)
		}
		// sing-box has no multi-mode, so a node asking for it runs in single mode. mihomo says so
		// already, and saying it on one side only is how a limitation goes unnoticed.
		if (grpc.xBool("multiMode")) {
			notes.add(
				"the node still uses gRPC, but grpcSettings.multiMode has no " +
					"sing-box equivalent; the node will use single mode"
			)
		}
		transport.put("service_name", serviceName)
		if (grpc.xInt("initial_windows_size") > 0) {
			notes.add(
				"the node still uses gRPC, but grpcSettings.initial_windows_size has no " +
					"sing-box equivalent and was dropped"
			)
		}
		val idle = SingBoxUtil.toDuration(grpc.opt("idle_timeout"))
		if (idle != null) transport.put("idle_timeout", idle)
		val hct = SingBoxUtil.toDuration(grpc.opt("health_check_timeout"))
		if (hct != null) transport.put("ping_timeout", hct)
		if (grpc.xBool("permit_without_stream")) transport.put("permit_without_stream", true)
		return transport
	}

	// HTTP/2: host/path/headers/timeouts
	private fun buildHttpTransport(stream: JSONObject): JSONObject? {
		val http = stream.optJSONObject("httpSettings") ?: JSONObject()
		val transport = JSONObject()
		transport.put("type", "http")
		val path = http.optString("path", "")
		if (path.isNotEmpty()) transport.put("path", path)
		val host = http.opt("host")
		if (host != null && host !== JSONObject.NULL) {
			if (host is JSONArray) {
				if (host.length() > 0) transport.put("host", host)
			} else if (host is String) {
				if (host.isNotEmpty()) transport.put("host", JSONArray().put(host))
			} else {
				val hostText = host.toString()
				if (hostText.isNotEmpty()) transport.put("host", JSONArray().put(hostText))
			}
		}
		val method = http.optString("method", "")
		if (method.isNotEmpty()) transport.put("method", method)
		val headers = http.optJSONObject("headers")
		if (headers != null && headers.length() > 0) {
			transport.put("headers", normalizeHeadersV2Ray(headers, singleValue = false))
		}
		val idle = SingBoxUtil.toDuration(http.opt("read_idle_timeout"))
		if (idle != null) transport.put("idle_timeout", idle)
		val hct = SingBoxUtil.toDuration(http.opt("health_check_timeout"))
		if (hct != null) transport.put("ping_timeout", hct)
		return transport
	}

	// HTTPUpgrade: host (top-level or from the headers)
	private fun buildHttpUpgradeTransport(stream: JSONObject): JSONObject? {
		val httpUpgrade = stream.optJSONObject("httpupgradeSettings") ?: JSONObject()
		val transport = JSONObject()
		transport.put("type", "httpupgrade")
		val path = httpUpgrade.optString("path", "")
		if (path.isNotEmpty()) transport.put("path", path)
		var hostTop = httpUpgrade.optString("host", "")
		val headers = normalizeHeadersV2Ray(httpUpgrade.optJSONObject("headers"), singleValue = true)
		var hostFromHeaders: String? = null
		val headerKeys = headers.keys()
		val toRemove = mutableListOf<String>()
		while (headerKeys.hasNext()) {
			val key = headerKeys.next()
			if (key.lowercase() == "host") {
				hostFromHeaders = headers.opt(key)?.toString()
				toRemove.add(key)
			}
		}
		for (key in toRemove) headers.remove(key)
		if (hostTop.isEmpty() && !hostFromHeaders.isNullOrEmpty()) hostTop = hostFromHeaders
		if (hostTop.isNotEmpty()) transport.put("host", hostTop)
		if (headers.length() > 0) transport.put("headers", headers)
		return transport
	}
}
