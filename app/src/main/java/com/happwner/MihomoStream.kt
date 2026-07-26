package com.happwner

import org.json.JSONObject

/**
 * The security layer and transport of an outbound: TLS, REALITY, ECH, and the
 * websocket/gRPC/HTTP/2/mKCP/XHTTP transports.
 */

/**
 * Describes how a protocol spells its TLS fields, which differs between the
 * V2Ray-family protocols and the rest.
 */
internal class TlsTarget(
    /** "servername" for vless/vmess, "sni" for everything else. */
    val sniKey: String,
    /**
     * True when the protocol needs "tls: true" to enable TLS. Trojan, Hysteria2
     * and TUIC are always TLS and have no such field.
     */
    val explicitTls: Boolean,
    val supportsReality: Boolean,
    val supportsEch: Boolean
)

internal val TLS_V2RAY = TlsTarget("servername", explicitTls = true, supportsReality = true, supportsEch = true)
internal val TLS_TROJAN = TlsTarget("sni", explicitTls = false, supportsReality = true, supportsEch = true)

/** Maps the stream's security layer onto the proxy entry. */
internal fun MihomoConv.applyTls(m: YamlMap, ss: JSONObject?, target: TlsTarget) {
    val security = streamSecurity(ss)
    val tlsCfg = streamTls(ss)

    when (security) {
        "none" -> {
            // Nothing to do for a protocol that defaults to plaintext.
            if (target.explicitTls) return
            // Trojan and friends always speak TLS in mihomo; an Xray config
            // that disables it cannot be represented.
            if (tlsCfg == null) {
                warn("the source has no TLS layer, but mihomo always uses TLS for this protocol")
            }
        }
        "tls" -> if (target.explicitTls) m.set("tls", true)
        "reality" -> {
            if (target.explicitTls) m.set("tls", true)
            if (!target.supportsReality) {
                warn("REALITY is not supported by mihomo for this protocol and was dropped")
            }
        }
        else -> {
            warn("unknown security \"$security\" was treated as plaintext")
            return
        }
    }

    if (security == "reality") {
        applyReality(m, ss, target)
        return
    }
    if (tlsCfg == null) return

    // The SNI is kept even when it repeats the server address: it is what the
    // source asked for, and it keeps the output easy to compare with it.
    m.setStr(target.sniKey, tlsCfg.xStr("serverName"))

    val alpn = tlsCfg.xStrList("alpn")
    if (alpn.isNotEmpty()) m.set("alpn", toFlowSeq(alpn))
    if (tlsCfg.xBool("allowInsecure") || opts.skipCertVerify) m.set("skip-cert-verify", true)
    applyClientFingerprint(m, tlsCfg.xStr("fingerprint"))
    applyCertPin(m, tlsCfg.xStr("pinnedPeerCertSha256"))
    m.setStr("name-cert-verify", tlsCfg.xStr("verifyPeerCertByName"))
    applyCertificates(m, tlsCfg)
    applyEch(m, tlsCfg, target)

    if (tlsCfg.xStr("minVersion").isNotEmpty()) {
        warn("tlsSettings.minVersion is not configurable per proxy in mihomo and was dropped")
    }
    if (tlsCfg.xStrList("curvePreferences").isNotEmpty()) {
        warn("tlsSettings.curvePreferences has no mihomo equivalent and was dropped")
    }
}

/** Maps realitySettings onto mihomo's reality-opts. */
private fun MihomoConv.applyReality(m: YamlMap, ss: JSONObject?, target: TlsTarget) {
    val r = ss.xObj("realitySettings")
    if (r == null) {
        warn("security is REALITY but realitySettings is missing")
        return
    }
    if (!target.supportsReality) return

    val sni = realitySni(r)
    if (sni.isNotEmpty()) m.set(target.sniKey, sni)
    applyClientFingerprint(m, r.xStr("fingerprint"))
    if (opts.skipCertVerify) m.set("skip-cert-verify", true)

    val optsMap = YamlMap()
    val pub = realityPublicKey(r)
    if (pub.isEmpty()) warn("realitySettings has no publicKey; mihomo will refuse the node")
    optsMap.setStr("public-key", pub)
    optsMap.setStr("short-id", realityShortId(r))
    m.set("reality-opts", optsMap)

    if (r.xStr("mldsa65Verify").isNotEmpty()) {
        warn(
            "realitySettings.mldsa65Verify (post-quantum certificate verification) " +
                "is not supported by mihomo and was dropped"
        )
    }
    val alpn = streamTls(ss).xStrList("alpn")
    if (alpn.isNotEmpty()) m.set("alpn", toFlowSeq(alpn))
}

/** The REALITY server name. */
internal fun realitySni(r: JSONObject): String {
    val v = r.xStr("serverName")
    if (v.isNotEmpty()) return v
    return r.xStrList("serverNames").firstOrNull().orEmpty()
}

/** The REALITY short id. */
internal fun realityShortId(r: JSONObject): String {
    val v = r.xStr("shortId")
    if (v.isNotEmpty()) return v
    return r.xStrList("shortIds").firstOrNull().orEmpty()
}

/**
 * The REALITY public key. Newer Xray builds call the client-side field
 * "password"; older ones call it "publicKey".
 */
internal fun realityPublicKey(r: JSONObject): String = r.xStrOf("publicKey", "password")

/** The uTLS profiles mihomo knows by name. */
private val UTLS_FINGERPRINTS = setOf(
    "chrome", "firefox", "safari", "ios", "android", "edge",
    "360", "qq", "random", "randomized",
    "chrome120", "firefox120", "safari16"
)

internal fun MihomoConv.applyClientFingerprint(m: YamlMap, raw: String) {
    val fp = raw.trim().lowercase()
    if (fp.isEmpty()) {
        if (opts.clientFingerprint.isNotEmpty()) m.set("client-fingerprint", opts.clientFingerprint)
        return
    }
    if (fp in UTLS_FINGERPRINTS) {
        m.set("client-fingerprint", fp)
        return
    }
    when (fp) {
        "randomizednoalpn", "randomizedalpn" -> {
            m.set("client-fingerprint", "randomized")
            warn("uTLS fingerprint \"$fp\" has no exact mihomo equivalent; used \"randomized\"")
        }
        "unsafe", "golang", "hellogolang" ->
            warn("uTLS fingerprint \"$fp\" has no mihomo equivalent and was dropped")
        else -> warn("unknown uTLS fingerprint \"$fp\" was dropped")
    }
}

/**
 * Converts Xray's base64 certificate pin to the hex form mihomo expects for its
 * "fingerprint" field.
 */
internal fun MihomoConv.applyCertPin(m: YamlMap, raw: String) {
    val pin = raw.trim()
    if (pin.isEmpty()) return
    val decoded = decodeBase64Any(pin)
    if (decoded != null && decoded.size == 32) {
        m.set("fingerprint", toHex(decoded))
        return
    }
    // It may already be hex, in which case mihomo takes it as-is.
    val clean = pin.replace(":", "")
    val hex = fromHex(clean)
    if (hex != null && hex.size == 32) {
        m.set("fingerprint", clean.lowercase())
        return
    }
    warn("could not decode tlsSettings.pinnedPeerCertSha256 as a SHA-256 value; it was dropped")
}

/** Carries a pinned CA certificate over to mihomo. */
internal fun MihomoConv.applyCertificates(m: YamlMap, tlsCfg: JSONObject) {
    for (cert in tlsCfg.xObjList("certificates")) {
        when (cert.xStr("usage").lowercase()) {
            "verify", "" -> {
                val pem = cert.xStrList("certificate").joinToString("\n")
                if (pem.isNotEmpty()) {
                    m.set("certificate", pem)
                } else {
                    val file = cert.xStr("certificateFile")
                    if (file.isNotEmpty()) {
                        warn(
                            "tlsSettings.certificates references the file \"$file\"; " +
                                "copy it next to the mihomo config and set \"certificate\" by hand"
                        )
                    }
                }
                val key = cert.xStrList("key").joinToString("\n")
                if (key.isNotEmpty()) m.set("private-key", key)
            }
            "encipherment", "issue" ->
                warn(
                    "tlsSettings.certificates with usage \"${cert.xStr("usage")}\" " +
                        "is a server-side setting and was dropped"
                )
        }
    }
}

/** Maps Xray's ECH configuration list onto mihomo's ech-opts. */
internal fun MihomoConv.applyEch(m: YamlMap, tlsCfg: JSONObject, target: TlsTarget) {
    val list = tlsCfg.xStr("echConfigList")
    if (list.isEmpty()) return
    if (!target.supportsEch) {
        warn("ECH is not supported by mihomo for this protocol and was dropped")
        return
    }
    val optsMap = YamlMap()
    optsMap.set("enable", true)
    val std = decodeBase64(list, urlSafe = false, padded = true)
    val any = if (std == null) decodeBase64Any(list) else null
    when {
        list.startsWith("http://") || list.startsWith("https://") ->
            // Xray can fetch the list over DoH; mihomo instead queries the
            // HTTPS record itself when no literal config is given.
            warn("tlsSettings.echConfigList points at a URL; mihomo will look the ECH config up in DNS instead")
        std != null -> optsMap.set("config", list)
        any != null -> optsMap.set("config", encodeBase64Std(any))
        else -> warn("could not decode tlsSettings.echConfigList; only ECH itself was enabled")
    }
    m.set("ech-opts", optsMap)
}

// ------------------------------------------------------------ transports ----

/** The transports mihomo implements per protocol. */
private val NETWORK_SUPPORT = mapOf(
    "vless" to setOf("tcp", "ws", "h2", "grpc", "xhttp", "httpupgrade"),
    "vmess" to setOf("tcp", "ws", "h2", "grpc", "kcp", "httpupgrade"),
    "trojan" to setOf("tcp", "ws", "grpc", "httpupgrade")
)

/** Maps streamSettings onto mihomo's network and *-opts fields. */
internal fun MihomoConv.applyTransport(m: YamlMap, ss: JSONObject?, proto: String) {
    val network = streamNetwork(ss)

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
        "tcp" -> applyTcp(m, ss, proto)
        "ws" -> applyWebsocket(m, ss, httpUpgrade = false)
        "httpupgrade" -> applyWebsocket(m, ss, httpUpgrade = true)
        "h2" -> applyH2(m, ss)
        "grpc" -> applyGrpc(m, ss)
        "xhttp" -> applyXhttp(m, ss)
        "kcp" -> applyKcp(m, ss)
        else -> throw MihomoUnsupported("unsupported transport \"$network\"")
    }
}

/**
 * Handles the raw transport, including its HTTP masquerade, which mihomo
 * exposes as network "http".
 */
private fun MihomoConv.applyTcp(m: YamlMap, ss: JSONObject?, proto: String) {
    val header = streamTcp(ss).xObj("header") ?: return // plain TCP is mihomo's default
    when (val headerType = header.xStr("type").lowercase()) {
        "", "none" -> return
        "http" -> {
            if (proto == "trojan") {
                throw MihomoUnsupported(
                    "mihomo does not support the HTTP masquerade over raw TCP for trojan"
                )
            }
            m.set("network", "http")
            val optsMap = YamlMap()
            val req = header.xObj("request")
            if (req != null) {
                optsMap.setStr("method", req.xStr("method"))
                val path = req.xStrList("path")
                if (path.isNotEmpty()) optsMap.set("path", toFlowSeq(path))
                val headers = req.xHeaderLists("headers")
                if (headers.isNotEmpty()) {
                    val hdr = YamlMap()
                    for (k in headers.keys.sorted()) hdr.set(k, toFlowSeq(headers[k].orEmpty()))
                    optsMap.set("headers", hdr)
                }
            }
            m.set("http-opts", optsMap)
        }
        else -> throw MihomoUnsupported("unsupported raw header type \"$headerType\"")
    }
}

/**
 * Handles both the websocket transport and HTTPUpgrade, which mihomo models as
 * websocket with a flag.
 */
private fun MihomoConv.applyWebsocket(m: YamlMap, ss: JSONObject?, httpUpgrade: Boolean) {
    m.set("network", "ws")
    val optsMap = YamlMap()

    var path = ""
    var host = ""
    var headers: Map<String, String> = emptyMap()
    var maxEd = 0
    var edName = ""

    if (httpUpgrade) {
        val hu = ss.xObj("httpupgradeSettings")
        if (hu != null) {
            path = hu.xStr("path")
            host = hu.xStr("host")
            headers = hu.xHeaders("headers")
        }
    } else {
        val ws = streamWs(ss)
        if (ws != null) {
            path = ws.xStr("path")
            host = ws.xStr("host")
            headers = ws.xHeaders("headers")
            maxEd = ws.xInt("maxEarlyData")
            edName = ws.xStr("earlyDataHeaderName")
            if (ws.xBool("useBrowserForwarding")) {
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
    optsMap.setStr("path", split.first)

    val hdr = YamlMap()
    for (k in headers.keys.sorted()) {
        val v = headers[k].orEmpty().trim()
        if (k.equals("host", ignoreCase = true)) {
            // Xray moves a Host header into the dedicated host field.
            if (host.isEmpty()) host = v
            continue
        }
        hdr.setStr(k, v)
    }
    host = host.trim()
    // mihomo reads the SNI/Host override from the Host header.
    if (host.isNotEmpty()) hdr.set("Host", host)
    optsMap.set("headers", hdr)

    if (maxEd > 0) {
        optsMap.set("max-early-data", maxEd)
        if (edName.isEmpty()) edName = "Sec-WebSocket-Protocol"
        optsMap.set("early-data-header-name", edName)
    }
    if (httpUpgrade) optsMap.set("v2ray-http-upgrade", true)
    m.set("ws-opts", optsMap)
}

/** Handles the HTTP/2 transport. */
private fun MihomoConv.applyH2(m: YamlMap, ss: JSONObject?) {
    m.set("network", "h2")
    val optsMap = YamlMap()
    val h = ss.xObj("httpSettings")
    if (h != null) {
        val host = h.xStrList("host")
        if (host.isNotEmpty()) optsMap.set("host", toFlowSeq(host))
        optsMap.setStr("path", h.xStr("path"))
        val method = h.xStr("method")
        if (method.isNotEmpty() && !method.equals("PUT", ignoreCase = true)) {
            warn("httpSettings.method \"$method\" is not configurable in mihomo's h2-opts and was dropped")
        }
        if (h.xHeaders("headers").isNotEmpty()) {
            warn("httpSettings.headers has no mihomo equivalent for the h2 transport and was dropped")
        }
    }
    m.set("h2-opts", optsMap)
    if (streamSecurity(ss) == "none") {
        warn("the h2 transport without TLS is unusual; mihomo requires TLS for h2")
    }
}

/** Handles the gRPC transport. */
private fun MihomoConv.applyGrpc(m: YamlMap, ss: JSONObject?) {
    m.set("network", "grpc")
    val optsMap = YamlMap()
    val g = streamGrpc(ss)
    if (g != null) {
        optsMap.setStr("grpc-service-name", g.xStr("serviceName"))
        optsMap.setStr("grpc-user-agent", g.xStr("user_agent"))
        if (g.xBool("multiMode")) {
            warn("grpcSettings.multiMode has no mihomo equivalent; the node will use single mode")
        }
        if (g.xStr("authority").isNotEmpty()) {
            warn("grpcSettings.authority has no mihomo equivalent and was dropped")
        }
    }
    m.set("grpc-opts", optsMap)
}

/** Handles the mKCP transport, which mihomo supports for vmess only. */
private fun MihomoConv.applyKcp(m: YamlMap, ss: JSONObject?) {
    m.set("network", "kcp")
    val optsMap = YamlMap()
    val k = ss.xObj("kcpSettings")
    if (k != null) {
        optsMap.setInt("mtu", k.xInt("mtu"))
        optsMap.setInt("tti", k.xInt("tti"))
        optsMap.setInt("uplink-capacity", k.xInt("uplinkCapacity"))
        optsMap.setInt("downlink-capacity", k.xInt("downlinkCapacity"))
        optsMap.setBoolTrue("congestion", k.xBool("congestion"))
        optsMap.setStr("seed", k.xStr("seed"))
        val headerType = k.xObj("header").xStr("type").lowercase()
        if (headerType.isNotEmpty() && headerType != "none") optsMap.set("header", headerType)
        if (k.xInt("readBufferSize") != 0 || k.xInt("writeBufferSize") != 0) {
            warn("kcpSettings read/write buffer sizes use different units in mihomo and were dropped")
        }
    }
    m.set("mkcp-opts", optsMap)
}

/**
 * Maps Xray's XHTTP transport, including the "extra" object, xmux and
 * downloadSettings, onto mihomo's xhttp-opts.
 */
private fun MihomoConv.applyXhttp(m: YamlMap, ss: JSONObject?) {
    m.set("network", "xhttp")
    val cfg = streamXhttp(ss)
    if (cfg == null) {
        m.set("xhttp-opts", YamlMap().set("mode", "auto"))
        return
    }
    m.set("xhttp-opts", buildXhttpOpts(cfg))
}

/** The transfer modes Xray accepts. */
private val XHTTP_MODES = setOf("auto", "packet-up", "stream-up", "stream-one")

internal fun MihomoConv.buildXhttpOpts(cfg: JSONObject): YamlMap {
    val optsMap = YamlMap()

    optsMap.setStr("path", cfg.xStr("path"))
    optsMap.setStr("host", cfg.xStr("host"))

    var mode = cfg.xStr("mode").lowercase()
    if (mode.isEmpty()) mode = "auto"
    if (mode !in XHTTP_MODES) throw MihomoUnsupported("unsupported xhttp mode \"$mode\"")
    optsMap.set("mode", mode)

    val headers = cfg.xHeaders("headers")
    if (headers.isNotEmpty()) {
        val hdr = YamlMap()
        for (k in headers.keys.sorted()) {
            if (k.equals("host", ignoreCase = true)) {
                // Xray rejects a Host header here; fold it into "host".
                if (!optsMap.has("host")) optsMap.setStr("host", headers[k].orEmpty().trim())
                continue
            }
            hdr.setStr(k, headers[k].orEmpty().trim())
        }
        optsMap.set("headers", hdr)
    }

    optsMap.setBoolTrue("no-grpc-header", cfg.xBool("noGRPCHeader"))

    // Padding controls.
    optsMap.setStr("x-padding-bytes", cfg.xRange("xPaddingBytes").render())
    optsMap.setBoolTrue("x-padding-obfs-mode", cfg.xBool("xPaddingObfsMode"))
    optsMap.setStr("x-padding-key", cfg.xStr("xPaddingKey"))
    optsMap.setStr("x-padding-header", cfg.xStr("xPaddingHeader"))
    val placement = cfg.xStr("xPaddingPlacement")
    if (placement.isNotEmpty()) {
        if (placement !in setOf("cookie", "header", "query", "queryInHeader")) {
            throw MihomoUnsupported("unsupported xPaddingPlacement \"$placement\"")
        }
        optsMap.set("x-padding-placement", placement)
    }
    val padMethod = cfg.xStr("xPaddingMethod")
    if (padMethod.isNotEmpty()) {
        if (padMethod !in setOf("repeat-x", "tokenish")) {
            throw MihomoUnsupported("unsupported xPaddingMethod \"$padMethod\"")
        }
        optsMap.set("x-padding-method", padMethod)
    }

    // Uplink and session controls.
    val uplinkMethod = cfg.xStr("uplinkHTTPMethod")
    if (uplinkMethod.isNotEmpty()) {
        val upper = uplinkMethod.uppercase()
        if (upper == "GET" && mode != "packet-up") {
            throw MihomoUnsupported("uplinkHTTPMethod GET is only valid in packet-up mode")
        }
        optsMap.set("uplink-http-method", upper)
    }
    val sessionPlacement = cfg.xStr("sessionIDPlacement")
    if (sessionPlacement.isNotEmpty()) {
        if (sessionPlacement !in setOf("path", "cookie", "header", "query")) {
            throw MihomoUnsupported("unsupported sessionIDPlacement \"$sessionPlacement\"")
        }
        optsMap.set("session-placement", sessionPlacement)
    }
    optsMap.setStr("session-key", cfg.xStr("sessionIDKey"))
    optsMap.setStr("session-table", cfg.xStr("sessionIDTable"))
    optsMap.setStr("session-length", cfg.xRange("sessionIDLength").render())

    val seqPlacement = cfg.xStr("seqPlacement")
    if (seqPlacement.isNotEmpty()) {
        if (seqPlacement !in setOf("path", "cookie", "header", "query")) {
            throw MihomoUnsupported("unsupported seqPlacement \"$seqPlacement\"")
        }
        optsMap.set("seq-placement", seqPlacement)
    }
    optsMap.setStr("seq-key", cfg.xStr("seqKey"))

    val uplinkData = cfg.xStr("uplinkDataPlacement")
    if (uplinkData.isNotEmpty()) {
        if (uplinkData !in setOf("auto", "body", "cookie", "header")) {
            throw MihomoUnsupported("unsupported uplinkDataPlacement \"$uplinkData\"")
        }
        if ((uplinkData == "cookie" || uplinkData == "header") && mode != "packet-up") {
            throw MihomoUnsupported("uplinkDataPlacement \"$uplinkData\" is only valid in packet-up mode")
        }
        optsMap.set("uplink-data-placement", uplinkData)
    }
    optsMap.setStr("uplink-data-key", cfg.xStr("uplinkDataKey"))
    optsMap.setStr("uplink-chunk-size", cfg.xRange("uplinkChunkSize").render())

    optsMap.setStr("sc-max-each-post-bytes", cfg.xRange("scMaxEachPostBytes").render())
    optsMap.setStr("sc-min-posts-interval-ms", cfg.xRange("scMinPostsIntervalMs").render())

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
        reuse.setStr("max-concurrency", xmux.xRange("maxConcurrency").renderNonZero())
        reuse.setStr("max-connections", xmux.xRange("maxConnections").renderNonZero())
        reuse.setStr("c-max-reuse-times", xmux.xRange("cMaxReuseTimes").renderNonZero())
        reuse.setStr("h-max-request-times", xmux.xRange("hMaxRequestTimes").renderNonZero())
        reuse.setStr("h-max-reusable-secs", xmux.xRange("hMaxReusableSecs").renderNonZero())
        reuse.setInt("h-keep-alive-period", xmux.xInt("hKeepAlivePeriod"))
        if (xmux.xRange("cMaxLifetimeMs").set) {
            warn("xmux cMaxLifetimeMs has no mihomo equivalent and was dropped")
        }
        if (reuse.size > 0) optsMap.set("reuse-settings", reuse)
    }

    // downloadSettings splits the download half onto a separate endpoint.
    val download = cfg.xObj("downloadSettings")
    if (download != null) {
        val dl = buildXhttpDownload(download)
        if (dl.size > 0) optsMap.set("download-settings", dl)
    }
    return optsMap
}

/** True when no xmux field was set, so the block says nothing. */
private fun xmuxIsZero(x: JSONObject): Boolean =
    !x.xRange("maxConcurrency").set && !x.xRange("maxConnections").set &&
        !x.xRange("cMaxReuseTimes").set && !x.xRange("cMaxLifetimeMs").set &&
        !x.xRange("hMaxRequestTimes").set && !x.xRange("hMaxReusableSecs").set &&
        x.xInt("hKeepAlivePeriod") == 0

/**
 * Maps an XHTTP downloadSettings block, which is a full stream configuration
 * plus its own address.
 */
private fun MihomoConv.buildXhttpDownload(dl: JSONObject): YamlMap {
    val out = YamlMap()

    val addr = dl.xStr("address")
    if (addr.isNotEmpty()) out.set("server", stripBrackets(addr))
    val port = dl.xInt("port")
    if (port > 0) out.set("port", port)

    val net = streamNetwork(dl)
    if (net != "xhttp" && net != "tcp") {
        warn("downloadSettings uses the $net transport, which mihomo only supports as xhttp here")
    }
    val cfg = streamXhttp(dl)
    if (cfg != null) {
        val optsMap = buildXhttpOpts(cfg)
        // The download half reuses the upload settings for anything it does not
        // override; mihomo only accepts this subset.
        for (key in listOf("path", "host", "headers", "reuse-settings")) {
            optsMap.get(key)?.let { out.set(key, it) }
        }
    }

    // The download endpoint carries its own security layer.
    when (streamSecurity(dl)) {
        "tls" -> {
            out.set("tls", true)
            val t = streamTls(dl)
            if (t != null) {
                out.setStr("servername", t.xStr("serverName"))
                val alpn = t.xStrList("alpn")
                if (alpn.isNotEmpty()) out.set("alpn", toFlowSeq(alpn))
                if (t.xBool("allowInsecure") || opts.skipCertVerify) out.set("skip-cert-verify", true)
                val fp = t.xStr("fingerprint").lowercase()
                if (fp in UTLS_FINGERPRINTS) out.set("client-fingerprint", fp)
            }
        }
        "reality" -> {
            out.set("tls", true)
            val r = dl.xObj("realitySettings")
            if (r != null) {
                out.setStr("servername", realitySni(r))
                val reality = YamlMap()
                reality.setStr("public-key", realityPublicKey(r))
                reality.setStr("short-id", realityShortId(r))
                out.set("reality-opts", reality)
                val fp = r.xStr("fingerprint").lowercase()
                if (fp in UTLS_FINGERPRINTS) out.set("client-fingerprint", fp)
            }
        }
    }
    return out
}

/**
 * Pulls Xray's "ed" query parameter out of a transport path, returning the path
 * without it and the early-data size.
 *
 * The remaining parameters keep their original text and order, so a path that
 * carries more than early data survives unchanged.
 */
internal fun splitEarlyData(path: String): Pair<String, Int> {
    if (path.isEmpty() || !path.contains("ed=")) return path to 0
    val q = path.indexOf('?')
    if (q < 0) return path to 0
    val base = path.substring(0, q)
    val query = path.substring(q + 1)

    var ed = 0
    val kept = ArrayList<String>()
    for (pair in query.split("&")) {
        if (pair.isEmpty()) continue
        if (pair.startsWith("ed=") && ed == 0) {
            val n = pair.substring(3).toIntOrNull()
            if (n != null && n > 0) {
                ed = n
                continue
            }
        }
        kept.add(pair)
    }
    if (ed == 0) return path to 0
    val rest = kept.joinToString("&")
    return (if (rest.isEmpty()) base else "$base?$rest") to ed
}
