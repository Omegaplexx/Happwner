package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// The per-protocol converters.

// Builds a flow sequence from strings, dropping the blank ones.
internal fun toFlowSeq(items: List<String>): YamlFlowSeq {
    val out = YamlFlowSeq()
    for (s in items) {
        val v = s.trim()
        if (v.isNotEmpty()) out.add(v)
    }
    return out
}

// ---------------------------------------------------------------- VLESS ----

private class VlessEndpoint(
    val address: String,
    val port: Int,
    val id: String,
    var flow: String,
    var encryption: String
)

private fun vlessEndpoints(s: JSONObject): List<VlessEndpoint> {
    val out = ArrayList<VlessEndpoint>()
    for (v in s.xObjList("vnext")) {
        val users = v.xObjList("users")
        if (users.isEmpty()) {
            out.add(VlessEndpoint(v.xStr("address"), v.xInt("port"), "", "", ""))
            continue
        }
        for (u in users) {
            out.add(
                VlessEndpoint(
                    address = v.xStr("address"),
                    port = v.xInt("port"),
                    id = u.xStr("id"),
                    flow = u.xStr("flow"),
                    encryption = u.xStr("encryption")
                )
            )
        }
    }
    if (out.isEmpty() && (s.xStr("address").isNotEmpty() || s.xStr("id").isNotEmpty())) {
        out.add(
            VlessEndpoint(
                address = s.xStr("address"),
                port = s.xInt("port"),
                id = s.xStr("id"),
                flow = s.xStr("flow"),
                encryption = s.xStr("encryption")
            )
        )
    }
    // The flat "encryption"/"flow" keys act as defaults for users that do not
    // carry their own.
    for (ep in out) {
        if (ep.encryption.isEmpty()) ep.encryption = s.xStr("encryption")
        if (ep.flow.isEmpty()) ep.flow = s.xStr("flow")
    }
    return out
}

internal fun MihomoConv.convertVless(ob: JSONObject, preferred: String): List<YamlMap> {
    val settings = outboundSettings(ob)
    val endpoints = vlessEndpoints(settings)
    if (endpoints.isEmpty()) throw MihomoUnsupported("the vless outbound has no server")
    if (settings.xStr("seed").isNotEmpty()) {
        warn("vless \"seed\" has no mihomo equivalent and was dropped")
    }

    val ss = ob.xObj("streamSettings")
    val out = ArrayList<YamlMap>(endpoints.size)
    for (ep in endpoints) {
        val name = name(preferred, ob.xStr("tag"), "vless", ep.address, ep.port)
        val m = base(name, "vless", ep.address, ep.port)
        if (ep.id.isEmpty()) throw MihomoUnsupported("the vless outbound has no user id")
        m.set("uuid", ep.id)

        val flow = normaliseFlow(ep.flow)
        if (flow.isNotEmpty()) {
            if (flow != "xtls-rprx-vision") {
                throw MihomoUnsupported(
                    "mihomo only supports the xtls-rprx-vision flow, not \"${ep.flow}\""
                )
            }
            m.set("flow", flow)
        }

        val enc = vlessEncryption(ep.encryption)
        if (enc.isNotEmpty()) m.set("encryption", enc)

        udpFlag(m)
        applyMux(m, ob, "vless")
        applyTls(m, ss, TLS_V2RAY)
        applyTransport(m, ss, "vless")
        applyDialer(m, ob)
        out.add(m)
    }
    return out
}

// Trims the flow to the part mihomo understands. Xray's "-udp443" suffix only changes how UDP/443
// is handled, and mihomo drops it.
internal fun normaliseFlow(raw: String): String {
    val flow = raw.trim()
    if (flow.isEmpty() || flow == "none") return ""
    return flow.removeSuffix("-udp443")
}

// Validates Xray's VLESS encryption string.
internal fun vlessEncryption(raw: String): String {
    val enc = raw.trim()
    if (enc.isEmpty() || enc == "none") return ""

    val parts = enc.split(".")
    if (parts.size < 4 || parts[0] != "mlkem768x25519plus") {
        throw MihomoUnsupported(
            "unsupported vless encryption \"$enc\": mihomo only implements mlkem768x25519plus"
        )
    }
    if (parts[1] !in setOf("native", "xorpub", "random")) {
        throw MihomoUnsupported(
            "invalid vless encryption \"$enc\": mode must be native, xorpub or random"
        )
    }
    if (parts[2] !in setOf("1rtt", "0rtt")) {
        // A "600s"-style value belongs in the server's decryption field; using
        // it on a client makes mihomo (and Xray) reject the node.
        throw MihomoUnsupported(
            "invalid vless encryption \"$enc\": the client field takes 1rtt or 0rtt, " +
                "not \"${parts[2]}\" (a value like \"600s\" belongs in the server's decryption field)"
        )
    }

    // Remaining tokens are either padding descriptors or base64 keys. mihomo
    // tells them apart by length, so the same rule is applied here.
    var keys = 0
    val padding = ArrayList<String>()
    for (token in parts.subList(3, parts.size)) {
        if (token.length < 20) {
            padding.add(token)
            continue
        }
        val decoded = decodeBase64RawUrl(token)
            ?: throw MihomoUnsupported(
                "invalid vless encryption \"$enc\": key \"${truncateToken(token)}\" is not raw-URL base64"
            )
        // 32 bytes is an X25519 public key, 1184 an ML-KEM-768 encapsulation key.
        if (decoded.size != 32 && decoded.size != 1184) {
            throw MihomoUnsupported(
                "invalid vless encryption \"$enc\": key \"${truncateToken(token)}\" " +
                    "decodes to ${decoded.size} bytes, expected 32 or 1184"
            )
        }
        keys++
    }
    if (keys == 0) {
        throw MihomoUnsupported("invalid vless encryption \"$enc\": no server key found")
    }
    validateVlessPadding(padding, enc)
    return enc
}

// Checks the padding descriptors of a VLESS encryption string ("a-b-c", alternating length and gap,
// the first with minimum values).
private fun validateVlessPadding(tokens: List<String>, enc: String) {
    if (tokens.isEmpty()) return
    var maxLen = 0
    for ((i, token) in tokens.withIndex()) {
        val fields = token.split("-")
        if (fields.size < 3 || fields[0].isEmpty() || fields[1].isEmpty() || fields[2].isEmpty()) {
            throw MihomoUnsupported(
                "invalid vless encryption \"$enc\": padding parameter \"$token\" must have the form a-b-c"
            )
        }
        val values = IntArray(3)
        for (j in 0 until 3) {
            values[j] = fields[j].toIntOrNull()
                ?: throw MihomoUnsupported(
                    "invalid vless encryption \"$enc\": padding parameter \"$token\" is not numeric"
                )
        }
        if (i == 0 && (values[0] < 100 || values[1] < 35 || values[2] < 35)) {
            throw MihomoUnsupported(
                "invalid vless encryption \"$enc\": the first padding parameter \"$token\" " +
                    "must be at least 100-35-35"
            )
        }
        if (i % 2 == 0) maxLen += maxOf(values[1], values[2])
    }
    if (maxLen > 18 + 65535) {
        throw MihomoUnsupported(
            "invalid vless encryption \"$enc\": the total padding length must not exceed 65553"
        )
    }
}

private fun truncateToken(s: String): String = if (s.length <= 16) s else s.substring(0, 16) + "..."

// ---------------------------------------------------------------- VMess ----

private class VmessEndpoint(
    val address: String,
    val port: Int,
    val id: String,
    val alterId: Int,
    val security: String,
    val experiments: String
)

private fun vmessEndpoints(s: JSONObject): List<VmessEndpoint> {
    val out = ArrayList<VmessEndpoint>()
    for (v in s.xObjList("vnext")) {
        for (u in v.xObjList("users")) {
            var alter = u.xInt("alterId")
            if (alter == 0) alter = u.xInt("alterid")
            out.add(
                VmessEndpoint(
                    address = v.xStr("address"),
                    port = v.xInt("port"),
                    id = u.xStr("id"),
                    alterId = alter,
                    security = u.xStr("security").lowercase(),
                    experiments = u.xStr("experiments")
                )
            )
        }
    }
    if (out.isEmpty() && (s.xStr("address").isNotEmpty() || s.xStr("id").isNotEmpty())) {
        out.add(
            VmessEndpoint(
                address = s.xStr("address"),
                port = s.xInt("port"),
                id = s.xStr("id"),
                alterId = s.xInt("alterId"),
                security = s.xStr("security").lowercase(),
                experiments = ""
            )
        )
    }
    return out
}

internal fun MihomoConv.convertVmess(ob: JSONObject, preferred: String): List<YamlMap> {
    val settings = outboundSettings(ob)
    val endpoints = vmessEndpoints(settings)
    if (endpoints.isEmpty()) throw MihomoUnsupported("the vmess outbound has no server")

    val ss = ob.xObj("streamSettings")
    val out = ArrayList<YamlMap>(endpoints.size)
    for (ep in endpoints) {
        val name = name(preferred, ob.xStr("tag"), "vmess", ep.address, ep.port)
        val m = base(name, "vmess", ep.address, ep.port)
        if (ep.id.isEmpty()) throw MihomoUnsupported("the vmess outbound has no user id")
        m.set("uuid", ep.id)
        // mihomo requires alterId, including the modern value of 0.
        m.set("alterId", ep.alterId)
        m.set("cipher", vmessCipher(ep.security))

        if (ep.experiments.isNotEmpty()) {
            // The experiment flags have dedicated mihomo options.
            if (ep.experiments.contains("AuthenticatedLength")) {
                m.set("authenticated-length", true)
            }
            if (ep.experiments.contains("NoTerminationSignal")) {
                warn("the vmess NoTerminationSignal experiment has no mihomo equivalent and was dropped")
            }
        }

        udpFlag(m)
        applyMux(m, ob, "vmess")
        applyTls(m, ss, TLS_V2RAY)
        applyTransport(m, ss, "vmess")
        applyDialer(m, ob)
        out.add(m)
    }
    return out
}

// Maps Xray's user security to a cipher mihomo accepts.
internal fun vmessCipher(security: String): String = when (security.trim().lowercase()) {
    "aes-128-gcm" -> "aes-128-gcm"
    "chacha20-poly1305" -> "chacha20-poly1305"
    "none" -> "none"
    "zero" -> "zero"
    else -> "auto"
}

// --------------------------------------------------------------- Trojan ----

internal fun MihomoConv.convertTrojan(ob: JSONObject, preferred: String): List<YamlMap> {
    val settings = outboundSettings(ob)
    var servers = settings.xObjList("servers")
    if (servers.isEmpty() &&
        (settings.xStr("address").isNotEmpty() || settings.xStr("password").isNotEmpty())
    ) {
        servers = listOf(settings)
    }
    if (servers.isEmpty()) throw MihomoUnsupported("the trojan outbound has no server")

    val ss = ob.xObj("streamSettings")
    val out = ArrayList<YamlMap>(servers.size)
    for (sv in servers) {
        val address = sv.xStr("address")
        val port = sv.xInt("port")
        val name = name(preferred, ob.xStr("tag"), "trojan", address, port)
        val m = base(name, "trojan", address, port)
        val password = sv.xStrRaw("password")
        if (password.isEmpty()) throw MihomoUnsupported("the trojan outbound has no password")
        m.set("password", password)

        val flow = sv.xStr("flow")
        if (normaliseFlow(flow).isNotEmpty()) {
            // mihomo's trojan has no flow field at all.
            warn("trojan flow \"$flow\" has no mihomo equivalent and was dropped")
        }

        udpFlag(m)
        applyMux(m, ob, "trojan")
        applyTls(m, ss, TLS_TROJAN)
        applyTransport(m, ss, "trojan")
        applyDialer(m, ob)
        out.add(m)
    }
    return out
}

// ---------------------------------------------------------- Shadowsocks ----

internal fun MihomoConv.convertShadowsocks(ob: JSONObject, preferred: String): List<YamlMap> {
    val settings = outboundSettings(ob)
    var servers = settings.xObjList("servers")
    if (servers.isEmpty() &&
        (settings.xStr("address").isNotEmpty() || settings.xStr("password").isNotEmpty())
    ) {
        servers = listOf(settings)
    }
    if (servers.isEmpty()) throw MihomoUnsupported("the shadowsocks outbound has no server")

    val ss = ob.xObj("streamSettings")
    val out = ArrayList<YamlMap>(servers.size)
    for (sv in servers) {
        val address = sv.xStr("address")
        val port = sv.xInt("port")
        val name = name(preferred, ob.xStr("tag"), "ss", address, port)
        val m = base(name, "ss", address, port)
        val cipher = ssCipher(sv.xStr("method"))
        if (cipher.isEmpty()) {
            throw MihomoUnsupported("unsupported shadowsocks method \"${sv.xStr("method")}\"")
        }
        m.set("cipher", cipher)
        m.set("password", sv.xStrRaw("password"))
        udpFlag(m)
        if (sv.xBool("uot")) {
            m.set("udp-over-tcp", true)
            m.setInt("udp-over-tcp-version", sv.xInt("UoTVersion"))
        }

        // Shadowsocks in Xray ignores streamSettings, but generated configs
        // sometimes carry one anyway.
        if (ss != null && streamNetwork(ss) != "tcp") {
            warn("shadowsocks ignores streamSettings; the ${streamNetwork(ss)} transport was dropped")
        }
        applyDialer(m, ob)
        out.add(m)
    }
    return out
}

// The Shadowsocks methods mihomo implements, established by offering the core each name with a key of
// the right length (2022-blake3-aes-128-gcm looks unsupported until given a 16-byte key).
private val MIHOMO_SS_METHODS = setOf(
    "none",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ccm", "aes-192-ccm", "aes-256-ccm",
    "lea-128-gcm", "lea-192-gcm", "lea-256-gcm",
    "rc4-md5", "chacha20", "chacha20-ietf"
)

// The method under mihomo's spelling, or empty when it has none. An unknown name reaching the core is
// answered with "cipher: ... initialize error", which refuses the whole config file.
internal fun ssCipher(method: String): String = when (val m = method.trim().lowercase()) {
    "" -> ""
    "plain", "none" -> "none"
    "chacha20-poly1305", "chacha20-ietf-poly1305" -> "chacha20-ietf-poly1305"
    "xchacha20-poly1305", "xchacha20-ietf-poly1305" -> "xchacha20-ietf-poly1305"
    // AEAD, AEAD-2022 and the stream ciphers use the same names in both
    // projects - but only the ones mihomo actually has.
    else -> if (m in MIHOMO_SS_METHODS) m else ""
}

// ------------------------------------------------------- SOCKS and HTTP ----

private class ProxyEndpoint(
    val address: String,
    val port: Int,
    val user: String,
    val pass: String,
    val headers: Map<String, String>
)

private fun proxyEndpoints(s: JSONObject): List<ProxyEndpoint> {
    val out = ArrayList<ProxyEndpoint>()
    for (sv in s.xObjList("servers")) {
        var user = ""
        var pass = ""
        val users = sv.xObjList("users")
        if (users.isNotEmpty()) {
            user = users[0].xStrOf("user", "username")
            pass = users[0].xStrRawOf("pass", "password")
        }
        out.add(
            ProxyEndpoint(
                address = sv.xStr("address"),
                port = sv.xInt("port"),
                user = user,
                pass = pass,
                headers = sv.xHeaders("headers")
            )
        )
    }
    if (out.isEmpty() && s.xStr("address").isNotEmpty()) {
        out.add(
            ProxyEndpoint(
                address = s.xStr("address"),
                port = s.xInt("port"),
                user = s.xStr("user"),
                pass = s.xStrRaw("pass"),
                headers = emptyMap()
            )
        )
    }
    return out
}

internal fun MihomoConv.convertSocks(ob: JSONObject, preferred: String): List<YamlMap> {
    val settings = outboundSettings(ob)
    val endpoints = proxyEndpoints(settings)
    if (endpoints.isEmpty()) throw MihomoUnsupported("the socks outbound has no server")

    val ss = ob.xObj("streamSettings")
    val out = ArrayList<YamlMap>(endpoints.size)
    for (ep in endpoints) {
        val name = name(preferred, ob.xStr("tag"), "socks5", ep.address, ep.port)
        val m = base(name, "socks5", ep.address, ep.port)
        m.setStr("username", ep.user)
        m.setStr("password", ep.pass)
        udpFlag(m)
        if (ss != null && streamSecurity(ss) == "tls") {
            m.set("tls", true)
            val t = streamTls(ss)
            if (t != null && (t.xBool("allowInsecure") || opts.skipCertVerify)) {
                m.set("skip-cert-verify", true)
            }
        }
        applyDialer(m, ob)
        out.add(m)
    }
    return out
}

internal fun MihomoConv.convertHttp(ob: JSONObject, preferred: String): List<YamlMap> {
    val settings = outboundSettings(ob)
    val endpoints = proxyEndpoints(settings)
    if (endpoints.isEmpty()) throw MihomoUnsupported("the http outbound has no server")

    val ss = ob.xObj("streamSettings")
    val out = ArrayList<YamlMap>(endpoints.size)
    for (ep in endpoints) {
        val name = name(preferred, ob.xStr("tag"), "http", ep.address, ep.port)
        val m = base(name, "http", ep.address, ep.port)
        m.setStr("username", ep.user)
        m.setStr("password", ep.pass)
        if (ss != null && streamSecurity(ss) == "tls") {
            m.set("tls", true)
            val t = streamTls(ss)
            if (t != null) {
                m.setStr("sni", t.xStr("serverName"))
                if (t.xBool("allowInsecure") || opts.skipCertVerify) m.set("skip-cert-verify", true)
            }
        }
        if (ep.headers.isNotEmpty()) {
            val headers = YamlMap()
            for (k in ep.headers.keys.sorted()) headers.setStr(k, ep.headers[k])
            m.set("headers", headers)
        }
        applyDialer(m, ob)
        out.add(m)
    }
    return out
}

// ------------------------------------------------------------ WireGuard ----

internal fun MihomoConv.convertWireGuard(ob: JSONObject, preferred: String): List<YamlMap> {
    val settings = outboundSettings(ob)
    val peers = settings.xObjList("peers")
    if (peers.isEmpty()) throw MihomoUnsupported("the wireguard outbound has no peers")
    val secret = settings.xStr("secretKey")
    if (secret.isEmpty()) throw MihomoUnsupported("the wireguard outbound has no secretKey")

    // mihomo takes the first peer's endpoint as the proxy address and carries
    // any further peers in a "peers" list.
    val primary = peers[0]
    val endpoint = splitEndpoint(primary.xStr("endpoint"))
        ?: throw MihomoUnsupported("peer endpoint \"${primary.xStr("endpoint")}\" is not host:port")

    val name = name(preferred, ob.xStr("tag"), "wireguard", endpoint.first, endpoint.second)
    val m = base(name, "wireguard", endpoint.first, endpoint.second)
    m.set("private-key", secret)
    m.setStr("public-key", primary.xStr("publicKey"))
    m.setStr("pre-shared-key", primary.xStr("preSharedKey"))

    for (raw in settings.xStrList("address")) {
        var a = raw.trim()
        if (a.isEmpty()) continue
        // mihomo wants the bare interface address, not a CIDR.
        val slash = a.indexOf('/')
        if (slash >= 0) a = a.substring(0, slash)
        if (a.contains(":")) {
            if (!m.has("ipv6")) m.set("ipv6", a)
        } else if (!m.has("ip")) {
            m.set("ip", a)
        }
    }

    val allowed = primary.xStrList("allowedIPs")
    if (allowed.isNotEmpty()) m.set("allowed-ips", toFlowSeq(allowed))
    m.setInt("mtu", settings.xInt("mtu"))
    m.setInt("persistent-keepalive", primary.xInt("keepAlive"))
    val reserved = parseReserved(settings.xOpt("reserved"))
    if (reserved != null && reserved.isNotEmpty()) {
        if (reserved.size == WG_RESERVED_BYTES) {
            val seq = YamlFlowSeq()
            for (b in reserved) seq.add(b.toInt() and 0xFF)
            m.set("reserved", seq)
        } else {
            // The core wants exactly three bytes and refuses the whole config file otherwise
            // ("invalid reserved value, required 3 bytes, got N"), so a hand-edited four-byte value
            warn(
                "wireguard reserved is ${reserved.size} bytes and mihomo wants " +
                    "$WG_RESERVED_BYTES, so it was dropped"
            )
        }
    }
    udpFlag(m)

    if (peers.size > 1) {
        val list = YamlSeq()
        for (p in peers) {
            val pe = splitEndpoint(p.xStr("endpoint"))
            if (pe == null) {
                warn("wireguard peer with endpoint \"${p.xStr("endpoint")}\" was dropped: not host:port")
                continue
            }
            val pm = YamlMap()
            pm.set("server", pe.first)
            pm.set("port", pe.second)
            pm.setStr("public-key", p.xStr("publicKey"))
            pm.setStr("pre-shared-key", p.xStr("preSharedKey"))
            val pAllowed = p.xStrList("allowedIPs")
            if (pAllowed.isNotEmpty()) pm.set("allowed-ips", toFlowSeq(pAllowed))
            list.add(pm)
        }
        if (list.size > 1) m.set("peers", list)
    }

    applyDialer(m, ob)
    return listOf(m)
}

// WireGuard's reserved field is three bytes; the core refuses any other length.
internal const val WG_RESERVED_BYTES = 3

// Accepts the reserved bytes as a JSON array or a base64 string.
internal fun parseReserved(raw: Any?): ByteArray? {
    if (raw == null) return null
    if (raw is JSONArray) {
        val out = ByteArray(raw.length())
        for (i in 0 until raw.length()) {
            val n = raw.opt(i) as? Number ?: return null
            out[i] = n.toInt().toByte()
        }
        return out
    }
    val s = xScalarString(raw).trim()
    if (s.isEmpty()) return null
    return decodeBase64Any(s)
}

// Splits a "host:port" endpoint, handling a bracketed IPv6 literal.
internal fun splitEndpoint(endpoint: String): Pair<String, Int>? {
    val trimmed = endpoint.trim()
    if (trimmed.isEmpty()) return null
    val hp = splitHostPort(trimmed) ?: return null
    val port = parsePort(hp.second) ?: return null
    return hp.first to port
}
