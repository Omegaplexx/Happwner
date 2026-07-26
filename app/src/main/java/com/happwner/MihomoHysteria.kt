package com.happwner

import org.json.JSONObject

/**
 * A Hysteria2 node reaches this converter in two shapes.
 *
 * Xray writes one natively: the "hysteria" outbound protocol holds nothing but
 * the address and port, while the password and everything else live in
 * streamSettings -- "hysteriaSettings" for the credential, "finalmask" for the
 * QUIC parameters and the obfuscator. Configuration sets that mix protocols
 * carry the other shape, written the way the Hysteria2 client or a sing-box
 * style generator writes it, with every field inside "settings".
 *
 * Both describe the same server, and both become a mihomo hysteria2 proxy.
 */

/**
 * Gathers the settings of a Hysteria2 node from wherever the configuration
 * happens to put them. Values found in the outbound's own settings win, since a
 * generator that filled those meant them.
 */
private class HysteriaParams(
    var password: String = "",
    var up: String = "",
    var down: String = "",
    var ports: String = "",
    var hopInterval: String = "",
    var obfs: String = "",
    var obfsPassword: String = "",
    var obfsMinSize: Int = 0,
    var obfsMaxSize: Int = 0,
    var bbrProfile: String = "",
    var initStreamWindow: Long = 0,
    var maxStreamWindow: Long = 0,
    var initConnectionWindow: Long = 0,
    var maxConnectionWindow: Long = 0
)

/**
 * Reads the parts of a Hysteria2 node that Xray keeps in streamSettings, which
 * is where a natively written config puts the password.
 */
private fun HysteriaParams.fromStream(conv: MihomoConv, ss: JSONObject?) {
    if (ss == null) return

    val h = ss.xObj("hysteriaSettings")
    if (h != null) {
        password = firstNonEmpty(password, h.xStr("auth"))
        up = firstNonEmpty(up, h.xStr("up"))
        down = firstNonEmpty(down, h.xStr("down"))
        val hop = h.xObj("udphop")
        if (hop != null) {
            ports = firstNonEmpty(ports, hop.xPortList("ports"))
            hopInterval = firstNonEmpty(hopInterval, hop.xRange("interval").render())
        }
        if (h.xInt("udpIdleTimeout") != 0) {
            conv.warn("hysteriaSettings.udpIdleTimeout has no mihomo equivalent and was dropped")
        }
    }

    // Newer Xray builds moved the bandwidth, port hopping and QUIC window
    // settings out of hysteriaSettings and into finalmask.
    val q = streamQuicParams(ss)
    if (q != null) {
        up = firstNonEmpty(up, q.xStr("brutalUp"))
        down = firstNonEmpty(down, q.xStr("brutalDown"))
        bbrProfile = firstNonEmpty(bbrProfile, q.xStr("bbrProfile"))
        val hop = q.xObj("udpHop")
        if (hop != null) {
            ports = firstNonEmpty(ports, hop.xPortList("ports"))
            hopInterval = firstNonEmpty(hopInterval, hop.xRange("interval").render())
        }
        initStreamWindow = q.xLong("initStreamReceiveWindow")
        maxStreamWindow = q.xLong("maxStreamReceiveWindow")
        initConnectionWindow = q.xLong("initConnectionReceiveWindow")
        maxConnectionWindow = q.xLong("maxConnectionReceiveWindow")

        // mihomo uses Brutal when a rate is given and BBR otherwise, which is
        // what the congestion field selects here, so it needs no mapping.
        val congestion = q.xStr("congestion")
        when (congestion.lowercase()) {
            "", "bbr", "brutal" -> {}
            else -> conv.warn(
                "quicParams.congestion \"$congestion\" has no mihomo equivalent; " +
                    "mihomo uses Brutal when a rate is set and BBR otherwise"
            )
        }
    }

    // The Hysteria obfuscator is a finalmask UDP mask.
    val mask = streamUdpMask(ss, "salamander")
    if (mask != null && obfs.isEmpty()) {
        val settings = mask.xObj("settings")
        obfsPassword = firstNonEmpty(obfsPassword, settings.xStr("password"))
        val packetSize = settings.xRange("packetSize")
        if (packetSize.set && packetSize.to > 0) {
            // A packet size range selects the gecko variant of the obfuscator.
            obfs = "gecko"
            obfsMinSize = packetSize.from
            obfsMaxSize = packetSize.to
        } else {
            obfs = "salamander"
        }
    }
}

/** A resolved Hysteria server. */
private class HysteriaEndpoint(
    val address: String,
    val port: Int,
    val ports: String,
    val password: String,
    val up: String,
    val down: String
)

/**
 * Resolves the server list of a Hysteria settings object, falling back to the
 * flat form.
 */
private fun hysteriaEndpoints(s: JSONObject): List<HysteriaEndpoint> {
    val flatPassword = firstNonEmpty(
        s.xStr("password"), s.xStr("auth"), s.xStr("auth_str"), s.xStr("authStr")
    )
    val (flatUp, flatDown) = hysteriaBandwidth(s)

    val out = ArrayList<HysteriaEndpoint>()
    for (sv in s.xObjList("servers")) {
        out.add(
            HysteriaEndpoint(
                address = firstNonEmpty(sv.xStr("address"), sv.xStr("server")),
                port = sv.xInt("port"),
                ports = sv.xStr("ports"),
                password = firstNonEmpty(
                    sv.xStr("password"), sv.xStr("auth"), sv.xStr("auth_str"), flatPassword
                ),
                up = firstNonEmpty(sv.xStr("up"), mbpsString(sv.xInt("upMbps")), flatUp),
                down = firstNonEmpty(sv.xStr("down"), mbpsString(sv.xInt("downMbps")), flatDown)
            )
        )
    }
    if (out.isEmpty()) {
        var address = firstNonEmpty(s.xStr("address"), s.xStr("server"))
        var port = s.xInt("port")
        // A "host:port" address is common in Hysteria2-style configs.
        if (port == 0) {
            val hp = splitHostPort(address)
            val parsed = hp?.let { parsePort(it.second) }
            if (hp != null && parsed != null) {
                address = hp.first
                port = parsed
            }
        }
        out.add(
            HysteriaEndpoint(
                address = address,
                port = port,
                ports = s.xStr("ports"),
                password = flatPassword,
                up = flatUp,
                down = flatDown
            )
        )
    }
    return out
}

/**
 * Resolves the up/down rates from any of the spellings the Hysteria clients
 * accept.
 */
private fun hysteriaBandwidth(s: JSONObject): Pair<String, String> {
    var up = s.xStr("up")
    var down = s.xStr("down")
    val bandwidth = s.xObj("bandwidth")
    if (bandwidth != null) {
        up = firstNonEmpty(up, bandwidth.xStr("up"))
        down = firstNonEmpty(down, bandwidth.xStr("down"))
    }
    up = firstNonEmpty(up, mbpsString(s.xInt("upMbps")))
    down = firstNonEmpty(down, mbpsString(s.xInt("downMbps")))
    return up to down
}

private fun mbpsString(v: Int): String = if (v <= 0) "" else "$v Mbps"

/**
 * Renders a rate the way mihomo expects. A bare number is megabits per second
 * there, so a unit-less value gets the unit spelled out.
 */
internal fun normaliseBandwidth(raw: String): String {
    val v = raw.trim()
    if (v.isEmpty()) return ""
    if (v.toDoubleOrNull() != null) return "$v Mbps"
    return v
}

/**
 * Returns the obfuscation mode and password, accepting both the string form
 * ("salamander") and the object form used by the Hysteria2 client.
 */
private fun parsedObfs(s: JSONObject): Pair<String, String> {
    var password = firstNonEmpty(s.xStr("obfsPassword"), s.xStr("obfs-password"))
    val obfs = s.xOpt("obfs") ?: return "" to password
    if (obfs is JSONObject) {
        val mode = obfs.xStr("type")
        val salamander = obfs.xObj("salamander")
        if (salamander != null && salamander.xStr("password").isNotEmpty()) {
            password = salamander.xStr("password")
        } else if (obfs.xStr("password").isNotEmpty()) {
            password = obfs.xStr("password")
        }
        return mode to password
    }
    return xScalarString(obfs).trim() to password
}

/** Returns the port-hopping interval in seconds. */
private fun hysteriaHopInterval(s: JSONObject): String {
    val v = s.xStr("hopInterval")
    // Hysteria2 writes durations as "30s"; mihomo takes plain seconds.
    if (v.isNotEmpty()) return v.removeSuffix("s")
    val alt = s.xInt("hop_interval")
    if (alt > 0) return alt.toString()
    return ""
}

private class HysteriaTls(val sni: String, val insecure: Boolean, val alpn: List<String>)

/**
 * Resolves the TLS parameters, which may live in the settings object or in
 * streamSettings depending on which tool wrote the config.
 */
private fun hysteriaTls(s: JSONObject, ss: JSONObject?): HysteriaTls {
    var sni = ""
    var insecure = false
    var alpn: List<String> = emptyList()

    val tls = s.xObj("tls")
    if (tls != null) {
        sni = firstNonEmpty(tls.xStr("sni"), tls.xStr("serverName"))
        insecure = tls.xBool("insecure")
        alpn = tls.xStrList("alpn")
    }
    sni = firstNonEmpty(sni, s.xStr("sni"))
    if (s.xBool("insecure")) insecure = true
    if (alpn.isEmpty()) alpn = s.xStrList("alpn")

    val t = streamTls(ss)
    if (t != null) {
        sni = firstNonEmpty(sni, t.xStr("serverName"))
        if (t.xBool("allowInsecure")) insecure = true
        if (alpn.isEmpty()) alpn = t.xStrList("alpn")
    }
    return HysteriaTls(sni, insecure, alpn)
}

/** Returns the first port of a "443-8443,9000" style list. */
private fun firstPortOfRange(ports: String): Int? {
    for (raw in ports.split(",")) {
        var part = raw.trim()
        if (part.isEmpty()) continue
        val dash = part.indexOf('-')
        if (dash > 0) part = part.substring(0, dash)
        parsePort(part)?.let { return it }
    }
    return null
}

internal fun MihomoConv.convertHysteria2(ob: JSONObject, preferred: String): List<YamlMap> {
    val settings = outboundSettings(ob)
    val ss = ob.xObj("streamSettings")

    val (obfsMode, obfsPassword) = parsedObfs(settings)
    val tls = hysteriaTls(settings, ss)

    val out = ArrayList<YamlMap>()
    for (ep in hysteriaEndpoints(settings)) {
        // Anything the outbound's own settings did not supply comes from
        // streamSettings, which is where Xray itself keeps it.
        val params = HysteriaParams(
            password = ep.password,
            up = ep.up,
            down = ep.down,
            ports = ep.ports,
            hopInterval = hysteriaHopInterval(settings),
            obfs = obfsMode,
            obfsPassword = obfsPassword
        )
        params.fromStream(this, ss)

        var port = ep.port
        if (port == 0 && params.ports.isNotEmpty()) {
            // Port hopping without a base port: use the low end of the range so
            // mihomo has something to dial before it starts hopping.
            firstPortOfRange(params.ports)?.let { port = it }
        }
        val name = name(preferred, ob.xStr("tag"), "hysteria2", ep.address, port)
        val m = base(name, "hysteria2", ep.address, port)
        m.setStr("ports", params.ports)
        if (params.password.isEmpty()) {
            throw MihomoUnsupported(
                "the hysteria2 outbound has no password " +
                    "(Xray keeps it in streamSettings.hysteriaSettings.auth)"
            )
        }
        m.set("password", params.password)

        when {
            params.obfs.isNotEmpty() -> {
                m.set("obfs", params.obfs)
                m.setStr("obfs-password", params.obfsPassword)
                m.setInt("obfs-min-packet-size", params.obfsMinSize)
                m.setInt("obfs-max-packet-size", params.obfsMaxSize)
            }
            params.obfsPassword.isNotEmpty() -> {
                // A password without a type means Salamander, the only
                // obfuscator Hysteria2 shipped for a long time.
                m.set("obfs", "salamander")
                m.set("obfs-password", params.obfsPassword)
            }
        }

        m.setStr("up", normaliseBandwidth(params.up))
        m.setStr("down", normaliseBandwidth(params.down))

        if (params.hopInterval.isNotEmpty()) m.set("hop-interval", params.hopInterval)
        m.setStr("sni", tls.sni)
        if (tls.alpn.isNotEmpty()) m.set("alpn", toFlowSeq(tls.alpn))
        if (tls.insecure || opts.skipCertVerify) m.set("skip-cert-verify", true)

        settings.xObj("tls")?.let { applyCertPin(m, it.xStr("pinSHA256")) }
        val t = streamTls(ss)
        if (t != null) {
            applyCertPin(m, t.xStr("pinnedPeerCertSha256"))
            applyCertificates(m, t)
            val fp = t.xStr("fingerprint")
            if (fp.isNotEmpty()) {
                // Hysteria2 is QUIC, so there is no TLS ClientHello for a uTLS
                // profile to shape and mihomo offers no field for one.
                warn("the uTLS fingerprint \"$fp\" does not apply to a QUIC protocol and was dropped")
            }
        }
        m.setStr("bbr-profile", params.bbrProfile)
        m.setInt("cwnd", settings.xInt("cwnd"))
        m.setInt("udp-mtu", settings.xInt("udpMTU"))
        if (params.initStreamWindow > 0) m.set("initial-stream-receive-window", params.initStreamWindow)
        if (params.maxStreamWindow > 0) m.set("max-stream-receive-window", params.maxStreamWindow)
        if (params.initConnectionWindow > 0) {
            m.set("initial-connection-receive-window", params.initConnectionWindow)
        }
        if (params.maxConnectionWindow > 0) {
            m.set("max-connection-receive-window", params.maxConnectionWindow)
        }
        udpFlag(m)
        applyDialer(m, ob)
        out.add(m)
    }
    return out
}

/**
 * Reports whether a "hysteria" outbound is version 2.
 *
 * The version may be stated in the outbound settings, in hysteriaSettings, or
 * implied by Xray's hysteria transport, whose outbound protocol only ever
 * speaks version 2.
 */
private fun isHysteria2(s: JSONObject, ss: JSONObject?): Boolean {
    if (s.xInt("version") == 2) return true
    if (ss == null) return false
    if (ss.xObj("hysteriaSettings").xInt("version") == 2) return true
    return streamNetwork(ss) == "hysteria"
}

/** Handles a "hysteria" outbound, which may be either version. */
internal fun MihomoConv.convertHysteria(ob: JSONObject, preferred: String): List<YamlMap> {
    val settings = outboundSettings(ob)
    val ss = ob.xObj("streamSettings")
    if (isHysteria2(settings, ss)) return convertHysteria2(ob, preferred)

    val (obfsMode, obfsPassword) = parsedObfs(settings)
    val tls = hysteriaTls(settings, ss)

    val out = ArrayList<YamlMap>()
    for (ep in hysteriaEndpoints(settings)) {
        val name = name(preferred, ob.xStr("tag"), "hysteria", ep.address, ep.port)
        val m = base(name, "hysteria", ep.address, ep.port)
        // Hysteria v1 authenticates with a plain string.
        m.setStr("auth-str", ep.password)
        // Version 1 requires both rates; mihomo refuses the node without them.
        val up = normaliseBandwidth(ep.up)
        val down = normaliseBandwidth(ep.down)
        if (up.isEmpty() || down.isEmpty()) {
            throw MihomoUnsupported("hysteria v1 needs both up and down rates")
        }
        m.set("up", up)
        m.set("down", down)

        if (obfsPassword.isNotEmpty()) {
            m.set("obfs", obfsPassword)
        } else if (obfsMode.isNotEmpty()) {
            m.set("obfs", obfsMode)
        }
        m.setStr("sni", tls.sni)
        if (tls.alpn.isNotEmpty()) m.set("alpn", toFlowSeq(tls.alpn))
        if (tls.insecure || opts.skipCertVerify) m.set("skip-cert-verify", true)
        m.setStr("ports", ep.ports)
        udpFlag(m)
        applyDialer(m, ob)
        out.add(m)
    }
    return out
}

// ------------------------------------------------------------------ TUIC ----

private class TuicEndpoint(
    val address: String,
    val port: Int,
    val uuid: String,
    val password: String,
    val token: String
)

/** Handles standalone TUIC nodes. */
internal fun MihomoConv.convertTuic(ob: JSONObject, preferred: String): List<YamlMap> {
    val settings = outboundSettings(ob)
    val ss = ob.xObj("streamSettings")

    val endpoints = ArrayList<TuicEndpoint>()
    for (sv in settings.xObjList("servers")) {
        endpoints.add(
            TuicEndpoint(
                address = firstNonEmpty(sv.xStr("address"), sv.xStr("server")),
                port = sv.xInt("port"),
                uuid = sv.xStr("uuid"),
                password = sv.xStr("password"),
                token = sv.xStr("token")
            )
        )
    }
    if (endpoints.isEmpty()) {
        endpoints.add(
            TuicEndpoint(
                address = firstNonEmpty(settings.xStr("address"), settings.xStr("server")),
                port = settings.xInt("port"),
                uuid = settings.xStr("uuid"),
                password = settings.xStr("password"),
                token = settings.xStr("token")
            )
        )
    }

    val out = ArrayList<YamlMap>(endpoints.size)
    for (ep in endpoints) {
        val name = name(preferred, ob.xStr("tag"), "tuic", ep.address, ep.port)
        val m = base(name, "tuic", ep.address, ep.port)
        when {
            ep.uuid.isNotEmpty() -> {
                m.set("uuid", ep.uuid)
                m.setStr("password", ep.password)
            }
            // TUIC v4 authenticates with a token instead of a uuid/password.
            ep.token.isNotEmpty() -> m.set("token", ep.token)
            else -> throw MihomoUnsupported("the tuic outbound has neither a uuid nor a token")
        }

        var sni = settings.xStr("sni")
        var insecure = settings.xBool("insecure")
        var alpn = settings.xStrList("alpn")
        val t = streamTls(ss)
        if (t != null) {
            sni = firstNonEmpty(sni, t.xStr("serverName"))
            if (t.xBool("allowInsecure")) insecure = true
            if (alpn.isEmpty()) alpn = t.xStrList("alpn")
        }
        m.setStr("sni", sni)
        if (alpn.isNotEmpty()) m.set("alpn", toFlowSeq(alpn))
        if (insecure || opts.skipCertVerify) m.set("skip-cert-verify", true)
        m.setStr(
            "congestion-controller",
            firstNonEmpty(settings.xStr("congestion_control"), settings.xStr("congestionController"))
        )
        m.setStr(
            "udp-relay-mode",
            firstNonEmpty(settings.xStr("udp_relay_mode"), settings.xStr("udpRelayMode"))
        )
        if (settings.xBool("reduce_rtt") || settings.xBool("reduceRtt")) m.set("reduce-rtt", true)
        m.setInt("heartbeat-interval", settings.xInt("heartbeat_interval"))
        if (settings.xBool("disable_sni")) m.set("disable-sni", true)
        udpFlag(m)
        applyDialer(m, ob)
        out.add(m)
    }
    return out
}
