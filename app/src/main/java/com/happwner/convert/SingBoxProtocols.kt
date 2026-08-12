package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// The proxy protocols, plus the auxiliary freedom/blackhole/dns outbounds; the QUIC-based three are
// built in SingBoxHysteria. normalizeFlow is NOT the mihomo converter's normaliseFlow.
internal object SingBoxProtocols {
    internal val XRAY_PROTOCOLS_PROXY = setOf(
        "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard",
        // Xray-core has no outbound of these three, but panels and generators write them in Xray-
        // shaped configurations anyway, and sing-box implements all of them natively.
        "hysteria2", "hysteria", "tuic"
    )

    // The three handled by SingBoxHysteria rather than by the mapping below.
    private val QUIC_PROTOCOLS = setOf("hysteria2", "hysteria", "tuic")

    internal val XRAY_PROTOCOLS_AUX = setOf("freedom", "blackhole", "dns", "loopback")

    internal val VLESS_FLOW_OK = setOf("", "xtls-rprx-vision")

    internal val VLESS_FLOW_MAP = mapOf("xtls-rprx-vision-udp443" to "xtls-rprx-vision")

    internal val VMESS_SECURITY_OK = setOf(
        "auto", "none", "zero", "aes-128-gcm",
        "chacha20-poly1305", "aes-128-ctr"
    )

    internal val SS_METHODS_OK = setOf(
        "none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
        "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
        "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
        "rc4-md5", "chacha20-ietf", "xchacha20"
    )

    internal val SS_METHOD_ALIAS = mapOf(
        "chacha20-poly1305" to "chacha20-ietf-poly1305",
        "xchacha20-poly1305" to "xchacha20-ietf-poly1305",
        "plain" to "none"
    )

    internal val SS_PLUGINS_OK = setOf("", "obfs-local", "v2ray-plugin")

    // Deliberately NOT the same as the mihomo converter's normaliseFlow(): that one strips
    // "-udp443" from any flow, this one maps only the vision variant.
    internal fun normalizeFlow(flow: String?): String {
        val f = flow?.trim().orEmpty()
        if (f.isEmpty() || f == "none") return ""
        return VLESS_FLOW_MAP[f] ?: f
    }

    internal fun serializePluginOpts(opts: Any?): String {
        if (opts == null || opts === JSONObject.NULL) return ""
        if (opts is String) return opts
        if (opts is JSONObject) {
            val parts = mutableListOf<String>()
            val keys = opts.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                val v = opts.opt(k)
                if (v is Boolean) {
                    parts.add(if (v) k else "$k=0")
                } else {
                    parts.add("$k=$v")
                }
            }
            return parts.joinToString(";")
        }
        return ""
    }

    // Whether an outbound is supported (protocol/transport/security/flow/method), with the specific
    // reason instead of a bare false.
    internal fun unsupportedReason(o: JSONObject): String? {
        val proto = o.xStr("protocol")
        if (proto !in XRAY_PROTOCOLS_PROXY && proto !in XRAY_PROTOCOLS_AUX) {
            return if (proto.isEmpty()) "no protocol specified" else "unknown or unimplemented protocol \"$proto\""
        }
        if (proto in XRAY_PROTOCOLS_AUX || proto == "wireguard") return null
        // The QUIC-based three carry their own parameters, and their
        // streamSettings hold TLS and nothing the transport check applies to.
        if (proto in QUIC_PROTOCOLS) return null
        val stream = o.optJSONObject("streamSettings") ?: JSONObject()
        val net = stream.xStr("network").ifEmpty { "tcp" }
        if (net !in SingBoxStream.XRAY_TRANSPORTS_OK) return "transport \"$net\" has no sing-box equivalent"
        if (net == "tcp" || net == "raw") {
            val ts = stream.optJSONObject("tcpSettings") ?: stream.optJSONObject("rawSettings")
            val hdrType = ts.xObj("header").xStr("type").ifEmpty { "none" }
            if (hdrType != "none" && hdrType != "http") {
                return "tcp header type \"$hdrType\" is not supported (only the http masquerade is)"
            }
        }
        if (net == "quic") {
            val qs = stream.optJSONObject("quicSettings") ?: JSONObject()
            val qsec = qs.xStr("security").lowercase().ifEmpty { "none" }
            if (qsec != "none" && qsec != "") return "quic transport security \"$qsec\" is not supported"
            val qhdr = qs.xObj("header").xStr("type").lowercase().ifEmpty { "none" }
            if (qhdr != "none" && qhdr != "") return "quic transport header \"$qhdr\" is not supported"
            // sing-box's QUIC transport is TLS-only and refuses the whole config at load without one. Measured
            // against 1.13.15: tls and reality load, none does not - Xray allows the combination, so it arrives.
            val streamSec = stream.xStr("security").lowercase().ifEmpty { "none" }
            if (streamSec != "tls" && streamSec != "reality") {
                return "quic transport needs TLS in sing-box, and this one has security \"$streamSec\""
            }
        }
        // The empty string is in XRAY_SECURITY_OK: an absent security field is
        // plain TCP, which converts fine. Nothing reaches here with sec empty.
        val sec = stream.xStr("security")
        if (sec !in SingBoxStream.XRAY_SECURITY_OK) {
            return "security \"$sec\" has no sing-box equivalent"
        }
        if (proto == "vless") {
            val user = firstUser(o)
            val flowRaw = user.xStr("flow")
            val flow = normalizeFlow(flowRaw)
            if (flow !in VLESS_FLOW_OK) return "vless flow \"$flowRaw\" has no sing-box equivalent"
            val enc = user.xStr("encryption")
            if (enc.isNotEmpty() && enc != "none") return "vless encryption \"$enc\" is not supported (only \"none\" is)"
        }
        if (proto == "vmess") {
            val user = firstUser(o)
            val vsec = user.xStr("security").ifEmpty { "auto" }
            if (vsec !in VMESS_SECURITY_OK) return "vmess security \"$vsec\" has no sing-box equivalent"
        }
        if (proto == "shadowsocks") {
            val srv = firstServer(o)
            // An absent method is Xray's own default.
            val rawMethod = if (srv.xHas("method")) srv.xStr("method") else "aes-256-gcm"
            if (rawMethod.isEmpty()) return "shadowsocks method is empty"
            val method = SS_METHOD_ALIAS[rawMethod] ?: rawMethod
            if (method !in SS_METHODS_OK) return "shadowsocks method \"$rawMethod\" has no sing-box equivalent"
            val plugin = srv.xStr("plugin")
            if (plugin.isNotEmpty() && plugin !in SS_PLUGINS_OK) return "shadowsocks plugin \"$plugin\" has no sing-box equivalent"
        }
        return null
    }

    internal fun isOutboundSupported(o: JSONObject): Boolean = unsupportedReason(o) == null

    internal fun firstUser(o: JSONObject): JSONObject? {
        val settings = o.optJSONObject("settings") ?: return null
        val vnext = settings.optJSONArray("vnext") ?: return null
        val first = vnext.optJSONObject(0) ?: return null
        val users = first.optJSONArray("users") ?: return null
        return users.optJSONObject(0)
    }

    internal fun firstServer(o: JSONObject): JSONObject? {
        val settings = o.optJSONObject("settings") ?: return null
        val servers = settings.optJSONArray("servers") ?: return null
        return servers.optJSONObject(0)
    }

    // packetEncoding (xudp/packetaddr), protocol-aware
    internal fun convPacketEncoding(o: JSONObject, proto: String): String? {
        val settings = o.optJSONObject("settings") ?: JSONObject()
        var v: Any? = settings.opt("packetEncoding")
        if (v == null || v === JSONObject.NULL) {
            val vnext = settings.optJSONArray("vnext")?.optJSONObject(0)
            val user = vnext?.optJSONArray("users")?.optJSONObject(0)
            v = user?.opt("packetEncoding")
        }
        if (v == null || v === JSONObject.NULL) return null
        val s = v.toString().lowercase()
        return when (s) {
            "packet" -> "packetaddr"
            "xudp" -> if (proto == "vless") null else "xudp"
            "none", "" -> if (proto == "vless") "" else null
            else -> null
        }
    }

    internal fun applyProxySettings(sb: JSONObject, o: JSONObject) {
        var chainTag = o.optJSONObject("proxySettings")?.optString("tag", "") ?: ""
        if (chainTag.isEmpty()) {
            val ss = o.optJSONObject("streamSettings") ?: JSONObject()
            chainTag = ss.optString("dialerProxy", "")
            if (chainTag.isEmpty()) {
                chainTag = ss.optJSONObject("sockopt")?.optString("dialerProxy", "") ?: ""
            }
        }
        if (chainTag.isNotEmpty()) sb.put("detour", chainTag)
    }

    internal val FREEDOM_STRATEGY_MAP = mapOf(
        "AsIs" to "",
        "UseIP" to "prefer_ipv4",
        "UseIPv4" to "ipv4_only",
        "UseIPv4v6" to "prefer_ipv4",
        "UseIPv6" to "ipv6_only",
        "UseIPv6v4" to "prefer_ipv6",
        "ForceIP" to "prefer_ipv4",
        "ForceIPv4" to "ipv4_only",
        "ForceIPv4v6" to "prefer_ipv4",
        "ForceIPv6" to "ipv6_only",
        "ForceIPv6v4" to "prefer_ipv6"
    )

    // Maps Xray's sockopt onto the dial fields. dnsResolverTag names a DNS server the finished
    // document is known to carry.
    internal fun applySockopt(
        sb: JSONObject,
        stream: JSONObject?,
        dnsResolverTag: String? = null,
        notes: MutableList<String>? = null
    ) {
        val sock = stream?.optJSONObject("sockopt") ?: return
        val ds = sock.optString("domainStrategy", "").trim()
        val strat = FREEDOM_STRATEGY_MAP[ds] ?: ""
        if (strat.isNotEmpty() && !sb.has("domain_resolver") && dnsResolverTag != null) {
            val resolver = JSONObject()
            resolver.put("server", dnsResolverTag)
            resolver.put("strategy", strat)
            sb.put("domain_resolver", resolver)
        }
        val tfo = sock.opt("tcpFastOpen")
        if (tfo is Boolean) sb.put("tcp_fast_open", tfo)
        // sing-box has tcp_keep_alive and its two companions only since 1.13.0, and an unknown
        // field stops a configuration loading, so writing them would break every 1.12 core.
        if (sock.xAsksForKeepAlive()) {
            notes?.add(
                "sockopt.tcpKeepAliveIdle / tcpKeepAliveInterval were not carried: sing-box has " +
                    "these fields only since 1.13, and writing them would stop a 1.12 core loading " +
                    "the configuration"
            )
        }

        // SO_MARK, SO_BINDTODEVICE and MPTCP are kernel-side options neither end negotiates, so they carry
        // over safely. Checked against 1.13.15: routing_mark refuses a negative, tcp_multi_path a non-boolean.
        val markRaw = sock.opt("mark")
        if (markRaw is Number) {
            val mark = markRaw.toLong()
            if (mark > 0L && mark <= 0xFFFFFFFFL) sb.put("routing_mark", mark)
        }

        val iface = sock.optString("interface", "").trim()
        if (iface.isNotEmpty()) sb.put("bind_interface", iface)

        val mptcp = sock.opt("tcpMptcp")
        if (mptcp is Boolean && mptcp) sb.put("tcp_multi_path", true)

        // The rest of sockopt has nowhere to go.
        if (notes != null) {
            for ((key, why) in SOCKOPT_WITHOUT_EQUIVALENT) {
                if (SingBoxUtil.isTruthy(sock.opt(key))) notes.add("sockopt.$key $why")
            }
        }
    }

    // The tail every proxy outbound shares: options that hang off the outbound rather than the
    // protocol.
    private fun finishProxy(
        sb: JSONObject,
        o: JSONObject,
        stream: JSONObject?,
        dnsResolverTag: String?,
        notes: MutableList<String>
    ): OutboundResult {
        applyProxySettings(sb, o)
        applySockopt(sb, stream, dnsResolverTag, notes)
        applyMux(sb, o, notes)
        applySendThrough(sb, o, notes)
        return OutboundResult(sb, "proxy", notes)
    }

    // Reports Xray's mux rather than translating it: mux.cool and smux/yamux/h2mux are different
    // protocols. Verified against Xray 26.3.27 - the node carries traffic without the block and none with it.
    internal fun applyMux(sb: JSONObject, o: JSONObject, notes: MutableList<String>?) {
        val mux = o.optJSONObject("mux") ?: return
        if (!SingBoxUtil.isTruthy(mux.opt("enabled"))) return
        notes?.add(
            "mux is Xray's own multiplexer (mux.cool) and sing-box implements a different one, " +
                "so it was left out; the node connects without multiplexing"
        )
    }

    // Xray's sendThrough is the local address an outbound leaves from, which sing-box spells
    // inet4_bind_address or inet6_bind_address in its dial fields, one per address family.
    internal fun applySendThrough(sb: JSONObject, o: JSONObject, notes: MutableList<String>?) {
        if (!o.xBindsLocalAddress()) return
        val addr = o.xStr("sendThrough")
        when {
            SingBoxUtil.parseInet4(addr) -> sb.put("inet4_bind_address", addr)
            SingBoxUtil.parseInet6(addr) -> sb.put("inet6_bind_address", addr)
            // Xray resolves a name here; sing-box takes an address, and guessing which one it
            // would have picked is not something this can do for somebody else's machine.
            else -> notes?.add(
                "sendThrough \"$addr\" is not an IP address, and sing-box binds to an address " +
                    "rather than a name, so it was dropped"
            )
        }
    }

    // sockopt options sing-box has no field for, and why. Checked against 1.13.15 by offering the
    // core each name and seeing `unknown field`.
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
        // deprecated"; the choice now lives in the route's default_domain_resolver, which the DNS
        "domainStrategy" to "is set for the whole route rather than per outbound, " +
            "so the route's resolver strategy decides instead"
    )

    // notes carries what the conversion had to drop, for the caller to report alongside the ones it
    // produces itself.
    internal data class OutboundResult(
        val sb: JSONObject?,
        val kind: String?,
        val notes: List<String> = emptyList()
    )

    // One Xray outbound to one sing-box outbound
    internal fun convOutbound(o: JSONObject, dnsResolverTag: String? = null): OutboundResult {
        val proto = o.xStr("protocol")
        val tag = o.optString("tag", proto)
        // One list for the whole conversion: applySockopt and the QUIC branch both add to it, and
        // every exit hands it back so nothing is lost in silence.
        val notes = ArrayList<String>()

        // freedom -> direct
        if (proto == "freedom") {
            val sb = JSONObject()
            sb.put("type", "direct")
            sb.put("tag", tag)
            val settings = o.optJSONObject("settings") ?: JSONObject()
            // Same replacement as in applySockopt: the outbound-level domain_strategy is refused by sing-box 1.12
            // and later, and the resolver it gives way to has to name a server that exists.
            val ds = settings.optString("domainStrategy", "").trim()
            val strat = FREEDOM_STRATEGY_MAP[ds] ?: ""
            if (strat.isNotEmpty() && dnsResolverTag != null) {
                val resolver = JSONObject()
                resolver.put("server", dnsResolverTag)
                resolver.put("strategy", strat)
                sb.put("domain_resolver", resolver)
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
            applyProxySettings(sb, o)
            return OutboundResult(sb, "aux", notes)
        }

        if (proto == "blackhole" || proto == "dns") {
            val resp = o.optJSONObject("settings")?.optJSONObject("response")
            if (resp != null && resp.optString("type", "") == "http") {
                notes.add(
                    "blackhole answers with a canned HTTP response; sing-box only closes the " +
                        "connection, so the reply body was dropped"
                )
            }
            return OutboundResult(null, "aux", notes)
        }
        if (proto == "loopback") return OutboundResult(null, "aux", notes)

        val stream = o.optJSONObject("streamSettings") ?: JSONObject()
        val settings = o.optJSONObject("settings") ?: JSONObject()

        if (proto == "wireguard") {
            return OutboundResult(convWireguard(o, settings, tag, dnsResolverTag, notes), "wireguard", notes)
        }

        if (proto in QUIC_PROTOCOLS) {
            val sb = when (proto) {
                "hysteria2" -> SingBoxHysteria.convertHysteria2(o, notes)
                // A node written as v1 may describe v2; the same test the
                // mihomo side uses decides which.
                "hysteria" ->
                    if (isHysteria2(settings, o.xObj("streamSettings"))) {
                        SingBoxHysteria.convertHysteria2(o, notes)
                    } else {
                        SingBoxHysteria.convertHysteria(o, notes)
                    }
                else -> SingBoxHysteria.convertTuic(o, notes)
            }
            if (sb != null) {
                sb.put("tag", tag)
                applySendThrough(sb, o, notes)
            }
            return OutboundResult(sb, proto, notes)
        }

        // VLESS / VMess: server/uuid + flow or vmess security, tls, transport
        if (proto == "vless" || proto == "vmess") {
            val vnext = settings.optJSONArray("vnext")?.optJSONObject(0) ?: JSONObject()
            val user = vnext.optJSONArray("users")?.optJSONObject(0) ?: JSONObject()
            val sb = JSONObject()
            sb.put("type", proto)
            sb.put("tag", tag)
            sb.put("server", vnext.xStr("address"))
            sb.put("server_port", vnext.xInt("port"))
            sb.put("uuid", user.xStr("id"))
            if (proto == "vless") {
                val flowRaw = user.xStr("flow")
                val flow = normalizeFlow(flowRaw)
                if (flow.isNotEmpty()) sb.put("flow", flow)
            } else {
                sb.put("security", user.xStr("security").ifEmpty { "auto" })
                sb.put("alter_id", user.xInt("alterId"))
                var gp: Any? = user.opt("global_padding")
                if (gp == null || gp === JSONObject.NULL) gp = user.opt("globalPadding")
                if (gp == null || gp === JSONObject.NULL) {
                    sb.put("global_padding", true)
                } else if (gp is Boolean) {
                    sb.put("global_padding", gp)
                } else {
                    sb.put("global_padding", gp.toString().lowercase() == "true")
                }
                var al: Any? = user.opt("authenticated_length")
                if (al == null || al === JSONObject.NULL) al = user.opt("authenticatedLength")
                if (al is Boolean && !al) sb.put("authenticated_length", false)
            }
            val pe = convPacketEncoding(o, proto)
            if (pe != null) sb.put("packet_encoding", pe)
            val tls = SingBoxStream.convTls(stream, notes)
            if (tls != null) sb.put("tls", tls)
            val tr = SingBoxStream.convTransport(stream, notes)
            if (tr != null) sb.put("transport", tr)
            return finishProxy(sb, o, stream, dnsResolverTag, notes)
        }

        // Trojan
        if (proto == "trojan") {
            val srv = settings.optJSONArray("servers")?.optJSONObject(0) ?: JSONObject()
            val sb = JSONObject()
            sb.put("type", "trojan")
            sb.put("tag", tag)
            sb.put("server", srv.xStr("address"))
            sb.put("server_port", srv.xInt("port"))
            sb.put("password", srv.xStrRaw("password"))
            val tls = SingBoxStream.convTls(stream, notes)
            if (tls != null) sb.put("tls", tls)
            val tr = SingBoxStream.convTransport(stream, notes)
            if (tr != null) sb.put("transport", tr)
            return finishProxy(sb, o, stream, dnsResolverTag, notes)
        }

        // Shadowsocks (+ plugin / udp-over-tcp)
        if (proto == "shadowsocks") {
            val srv = settings.optJSONArray("servers")?.optJSONObject(0) ?: JSONObject()
            // Same read as unsupportedReason above, so the check and the conversion can't disagree.
            val rawMethod = (if (srv.xHas("method")) srv.xStr("method") else "aes-256-gcm")
                .ifEmpty { "aes-256-gcm" }
            val method = SS_METHOD_ALIAS[rawMethod] ?: rawMethod
            val sb = JSONObject()
            sb.put("type", "shadowsocks")
            sb.put("tag", tag)
            sb.put("server", srv.xStr("address"))
            sb.put("server_port", srv.xInt("port"))
            sb.put("method", method)
            sb.put("password", srv.xStrRaw("password"))
            val plugin = srv.xStr("plugin")
            if (plugin.isNotEmpty()) sb.put("plugin", plugin)
            var po: Any? = srv.opt("plugin_opts")
            if (po == null || po === JSONObject.NULL) po = srv.opt("pluginOpts")
            if (po != null && po !== JSONObject.NULL) {
                val ser = serializePluginOpts(po)
                if (ser.isNotEmpty()) sb.put("plugin_opts", ser)
            }
            if (srv.xBool("uot")) {
                val v = srv.opt("UoTVersion")
                val ver = when (v) {
                    null, JSONObject.NULL -> 1
                    is Number -> v.toInt()
                    is String -> v.toIntOrNull() ?: 1
                    else -> 1
                }
                val uot = JSONObject()
                uot.put("enabled", true)
                uot.put("version", ver)
                sb.put("udp_over_tcp", uot)
            }
            return finishProxy(sb, o, stream, dnsResolverTag, notes)
        }

        // SOCKS
        if (proto == "socks") {
            val srv = settings.optJSONArray("servers")?.optJSONObject(0) ?: JSONObject()
            val sb = JSONObject()
            sb.put("type", "socks")
            sb.put("tag", tag)
            sb.put("server", srv.xStr("address"))
            sb.put("server_port", srv.xInt("port"))
            val users = srv.optJSONArray("users")
            if (users != null && users.length() > 0) {
                val u0 = users.optJSONObject(0) ?: JSONObject()
                sb.put("username", u0.optString("user", ""))
                sb.put("password", u0.optString("pass", ""))
            }
            val ver = srv.opt("version") ?: settings.opt("version")
            if (ver != null && ver !== JSONObject.NULL) {
                val v = ver.toString().replace("socks", "")
                if (v == "4" || v == "4a" || v == "5") sb.put("version", v)
            }
            if (srv.xBool("uot")) {
                val uot = JSONObject()
                uot.put("enabled", true)
                sb.put("udp_over_tcp", uot)
            }
            return finishProxy(sb, o, stream, dnsResolverTag, notes)
        }

        // HTTP proxy
        if (proto == "http") {
            val srv = settings.optJSONArray("servers")?.optJSONObject(0) ?: JSONObject()
            val sb = JSONObject()
            sb.put("type", "http")
            sb.put("tag", tag)
            sb.put("server", srv.xStr("address"))
            sb.put("server_port", srv.xInt("port"))
            val users = srv.optJSONArray("users")
            if (users != null && users.length() > 0) {
                val u0 = users.optJSONObject(0) ?: JSONObject()
                sb.put("username", u0.optString("user", ""))
                sb.put("password", u0.optString("pass", ""))
            }
            val tls = SingBoxStream.convTls(stream, notes)
            if (tls != null) sb.put("tls", tls)
            return finishProxy(sb, o, stream, dnsResolverTag, notes)
        }

        return OutboundResult(null, null, notes)
    }

    // WireGuard's reserved field, only at the three bytes the core insists on: measured against both
    // cores, any other length is answered with "invalid reserved value" and refuses the whole document.
    private fun reservedThreeBytes(raw: Any?, notes: MutableList<String>?): JSONArray? {
        if (!SingBoxUtil.isTruthy(raw)) return null
        val arr = raw as? JSONArray
        if (arr == null || arr.length() != 3) {
            val size = arr?.length()
            notes?.add(
                "wireguard reserved is ${size ?: "not a list of bytes"} where sing-box wants " +
                    "three, so it was dropped"
            )
            return null
        }
        for (i in 0 until 3) {
            val n = arr.opt(i) as? Number ?: run {
                notes?.add("wireguard reserved holds something that is not a byte, so it was dropped")
                return null
            }
            if (n.toInt() !in 0..255) {
                notes?.add("wireguard reserved holds ${n.toInt()}, which is not a byte, so it was dropped")
                return null
            }
        }
        return arr
    }

    // WireGuard to a sing-box endpoint
    internal fun convWireguard(
        o: JSONObject,
        settings: JSONObject,
        tag: String,
        dnsResolverTag: String? = null,
        notes: MutableList<String>? = null
    ): JSONObject {
        val addressesAny = settings.opt("address")
        val addresses = JSONArray()
        when (addressesAny) {
            is JSONArray -> for (i in 0 until addressesAny.length()) {
                addressesAny.opt(i)?.let { addresses.put(it) }
            }
            is String -> if (addressesAny.isNotEmpty()) addresses.put(addressesAny)
        }
        val ep = JSONObject()
        ep.put("type", "wireguard")
        ep.put("tag", tag)
        if (addresses.length() > 0) {
            ep.put("address", addresses)
        } else {
            val fallback = JSONArray()
            fallback.put("10.0.0.2/32")
            ep.put("address", fallback)
        }
        ep.put("private_key", settings.optString("secretKey", ""))
        val mtuVal = settings.opt("mtu")
        if (SingBoxUtil.isTruthy(mtuVal)) {
            val mtu = when (mtuVal) {
                is Number -> mtuVal.toInt()
                is String -> mtuVal.toIntOrNull()
                else -> null
            }
            if (mtu != null) ep.put("mtu", mtu)
        }
        val workersVal = settings.opt("workers")
        if (SingBoxUtil.isTruthy(workersVal)) {
            val w = when (workersVal) {
                is Number -> workersVal.toInt()
                is String -> workersVal.toIntOrNull()
                else -> null
            }
            if (w != null) ep.put("workers", w)
        }
        // Xray keeps one reserved value for the whole outbound; sing-box has it on each peer and
        // nowhere else - putting it on the endpoint is an unknown field there and refuses the whole
        val sharedReserved = reservedThreeBytes(settings.opt("reserved"), notes)
        // Map each peer (endpoint, keys, allowed-ips, keepalive)
        val peers = JSONArray()
        val peerArr = settings.optJSONArray("peers")
        if (peerArr != null) {
            for (i in 0 until peerArr.length()) {
                val p = peerArr.optJSONObject(i) ?: continue
                val endpoint = p.optString("endpoint", "")
                val hp = SingBoxUtil.splitHostPort(endpoint)
                val peer = JSONObject()
                peer.put("address", hp.host)
                peer.put("port", hp.port ?: 0)
                peer.put("public_key", p.optString("publicKey", ""))
                val allowed = p.optJSONArray("allowedIPs")
                if (allowed != null && allowed.length() > 0) {
                    peer.put("allowed_ips", allowed)
                } else {
                    val def = JSONArray()
                    def.put("0.0.0.0/0")
                    def.put("::/0")
                    peer.put("allowed_ips", def)
                }
                val psk = p.optString("preSharedKey", "")
                if (psk.isNotEmpty()) peer.put("pre_shared_key", psk)
                val ka = p.opt("keepAlive")
                if (SingBoxUtil.isTruthy(ka)) {
                    val v = when (ka) {
                        is Number -> ka.toInt()
                        is String -> ka.toIntOrNull()
                        else -> null
                    }
                    if (v != null) peer.put("persistent_keepalive_interval", v)
                }
                val ownReserved = reservedThreeBytes(p.opt("reserved"), notes) ?: sharedReserved
                ownReserved?.let { peer.put("reserved", it) }
                peers.put(peer)
            }
        }
        if (peers.length() > 0) ep.put("peers", peers)
        applyProxySettings(ep, o)
        applySockopt(ep, o.optJSONObject("streamSettings"), dnsResolverTag, notes)
        applySendThrough(ep, o, notes)
        return ep
    }
}
