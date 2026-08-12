package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// The stream layer shared by every proxy protocol: TLS, REALITY, uTLS and the transports. UTLS_FP is
// a sing-box vocabulary; the mihomo converter has its own, longer list - do not merge the two.
internal object SingBoxStream {
    internal val UTLS_FP = setOf(
        "chrome", "firefox", "edge", "safari", "360", "qq",
        "ios", "android", "random", "randomized"
    )

    internal val XRAY_TRANSPORTS_OK = setOf(
        "tcp", "raw", "", "ws", "grpc", "http", "h2", "httpupgrade", "quic"
    )

    internal val XRAY_SECURITY_OK = setOf("", "none", "tls", "reality")

    internal fun utlsFp(fp: Any?): String {
        if (fp is String && fp in UTLS_FP) return fp
        return "chrome"
    }

    internal data class WsPath(val path: String, val earlyData: Int?)

    internal fun parseWsPath(path: Any?): WsPath {
        if (path !is String || !path.contains("?") || !path.contains("ed=")) {
            return WsPath(path as? String ?: "", null)
        }
        val qIdx = path.indexOf("?")
        val base = path.substring(0, qIdx)
        val query = path.substring(qIdx + 1)
        val kept = mutableListOf<String>()
        var edValue: Int? = null
        for (pair in query.split("&")) {
            if (pair.isEmpty()) continue
            if (pair.startsWith("ed=")) {
                val n = pair.substring(3).toIntOrNull()
                if (n != null) edValue = n else kept.add(pair)
            } else {
                kept.add(pair)
            }
        }
        val newQuery = kept.joinToString("&")
        val newPath = if (newQuery.isEmpty()) base else "$base?$newQuery"
        return WsPath(newPath, edValue)
    }

    internal fun normalizeHeadersV2ray(headers: JSONObject?, singleValue: Boolean): JSONObject {
        val out = JSONObject()
        if (headers == null) return out
        val keys = headers.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            val v = headers.opt(k) ?: continue
            if (v === JSONObject.NULL) continue
            if (singleValue) {
                if (v is JSONArray) {
                    if (v.length() > 0) out.put(k, v.opt(0)?.toString() ?: "") else out.put(k, "")
                } else {
                    out.put(k, v.toString())
                }
            } else {
                if (v is JSONArray) {
                    out.put(k, v)
                } else {
                    out.put(k, JSONArray().put(v.toString()))
                }
            }
        }
        return out
    }

    internal fun getTcpHttpRequest(stream: JSONObject): JSONObject? {
        val net = stream.xStr("network").ifEmpty { "tcp" }
        if (net !in setOf("tcp", "raw", "")) return null
        val ts = stream.optJSONObject("tcpSettings")
            ?: stream.optJSONObject("rawSettings")
            ?: return null
        val hdr = ts.optJSONObject("header") ?: return null
        if (hdr.xStr("type").ifEmpty { "none" } != "http") return null
        return hdr.optJSONObject("request") ?: JSONObject()
    }

    // streamSettings to the tls block (including reality/utls/ech)
    // The TLS versions the core accepts; anything else refuses the document.
    internal val TLS_VERSIONS = setOf("1.0", "1.1", "1.2", "1.3")

    internal fun convTls(stream: JSONObject, notes: MutableList<String>? = null): JSONObject? {
        val sec = stream.xStr("security")
        if (sec != "tls" && sec != "reality") return null
        val tls = JSONObject()
        tls.put("enabled", true)

        // Reality: utls fingerprint + public key / short id
        if (sec == "reality") {
            val rs = stream.optJSONObject("realitySettings") ?: JSONObject()
            val sn = rs.optString("serverName", "")
            if (sn.isNotEmpty()) tls.put("server_name", sn)
            val utls = JSONObject()
            utls.put("enabled", true)
            utls.put("fingerprint", utlsFp(rs.opt("fingerprint")))
            tls.put("utls", utls)
            val reality = JSONObject()
            reality.put("enabled", true)
            reality.put("public_key", rs.optString("publicKey", ""))
            reality.put("short_id", rs.optString("shortId", ""))
            // spiderX is Xray's own probing path and sing-box has nothing to put it in - small, but
            // nobody can act on a setting that vanishes without being named.
            if (rs.optString("spiderX", "").isNotEmpty()) {
                notes?.add("realitySettings.spiderX has no sing-box equivalent and was dropped")
            }
            tls.put("reality", reality)
            return tls
        }

        // Plain TLS: sni, alpn, versions, utls, certs, ECH
        val ts = stream.optJSONObject("tlsSettings") ?: JSONObject()
        val sn = ts.optString("serverName", "")
        if (sn.isNotEmpty()) tls.put("server_name", sn)
        if (ts.xBool("allowInsecure")) tls.put("insecure", true)
        val alpn = ts.opt("alpn")
        if (alpn != null && alpn !== JSONObject.NULL) {
            if (alpn is JSONArray) {
                if (alpn.length() > 0) tls.put("alpn", alpn)
            } else {
                tls.put("alpn", JSONArray().put(alpn.toString()))
            }
        }
        // The core knows four version names and refuses the whole document on anything else
        // ("unknown tls version"), so a hand-edited typo used to cost the subscription.
        val suites = ts.optString("cipherSuites", "").trim()
        if (suites.isNotEmpty()) {
            val arr = JSONArray()
            for (c in suites.split(":")) {
                val t = c.trim()
                if (t.isNotEmpty()) arr.put(t)
            }
            if (arr.length() > 0) tls.put("cipher_suites", arr)
        }
        // curve_preferences is a sing-box 1.13.0 field, and an unknown field stops a configuration
        // loading, so it stays out for the sake of the 1.12 cores still in use.
        if (ts.xStrList("curvePreferences").isNotEmpty()) {
            notes?.add(
                "tlsSettings.curvePreferences was not carried: sing-box has curve_preferences only " +
                    "since 1.13, and writing it would stop a 1.12 core loading the configuration"
            )
        }
        // sing-box verifies against server_name and has no separate name for the check, so it
        // cannot be pointed elsewhere the way Xray points it.
        if (ts.xStrList("verifyPeerCertInNames").isNotEmpty()) {
            notes?.add(
                "tlsSettings.verifyPeerCertInNames checks the certificate against other names, " +
                    "which sing-box has no field for, so it was dropped"
            )
        }

        if (notes != null) {
            // Named on purpose rather than mapped: the core pins the public key of a certificate while Xray pins
            // the certificate itself, so the two hashes are of different things and cannot stand in for each other.
            if (ts.optString("pinnedPeerCertSha256", "").isNotEmpty()) {
                notes.add(
                    "tlsSettings.pinnedPeerCertSha256 pins the certificate, while sing-box pins " +
                        "the public key inside it - the two hashes are not the same value, so it was left out"
                )
            }
            if (ts.xBool("disableSystemRoot")) {
                notes.add(
                    "tlsSettings.disableSystemRoot has no sing-box equivalent; " +
                        "the system trust store stays in use"
                )
            }
            if (ts.optString("masterKeyLog", "").isNotEmpty()) {
                notes.add("tlsSettings.masterKeyLog has no sing-box equivalent and was dropped")
            }
        }

        for ((from, to) in listOf("minVersion" to "min_version", "maxVersion" to "max_version")) {
            if (!ts.has(from) || ts.isNull(from)) continue
            val v = ts.optString(from, "").trim()
            if (v.isEmpty()) continue
            if (v in TLS_VERSIONS) tls.put(to, v)
            else notes?.add("tlsSettings.$from \"$v\" is not a TLS version sing-box knows and was dropped")
        }
        val fp = ts.optString("fingerprint", "")
        if (fp.isNotEmpty()) {
            val utls = JSONObject()
            utls.put("enabled", true)
            utls.put("fingerprint", utlsFp(fp))
            tls.put("utls", utls)
        }
        val certs = ts.optJSONArray("certificates")
        if (certs != null && certs.length() > 0) {
            val cert = certs.optJSONObject(0) ?: JSONObject()
            val certFile = cert.optString("certificateFile", "")
            if (certFile.isNotEmpty()) {
                // Deliberately not carried: the core opens the file at load and refuses everything if it is missing,
                // and an Xray path names a file on the machine that ran Xray - one failed node beats a dead config.
                notes?.add(
                    "tlsSettings.certificates[0].certificateFile points at \"$certFile\" on the " +
                        "machine that wrote the configuration, so it was dropped; inline " +
                        "certificates are carried"
                )
            } else if (cert.has("certificate") && !cert.isNull("certificate")) {
                val cval = cert.opt("certificate")
                if (cval is JSONArray) {
                    val parts = mutableListOf<String>()
                    for (i in 0 until cval.length()) {
                        parts.add(cval.opt(i)?.toString() ?: "")
                    }
                    tls.put("certificate", parts.joinToString("\n"))
                } else if (cval is String) {
                    tls.put("certificate", cval)
                }
            }
        }
        var ech: Any? = ts.opt("echConfigList")
        if (ech == null || ech === JSONObject.NULL ||
            (ech is JSONArray && ech.length() == 0) ||
            (ech is String && ech.isEmpty())) {
            ech = ts.opt("ech")
        }
        if (ech != null && ech !== JSONObject.NULL &&
            !(ech is JSONArray && ech.length() == 0) &&
            !(ech is String && ech.isEmpty())) {
            val echObj = JSONObject()
            echObj.put("enabled", true)
            // The core reads the client-side list as PEM, inline in "config" or from "config_path".
            when (ech) {
                is JSONArray -> echObj.put("config", echPem(ech))
                is String -> {
                    val v = ech.trim()
                    when {
                        // Already PEM: pass the lines through as they are.
                        v.startsWith("-----BEGIN") ->
                            echObj.put("config", JSONArray(v.lines()))
                        // Xray can fetch the list over DoH.
                        v.startsWith("http://") || v.startsWith("https://") ->
                            notes?.add(
                                "tlsSettings.echConfigList points at a resolver; " +
                                    "sing-box looks the ECH config up in DNS instead"
                            )
                        // The ordinary case: a base64 body, which becomes PEM.
                        decodeBase64Any(v) != null ->
                            echObj.put("config", echPem(JSONArray().put(v)))
                        else ->
                            notes?.add(
                                "could not read tlsSettings.echConfigList; only ECH itself was enabled"
                            )
                    }
                }
            }
            tls.put("ech", echObj)
        }
        return tls
    }

    // Wraps base64 ECH config bodies in the PEM envelope the core parses.
    private fun echPem(body: JSONArray): JSONArray {
        val lines = (0 until body.length()).mapNotNull { body.opt(it)?.toString()?.trim() }
            .filter { it.isNotEmpty() }
        if (lines.any { it.startsWith("-----BEGIN") }) return JSONArray(lines)
        val out = JSONArray()
        out.put("-----BEGIN ECH CONFIGS-----")
        for (l in lines) out.put(l)
        out.put("-----END ECH CONFIGS-----")
        return out
    }

    // streamSettings to the transport block (ws/grpc/http/httpupgrade/quic/tcp-http)
    internal fun convTransport(stream: JSONObject, notes: MutableList<String>? = null): JSONObject? {
        var net = stream.xStr("network").ifEmpty { "tcp" }
        if (net == "raw") net = "tcp"

        // tcp + http header -> http transport
        if (net == "tcp") {
            val req = getTcpHttpRequest(stream) ?: return null
            val tr = JSONObject()
            tr.put("type", "http")
            val pathRaw = req.opt("path")
            when (pathRaw) {
                is JSONArray -> if (pathRaw.length() > 0) tr.put("path", pathRaw.opt(0))
                is String -> if (pathRaw.isNotEmpty()) tr.put("path", pathRaw)
            }
            val method = req.optString("method", "")
            if (method.isNotEmpty()) tr.put("method", method)
            val headersIn = req.optJSONObject("headers")
            val workingHeaders = if (headersIn != null) {
                val copy = JSONObject()
                val keys = headersIn.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    copy.put(k, headersIn.opt(k))
                }
                copy
            } else null
            var hostVals: Any? = null
            if (workingHeaders != null) {
                if (workingHeaders.has("Host")) {
                    hostVals = workingHeaders.opt("Host"); workingHeaders.remove("Host")
                } else if (workingHeaders.has("host")) {
                    hostVals = workingHeaders.opt("host"); workingHeaders.remove("host")
                }
            }
            if (hostVals != null && hostVals !== JSONObject.NULL) {
                if (hostVals is JSONArray) {
                    tr.put("host", hostVals)
                } else {
                    tr.put("host", JSONArray().put(hostVals.toString()))
                }
            }
            if (workingHeaders != null && workingHeaders.length() > 0) {
                tr.put("headers", normalizeHeadersV2ray(workingHeaders, singleValue = false))
            }
            return tr
        }

        // WebSocket: path, headers, early-data
        if (net == "ws") {
            val ws = stream.optJSONObject("wsSettings") ?: JSONObject()
            val tr = JSONObject()
            tr.put("type", "ws")
            if (ws.xInt("heartbeatPeriod") > 0) {
                notes?.add("wsSettings.heartbeatPeriod has no sing-box equivalent and was dropped")
            }
            val rawPath = ws.optString("path", "")
            val parsed = parseWsPath(rawPath)
            if (parsed.path.isNotEmpty()) tr.put("path", parsed.path)
            val headers = normalizeHeadersV2ray(ws.optJSONObject("headers"), singleValue = true)
            if (headers.length() > 0) tr.put("headers", headers)
            var earlyData = parsed.earlyData
            if (earlyData == null && ws.has("maxEarlyData") && !ws.isNull("maxEarlyData")) {
                val v = ws.opt("maxEarlyData")
                earlyData = when (v) {
                    is Int -> v
                    is Long -> v.toInt()
                    is Number -> v.toInt()
                    is String -> v.toIntOrNull()
                    else -> null
                }
            }
            if (earlyData != null && earlyData != 0) {
                tr.put("max_early_data", earlyData)
                tr.put(
                    "early_data_header_name",
                    ws.optString("earlyDataHeaderName", "").ifEmpty { "Sec-WebSocket-Protocol" }
                )
            } else {
                val edh = ws.optString("earlyDataHeaderName", "")
                if (edh.isNotEmpty()) tr.put("early_data_header_name", edh)
            }
            return tr
        }

        // gRPC: service name and timeouts
        if (net == "grpc") {
            val g = stream.optJSONObject("grpcSettings") ?: JSONObject()
            var sn = g.optString("serviceName", "")
            if (sn.startsWith("/")) sn = sn.trimStart('/')
            val tr = JSONObject()
            tr.put("type", "grpc")
            // The transport crosses over; these settings of it do not. Said plainly, because a line
            // naming grpcSettings reads as though the gRPC node itself had been dropped.
            if (g.optString("authority", "").isNotEmpty()) {
                notes?.add(
                    "the node still uses gRPC, but grpcSettings.authority has no " +
                        "sing-box equivalent and was dropped"
                )
            }
            // sing-box has no multi-mode, so a node asking for it runs in single mode. mihomo says so
            // already, and saying it on one side only is how a limitation goes unnoticed.
            if (g.xBool("multiMode")) {
                notes?.add(
                    "the node still uses gRPC, but grpcSettings.multiMode has no " +
                        "sing-box equivalent; the node will use single mode"
                )
            }
            tr.put("service_name", sn)
            if (g.xInt("initial_windows_size") > 0) {
                notes?.add(
                    "the node still uses gRPC, but grpcSettings.initial_windows_size has no " +
                        "sing-box equivalent and was dropped"
                )
            }
            val idle = SingBoxUtil.toDuration(g.opt("idle_timeout"))
            if (idle != null) tr.put("idle_timeout", idle)
            val hct = SingBoxUtil.toDuration(g.opt("health_check_timeout"))
            if (hct != null) tr.put("ping_timeout", hct)
            if (g.xBool("permit_without_stream")) tr.put("permit_without_stream", true)
            return tr
        }

        // HTTP/2: host/path/headers/timeouts
        if (net == "http" || net == "h2") {
            val h = stream.optJSONObject("httpSettings") ?: JSONObject()
            val tr = JSONObject()
            tr.put("type", "http")
            val path = h.optString("path", "")
            if (path.isNotEmpty()) tr.put("path", path)
            val host = h.opt("host")
            if (host != null && host !== JSONObject.NULL) {
                if (host is JSONArray) {
                    if (host.length() > 0) tr.put("host", host)
                } else if (host is String) {
                    if (host.isNotEmpty()) tr.put("host", JSONArray().put(host))
                } else {
                    val hs = host.toString()
                    if (hs.isNotEmpty()) tr.put("host", JSONArray().put(hs))
                }
            }
            val method = h.optString("method", "")
            if (method.isNotEmpty()) tr.put("method", method)
            val headers = h.optJSONObject("headers")
            if (headers != null && headers.length() > 0) {
                tr.put("headers", normalizeHeadersV2ray(headers, singleValue = false))
            }
            val idle = SingBoxUtil.toDuration(h.opt("read_idle_timeout"))
            if (idle != null) tr.put("idle_timeout", idle)
            val hct = SingBoxUtil.toDuration(h.opt("health_check_timeout"))
            if (hct != null) tr.put("ping_timeout", hct)
            return tr
        }

        // HTTPUpgrade: host (top-level or from the headers)
        if (net == "httpupgrade") {
            val hu = stream.optJSONObject("httpupgradeSettings") ?: JSONObject()
            val tr = JSONObject()
            tr.put("type", "httpupgrade")
            val path = hu.optString("path", "")
            if (path.isNotEmpty()) tr.put("path", path)
            var hostTop = hu.optString("host", "")
            val headers = normalizeHeadersV2ray(hu.optJSONObject("headers"), singleValue = true)
            var hostFromHeaders: String? = null
            val hk = headers.keys()
            val toRemove = mutableListOf<String>()
            while (hk.hasNext()) {
                val k = hk.next()
                if (k.lowercase() == "host") {
                    hostFromHeaders = headers.opt(k)?.toString()
                    toRemove.add(k)
                }
            }
            for (k in toRemove) headers.remove(k)
            if (hostTop.isEmpty() && !hostFromHeaders.isNullOrEmpty()) hostTop = hostFromHeaders
            if (hostTop.isNotEmpty()) tr.put("host", hostTop)
            if (headers.length() > 0) tr.put("headers", headers)
            return tr
        }

        if (net == "quic") {
            val tr = JSONObject()
            tr.put("type", "quic")
            return tr
        }

        return null
    }
}
