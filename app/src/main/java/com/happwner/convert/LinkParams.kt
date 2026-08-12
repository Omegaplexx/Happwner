package com.happwner.convert

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

    // Collects every query parameter the stream settings imply.
    internal fun streamParams(
        ss: JSONObject?,
        params: MutableMap<String, String>,
        mirrorSniToHost: Boolean = false
    ) {
        // A node with no stream settings is plain TCP with no TLS.
        if (ss == null) {
            params["type"] = "tcp"
            params["security"] = "none"
            return
        }
        val net = linkNetwork(ss.optString("network", ""))
        params["type"] = net

        // ------------------------------------------------------------ TLS ----
        val security = ss.optString("security", "").trim().lowercase()
        val tls = ss.optJSONObject("tlsSettings")
        val reality = ss.optJSONObject("realitySettings")
        when (security) {
            "tls", "xtls" -> {
                params["security"] = "tls"
                applyTlsParams(tls, params, mirrorSniToHost)
            }
            "reality" -> {
                params["security"] = "reality"
                applyTlsParams(reality, params, mirrorSniToHost)
                putIfNotEmpty(params, "pbk", reality?.optString("publicKey"))
                putIfNotEmpty(params, "sid", reality?.optString("shortId"))
                putIfNotEmpty(params, "spx", reality?.optString("spiderX"))
            }
            "none", "" -> {
                // Some clients want to be told rather than left to assume.
                params["security"] = "none"
            }
            else -> params["security"] = security
        }

        // ------------------------------------------------------ transport ----
        when (net) {
            "ws" -> {
                val ws = ss.optJSONObject("wsSettings")
                putIfNotEmpty(params, "path", ws?.optString("path"))
                putIfNotEmpty(params, "host", headerHost(ws) ?: ws?.optString("host"))
            }
            "httpupgrade" -> {
                val hu = ss.optJSONObject("httpupgradeSettings")
                putIfNotEmpty(params, "path", hu?.optString("path"))
                putIfNotEmpty(params, "host", hu?.optString("host") ?: headerHost(hu))
            }
            "xhttp" -> {
                val x = ss.optJSONObject("xhttpSettings") ?: ss.optJSONObject("splithttpSettings")
                putIfNotEmpty(params, "path", x?.optString("path"))
                putIfNotEmpty(params, "host", x?.optString("host") ?: headerHost(x))
                putIfNotEmpty(params, "mode", x?.optString("mode"))
            }
            "http" -> {
                val h = ss.optJSONObject("httpSettings")
                putIfNotEmpty(params, "path", h?.optString("path"))
                putIfNotEmpty(params, "host", firstOfList(h?.opt("host")) ?: headerHost(h))
            }
            "grpc" -> {
                val g = ss.optJSONObject("grpcSettings")
                putIfNotEmpty(params, "serviceName", g?.optString("serviceName"))
                if (g?.optBoolean("multiMode") == true) params["mode"] = "multi"
                putIfNotEmpty(params, "authority", g?.optString("authority"))
            }
            "kcp" -> {
                val k = ss.optJSONObject("kcpSettings")
                putIfNotEmpty(params, "seed", k?.optString("seed"))
                putIfNotEmpty(params, "headerType", k?.optJSONObject("header")?.optString("type"))
            }
            "quic" -> {
                val q = ss.optJSONObject("quicSettings")
                putIfNotEmpty(params, "quicSecurity", q?.optString("security"))
                putIfNotEmpty(params, "key", q?.optString("key"))
                putIfNotEmpty(params, "headerType", q?.optJSONObject("header")?.optString("type"))
            }
            "tcp" -> {
                // The raw transport carries an HTTP masquerade, and its host and
                // path belong in the link the same as any other transport's.
                val t = ss.optJSONObject("tcpSettings") ?: ss.optJSONObject("rawSettings")
                val header = t?.optJSONObject("header")
                val type = header?.optString("type", "") ?: ""
                if (type.isNotEmpty() && type != "none" && header != null) {
                    params["headerType"] = type
                    val req = header.optJSONObject("request")
                    putIfNotEmpty(params, "path", firstOfList(req?.opt("path")))
                    val hdrHost = req?.optJSONObject("headers")?.opt("Host")
                    putIfNotEmpty(params, "host", firstOfList(hdrHost))
                }
            }
        }
    }

    private fun applyTlsParams(
        tls: JSONObject?,
        params: MutableMap<String, String>,
        mirrorSniToHost: Boolean
    ) {
        if (tls == null) return
        val sni = firstNonEmptyOf(tls.optString("serverName"), firstOfList(tls.opt("serverNames")))
        if (sni.isNotEmpty()) {
            params["sni"] = sni
            // Trojan links have always repeated it here and some parsers read
            // only this one.
            if (mirrorSniToHost && !params.containsKey("host")) params["host"] = sni
        }
        val alpn = joinList(tls.opt("alpn"))
        if (alpn.isNotEmpty()) params["alpn"] = alpn
        // Only when the source asked for one. A fingerprint invented here would
        // tell the client to mimic a browser the configuration never named.
        putIfNotEmpty(params, "fp", tls.optString("fingerprint"))
        if (tls.optBoolean("allowInsecure", false)) params["allowInsecure"] = "1"
    }

    private fun headerHost(o: JSONObject?): String? {
        val headers = o?.optJSONObject("headers") ?: return null
        val keys = headers.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            if (k.equals("Host", ignoreCase = true)) return firstOfList(headers.opt(k))
        }
        return null
    }

    // A string, or the first entry of an array of them.
    internal fun firstOfList(v: Any?): String? = when (v) {
        null, JSONObject.NULL -> null
        is String -> v.ifEmpty { null }
        is JSONArray -> (0 until v.length()).asSequence()
            .mapNotNull { v.opt(it) as? String }
            .firstOrNull { it.isNotEmpty() }
        else -> v.toString().ifEmpty { null }
    }

    // Comma-separated, which is how a link carries a list.
    internal fun joinList(v: Any?): String = when (v) {
        null, JSONObject.NULL -> ""
        is String -> v
        is JSONArray -> (0 until v.length()).mapNotNull { v.opt(it) as? String }
            .filter { it.isNotEmpty() }.joinToString(",")
        else -> v.toString()
    }

    private fun firstNonEmptyOf(vararg values: String?): String {
        for (v in values) if (!v.isNullOrEmpty()) return v
        return ""
    }

    private fun putIfNotEmpty(params: MutableMap<String, String>, key: String, value: String?) {
        if (!value.isNullOrEmpty()) params[key] = value
    }

    // The host as a link may hold it: an IPv6 literal must be bracketed, or its colons read as the
    // port separator and the link won't parse.
    internal fun hostForUri(host: String): String {
        val h = host.trim()
        if (h.startsWith("[")) return h
        return if (h.count { it == ':' } >= 2) "[$h]" else h
    }

    // The query string, sorted so the same input always produces the same link.
    internal fun queryString(params: Map<String, String>): String {
        if (params.isEmpty()) return ""
        return "?" + params.entries.sortedBy { it.key }.joinToString("&") {
            "${it.key}=${enc(it.value)}"
        }
    }

    internal fun enc(s: String): String = URLEncoder.encode(s, "UTF-8").replace("+", "%20")
}
