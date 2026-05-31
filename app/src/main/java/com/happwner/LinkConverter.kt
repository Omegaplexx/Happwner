package com.happwner

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.json.JSONTokener
import java.net.URLEncoder

object LinkConverter {
    data class ConversionStats(val text: String, val xraySkipped: Int)

    fun convert(
        input: String,
        jsonToUri: Boolean = true,
        tryBase64: Boolean = true,
        xrayToSb: Boolean = false
    ): String {
        return convertWithStats(input, jsonToUri, tryBase64, xrayToSb).text
    }

    // Main converter. Pass order: base64 -> xray-to-sing-box -> JSON-to-URI
    fun convertWithStats(
        input: String,
        jsonToUri: Boolean = true,
        tryBase64: Boolean = true,
        xrayToSb: Boolean = false
    ): ConversionStats {
        if (!jsonToUri && !tryBase64 && !xrayToSb) return ConversionStats(input.trim(), 0)

        val trimmed = input.trim()
        val compact = isCompactJson(trimmed)

        // If the whole body is base64, decode it and recurse
        if (tryBase64 || xrayToSb) {
            val b64 = tryDecodeBase64WithFlag(input)
            if (b64 != null) {
                val inner = convertWithStats(b64.decoded, jsonToUri, tryBase64, xrayToSb)
                return if (tryBase64) {
                    inner
                } else {
                    ConversionStats(
                        encodeBase64Like(inner.text, b64),
                        inner.xraySkipped
                    )
                }
            }
        }

        // xray-to-sing-box only: merge every config into a single one (mergeUnified)
        if (xrayToSb && !jsonToUri) {
            val merged = convertXrayToSingbox(input, trimmed, compact)
            if (merged != null) return merged
        }

        // Both modes: first drop unsupported xray outbounds, then run JSON-to-URI
        if (xrayToSb && jsonToUri) {
            val filtered = preFilterUnsupportedXray(input)
            val inner = convertWithStats(filtered.text, jsonToUri = true, tryBase64 = tryBase64, xrayToSb = false)
            return ConversionStats(inner.text, inner.xraySkipped + filtered.skipped)
        }

        // Whole body is a single xray config -> sing-box
        if (xrayToSb && trimmed.startsWith("{") && isWholeJsonValue(trimmed)) {
            val r = SingBoxConverter.convert(trimmed, "")
            if (r is SingBoxConverter.Result.Ok) {
                return ConversionStats(formatJson(r.config, compact), 0)
            }
        }

        // Whole body is an xray array -> sing-box
        if (xrayToSb && trimmed.startsWith("[") && isWholeJsonValue(trimmed)) {
            val arr = tryConvertXrayArray(trimmed, compact)
            if (arr != null) return ConversionStats(arr.text, arr.skipped)
        }

        val res = StringBuilder()
        var skipped = 0
        // Otherwise walk line by line
        input.lines().forEach { line ->
            val t = line.trim()
            if (t.isEmpty()) return@forEach
            val lineCompact = isCompactJson(t)

            if (tryBase64 || xrayToSb) {
                val b64 = tryDecodeBase64WithFlag(t)
                if (b64 != null) {
                    val inner = convertWithStats(b64.decoded, jsonToUri, tryBase64, xrayToSb)
                    val output = if (tryBase64) {
                        inner.text
                    } else {
                        encodeBase64Like(inner.text, b64)
                    }
                    res.append(output).append("\n")
                    skipped += inner.xraySkipped
                    return@forEach
                }
            }

            if (xrayToSb && t.startsWith("{") && isWholeJsonValue(t)) {
                when (val r = SingBoxConverter.convert(t, "")) {
                    is SingBoxConverter.Result.Ok -> {
                        res.append(formatJson(r.config, lineCompact)).append("\n")
                        return@forEach
                    }
                    SingBoxConverter.Result.Unsupported -> {
                        skipped++
                        return@forEach
                    }
                    SingBoxConverter.Result.NotXray -> {}
                }
            }

            if (xrayToSb && t.startsWith("[") && isWholeJsonValue(t)) {
                val arr = tryConvertXrayArray(t, lineCompact)
                if (arr != null) {
                    res.append(arr.text).append("\n")
                    skipped += arr.skipped
                    return@forEach
                }
            }

            // A JSON outbound on this line -> proxy link
            if (jsonToUri && (t.startsWith("{") || t.startsWith("[")) && isWholeJsonValue(t)) {
                try {
                    if (t.startsWith("[")) {
                        val arr = JSONArray(t)
                        for (i in 0 until arr.length()) {
                            val obj = arr.optJSONObject(i)
                            val piece: String? = if (obj != null) {
                                processJson(obj) ?: obj.toString()
                            } else {
                                val raw = arr.opt(i)
                                if (raw == null || raw === JSONObject.NULL) null
                                else raw.toString().trim().takeIf { it.isNotEmpty() }
                            }
                            if (piece != null) res.append(piece).append("\n")
                        }
                    } else {
                        val obj = JSONObject(t)
                        val converted = processJson(obj)
                        if (converted != null) res.append(converted).append("\n")
                        else res.append(t).append("\n")
                    }
                    return@forEach
                } catch (_: Exception) {}
            }

            res.append(t).append("\n")
        }
        return ConversionStats(res.toString().trim(), skipped)
    }

    // Single-line JSON? (no newline within the first 1KB)
    private fun isCompactJson(s: String): Boolean {
        val limit = minOf(s.length, 1024)
        for (i in 0 until limit) {
            val c = s[i]
            if (c == '\n' || c == '\r') return false
        }
        return true
    }

    // true if the whole string is one valid JSON value (no trailing junk)
    private fun isWholeJsonValue(s: String): Boolean {
        return try {
            val t = JSONTokener(s)
            t.nextValue()
            t.nextClean().code == 0
        } catch (_: JSONException) {
            false
        }
    }

    private fun formatJson(obj: JSONObject, compact: Boolean): String =
        if (compact) obj.toString() else obj.toString(2)

    private fun formatJsonArray(arr: JSONArray, compact: Boolean): String =
        if (compact) arr.toString() else arr.toString(2)

    private data class ArrayConvResult(val text: String, val skipped: Int)

    private data class FilterResult(val text: String, val skipped: Int)

    // Keep one xray config/array, dropping unsupported outbounds
    private fun preFilterUnsupportedXrayOne(t: String): FilterResult? {
        if (t.isEmpty()) return null
        if (!isWholeJsonValue(t)) return null
        if (t.startsWith("{")) {
            return when (SingBoxConverter.convertToOutbounds(t, "")) {
                is SingBoxConverter.OutboundsResult.Ok -> FilterResult(t, 0)
                SingBoxConverter.OutboundsResult.Unsupported -> FilterResult("", 1)
                SingBoxConverter.OutboundsResult.NotXray -> null
            }
        }
        if (t.startsWith("[")) {
            val arr = try { JSONArray(t) } catch (_: JSONException) { return null }
            val out = JSONArray()
            var anyXray = false
            var skipped = 0
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i)
                if (obj == null) {
                    val raw = arr.opt(i)
                    if (raw != null && raw !== JSONObject.NULL) out.put(raw)
                    continue
                }
                when (SingBoxConverter.convertToOutbounds(obj.toString(), "")) {
                    is SingBoxConverter.OutboundsResult.Ok -> {
                        out.put(obj)
                        anyXray = true
                    }
                    SingBoxConverter.OutboundsResult.Unsupported -> {
                        skipped++
                        anyXray = true
                    }
                    SingBoxConverter.OutboundsResult.NotXray -> out.put(obj)
                }
            }
            if (!anyXray) return null
            return FilterResult(formatJsonArray(out, isCompactJson(t)), skipped)
        }
        return null
    }

    // Drop unsupported xray configs/outbounds and count the skipped ones
    private fun preFilterUnsupportedXray(input: String): FilterResult {
        val trimmed = input.trim()
        if ((trimmed.startsWith("{") || trimmed.startsWith("[")) && isWholeJsonValue(trimmed)) {
            val single = preFilterUnsupportedXrayOne(trimmed)
            if (single != null) return single
        }
        val res = StringBuilder()
        var totalSkipped = 0
        var anyFiltered = false
        for (line in input.lines()) {
            val tt = line.trim()
            if (tt.isEmpty()) continue
            val one = preFilterUnsupportedXrayOne(tt)
            if (one != null) {
                anyFiltered = true
                if (one.text.isNotEmpty()) res.append(one.text).append("\n")
                totalSkipped += one.skipped
            } else {
                res.append(tt).append("\n")
            }
        }
        if (!anyFiltered) return FilterResult(input, 0)
        return FilterResult(res.toString().trimEnd('\n'), totalSkipped)
    }

    // Convert each xray config inside an array to sing-box
    private fun tryConvertXrayArray(text: String, compact: Boolean): ArrayConvResult? {
        val arr = try { JSONArray(text) } catch (_: JSONException) { return null }
        if (arr.length() == 0) return null

        var anyXray = false
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val outs = obj.optJSONArray("outbounds") ?: continue
            for (j in 0 until outs.length()) {
                val o = outs.optJSONObject(j) ?: continue
                if (o.has("protocol")) { anyXray = true; break }
            }
            if (anyXray) break
        }
        if (!anyXray) return null

        val outArr = JSONArray()
        var skipped = 0
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i)
            if (obj == null) {
                val raw = arr.opt(i)
                if (raw != null && raw !== JSONObject.NULL) outArr.put(raw)
                continue
            }
            when (val r = SingBoxConverter.convert(obj.toString(), "")) {
                is SingBoxConverter.Result.Ok -> outArr.put(r.config)
                SingBoxConverter.Result.Unsupported -> skipped++
                SingBoxConverter.Result.NotXray -> outArr.put(obj)
            }
        }
        return ArrayConvResult(formatJsonArray(outArr, compact), skipped)
    }

    // Merge xray configs into one sing-box; pass any other lines through unchanged
    private fun convertXrayToSingbox(input: String, trimmed: String, compact: Boolean): ConversionStats? {
        val configs = mutableListOf<JSONObject>()
        var skipped = 0
        var hadXray = false
        val passthroughLines = mutableListOf<String>()

        fun ingestObject(s: String): Boolean {
            return when (val r = SingBoxConverter.convert(s, "")) {
                is SingBoxConverter.Result.Ok -> {
                    configs.add(r.config); hadXray = true; true
                }
                SingBoxConverter.Result.Unsupported -> {
                    skipped++; hadXray = true; true
                }
                SingBoxConverter.Result.NotXray -> false
            }
        }

        fun ingestArray(s: String): Boolean {
            val arr = try { JSONArray(s) } catch (_: JSONException) { return false }
            var any = false
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                when (val r = SingBoxConverter.convert(obj.toString(), "")) {
                    is SingBoxConverter.Result.Ok -> {
                        configs.add(r.config); any = true
                    }
                    SingBoxConverter.Result.Unsupported -> {
                        skipped++; any = true
                    }
                    SingBoxConverter.Result.NotXray -> {}
                }
            }
            if (any) hadXray = true
            return any
        }

        val consumedWhole = when {
            trimmed.startsWith("{") && isWholeJsonValue(trimmed) -> ingestObject(trimmed)
            trimmed.startsWith("[") && isWholeJsonValue(trimmed) -> ingestArray(trimmed)
            else -> false
        }

        if (!consumedWhole) {
            for (line in input.lines()) {
                val t = line.trim()
                if (t.isEmpty()) continue
                val consumed = when {
                    t.startsWith("{") && isWholeJsonValue(t) -> ingestObject(t)
                    t.startsWith("[") && isWholeJsonValue(t) -> ingestArray(t)
                    else -> false
                }
                if (!consumed) passthroughLines.add(t)
            }
        }

        if (!hadXray) return null
        if (configs.isEmpty() && passthroughLines.isEmpty()) return null

        val builder = StringBuilder()
        if (configs.isNotEmpty()) {
            val merged = SingBoxConverter.mergeUnified(configs)
            if (merged != null) builder.append(formatJson(merged, compact))
        }
        for (l in passthroughLines) {
            if (builder.isNotEmpty()) builder.append("\n")
            builder.append(l)
        }

        return ConversionStats(builder.toString(), skipped)
    }

    private val PROXY_SCHEMES = arrayOf(
        "vless://", "vmess://", "trojan://", "ss://", "ssr://",
        "hysteria://", "hysteria2://", "hy2://", "tuic://", "socks://",
        "http://", "https://", "happ://"
    )

    private data class Base64Result(
        val decoded: String,
        val flag: Int,
        val hadNewlines: Boolean,
        val hadCrlf: Boolean,
        val hadPadding: Boolean,
        val hadTrailingNewline: Boolean,
        val hadTrailingCrlf: Boolean
    )

    // Try to decode as Base64 (remember flag/newlines/padding so we can re-encode the same way)
    private fun tryDecodeBase64WithFlag(input: String): Base64Result? {
        if (input.length < 10) return null
        val cleaned = input.trim()
        if (cleaned.isEmpty()) return null

        var hasStd = false
        var hasUrl = false
        var hadNewlines = false
        var hadPadding = false
        // Scan the alphabet: std vs url-safe, padding, newlines; bail on anything non-base64
        for (c in cleaned) {
            when {
                c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == ' ' || c == '\t' -> {}
                c == '=' -> hadPadding = true
                c == '\r' || c == '\n' -> { hadNewlines = true }
                c == '+' || c == '/' -> hasStd = true
                c == '-' || c == '_' -> hasUrl = true
                else -> return null
            }
        }
        if (hasStd && hasUrl) return null
        val rstripped = input.trimEnd(' ', '\t')
        val hadTrailingCrlf = rstripped.endsWith("\r\n")
        val hadTrailingNewline = hadTrailingCrlf || rstripped.endsWith("\n") || rstripped.endsWith("\r")
        val hadCrlf = (hadNewlines && cleaned.contains("\r\n")) || hadTrailingCrlf

        val flag = if (hasUrl) android.util.Base64.URL_SAFE else android.util.Base64.DEFAULT

        // Decode, then accept only if it's real text that looks like configs/links
        return try {
            val data = android.util.Base64.decode(cleaned, flag)
            if (data.isEmpty()) return null
            // Strict UTF-8 decode: binary/garbage is rejected (throws CharacterCodingException), valid text passes
            val decodedRaw = try {
                Charsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(data))
                    .toString()
            } catch (_: java.nio.charset.CharacterCodingException) {
                return null
            }
            // Control characters (except \t \n \r) and DEL indicate binary, so reject them
            for (ch in decodedRaw) {
                val cc = ch.code
                if (cc == 0x7f || (cc < 0x20 && cc != 0x09 && cc != 0x0a && cc != 0x0d)) return null
            }
            val decoded = decodedRaw.trimStart()
            val firstLine = decoded.lineSequence().firstOrNull { it.isNotBlank() }?.trimStart() ?: return null
            val looksLikeJson = firstLine.startsWith("{") || firstLine.startsWith("[")
            val looksLikeProxyList = PROXY_SCHEMES.any { firstLine.startsWith(it, ignoreCase = true) }
            if (looksLikeJson || looksLikeProxyList) {
                Base64Result(decoded, flag, hadNewlines, hadCrlf, hadPadding, hadTrailingNewline, hadTrailingCrlf)
            } else null
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    // Re-pack into base64 in exactly the same shape as the input
    private fun encodeBase64Like(text: String, b64: Base64Result): String {
        var flags = b64.flag
        if (!b64.hadNewlines) {
            flags = flags or android.util.Base64.NO_WRAP
        } else if (b64.hadCrlf) {
            flags = flags or android.util.Base64.CRLF
        }
        if (!b64.hadPadding) {
            flags = flags or android.util.Base64.NO_PADDING
        }
        val raw = android.util.Base64.encodeToString(text.toByteArray(Charsets.UTF_8), flags)
        val body = raw.trimEnd('\n', '\r')
        return when {
            b64.hadTrailingCrlf -> "$body\r\n"
            b64.hadTrailingNewline -> "$body\n"
            else -> body
        }
    }

    // JSON outbound to a link (vless/vmess/ss/trojan/hysteria2/tuic)
    private fun processJson(root: JSONObject): String? {
        if (isShadowsocks(root)) {
            return buildShadowsocks(root, root.optString("remarks", ""))
        }

        val protocol = root.optString("protocol", root.optString("type"))
        when (protocol) {
            "vmess" -> return buildVmess(root, root.optString("tag", root.optString("remarks", "")))
            "tuic" -> return buildTuic(root, root.optString("tag", root.optString("remarks", "")))
        }

        val obs = root.optJSONArray("outbounds")
        if (obs != null) {
            val rem = root.optString("remarks", "")
            for (i in 0 until obs.length()) {
                val ob = obs.getJSONObject(i)
                val p = ob.optString("protocol", ob.optString("type"))
                when (p) {
                    "vless" -> {
                        val c = buildVless(ob, rem)
                        if (c != null) return c
                    }
                    "vmess" -> {
                        val c = buildVmess(ob, rem)
                        if (c != null) return c
                    }
                    "shadowsocks" -> {
                        val c = buildShadowsocks(ob, rem)
                        if (c != null) return c
                    }
                    "trojan" -> {
                        val c = buildTrojan(ob, rem)
                        if (c != null) return c
                    }
                    "hysteria2" -> {
                        val c = buildHysteria2(ob, rem)
                        if (c != null) return c
                    }
                    "tuic" -> {
                        val c = buildTuic(ob, rem)
                        if (c != null) return c
                    }
                    else -> {
                       if (isShadowsocks(ob)) return buildShadowsocks(ob, rem)
                    }
                }
            }
        }
        return null
    }

    private fun isShadowsocks(obj: JSONObject): Boolean {
        if (obj.has("server") && obj.has("server_port") && obj.has("password") && obj.has("method")) return true
        val settings = obj.optJSONObject("settings")
        if (settings != null) {
            val servers = settings.optJSONArray("servers")
            if (servers != null && servers.length() > 0) {
                val s = servers.getJSONObject(0)
                if (s.has("address") && s.has("port") && s.has("password") && s.has("method")) return true
            }
        }
        return false
    }

    // --- Per-protocol link builders ---
    // VLESS: vnext/users plus reality/stream params
    private fun buildVless(ob: JSONObject, rem: String): String? {
        val s = ob.optJSONObject("settings") ?: return null
        val vnext = s.optJSONArray("vnext") ?: return null
        if (vnext.length() == 0) return null
        val vn = vnext.getJSONObject(0)
        val users = vn.optJSONArray("users") ?: return null
        if (users.length() == 0) return null
        val u = users.getJSONObject(0)
        val ss = ob.optJSONObject("streamSettings")
        val rs = ss?.optJSONObject("realitySettings")
        val enc = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        return "vless://${u.getString("id")}@${vn.getString("address")}:${vn.getInt("port")}?encryption=${u.optString("encryption","none")}&flow=${u.optString("flow","")}&fp=${rs?.optString("fingerprint","chrome")}&pbk=${rs?.optString("publicKey","")}&security=${ss?.optString("security","none")}&sid=${rs?.optString("shortId","")}&sni=${rs?.optString("serverName","")}&type=${ss?.optString("network","tcp")}#$enc"
    }

    // VMess: build the legacy JSON blob and base64 it
    private fun buildVmess(ob: JSONObject, rem: String): String? {
        return try {
            val linkJson = JSONObject()
            linkJson.put("v", "2")

            val settings = ob.optJSONObject("settings")
            val vnext = settings?.optJSONArray("vnext")?.optJSONObject(0)

            val addr = ob.optString("server", vnext?.optString("address", "") ?: "")
            val port = if (ob.has("server_port")) ob.getInt("server_port") else vnext?.optInt("port", 0) ?: 0
            val uuid = ob.optString("uuid", vnext?.optJSONArray("users")?.optJSONObject(0)?.optString("id", "") ?: "")

            linkJson.put("add", addr)
            linkJson.put("port", port.toString())
            linkJson.put("id", uuid)
            linkJson.put("aid", "0")
            linkJson.put("scy", "auto")

            val transport = ob.optJSONObject("transport")
            val stream = ob.optJSONObject("streamSettings")
            val net = transport?.optString("type") ?: stream?.optString("network") ?: "tcp"
            linkJson.put("net", net)

            val tlsObj = ob.optJSONObject("tls")
            val isTls = tlsObj?.optBoolean("enabled") ?: (stream?.optString("security") == "tls")
            linkJson.put("tls", if (isTls) "tls" else "")

            if (net == "ws") {
                val ws = transport ?: stream?.optJSONObject("wsSettings")
                linkJson.put("path", ws?.optString("path"))
                val host = ws?.optJSONObject("headers")?.optString("Host") ?: ws?.optString("headers")
                if (host != null) linkJson.put("host", host)
            }

            val finalRem = if (ob.has("tag")) ob.getString("tag") else (if (ob.has("remarks")) ob.getString("remarks") else rem)
            linkJson.put("ps", finalRem)

            val base64 = android.util.Base64.encodeToString(linkJson.toString().toByteArray(), android.util.Base64.NO_WRAP)
            "vmess://$base64"
        } catch (_: Exception) { null }
    }

    // Shadowsocks: base64(method:password)@host:port
    private fun buildShadowsocks(ob: JSONObject, rem: String): String? {
        return try {
            val address: String
            val port: Int
            val method: String
            val password: String
            if (ob.has("server")) {
                address = ob.getString("server")
                port = ob.getInt("server_port")
                method = ob.getString("method")
                password = ob.getString("password")
            } else {
                val settings = ob.optJSONObject("settings")
                val s = settings?.optJSONArray("servers")?.getJSONObject(0) ?: return null
                address = s.getString("address")
                port = s.getInt("port")
                method = s.getString("method")
                password = s.getString("password")
            }
            val credentials = "$method:$password"
            val ui = android.util.Base64.encodeToString(credentials.toByteArray(), android.util.Base64.NO_WRAP)
            val finalRem = if (ob.has("remarks")) ob.getString("remarks") else rem
            val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")
            "ss://$ui@$address:$port#$encRem"
        } catch (_: Exception) { null }
    }

    // Trojan: password@host:port with a tls/ws query
    private fun buildTrojan(ob: JSONObject, rem: String): String? {
        return try {
            val settings = ob.optJSONObject("settings")
            val server = settings?.optJSONArray("servers")?.optJSONObject(0) ?: return null
            val address = server.optString("address")
            val port = server.optInt("port")
            val password = server.optString("password")

            val ss = ob.optJSONObject("streamSettings")
            val network = ss?.optString("network")
            val security = ss?.optString("security")

            val query = mutableMapOf<String, String>()
            if (!network.isNullOrEmpty()) query["type"] = network

            if (security == "tls" || security == "reality") {
                val tls = ss.optJSONObject("tlsSettings") ?: ss.optJSONObject("realitySettings")
                val sni = tls?.optString("serverName")
                if (!sni.isNullOrEmpty()) {
                    query["sni"] = sni
                    query["host"] = sni
                }
            }

            if (network == "ws") {
                val ws = ss?.optJSONObject("wsSettings")
                val path = ws?.optString("path")
                val host = ws?.optJSONObject("headers")?.optString("Host")
                if (!path.isNullOrEmpty()) query["path"] = path
                if (!host.isNullOrEmpty()) query["host"] = host
            }

            val queryStr = query.toList().sortedBy { it.first }.joinToString("&") {
                "${it.first}=${URLEncoder.encode(it.second, "UTF-8")}"
            }

            val queryString = if (queryStr.isNotEmpty()) "?$queryStr" else ""
            val encPass = URLEncoder.encode(password, "UTF-8")
            val finalRem = if (ob.has("remarks")) ob.getString("remarks") else rem
            val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")

            "trojan://$encPass@$address:$port$queryString#$encRem"
        } catch (_: Exception) { null }
    }

    // Hysteria2: password@host:port with an obfs/sni query
    private fun buildHysteria2(ob: JSONObject, rem: String): String? {
        return try {
            val settings = ob.optJSONObject("settings")
            val server = settings?.optJSONArray("servers")?.optJSONObject(0) ?: return null
            val address = server.optString("address")
            val port = server.optInt("port")

            val ss = ob.optJSONObject("streamSettings")
            val hy2 = ss?.optJSONObject("hy2Settings")
            val password = hy2?.optString("password")
            val obfs = hy2?.optJSONObject("obfs")
            val obfsType = obfs?.optString("type")
            val obfsPassword = obfs?.optString("password")

            val tls = ss?.optJSONObject("tlsSettings")
            val sni = tls?.optString("serverName")

            val query = StringBuilder()
            if (!obfsType.isNullOrEmpty()) query.append("&obfs=").append(obfsType)
            if (!obfsPassword.isNullOrEmpty()) query.append("&obfs-password=").append(URLEncoder.encode(obfsPassword, "UTF-8"))
            if (!sni.isNullOrEmpty()) query.append("&sni=").append(sni)

            val queryString = if (query.isNotEmpty()) "?" + query.toString().substring(1) else ""
            val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")

            "hysteria2://$password@$address:$port/$queryString#$encRem"
        } catch (_: Exception) { null }
    }

    // TUIC: uuid:password@host:port with a congestion/tls query
    private fun buildTuic(ob: JSONObject, rem: String): String? {
        return try {
            val address = ob.optString("server")
            val port = ob.optInt("server_port")
            val uuid = ob.optString("uuid")
            val password = ob.optString("password")

            val query = mutableMapOf<String, String>()
            val cc = ob.optString("congestion_control")
            if (cc.isNotEmpty()) query["congestion_control"] = cc

            val mode = ob.optString("udp_relay_mode")
            if (mode.isNotEmpty()) query["udp_relay_mode"] = mode

            val tls = ob.optJSONObject("tls")
            if (tls != null && tls.optBoolean("enabled", false)) {
                val sni = tls.optString("server_name")
                if (sni.isNotEmpty()) query["sni"] = sni

                val alpnArr = tls.optJSONArray("alpn")
                if (alpnArr != null && alpnArr.length() > 0) {
                    query["alpn"] = alpnArr.getString(0)
                }

                if (tls.optBoolean("insecure", false)) {
                    query["allow_insecure"] = "1"
                }
            }

            val queryStr = query.toList().sortedBy { it.first }.joinToString("&") {
                "${it.first}=${URLEncoder.encode(it.second, "UTF-8")}"
            }
            val queryString = if (queryStr.isNotEmpty()) "?$queryStr" else ""

            val finalRem = if (ob.has("tag")) ob.getString("tag") else (if (ob.has("remarks")) ob.getString("remarks") else rem)
            val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")

            "tuic://$uuid:$password@$address:$port$queryString#$encRem"
        } catch (e: Exception) { null }
    }
}
