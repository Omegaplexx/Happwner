package com.happwner

import org.json.JSONArray
import org.json.JSONObject

/**
 * Lenient readers for Xray Core JSON.
 *
 * Xray accepts values that generators stringify inconsistently -- `"port": 443`
 * and `"port": "443"` both parse -- and most protocols accept both a nested
 * server list and a flat single-server form. These helpers hide that, so the
 * converter can read a field without caring how it was spelled.
 */

/** Returns the value at [key], mapping JSON null to Kotlin null. */
internal fun JSONObject?.xOpt(key: String): Any? {
    val v = this?.opt(key) ?: return null
    if (v === JSONObject.NULL) return null
    return v
}

internal fun JSONObject?.xObj(key: String): JSONObject? = this.xOpt(key) as? JSONObject

internal fun JSONObject?.xArr(key: String): JSONArray? = this.xOpt(key) as? JSONArray

/** Coerces a scalar to a string, so a number or boolean reads as text. */
internal fun xScalarString(v: Any?): String = when (v) {
    null -> ""
    is String -> v
    is JSONObject, is JSONArray -> ""
    else -> v.toString()
}

/** Reads [key] as a trimmed string, accepting numbers and booleans. */
internal fun JSONObject?.xStr(key: String): String = xScalarString(this.xOpt(key)).trim()

/** Reads the first of [keys] that holds a non-empty string. */
internal fun JSONObject?.xStrOf(vararg keys: String): String {
    for (k in keys) {
        val v = this.xStr(k)
        if (v.isNotEmpty()) return v
    }
    return ""
}

/** Reads [key] as an integer, accepting a quoted number or a float. */
internal fun JSONObject?.xInt(key: String): Int {
    val v = this.xOpt(key) ?: return 0
    if (v is Number) return v.toInt()
    if (v is Boolean) return 0
    val s = v.toString().trim().trim('"')
    if (s.isEmpty()) return 0
    s.toLongOrNull()?.let { return it.toInt() }
    s.toDoubleOrNull()?.let { return it.toInt() }
    return 0
}

/** Reads [key] as a 64-bit integer, for the QUIC window sizes. */
internal fun JSONObject?.xLong(key: String): Long {
    val v = this.xOpt(key) ?: return 0L
    if (v is Number) return v.toLong()
    if (v is Boolean) return 0L
    val s = v.toString().trim().trim('"')
    if (s.isEmpty()) return 0L
    s.toLongOrNull()?.let { return it }
    s.toDoubleOrNull()?.let { return it.toLong() }
    return 0L
}

/** Reads [key] as a boolean, accepting "true"/"false" strings and 0/1. */
internal fun JSONObject?.xBool(key: String): Boolean {
    val v = this.xOpt(key) ?: return false
    if (v is Boolean) return v
    if (v is Number) return v.toDouble() != 0.0
    return when (v.toString().trim().trim('"').lowercase()) {
        "true", "1", "yes", "on" -> true
        else -> false
    }
}

/** True when [key] is present and not JSON null. */
internal fun JSONObject?.xHas(key: String): Boolean = this.xOpt(key) != null

/**
 * Reads a string list, accepting either a JSON array or a single
 * comma-separated string, matching Xray's own StringList type.
 */
internal fun JSONObject?.xStrList(key: String): List<String> {
    val v = this.xOpt(key) ?: return emptyList()
    if (v is JSONArray) {
        val out = ArrayList<String>(v.length())
        for (i in 0 until v.length()) {
            val item = xScalarString(if (v.opt(i) === JSONObject.NULL) null else v.opt(i)).trim()
            if (item.isNotEmpty()) out.add(item)
        }
        return out
    }
    return xScalarString(v).split(",").map { it.trim() }.filter { it.isNotEmpty() }
}

/** Reads the objects of an array field, skipping nulls and non-objects. */
internal fun JSONObject?.xObjList(key: String): List<JSONObject> {
    val arr = this.xArr(key) ?: return emptyList()
    val out = ArrayList<JSONObject>(arr.length())
    for (i in 0 until arr.length()) {
        (arr.opt(i) as? JSONObject)?.let { out.add(it) }
    }
    return out
}

/**
 * Xray's Int32Range: a plain number or a "from-to" string. Mihomo takes the
 * same information as a string, so [render] gives it back in that form.
 */
internal data class XRange(val from: Int, val to: Int, val set: Boolean) {
    /** A bare number when both ends match, "from-to" otherwise, "" when unset. */
    fun render(): String = when {
        !set -> ""
        from == to -> from.toString()
        else -> "$from-$to"
    }

    /** Renders the range, treating an all-zero one as unset. */
    fun renderNonZero(): String = if (!set || (from == 0 && to == 0)) "" else render()

    companion object {
        val UNSET = XRange(0, 0, false)
    }
}

internal fun JSONObject?.xRange(key: String): XRange {
    val v = this.xOpt(key) ?: return XRange.UNSET
    if (v is Number) {
        val n = v.toInt()
        return XRange(n, n, true)
    }
    val s = xScalarString(v).trim().trim('"')
    if (s.isEmpty()) return XRange.UNSET
    return parseRangeString(s) ?: XRange.UNSET
}

/** Handles "114", "114-514" and negative bounds such as "-114-514". */
internal fun parseRangeString(s: String): XRange? {
    s.toIntOrNull()?.let { return XRange(it, it, true) }
    val parts = splitFromSecondDash(s) ?: return null
    val from = parts.first.trim().toIntOrNull() ?: return null
    val to = parts.second.trim().toIntOrNull() ?: return null
    return if (from > to) XRange(to, from, true) else XRange(from, to, true)
}

/** Splits "-114-514" into "-114" and "514", so a negative bound survives. */
private fun splitFromSecondDash(s: String): Pair<String, String>? {
    val parts = s.split("-", limit = 3)
    return when (parts.size) {
        2 -> parts[0] to parts[1]
        3 -> if (parts[0].isEmpty()) ("-" + parts[1]) to parts[2] else parts[0] to (parts[1] + "-" + parts[2])
        else -> null
    }
}

/**
 * Reads Xray's port list in any of its spellings: a single number, a
 * "1000-2000" range, a comma-separated list of either, or a JSON array of
 * those. The textual form is what mihomo's "ports" takes.
 */
internal fun JSONObject?.xPortList(key: String): String {
    val v = this.xOpt(key) ?: return ""
    if (v is JSONArray) {
        val parts = ArrayList<String>(v.length())
        for (i in 0 until v.length()) {
            val item = xScalarString(if (v.opt(i) === JSONObject.NULL) null else v.opt(i)).trim()
            if (item.isNotEmpty()) parts.add(item)
        }
        return parts.joinToString(",")
    }
    return xScalarString(v).trim()
}

/** Reads a string map, as transport headers use. */
internal fun JSONObject?.xHeaders(key: String): Map<String, String> {
    val obj = this.xObj(key) ?: return emptyMap()
    val out = LinkedHashMap<String, String>()
    for (name in obj.keys()) {
        out[name] = xScalarString(obj.xOpt(name)).trim()
    }
    return out
}

/** Reads a header map whose values may be lists, as the raw HTTP masquerade uses. */
internal fun JSONObject?.xHeaderLists(key: String): Map<String, List<String>> {
    val obj = this.xObj(key) ?: return emptyMap()
    val out = LinkedHashMap<String, List<String>>()
    for (name in obj.keys()) {
        out[name] = obj.xStrList(name)
    }
    return out
}

// ------------------------------------------------------------ stream ----

/** The normalised transport name of a streamSettings object. */
internal fun streamNetwork(ss: JSONObject?): String {
    if (ss == null) return "tcp"
    var n = ss.xStr("network").lowercase()
    if (n.isEmpty()) n = ss.xStr("type").lowercase()
    return when (n) {
        "", "tcp", "raw", "none" -> "tcp"
        "websocket" -> "ws"
        "splithttp" -> "xhttp"
        "mkcp" -> "kcp"
        "gun" -> "grpc"
        // In Xray, "http" is the HTTP/2 transport. It is not the same thing as
        // mihomo's "http" network, which is the HTTP masquerade that Xray
        // spells as a raw-TCP header.
        "http", "h2", "h3" -> "h2"
        else -> n
    }
}

/** The normalised security layer name of a streamSettings object. */
internal fun streamSecurity(ss: JSONObject?): String {
    if (ss == null) return "none"
    return when (val sec = ss.xStr("security").lowercase()) {
        "", "none", "auto" -> {
            // A config may omit "security" but still carry tlsSettings; Xray
            // ignores that, and so do we, except for REALITY which is only ever
            // present deliberately.
            if (sec.isEmpty() && ss.xObj("realitySettings") != null) "reality" else "none"
        }
        "xtls" -> "tls"
        else -> sec
    }
}

/** The effective TLS settings, under either spelling. */
internal fun streamTls(ss: JSONObject?): JSONObject? =
    ss.xObj("tlsSettings") ?: ss.xObj("xtlsSettings")

/** The raw/tcp transport settings, under either spelling. */
internal fun streamTcp(ss: JSONObject?): JSONObject? =
    ss.xObj("rawSettings") ?: ss.xObj("tcpSettings")

/** The websocket settings, under either spelling. */
internal fun streamWs(ss: JSONObject?): JSONObject? =
    ss.xObj("wsSettings") ?: ss.xObj("websocketSettings")

/** The gRPC settings, under either spelling. */
internal fun streamGrpc(ss: JSONObject?): JSONObject? =
    ss.xObj("grpcSettings") ?: ss.xObj("gunSettings")

/** The XHTTP settings, under either spelling, with "extra" already applied. */
internal fun streamXhttp(ss: JSONObject?): JSONObject? {
    val cfg = ss.xObj("xhttpSettings") ?: ss.xObj("splithttpSettings") ?: return null
    return resolveXhttpExtra(cfg)
}

/**
 * Applies XHTTP's "extra" object the way Xray does: everything comes from
 * "extra", except host, path and mode, which stay with the outer object.
 *
 * This matters, because a naive merge would keep outer values that Xray
 * discards -- headers and padding above all -- producing a node that behaves
 * differently from the source.
 */
internal fun resolveXhttpExtra(cfg: JSONObject): JSONObject {
    val extra = cfg.xObj("extra") ?: return cfg
    val out = JSONObject(extra.toString())
    for (key in listOf("host", "path", "mode")) {
        val outer = cfg.xOpt(key)
        if (outer != null) out.put(key, outer) else out.remove(key)
    }
    out.remove("extra")
    return out
}

/** The first finalmask UDP mask of the given type. */
internal fun streamUdpMask(ss: JSONObject?, maskType: String): JSONObject? {
    val masks = ss.xObj("finalmask").xArr("udp") ?: return null
    for (i in 0 until masks.length()) {
        val m = masks.opt(i) as? JSONObject ?: continue
        if (m.xStr("type").equals(maskType, ignoreCase = true)) return m
    }
    return null
}

/** The finalmask QUIC parameters, if any. */
internal fun streamQuicParams(ss: JSONObject?): JSONObject? = ss.xObj("finalmask").xObj("quicParams")

// -------------------------------------------------------------- JSONC ----

/**
 * Removes `//` and `/* */` comments and trailing commas.
 *
 * Xray accepts commented JSON and hand-maintained configs use it heavily, so
 * the converter has to as well. Comment characters inside string literals are
 * left alone. Android's JSON parser tolerates some of this already and the
 * reference one tolerates none of it, so doing it here keeps the result the
 * same everywhere.
 */
internal fun stripJsonComments(data: String): String {
    val out = StringBuilder(data.length)
    var inString = false
    var escaped = false
    var i = 0
    while (i < data.length) {
        val c = data[i]

        if (inString) {
            out.append(c)
            when {
                escaped -> escaped = false
                c == '\\' -> escaped = true
                c == '"' -> inString = false
            }
            i++
            continue
        }

        when {
            c == '"' -> {
                inString = true
                out.append(c)
                i++
            }
            c == '/' && i + 1 < data.length && data[i + 1] == '/' -> {
                while (i < data.length && data[i] != '\n') i++
                // Keep the newline so the text keeps its line structure.
                if (i < data.length) {
                    out.append('\n')
                    i++
                }
            }
            c == '/' && i + 1 < data.length && data[i + 1] == '*' -> {
                i += 2
                while (i + 1 < data.length && !(data[i] == '*' && data[i + 1] == '/')) {
                    if (data[i] == '\n') out.append('\n')
                    i++
                }
                i += 2
            }
            else -> {
                out.append(c)
                i++
            }
        }
    }
    return stripTrailingCommas(out.toString())
}

/**
 * Removes commas that directly precede a closing brace or bracket, which JSON
 * rejects but hand-written configs often contain.
 */
private fun stripTrailingCommas(data: String): String {
    val out = StringBuilder(data.length)
    var inString = false
    var escaped = false
    var i = 0
    while (i < data.length) {
        val c = data[i]
        if (inString) {
            out.append(c)
            when {
                escaped -> escaped = false
                c == '\\' -> escaped = true
                c == '"' -> inString = false
            }
            i++
            continue
        }
        if (c == '"') {
            inString = true
            out.append(c)
            i++
            continue
        }
        if (c == ',') {
            var j = i + 1
            while (j < data.length && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r')) j++
            if (j < data.length && (data[j] == '}' || data[j] == ']')) {
                i++ // drop the comma
                continue
            }
        }
        out.append(c)
        i++
    }
    return out.toString()
}

// ------------------------------------------------------------ shared ----

/** Returns the first non-blank value, or "". */
internal fun firstNonEmpty(vararg values: String?): String {
    for (v in values) {
        val s = v?.trim().orEmpty()
        if (s.isNotEmpty()) return s
    }
    return ""
}

/** Removes the brackets from a literal IPv6 address, which mihomo wants bare. */
internal fun stripBrackets(host: String): String =
    if (host.startsWith("[") && host.endsWith("]")) host.substring(1, host.length - 1) else host

/** Splits "host:port", accepting a bracketed IPv6 literal. */
internal fun splitHostPort(raw: String): Pair<String, String>? {
    val s = raw.trim()
    if (s.startsWith("[")) {
        val end = s.lastIndexOf(']')
        if (end < 0) return null
        val host = s.substring(1, end)
        val rest = s.substring(end + 1)
        if (!rest.startsWith(":")) return null
        return host to rest.substring(1)
    }
    val i = s.lastIndexOf(':')
    if (i < 0) return null
    val host = s.substring(0, i)
    // An unbracketed IPv6 literal is ambiguous, so it is not accepted.
    if (host.contains(":")) return null
    return host to s.substring(i + 1)
}

/** Parses a port, rejecting values outside 1-65535. */
internal fun parsePort(s: String): Int? {
    val p = s.trim().toIntOrNull() ?: return null
    if (p <= 0 || p > 65535) return null
    return p
}

// ------------------------------------------------------------ base64 ----

private const val B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
private const val B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

/**
 * Decodes base64 with the given alphabet. When [padded] is true the input must
 * carry its "=" padding, mirroring how Go tells the padded and raw encodings
 * apart; when false, padding is rejected.
 */
internal fun decodeBase64(input: String, urlSafe: Boolean, padded: Boolean): ByteArray? {
    val alphabet = if (urlSafe) B64_URL else B64_STD
    val s = input.trim()
    if (s.isEmpty()) return ByteArray(0)
    if (padded) {
        if (s.length % 4 != 0) return null
    } else {
        if (s.contains('=')) return null
        if (s.length % 4 == 1) return null
    }

    var body = s
    var padCount = 0
    while (body.endsWith("=")) {
        body = body.dropLast(1)
        padCount++
    }
    if (padCount > 2) return null
    if (padded && padCount != (4 - body.length % 4) % 4) return null

    val out = java.io.ByteArrayOutputStream(body.length * 3 / 4 + 3)
    var buffer = 0
    var bits = 0
    for (c in body) {
        val idx = alphabet.indexOf(c)
        if (idx < 0) return null
        buffer = (buffer shl 6) or idx
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out.write((buffer shr bits) and 0xFF)
        }
    }
    // Leftover bits must be zero padding, never data.
    if (bits > 0 && (buffer and ((1 shl bits) - 1)) != 0) return null
    return out.toByteArray()
}

/** Decodes standard or URL-safe base64, padded or not. */
internal fun decodeBase64Any(s: String): ByteArray? {
    decodeBase64(s, urlSafe = false, padded = true)?.let { return it }
    decodeBase64(s, urlSafe = false, padded = false)?.let { return it }
    decodeBase64(s, urlSafe = true, padded = true)?.let { return it }
    decodeBase64(s, urlSafe = true, padded = false)?.let { return it }
    return null
}

/** Decodes the unpadded URL-safe base64 that VLESS encryption keys use. */
internal fun decodeBase64RawUrl(s: String): ByteArray? = decodeBase64(s, urlSafe = true, padded = false)

/** Encodes bytes as padded standard base64. */
internal fun encodeBase64Std(data: ByteArray): String {
    val sb = StringBuilder((data.size + 2) / 3 * 4)
    var i = 0
    while (i + 2 < data.size) {
        val n = ((data[i].toInt() and 0xFF) shl 16) or
            ((data[i + 1].toInt() and 0xFF) shl 8) or
            (data[i + 2].toInt() and 0xFF)
        sb.append(B64_STD[(n shr 18) and 0x3F])
        sb.append(B64_STD[(n shr 12) and 0x3F])
        sb.append(B64_STD[(n shr 6) and 0x3F])
        sb.append(B64_STD[n and 0x3F])
        i += 3
    }
    when (data.size - i) {
        1 -> {
            val n = (data[i].toInt() and 0xFF) shl 16
            sb.append(B64_STD[(n shr 18) and 0x3F])
            sb.append(B64_STD[(n shr 12) and 0x3F])
            sb.append("==")
        }
        2 -> {
            val n = ((data[i].toInt() and 0xFF) shl 16) or ((data[i + 1].toInt() and 0xFF) shl 8)
            sb.append(B64_STD[(n shr 18) and 0x3F])
            sb.append(B64_STD[(n shr 12) and 0x3F])
            sb.append(B64_STD[(n shr 6) and 0x3F])
            sb.append('=')
        }
    }
    return sb.toString()
}

/** Renders bytes as lowercase hex. */
internal fun toHex(data: ByteArray): String {
    val sb = StringBuilder(data.size * 2)
    for (b in data) {
        val v = b.toInt() and 0xFF
        sb.append("0123456789abcdef"[v shr 4])
        sb.append("0123456789abcdef"[v and 0x0F])
    }
    return sb.toString()
}

/** Decodes lowercase or uppercase hex, or null when the text is not hex. */
internal fun fromHex(s: String): ByteArray? {
    if (s.length % 2 != 0) return null
    val out = ByteArray(s.length / 2)
    for (i in out.indices) {
        val hi = Character.digit(s[i * 2], 16)
        val lo = Character.digit(s[i * 2 + 1], 16)
        if (hi < 0 || lo < 0) return null
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}
