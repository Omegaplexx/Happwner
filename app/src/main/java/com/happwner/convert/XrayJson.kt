package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// Lenient accessors for reading Xray JSON. Xray configs in the wild are loosely typed: ports as
// `"443"`, booleans as `"true"`, single-element lists as bare strings, absent fields as JSON null.

// Reads key, mapping both a missing field and JSON null to null.
internal fun JSONObject?.xOpt(key: String): Any? {
    val v = this?.opt(key) ?: return null
    if (v === JSONObject.NULL) return null
    return v
}

// Reads key as an object, or null when it is missing or another type.
internal fun JSONObject?.xObj(key: String): JSONObject? = this.xOpt(key) as? JSONObject

// Reads key as an array, or null when it is missing or another type.
internal fun JSONObject?.xArr(key: String): JSONArray? = this.xOpt(key) as? JSONArray

// Coerces a scalar to a string, so a number or boolean reads as text.
internal fun xScalarString(v: Any?): String = when (v) {
    null -> ""
    is String -> v
    is JSONObject, is JSONArray -> ""
    else -> v.toString()
}

// Reads key as a trimmed string, accepting numbers and booleans.
internal fun JSONObject?.xStr(key: String): String = xScalarString(this.xOpt(key)).trim()

// Reads the first of keys that holds a non-empty string.
internal fun JSONObject?.xStrOf(vararg keys: String): String {
    for (k in keys) {
        val v = this.xStr(k)
        if (v.isNotEmpty()) return v
    }
    return ""
}

// Like xStr but without the trim, for values a person chose rather than a generator emitted -
// passwords and auth strings, where a leading or trailing space can be part of the secret.
internal fun JSONObject?.xStrRaw(key: String): String = xScalarString(this.xOpt(key))

// xStrOf without the trim - same reasoning as xStrRaw.
internal fun JSONObject?.xStrRawOf(vararg keys: String): String {
    for (k in keys) {
        val v = this.xStrRaw(k)
        if (v.isNotEmpty()) return v
    }
    return ""
}

// Reads key as an integer, accepting a quoted number or a float.
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

// Reads key as a 64-bit integer, for values such as QUIC window sizes.
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

// Reads key as a boolean, accepting "true"/"false" strings and 0/1.
internal fun JSONObject?.xBool(key: String): Boolean {
    val v = this.xOpt(key) ?: return false
    if (v is Boolean) return v
    if (v is Number) return v.toDouble() != 0.0
    return when (v.toString().trim().trim('"').lowercase()) {
        "true", "1", "yes", "on" -> true
        else -> false
    }
}

// True when key is present and not JSON null.
internal fun JSONObject?.xHas(key: String): Boolean = this.xOpt(key) != null

// True when sendThrough names a real local address to bind to. Xray's own default is "0.0.0.0",
// and "::" is the same thing for IPv6; neither binds anything, so neither is worth reporting.
internal fun JSONObject?.xBindsLocalAddress(): Boolean {
    val v = this.xStr("sendThrough")
    return v.isNotEmpty() && v != "0.0.0.0" && v != "::"
}

// True when a sockopt asks for a TCP keepalive of its own. Zero and absent both leave Xray's own
// 45s default alone; a positive value overrides it and a negative one switches it off.
internal fun JSONObject?.xAsksForKeepAlive(): Boolean =
    this.xInt("tcpKeepAliveIdle") != 0 || this.xInt("tcpKeepAliveInterval") != 0

// Reads a string list, accepting either a JSON array or a single comma-separated string, matching
// Xray's own StringList type. Empty entries are dropped.
internal fun JSONObject?.xStrList(key: String): List<String> {
    val v = this.xOpt(key) ?: return emptyList()
    if (v is JSONArray) {
        val out = ArrayList<String>(v.length())
        for (i in 0 until v.length()) {
            val raw = v.opt(i)
            val item = xScalarString(if (raw === JSONObject.NULL) null else raw).trim()
            if (item.isNotEmpty()) out.add(item)
        }
        return out
    }
    return xScalarString(v).split(",").map { it.trim() }.filter { it.isNotEmpty() }
}

// Reads the objects of an array field, skipping nulls and non-objects.
internal fun JSONObject?.xObjList(key: String): List<JSONObject> {
    val arr = this.xArr(key) ?: return emptyList()
    val out = ArrayList<JSONObject>(arr.length())
    for (i in 0 until arr.length()) {
        (arr.opt(i) as? JSONObject)?.let { out.add(it) }
    }
    return out
}
