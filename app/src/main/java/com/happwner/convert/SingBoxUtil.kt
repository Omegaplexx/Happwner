package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// Small shared helpers for the sing-box converter. An object rather than top-level functions because
// the mihomo converter has its own splitHostPort, and the two are not interchangeable.
internal object SingBoxUtil {
    internal fun deepCopyObj(obj: JSONObject): JSONObject = JSONObject(obj.toString())

    internal fun deepCopyArr(arr: JSONArray): JSONArray = JSONArray(arr.toString())

    internal fun isTruthy(v: Any?): Boolean {
        if (v == null || v === JSONObject.NULL) return false
        return when (v) {
            is Boolean -> v
            is Number -> v.toDouble() != 0.0
            is String -> v.isNotEmpty()
            is JSONArray -> v.length() > 0
            is JSONObject -> v.length() > 0
            else -> true
        }
    }

    internal fun asList(v: Any?): List<Any?> {
        if (v == null || v === JSONObject.NULL) return emptyList()
        if (v is JSONArray) {
            val out = ArrayList<Any?>(v.length())
            for (i in 0 until v.length()) out.add(v.opt(i))
            return out
        }
        return listOf(v)
    }

    internal fun asStringList(v: Any?): List<String> {
        return asList(v).mapNotNull {
            when (it) {
                null, JSONObject.NULL -> null
                is String -> it
                else -> it.toString()
            }
        }
    }

    internal fun isIpLiteral(s: Any?): Boolean {
        if (s !is String || s.isEmpty()) return false
        return parseInet4(s) || parseInet6(s)
    }

    internal fun parseInet4(s: String): Boolean {
        val parts = s.split(".")
        if (parts.size != 4) return false
        for (p in parts) {
            if (p.isEmpty() || p.length > 3) return false
            for (c in p) if (c !in '0'..'9') return false
            val n = p.toIntOrNull() ?: return false
            if (n < 0 || n > 255) return false
            if (p.length > 1 && p[0] == '0') return false
        }
        return true
    }

    // Rough IPv6 parsing (::, embedded IPv4, zone-id)
    internal fun parseInet6(s: String): Boolean {
        if (s.isEmpty()) return false
        val core = s.substringBefore('%')
        if (core.isEmpty()) return false
        if (core == "::") return true
        val hasDoubleColon = core.contains("::")
        val tail = core.substringAfterLast(":")
        val embedded4 = tail.contains(".")
        // Split into groups around '::', folding any embedded IPv4
        val groupsRaw: List<String> = if (hasDoubleColon) {
            val (left, right) = core.split("::", limit = 2)
            val l = if (left.isEmpty()) emptyList() else left.split(":")
            val r = if (right.isEmpty()) emptyList() else right.split(":")
            l + r
        } else {
            core.split(":")
        }
        val groups = groupsRaw.toMutableList()
        if (embedded4) {
            val last = groups.removeAt(groups.size - 1)
            if (!parseInet4(last)) return false
            groups.add("0")
            groups.add("0")
        }
        val expected = 8
        val countWithoutDC = groups.size
        if (hasDoubleColon) {
            // Strictly fewer, not "no more than": "::" stands for one or more groups of zeros. Measured on
            // 1.13.15, a bad dns.hosts address refuses the whole document, so it cost the subscription.
            if (countWithoutDC >= expected) return false
        } else {
            if (countWithoutDC != expected) return false
        }
        for (g in groups) {
            if (g.isEmpty() || g.length > 4) return false
            for (c in g) {
                val ok = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'
                if (!ok) return false
            }
        }
        return true
    }

    internal fun toDuration(v: Any?): String? {
        if (v == null || v === JSONObject.NULL) return null
        if (v is Boolean) return null
        if (v is Int || v is Long) return "${(v as Number).toInt()}s"
        if (v is Double || v is Float) return "${(v as Number).toInt()}s"
        if (v is String) {
            val s = v.trim()
            if (s.isEmpty()) return null
            if (s.all { it in '0'..'9' }) return "${s}s"
            return s
        }
        return null
    }

    internal data class HostPort(val host: String, val port: Int?)

    internal fun splitHostPort(s: String?): HostPort {
        if (s.isNullOrEmpty()) return HostPort(s ?: "", null)
        if (s.startsWith("[")) {
            val rb = s.indexOf("]")
            if (rb < 0) return HostPort(s, null)
            val host = s.substring(1, rb)
            val rest = s.substring(rb + 1)
            if (rest.startsWith(":") && rest.substring(1).all { it in '0'..'9' }) {
                return HostPort(host, rest.substring(1).toIntOrNull())
            }
            return HostPort(host, null)
        }
        if (s.count { it == ':' } == 1) {
            val idx = s.indexOf(':')
            val host = s.substring(0, idx)
            val port = s.substring(idx + 1)
            if (port.isNotEmpty() && port.all { it in '0'..'9' }) return HostPort(host, port.toIntOrNull())
        }
        return HostPort(s, null)
    }

    // Make the tag unique: base, "base (2)", "base (3)", and so on
    internal fun makeUniqueTag(base: String, used: MutableSet<String>): String {
        if (base !in used) return base
        var i = 2
        while ("$base ($i)" in used) i++
        return "$base ($i)"
    }

    // Whether a routing value is one the target cores will accept.
    internal fun normalizedCidr(raw: String): String? {
        val v = raw.trim()
        if (v.isEmpty()) return null
        val slash = v.lastIndexOf('/')
        val addr = if (slash < 0) v else v.substring(0, slash)
        val maskText = if (slash < 0) null else v.substring(slash + 1)
        val v6 = addr.contains(':')
        if (v6) {
            // A bare colon-form address, checked loosely: the core does the
            // strict reading, this only keeps out what is plainly not one.
            if (!addr.all { it.isLetterOrDigit() || it == ':' || it == '.' }) return null
            if (!addr.contains("::") && addr.count { it == ':' } != 7) return null
        } else {
            val parts = addr.split('.')
            if (parts.size != 4) return null
            for (p in parts) {
                if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
                if ((p.toIntOrNull() ?: return null) > 255) return null
            }
        }
        val maxMask = if (v6) 128 else 32
        if (maskText == null) return "$addr/$maxMask"
        val mask = maskText.toIntOrNull() ?: return null
        if (mask < 0 || mask > maxMask) return null
        return "$addr/$mask"
    }

    // True when the pattern compiles; an unusable one is refused by the cores.
    internal fun isUsableRegex(raw: String): Boolean = try {
        Regex(raw)
        raw.isNotEmpty()
    } catch (_: Exception) {
        false
    }

    internal fun isUsablePort(p: Int): Boolean = p in 1..65535
}
