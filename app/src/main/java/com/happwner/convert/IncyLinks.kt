package com.happwner.convert

import android.net.Uri
import android.util.Base64
import com.happwner.crypto.IncyCrypto

// Handler for INCY deep links (incy://add/<url>, incy://import/<base64>): mirrors INCY's own cg.h.b extraction
object IncyLinks {

    private const val ADD_PREFIX = "incy://add/"
    private const val IMPORT_PREFIX = "incy://import/"
    private const val INCY_SCHEME = "incy://"
    private const val EXTRACT_MAX_DEPTH = 2

    private val SCHEMES = arrayOf(
        "http://", "https://", "vless://", "vmess://", "trojan://",
        "ss://", "hy2://", "hysteria2://", "socks://", "socks5://",
        "wireguard://", "wg://"
    )

    // Is this an incy://add/ or incy://import/ deep link?
    fun isIncyLink(link: String?): Boolean {
        if (link == null) return false
        val t = link.trim()
        return t.regionMatches(0, ADD_PREFIX, 0, ADD_PREFIX.length, ignoreCase = true) ||
            t.regionMatches(0, IMPORT_PREFIX, 0, IMPORT_PREFIX.length, ignoreCase = true)
    }

    // Strip incy://add/ or incy://import/ and unwrap (url-decode, then scheme-or-base64) to the inner link
    fun stripIncyPrefix(link: String?): String? {
        if (link == null) return null
        val trimmed = link.trim()
        val tail = when {
            trimmed.regionMatches(0, ADD_PREFIX, 0, ADD_PREFIX.length, ignoreCase = true) ->
                trimmed.substring(ADD_PREFIX.length)
            trimmed.regionMatches(0, IMPORT_PREFIX, 0, IMPORT_PREFIX.length, ignoreCase = true) ->
                trimmed.substring(IMPORT_PREFIX.length)
            else -> return null
        }.trim()
        if (tail.isEmpty()) return null

        val decoded = try { Uri.decode(tail) } catch (_: Throwable) { tail }
        if (decoded.isEmpty()) return null
        if (looksLikeSchemeLink(decoded)) return decoded

        return decodeBase64OrNull(decoded)
    }

    // Extract an incy://add/, incy://import/ or incy://crypt1/ link wrapped in http(s) (up to 2 levels of URL-decoding)
    fun extractEmbeddedIncyLink(raw: String?): String? = extractEmbeddedIncyLink(raw, 0)

    private fun extractEmbeddedIncyLink(raw: String?, depth: Int): String? {
        if (raw == null) return null
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null

        if (trimmed.startsWith(INCY_SCHEME, ignoreCase = true)) return null
        if (!trimmed.startsWith("http://", ignoreCase = true) &&
            !trimmed.startsWith("https://", ignoreCase = true)) return null

        val start = indexOfIncyScheme(trimmed)
        if (start < 0) {
            if (depth < EXTRACT_MAX_DEPTH && trimmed.indexOf("incy%", ignoreCase = true) >= 0) {
                val once = try { Uri.decode(trimmed) } catch (_: Throwable) { null }
                if (once != null && once != trimmed) return extractEmbeddedIncyLink(once, depth + 1)
            }
            return null
        }

        val candidate = carveIncyCandidate(trimmed, start)
        val rawDecoded = try { Uri.decode(candidate) } catch (_: Throwable) { candidate }
        var decoded = (rawDecoded ?: candidate).trim()

        var guard = 0
        while (guard < EXTRACT_MAX_DEPTH && decoded.startsWith("incy%", ignoreCase = true)) {
            val next = try { Uri.decode(decoded) } catch (_: Throwable) { null } ?: break
            val nextTrimmed = next.trim()
            if (nextTrimmed == decoded) break
            decoded = nextTrimmed
            guard++
        }

        if (!isIncyLink(decoded) && !IncyCrypto.isCryptLink(decoded)) return null
        if (decoded == trimmed) return null
        return decoded
    }

    private fun looksLikeSchemeLink(s: String): Boolean {
        for (p in SCHEMES) if (s.startsWith(p, ignoreCase = true)) return true
        return false
    }

    // Decodes a base64 payload into the link it carries, or null when it is not one.
    private fun decodeBase64OrNull(s: String): String? {
        val cleaned = s.trim()
        if (cleaned.isEmpty()) return null

        var hasStd = false
        var hasUrl = false
        for (c in cleaned) {
            when {
                c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' -> {}
                c == '=' -> {}
                c == '+' || c == '/' -> hasStd = true
                c == '-' || c == '_' -> hasUrl = true
                else -> return null
            }
        }
        // Both alphabets at once is not an encoding, it is a coincidence.
        if (hasStd && hasUrl) return null

        val padded = when (cleaned.length % 4) {
            2 -> "$cleaned=="
            3 -> "$cleaned="
            else -> cleaned
        }
        val flag = if (hasUrl) Base64.URL_SAFE else Base64.DEFAULT

        return try {
            val data = Base64.decode(padded, flag)
            if (data.isEmpty()) return null
            // Text, not arbitrary bytes: a link is printable ASCII plus the
            // separators a multi-line list uses.
            for (b in data) {
                val v = b.toInt() and 0xff
                if (!(v in 0x20..0x7e || v == 0x09 || v == 0x0a || v == 0x0d)) return null
            }
            val text = String(data, Charsets.UTF_8).trim()
            if (looksLikeSchemeLink(text)) text else null
        } catch (_: Throwable) {
            null
        }
    }

    // Locate 'incy' followed by :// or %3a (case-insensitive)
    private fun indexOfIncyScheme(s: String): Int {
        val scheme = "incy"
        val n = s.length
        var i = 0
        while (i < n) {
            if (i + scheme.length <= n && s.regionMatches(i, scheme, 0, scheme.length, ignoreCase = true)) {
                val rest = i + scheme.length
                if (rest + 3 <= n && s[rest] == ':' && s[rest + 1] == '/' && s[rest + 2] == '/') return i
                if (rest + 3 <= n && s[rest] == '%' && s[rest + 1] == '3' &&
                    (s[rest + 2] == 'a' || s[rest + 2] == 'A')) return i
            }
            i++
        }
        return -1
    }

    // Take everything up to the first delimiter
    private fun carveIncyCandidate(s: String, start: Int): String {
        var end = start
        while (end < s.length && !isIncyDelimiter(s[end])) end++
        return s.substring(start, end)
    }

    // Characters that terminate an incy:// link
    private fun isIncyDelimiter(c: Char): Boolean {
        val o = c.code
        if (o < 0x20 || o > 0x7e) return true
        return when (c) {
            ' ', '&', '#', '"', '\'', '`', '<', '>', '\\', '|', '^', '{', '}', '[', ']' -> true
            else -> false
        }
    }
}
