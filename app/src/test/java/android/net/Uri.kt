package android.net

import java.net.URLDecoder

// android.net.Uri, for tests only. Enough of the platform class for the link parsers: the parts
// they read off a share link, and the encoding and decoding they do to build one.
class Uri private constructor(private val raw: String) {

    val scheme: String?
        get() {
            val i = raw.indexOf(':')
            if (i <= 0) return null
            val s = raw.substring(0, i)
            return if (s.all { it.isLetterOrDigit() || it == '+' || it == '-' || it == '.' }) s else null
        }

    private val afterScheme: String
        get() {
            val i = raw.indexOf(':')
            return if (i < 0) raw else raw.substring(i + 1)
        }

    val host: String?
        get() {
            val a = afterScheme
            if (!a.startsWith("//")) return null
            val rest = a.substring(2)
            val end = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }
            val authority = if (end < 0) rest else rest.substring(0, end)
            val hostPart = authority.substringAfterLast('@')
            return hostPart.substringBefore(':').ifEmpty { null }
        }

    val path: String?
        get() {
            var a = afterScheme
            if (a.startsWith("//")) {
                val rest = a.substring(2)
                val i = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }
                a = if (i < 0 || rest[i] != '/') "" else rest.substring(i)
            }
            return a.substringBefore('?').substringBefore('#')
        }

    val lastPathSegment: String?
        get() = path?.trim('/')?.substringAfterLast('/')?.ifEmpty { null }

    val pathSegments: List<String>
        get() = path?.split('/')?.filter { it.isNotEmpty() } ?: emptyList()

    val query: String?
        get() {
            val q = raw.substringAfter('?', "")
            if (q.isEmpty()) return null
            return q.substringBefore('#')
        }

    fun getQueryParameter(key: String): String? {
        val q = query ?: return null
        for (pair in q.split("&")) {
            if (pair.isEmpty()) continue
            val i = pair.indexOf('=')
            val k = if (i < 0) pair else pair.substring(0, i)
            if (decode(k) == key) {
                return if (i < 0) "" else decode(pair.substring(i + 1))
            }
        }
        return null
    }

    override fun toString(): String = raw

    companion object {
        @JvmStatic
        fun parse(uriString: String): Uri = Uri(uriString)

        // Android declares these as platform types, so callers use them without null checks; the
        // shim has to be shaped the same way to compile the same sources.
        @JvmStatic
        fun decode(s: String): String {
            return try {
                URLDecoder.decode(s.replace("+", "%2B"), "UTF-8")
            } catch (_: Exception) {
                s
            }
        }

        @JvmStatic
        fun encode(s: String): String =
            java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")
    }
}
