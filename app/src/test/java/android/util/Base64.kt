package android.util

// android.util.Base64 for tests only: every method in the android.jar stub throws "Stub!" when called,
// so without this the tests would exercise the stub rather than the converter.
object Base64 {
    const val DEFAULT = 0
    const val NO_PADDING = 1
    const val NO_WRAP = 2
    const val CRLF = 4
    const val URL_SAFE = 8
    const val NO_CLOSE = 16

    @JvmStatic
    fun decode(str: String, flags: Int): ByteArray {
        val sb = StringBuilder(str.length)
        for (ch in str) {
            when (ch) {
                '\n', '\r', ' ', '\t' -> {}
                '-' -> sb.append('+')
                '_' -> sb.append('/')
                else -> sb.append(ch)
            }
        }
        var s = sb.toString()
        val eq = s.indexOf('=')
        if (eq >= 0) s = s.substring(0, eq)
        when (s.length % 4) {
            1 -> throw IllegalArgumentException("bad base64 length")
            2 -> s += "=="
            3 -> s += "="
        }
        return java.util.Base64.getDecoder().decode(s) // throws IllegalArgumentException on junk
    }

    @JvmStatic
    fun encodeToString(input: ByteArray, flags: Int): String {
        val url = flags and URL_SAFE != 0
        val noPad = flags and NO_PADDING != 0
        val noWrap = flags and NO_WRAP != 0
        val crlf = flags and CRLF != 0
        var enc = if (url) java.util.Base64.getUrlEncoder() else java.util.Base64.getEncoder()
        if (noPad) enc = enc.withoutPadding()
        val encoded = enc.encodeToString(input)
        if (noWrap) return encoded
        val sep = if (crlf) "\r\n" else "\n"
        val out = StringBuilder()
        var i = 0
        while (i < encoded.length) {
            val end = minOf(i + 76, encoded.length)
            out.append(encoded, i, end).append(sep)
            i = end
        }
        return out.toString()
    }
}
