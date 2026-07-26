package com.happwner

/**
 * A small YAML emitter that preserves key insertion order.
 *
 * Mihomo reads its configuration with a standard YAML parser, so this only has
 * to cover the subset a proxy configuration uses: ordered mappings, sequences
 * and scalars. Keeping our own emitter lets us control key ordering, so the
 * generated file reads the way a hand-written mihomo config does.
 */

/** A sequence rendered in block style, one item per line. */
internal class YamlSeq() : ArrayList<Any>() {
    constructor(items: Collection<Any>) : this() {
        addAll(items)
    }
}

/**
 * A sequence rendered inline as `[a, b, c]`, for short scalar lists such as
 * alpn, where block style would be needlessly verbose.
 */
internal class YamlFlowSeq() : ArrayList<Any>() {
    constructor(items: Collection<Any>) : this() {
        addAll(items)
    }
}

/** A scalar emitted verbatim. Only for values known to be valid YAML scalars. */
internal data class YamlRaw(val text: String)

/** Wraps a sequence item with a comment written above it. */
internal data class YamlCommented(val comment: String, val value: Any)

/** An ordered mapping. */
internal class YamlMap {
    private val keys = ArrayList<String>()
    private val vals = ArrayList<Any>()

    val size: Int get() = keys.size

    /**
     * Appends [key] with [value]. A null value is ignored, which lets callers
     * chain optional fields without guarding every one of them. Setting a key
     * that already exists overwrites it in place, keeping its position.
     */
    fun set(key: String, value: Any?): YamlMap {
        if (value == null) return this
        // Empty containers carry no information in a proxy config; drop them so
        // we do not emit "ws-opts: {}" style noise.
        when (value) {
            is YamlMap -> if (value.size == 0) return this
            is YamlSeq -> if (value.isEmpty()) return this
            is YamlFlowSeq -> if (value.isEmpty()) return this
        }
        val idx = keys.indexOf(key)
        if (idx >= 0) {
            vals[idx] = value
            return this
        }
        keys.add(key)
        vals.add(value)
        return this
    }

    /** Sets [key] unless the value is null or empty. */
    fun setStr(key: String, value: String?): YamlMap {
        if (value.isNullOrEmpty()) return this
        return set(key, value)
    }

    /** Sets [key] unless the value is zero. */
    fun setInt(key: String, value: Int): YamlMap {
        if (value == 0) return this
        return set(key, value)
    }

    /** Sets [key] only when [value] is true, mirroring mihomo's omitempty. */
    fun setBoolTrue(key: String, value: Boolean): YamlMap {
        if (!value) return this
        return set(key, true)
    }

    fun get(key: String): Any? {
        val idx = keys.indexOf(key)
        return if (idx >= 0) vals[idx] else null
    }

    fun has(key: String): Boolean = keys.contains(key)

    internal fun entries(): List<Pair<String, Any>> = keys.indices.map { keys[it] to vals[it] }
}

/** Renders [value] as a YAML document. */
internal fun encodeYaml(value: Any?): String {
    val sb = StringBuilder()
    encodeYamlValue(sb, value, 0, false)
    return sb.toString()
}

private fun indentOf(n: Int): String = " ".repeat(n)

/**
 * Writes [value] at the given indent level. When [inline] is true the caller has
 * already written the indentation (and possibly a "- " or "key: " prefix) for
 * the first line.
 */
private fun encodeYamlValue(sb: StringBuilder, value: Any?, indent: Int, inline: Boolean) {
    when (value) {
        is YamlMap -> encodeYamlMap(sb, value, indent, inline)
        is YamlSeq -> encodeYamlSeq(sb, value, indent, inline)
        is YamlFlowSeq -> {
            if (!inline) sb.append(indentOf(indent))
            sb.append(encodeFlowSeq(value))
            sb.append('\n')
        }
        else -> {
            if (!inline) sb.append(indentOf(indent))
            sb.append(yamlScalar(value))
            sb.append('\n')
        }
    }
}

private fun encodeYamlMap(sb: StringBuilder, map: YamlMap, indent: Int, inline: Boolean) {
    val entries = map.entries()
    if (entries.isEmpty()) {
        if (!inline) sb.append(indentOf(indent))
        sb.append("{}\n")
        return
    }
    for ((i, entry) in entries.withIndex()) {
        if (i > 0 || !inline) sb.append(indentOf(indent))
        sb.append(quoteYamlString(entry.first))
        sb.append(':')

        when (val child = entry.second) {
            is YamlMap -> {
                if (child.size == 0) {
                    sb.append(" {}\n")
                    continue
                }
                sb.append('\n')
                encodeYamlMap(sb, child, indent + 2, false)
            }
            is YamlSeq -> {
                if (child.isEmpty()) {
                    sb.append(" []\n")
                    continue
                }
                sb.append('\n')
                encodeYamlSeq(sb, child, indent + 2, false)
            }
            is YamlFlowSeq -> {
                sb.append(' ')
                sb.append(encodeFlowSeq(child))
                sb.append('\n')
            }
            else -> {
                sb.append(' ')
                sb.append(yamlScalar(child))
                sb.append('\n')
            }
        }
    }
}

private fun encodeYamlSeq(sb: StringBuilder, seq: YamlSeq, indent: Int, inline: Boolean) {
    for ((i, item) in seq.withIndex()) {
        if (item is YamlCommented) {
            // The comment needs a line of its own, so an inline first item has
            // to give up its position on the parent's line.
            if (i > 0 || !inline) sb.append(indentOf(indent))
            writeYamlComment(sb, item.comment, indent)
            sb.append(indentOf(indent))
            sb.append("- ")
            encodeYamlValue(sb, item.value, indent + 2, true)
            continue
        }
        if (i > 0 || !inline) sb.append(indentOf(indent))
        sb.append("- ")
        // Nested collections continue on the same line, indented two further
        // columns so the "- " acts as the first two spaces of that indent.
        encodeYamlValue(sb, item, indent + 2, true)
    }
}

private fun writeYamlComment(sb: StringBuilder, comment: String, indent: Int) {
    val lines = comment.split("\n")
    for ((i, line) in lines.withIndex()) {
        if (i > 0) sb.append(indentOf(indent))
        sb.append("# ")
        sb.append(line.trimEnd(' ', '\t'))
        sb.append('\n')
    }
}

private fun encodeFlowSeq(seq: YamlFlowSeq): String =
    seq.joinToString(", ", "[", "]") { yamlScalar(it) }

private fun yamlScalar(value: Any?): String = when (value) {
    null -> "null"
    is YamlRaw -> value.text
    is String -> quoteYamlString(value)
    is Boolean -> value.toString()
    is Int, is Long, is Short, is Byte -> value.toString()
    is Double -> formatYamlFloat(value)
    is Float -> formatYamlFloat(value.toDouble())
    else -> quoteYamlString(value.toString())
}

private fun formatYamlFloat(f: Double): String = when {
    f == Double.POSITIVE_INFINITY -> ".inf"
    f == Double.NEGATIVE_INFINITY -> "-.inf"
    f.isNaN() -> ".nan"
    f == Math.floor(f) && !f.isInfinite() && Math.abs(f) < 1e15 -> f.toLong().toString()
    else -> f.toString()
}

/**
 * Characters that start a YAML construct (sequence entry, mapping key, alias,
 * tag, block scalar, flow collection, ...). A plain scalar may not begin with
 * any of them.
 */
private const val LEADING_INDICATORS = "-?:,[]{}#&*!|>'\"%@`"

/** Renders [s] as a YAML scalar, quoting only when a plain scalar is ambiguous. */
internal fun quoteYamlString(s: String): String {
    if (!yamlNeedsQuoting(s)) return s
    if (canSingleQuote(s)) return "'" + s.replace("'", "''") + "'"
    return yamlDoubleQuote(s)
}

private fun yamlNeedsQuoting(s: String): Boolean {
    if (s.isEmpty()) return true
    for (c in s) {
        // Control characters and DEL cannot appear in a plain scalar.
        if (c.code < 0x20 || c.code == 0x7f) return true
    }
    if (s.startsWith(" ") || s.endsWith(" ")) return true
    if (LEADING_INDICATORS.indexOf(s[0]) >= 0) return true
    // ": " ends a key, " #" starts a comment, and a trailing ":" reads as a key.
    if (s.contains(": ") || s.contains(" #") || s.endsWith(":")) return true
    // Anything a YAML resolver would turn into a non-string type has to be
    // quoted to survive the round trip as a string.
    return looksLikeNonString(s)
}

/**
 * Scalars that YAML 1.1 and/or 1.2 implementations resolve to booleans or null.
 * Quoting all of them costs nothing and keeps the output portable across the
 * parsers different mihomo forks and editors use.
 */
private val NON_STRING_WORDS = setOf(
    "true", "false", "yes", "no", "on", "off", "y", "n", "null", "~", "nil"
)

private fun looksLikeNonString(s: String): Boolean {
    val lower = s.lowercase()
    if (lower in NON_STRING_WORDS) return true
    if (lower == ".inf" || lower == "-.inf" || lower == "+.inf" || lower == ".nan") return true
    if (s.toLongOrNull() != null) return true
    if (isPlainFloat(s)) return true
    // Alternative integer bases understood by YAML resolvers, e.g. "0x1f"
    // resolves to 31 rather than to the string.
    if (s.length > 2) {
        val body = when {
            lower.startsWith("0x") -> s.substring(2).toLongOrNull(16)
            lower.startsWith("0o") -> s.substring(2).toLongOrNull(8)
            lower.startsWith("0b") -> s.substring(2).toLongOrNull(2)
            else -> null
        }
        if (body != null) return true
    }
    // YAML 1.1 sexagesimals, e.g. "1:30" or "12:34:56".
    if (s.contains(":") && isSexagesimal(s)) return true
    return false
}

/**
 * Reports whether [s] is a decimal float literal. Deliberately stricter than
 * [String.toDoubleOrNull], which also accepts hex floats and "1.0f" style
 * suffixes that YAML would keep as strings.
 */
private fun isPlainFloat(s: String): Boolean {
    if (s.isEmpty()) return false
    var seenDigit = false
    var seenDot = false
    var seenExp = false
    var i = 0
    if (s[i] == '+' || s[i] == '-') i++
    while (i < s.length) {
        val c = s[i]
        when {
            c in '0'..'9' -> seenDigit = true
            c == '.' && !seenDot && !seenExp -> seenDot = true
            (c == 'e' || c == 'E') && seenDigit && !seenExp -> {
                seenExp = true
                seenDigit = false
                if (i + 1 < s.length && (s[i + 1] == '+' || s[i + 1] == '-')) i++
            }
            else -> return false
        }
        i++
    }
    return seenDigit && (seenDot || seenExp)
}

private fun isSexagesimal(s: String): Boolean {
    val parts = s.removePrefix("-").removePrefix("+").split(":")
    if (parts.size < 2) return false
    for (p in parts) {
        if (p.isEmpty()) return false
        for (c in p) if (c < '0' || c > '9') return false
    }
    return true
}

private fun canSingleQuote(s: String): Boolean {
    // Single-quoted scalars cannot carry escapes, so any character that must be
    // escaped forces double quotes.
    for (c in s) if (c.code < 0x20 || c.code == 0x7f) return false
    return true
}

private fun yamlDoubleQuote(s: String): String {
    val sb = StringBuilder(s.length + 2)
    sb.append('"')
    for (c in s) {
        when {
            c == '"' -> sb.append("\\\"")
            c == '\\' -> sb.append("\\\\")
            c == '\n' -> sb.append("\\n")
            c == '\r' -> sb.append("\\r")
            c == '\t' -> sb.append("\\t")
            c.code == 0 -> sb.append("\\0")
            c.code < 0x20 || c.code == 0x7f -> sb.append("\\x").append(
                c.code.toString(16).padStart(2, '0')
            )
            else -> sb.append(c)
        }
    }
    sb.append('"')
    return sb.toString()
}
