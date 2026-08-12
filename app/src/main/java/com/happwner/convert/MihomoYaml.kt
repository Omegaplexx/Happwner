package com.happwner.convert

// A small YAML emitter that preserves key insertion order.

// A sequence rendered in block style, one item per line.
internal class YamlSeq() : ArrayList<Any>() {
    constructor(items: Collection<Any>) : this() {
        addAll(items)
    }
}

// A sequence rendered inline as `[a, b, c]`, for short scalar lists such as alpn, where block style
// would be needlessly verbose.
internal class YamlFlowSeq() : ArrayList<Any>() {
    constructor(items: Collection<Any>) : this() {
        addAll(items)
    }
}

// A scalar emitted verbatim. Only for values known to be valid YAML scalars.
internal data class YamlRaw(val text: String)

// Wraps a sequence item with a comment written above it.
internal data class YamlCommented(val comment: String, val value: Any)

// An ordered mapping.
internal class YamlMap {
    private val keys = ArrayList<String>()
    private val vals = ArrayList<Any>()

    val size: Int get() = keys.size

    // Appends key with value. A null value is ignored, so callers can chain optional fields
    // unguarded; an existing key is overwritten in place.
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

    // Sets key unless the value is null or empty.
    fun setStr(key: String, value: String?): YamlMap {
        if (value.isNullOrEmpty()) return this
        return set(key, value)
    }

    // Sets key unless the value is zero.
    fun setInt(key: String, value: Int): YamlMap {
        if (value == 0) return this
        return set(key, value)
    }

    // Sets key only when value is true, mirroring mihomo's omitempty.
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

// Renders value as a YAML document.
internal fun encodeYaml(value: Any?): String {
    val sb = StringBuilder()
    encodeYamlValue(sb, value, 0, false)
    return sb.toString()
}

private fun indentOf(n: Int): String = " ".repeat(n)

// Writes value at the given indent level. inline means the caller already wrote the indentation
// (and any "- " or "key: " prefix) for the first line.
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
            // The comment shares the parent's line ("- # text") with the real value in the block
            // underneath.
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

// Writes comment as one or more `#` lines. Comment text is not inert: it is built from the Xray
// configuration, which arrives from whoever served the subscription.
private fun writeYamlComment(sb: StringBuilder, comment: String, indent: Int) {
    val lines = comment.split("\r\n", "\n", "\r", "\u0085", "\u2028", "\u2029")
    for ((i, line) in lines.withIndex()) {
        if (i > 0) sb.append(indentOf(indent))
        sb.append("# ")
        sb.append(line.filter { it.code >= 0x20 && it.code != 0x7f }.trimEnd(' ', '\t'))
        sb.append('\n')
    }
}

private fun encodeFlowSeq(seq: YamlFlowSeq): String =
    seq.joinToString(", ", "[", "]") { yamlScalar(it, flow = true) }

private fun yamlScalar(value: Any?, flow: Boolean = false): String = when (value) {
    null -> "null"
    is YamlRaw -> value.text
    is String -> quoteYamlScalar(value, flow)
    is Boolean -> value.toString()
    is Int, is Long, is Short, is Byte -> value.toString()
    is Double -> formatYamlFloat(value)
    is Float -> formatYamlFloat(value.toDouble())
    else -> quoteYamlScalar(value.toString(), flow)
}

private fun formatYamlFloat(f: Double): String = when {
    f == Double.POSITIVE_INFINITY -> ".inf"
    f == Double.NEGATIVE_INFINITY -> "-.inf"
    f.isNaN() -> ".nan"
    f == Math.floor(f) && !f.isInfinite() && Math.abs(f) < 1e15 -> f.toLong().toString()
    else -> f.toString()
}

// Quoting: a port of resolve.go from gopkg.in/yaml.v3, which is what mihomo parses with.

// Characters that start a YAML construct (sequence entry, mapping key, alias, tag, block scalar,
// flow collection). A plain scalar may not begin with one.
private const val LEADING_INDICATORS = "-?:,[]{}#&*!|>'\"%@`"

// Characters that end a plain scalar inside a flow collection - allowed in block context, not in
// flow, which is why quoting must know which it emits into.
private const val FLOW_INDICATORS = ",[]{}?"

// Characters yaml.v3 treats as a line break (`is_break` in yamlprivateh.go): CR, LF, NEL,
// LINE/PARAGRAPH SEPARATOR. Emitted raw they end the scalar and the value comes back null.
private fun mustEscape(c: Char): Boolean =
    c.code < 0x20 || c.code == 0x7f || c.code == 0x85 ||
        c.code == 0x2028 || c.code == 0x2029 || c.code == 0xfeff

// Renders s as a YAML scalar, quoting only when a plain scalar is ambiguous.
internal fun quoteYamlString(s: String): String = quoteYamlScalar(s, flow = false)

internal fun quoteYamlScalar(s: String, flow: Boolean): String {
    if (!yamlNeedsQuoting(s, flow)) return s
    if (canSingleQuote(s)) return "'" + s.replace("'", "''") + "'"
    return yamlDoubleQuote(s)
}

private fun yamlNeedsQuoting(s: String, flow: Boolean): Boolean {
    if (s.isEmpty()) return true
    for (c in s) if (mustEscape(c)) return true
    if (s.startsWith(" ") || s.endsWith(" ")) return true
    if (LEADING_INDICATORS.indexOf(s[0]) >= 0) return true
    // ": " ends a key, " #" starts a comment, and a trailing ":" reads as a key.
    if (s.contains(": ") || s.contains(" #") || s.endsWith(":")) return true
    if (flow) {
        for (c in s) if (FLOW_INDICATORS.indexOf(c) >= 0) return true
    }
    // Anything a YAML resolver would turn into a non-string type has to be
    // quoted to survive the round trip as a string.
    return looksLikeNonString(s)
}

// The exact strings in yaml.v3's `resolveMap`, plus the YAML 1.1 boolean spellings it dropped:
// quoting those costs a pair of quotes and keeps the output readable by other parsers and forks.
private val NON_STRING_WORDS = setOf(
    "true", "false", "yes", "no", "on", "off", "y", "n", "null", "~", "nil",
    // Merge key: yaml.v3 resolves "<<" to its merge tag.
    "<<"
)

private fun looksLikeNonString(s: String): Boolean {
    val lower = s.lowercase()
    if (lower in NON_STRING_WORDS) return true
    if (lower == ".inf" || lower == "-.inf" || lower == "+.inf" || lower == ".nan") return true
    if (looksLikeTimestamp(s)) return true
    // yaml.v3 removes every underscore before it tries any numeric parse, so "1_000" resolves to
    // 1000. The checks below run on the stripped form for the same reason.
    val plain = s.replace("_", "")
    if (plain.isNotEmpty() && looksLikeNumber(plain)) return true
    // YAML 1.1 sexagesimals, e.g. "1:30" or "12:34:56". yaml.v3 deliberately does not resolve
    // these, but it does still quote them on output for other parsers, and so do we.
    if (s.contains(":") && isSexagesimal(s)) return true
    return false
}

// Mirrors yaml.v3's parseTimestamp, deliberately as a superset: over-quoting is free, while
// under-quoting turns a node name into a time.Time and takes the whole config down.
private fun looksLikeTimestamp(s: String): Boolean {
    if (s.length < 8) return false
    for (i in 0 until 4) if (s[i] !in '0'..'9') return false
    if (s[4] != '-') return false
    var i = 5
    var digits = 0
    while (i < s.length && s[i] in '0'..'9') { i++; digits++ }
    if (digits !in 1..2 || i >= s.length || s[i] != '-') return false
    i++
    digits = 0
    while (i < s.length && s[i] in '0'..'9') { i++; digits++ }
    if (digits !in 1..2) return false
    // Either the string ends here (date only) or a time part follows.
    return i == s.length || s[i] == 'T' || s[i] == 't' || s[i] == ' '
}

// Mirrors the numeric ladder in yaml.v3's resolver (base 0 reads a bare leading zero as octal).
// Magnitude is deliberately unchecked: toLongOrNull returns null on overflow, so Go read it as uint64.
private fun looksLikeNumber(plain: String): Boolean {
    var body = plain
    if (body.startsWith("+") || body.startsWith("-")) body = body.substring(1)
    if (body.isEmpty()) return false

    val lower = body.lowercase()
    val (digits, base) = when {
        lower.startsWith("0x") -> body.substring(2) to 16
        lower.startsWith("0o") -> body.substring(2) to 8
        lower.startsWith("0b") -> body.substring(2) to 2
        else -> body to 10
    }
    if (base != 10) {
        if (digits.isEmpty()) return false
        return digits.all { Character.digit(it, base) >= 0 }
    }
    // Plain decimal digits: int, uint or float, but never a string.
    if (body.all { it in '0'..'9' }) return true
    return YAML_FLOAT.matches(plain)
}

// yaml.v3's `yamlStyleFloat`, verbatim.
private val YAML_FLOAT =
    Regex("^[-+]?(\\.[0-9]+|[0-9]+(\\.[0-9]*)?)([eE][-+]?[0-9]+)?$")

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
    // Single-quoted scalars carry no escapes, so anything that has to be escaped forces double
    // quotes.
    for (c in s) if (mustEscape(c)) return false
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
            c.code < 0x20 || c.code == 0x7f || c.code == 0x85 -> sb.append("\\x").append(
                c.code.toString(16).padStart(2, '0')
            )
            // LINE SEPARATOR / PARAGRAPH SEPARATOR / BOM: line breaks and
            // scanner-special to yaml.v3, so they cannot be left literal.
            c.code == 0x2028 || c.code == 0x2029 || c.code == 0xfeff ->
                sb.append("\\u").append(c.code.toString(16).padStart(4, '0'))
            else -> sb.append(c)
        }
    }
    sb.append('"')
    return sb.toString()
}
