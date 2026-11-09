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

// Builds a flow sequence from strings, dropping the blank ones.
internal fun toFlowSeq(items: List<String>): YamlFlowSeq {
	val out = YamlFlowSeq()
	for (item in items) {
		val trimmed = item.trim()
		if (trimmed.isNotEmpty()) out.add(trimmed)
	}
	return out
}

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
	fun setString(key: String, value: String?): YamlMap {
		if (value.isNullOrEmpty()) return this
		return set(key, value)
	}

	// A rendered range: a single value as the integer it is, a real range as text. Quoted, a single
	// value is refused by a core reading an integer; written this way it reads under either type.
	fun setRange(key: String, rendered: String): YamlMap {
		val trimmed = rendered.trim()
		if (trimmed.isEmpty()) return this
		val single = trimmed.toIntOrNull()
		return if (single != null) setInt(key, single) else set(key, trimmed)
	}

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
	val out = StringBuilder()
	encodeYamlValue(out, value, 0, false)
	return out.toString()
}

private fun indentOf(width: Int): String = " ".repeat(width)

// Writes value at the given indent level. inline means the caller already wrote the indentation
// (and any "- " or "key: " prefix) for the first line.
private fun encodeYamlValue(out: StringBuilder, value: Any?, indent: Int, inline: Boolean) {
	when (value) {
		is YamlMap -> encodeYamlMap(out, value, indent, inline)
		is YamlSeq -> encodeYamlSeq(out, value, indent, inline)
		is YamlFlowSeq -> {
			if (!inline) out.append(indentOf(indent))
			out.append(encodeFlowSeq(value))
			out.append('\n')
		}
		else -> {
			if (!inline) out.append(indentOf(indent))
			out.append(yamlScalar(value))
			out.append('\n')
		}
	}
}

private fun encodeYamlMap(out: StringBuilder, map: YamlMap, indent: Int, inline: Boolean) {
	val entries = map.entries()
	if (entries.isEmpty()) {
		if (!inline) out.append(indentOf(indent))
		out.append("{}\n")
		return
	}
	for ((index, entry) in entries.withIndex()) {
		if (index > 0 || !inline) out.append(indentOf(indent))
		out.append(quoteYamlString(entry.first))
		out.append(':')

		when (val child = entry.second) {
			is YamlMap -> {
				if (child.size == 0) {
					out.append(" {}\n")
					continue
				}
				out.append('\n')
				encodeYamlMap(out, child, indent + 2, false)
			}
			is YamlSeq -> {
				if (child.isEmpty()) {
					out.append(" []\n")
					continue
				}
				out.append('\n')
				encodeYamlSeq(out, child, indent + 2, false)
			}
			is YamlFlowSeq -> {
				out.append(' ')
				out.append(encodeFlowSeq(child))
				out.append('\n')
			}
			else -> {
				out.append(' ')
				out.append(yamlScalar(child))
				out.append('\n')
			}
		}
	}
}

private fun encodeYamlSeq(out: StringBuilder, seq: YamlSeq, indent: Int, inline: Boolean) {
	for ((index, item) in seq.withIndex()) {
		if (item is YamlCommented) {
			// The comment shares the parent's line ("- # text") with the real value in the block underneath.
			if (index > 0 || !inline) out.append(indentOf(indent))
			writeYamlComment(out, item.comment, indent)
			out.append(indentOf(indent))
			out.append("- ")
			encodeYamlValue(out, item.value, indent + 2, true)
			continue
		}
		if (index > 0 || !inline) out.append(indentOf(indent))
		out.append("- ")
		// Nested collections continue on the same line, indented two further
		// columns so the "- " acts as the first two spaces of that indent.
		encodeYamlValue(out, item, indent + 2, true)
	}
}

// Writes comment as one or more `#` lines. Comment text is not inert: it is built from the Xray
// configuration, which arrives from whoever served the subscription.
private fun writeYamlComment(out: StringBuilder, comment: String, indent: Int) {
	val lines = comment.split("\r\n", "\n", "\r", "\u0085", "\u2028", "\u2029")
	for ((index, line) in lines.withIndex()) {
		if (index > 0) out.append(indentOf(indent))
		out.append("# ")
		out.append(line.filter { it.code >= 0x20 && it.code != 0x7f }.trimEnd(' ', '\t'))
		out.append('\n')
	}
}

private fun encodeFlowSeq(seq: YamlFlowSeq): String =
	seq.joinToString(", ", "[", "]") { yamlScalar(it, flow = true) }

// Only a string needs quoting: the other scalars the documents hold, integers and Booleans, read
// as they are written.
private fun yamlScalar(value: Any?, flow: Boolean = false): String =
	if (value is String) quoteYamlScalar(value, flow) else value.toString()

// Quoting: a port of resolve.go from gopkg.in/yaml.v3, which is what mihomo parses with.

// Characters that start a YAML construct (sequence entry, mapping key, alias, tag, block scalar,
// flow collection). A plain scalar may not begin with one.
private const val LEADING_INDICATORS = "-?:,[]{}#&*!|>'\"%@`"

// Characters that end a plain scalar inside a flow collection - allowed in block context, not in
// flow, which is why quoting must know which it emits into.
private const val FLOW_INDICATORS = ",[]{}?"

// Characters yaml.v3 treats as a line break (`is_break` in yamlprivateh.go): CR, LF, NEL,
// LINE/PARAGRAPH SEPARATOR. Emitted raw they end the scalar and the value comes back null.
private fun mustEscape(char: Char): Boolean =
	char.code < 0x20 || char.code == 0x7f || char.code == 0x85 ||
		char.code == 0x2028 || char.code == 0x2029 || char.code == 0xfeff

// Renders s as a YAML scalar, quoting only when a plain scalar is ambiguous.
internal fun quoteYamlString(text: String): String = quoteYamlScalar(text, flow = false)

internal fun quoteYamlScalar(text: String, flow: Boolean): String {
	if (!yamlNeedsQuoting(text, flow)) return text
	if (canSingleQuote(text)) return "'" + text.replace("'", "''") + "'"
	return yamlDoubleQuote(text)
}

private fun yamlNeedsQuoting(text: String, flow: Boolean): Boolean {
	if (text.isEmpty()) return true
	for (char in text) if (mustEscape(char)) return true
	if (text.startsWith(" ") || text.endsWith(" ")) return true
	if (LEADING_INDICATORS.indexOf(text[0]) >= 0) return true
	// ": " ends a key, " #" starts a comment, and a trailing ":" reads as a key.
	if (text.contains(": ") || text.contains(" #") || text.endsWith(":")) return true
	if (flow) {
		for (char in text) if (FLOW_INDICATORS.indexOf(char) >= 0) return true
	}
	// Anything a YAML resolver would turn into a non-string type has to be
	// quoted to survive the round trip as a string.
	return looksLikeNonString(text)
}

// The exact strings in yaml.v3's `resolveMap`, plus the YAML 1.1 boolean spellings it dropped:
// quoting those costs a pair of quotes and keeps the output readable by other parsers and forks.
private val NON_STRING_WORDS = setOf(
	"true", "false", "yes", "no", "on", "off", "y", "n", "null", "~", "nil",
	// Merge key: yaml.v3 resolves "<<" to its merge tag.
	"<<"
)

private fun looksLikeNonString(text: String): Boolean {
	val lower = text.lowercase()
	if (lower in NON_STRING_WORDS) return true
	if (lower == ".inf" || lower == "-.inf" || lower == "+.inf" || lower == ".nan") return true
	if (looksLikeTimestamp(text)) return true
	// yaml.v3 removes every underscore before it tries any numeric parse, so "1_000" resolves to
	// 1000. The checks below run on the stripped form for the same reason.
	val plain = text.replace("_", "")
	if (plain.isNotEmpty() && looksLikeNumber(plain)) return true
	// YAML 1.1 sexagesimals, e.g. "1:30" or "12:34:56". yaml.v3 deliberately does not resolve
	// these, but it does still quote them on output for other parsers, and so do we.
	if (text.contains(":") && isSexagesimal(text)) return true
	return false
}

// Mirrors yaml.v3's parseTimestamp, deliberately as a superset: over-quoting is free, while
// under-quoting turns a node name into a time.Time and takes the whole config down.
private fun looksLikeTimestamp(text: String): Boolean {
	if (text.length < 8) return false
	for (i in 0 until 4) if (text[i] !in '0'..'9') return false
	if (text[4] != '-') return false
	var position = 5
	var digits = 0
	while (position < text.length && text[position] in '0'..'9') { position++; digits++ }
	if (digits !in 1..2 || position >= text.length || text[position] != '-') return false
	position++
	digits = 0
	while (position < text.length && text[position] in '0'..'9') { position++; digits++ }
	if (digits !in 1..2) return false
	// Either the string ends here (date only) or a time part follows.
	return position == text.length || text[position] == 'T' || text[position] == 't' || text[position] == ' '
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

private fun isSexagesimal(text: String): Boolean {
	val parts = text.removePrefix("-").removePrefix("+").split(":")
	if (parts.size < 2) return false
	for (part in parts) {
		if (part.isEmpty()) return false
		for (char in part) if (char < '0' || char > '9') return false
	}
	return true
}

private fun canSingleQuote(text: String): Boolean {
	// Single-quoted scalars carry no escapes, so anything that has to be escaped forces double quotes.
	for (char in text) if (mustEscape(char)) return false
	return true
}

private fun yamlDoubleQuote(text: String): String {
	val out = StringBuilder(text.length + 2)
	out.append('"')
	for (char in text) {
		when {
			char == '"' -> out.append("\\\"")
			char == '\\' -> out.append("\\\\")
			char == '\n' -> out.append("\\n")
			char == '\r' -> out.append("\\r")
			char == '\t' -> out.append("\\t")
			char.code == 0 -> out.append("\\0")
			char.code < 0x20 || char.code == 0x7f || char.code == 0x85 -> out.append("\\x").append(
				char.code.toString(16).padStart(2, '0')
			)
			// LINE SEPARATOR / PARAGRAPH SEPARATOR / BOM: line breaks and
			// scanner-special to yaml.v3, so they cannot be left literal.
			char.code == 0x2028 || char.code == 0x2029 || char.code == 0xfeff ->
				out.append("\\u").append(char.code.toString(16).padStart(4, '0'))
			else -> out.append(char)
		}
	}
	out.append('"')
	return out.toString()
}
