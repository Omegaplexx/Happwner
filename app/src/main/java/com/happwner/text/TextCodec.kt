package com.happwner.text

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

// Text and codec helpers shared by the three passes: commented JSON, host:port splitting, ports,
// base64 in every alphabet, and hex.

// Removes what Xray tolerates in its JSON and org.json does not - `//` and slash-star comments, and
// a comma before a closing brace or bracket - outside string literals only, in one scan. A comment
// is replaced by the newlines it held, so the text keeps its line structure.
internal fun stripJsonComments(data: String): String {
	val out = StringBuilder(data.length)
	var inString = false
	var escaped = false
	var position = 0
	while (position < data.length) {
		val char = data[position]
		if (inString) {
			out.append(char)
			when {
				escaped -> escaped = false
				char == '\\' -> escaped = true
				char == '"' -> inString = false
			}
			position++
			continue
		}
		when {
			char == '"' -> {
				inString = true
				out.append(char)
				position++
			}
			char == '/' && position + 1 < data.length && data[position + 1] == '/' -> {
				while (position < data.length && data[position] != '\n') position++
				if (position < data.length) {
					out.append('\n')
					position++
				}
			}
			char == '/' && position + 1 < data.length && data[position + 1] == '*' -> {
				position += 2
				while (position + 1 < data.length && !(data[position] == '*' && data[position + 1] == '/')) {
					if (data[position] == '\n') out.append('\n')
					position++
				}
				position += 2
			}
			char == ',' && closesNext(data, position + 1) -> position++
			else -> {
				out.append(char)
				position++
			}
		}
	}
	return out.toString()
}

// The text a configuration is read from: without its comments, and a comma before a closer, where it
// opens with a comment or reads as JSON only once they are out - as the mihomo pass reads every one -
// and as written otherwise. A "#" line ahead is Happ's own parameter, so such a text stays as written.
internal fun withoutComments(text: String): String {
	val trimmed = text.trim()
	if (trimmed.isEmpty() || trimmed[0] !in "{[/") return text
	if (trimmed[0] != '/' && isWholeJsonValue(trimmed)) return text
	val stripped = stripJsonComments(text)
	val body = stripped.trim()
	return if ((body.startsWith("{") || body.startsWith("[")) && isWholeJsonValue(body)) stripped else text
}

// True when the next thing after whitespace and comments is a closing brace or bracket - the
// comma before it is one JSON rejects.
private fun closesNext(data: String, from: Int): Boolean {
	var position = from
	while (position < data.length) {
		val char = data[position]
		when {
			char == ' ' || char == '\t' || char == '\n' || char == '\r' -> position++
			char == '/' && position + 1 < data.length && data[position + 1] == '/' -> {
				while (position < data.length && data[position] != '\n') position++
			}
			char == '/' && position + 1 < data.length && data[position + 1] == '*' -> {
				position += 2
				while (position + 1 < data.length && !(data[position] == '*' && data[position +
					1] == '/')) position++
				position += 2
			}
			else -> return char == '}' || char == ']'
		}
	}
	return false
}

// The first value that is not blank, trimmed, or "".
internal fun firstNonEmpty(vararg values: String?): String {
	for (value in values) {
		val trimmed = value?.trim().orEmpty()
		if (trimmed.isNotEmpty()) return trimmed
	}
	return ""
}

// Removes the brackets from a literal IPv6 address, which mihomo wants bare.
internal fun stripBrackets(host: String): String =
	if (host.startsWith("[") && host.endsWith("]")) host.substring(1, host.length - 1) else host

// Splits "host:port", accepting a bracketed IPv6 literal.
// A host and, when the text names one, its port. A bracketed IPv6 address keeps its brackets off;
// an unbracketed one is a host with no port, since its colons cannot be told from a port's.
internal data class HostPort(val host: String, val port: Int?)

internal fun splitHostPort(raw: String?): HostPort {
	val text = raw?.trim().orEmpty()
	if (text.isEmpty()) return HostPort("", null)
	if (text.startsWith("[")) {
		val closingBracket = text.indexOf("]")
		if (closingBracket < 0) return HostPort(text, null)
		val host = text.substring(1, closingBracket)
		val rest = text.substring(closingBracket + 1)
		if (rest.startsWith(":") && rest.substring(1).all { it in '0'..'9' }) {
			return HostPort(host, rest.substring(1).toIntOrNull())
		}
		return HostPort(host, null)
	}
	if (text.count { it == ':' } == 1) {
		val idx = text.indexOf(':')
		val port = text.substring(idx + 1)
		if (port.isNotEmpty() && port.all { it in '0'..'9' }) return HostPort(text.substring(0, idx),
			port.toIntOrNull())
	}
	return HostPort(text, null)
}

// Parses a port, rejecting values outside 1-65535.
internal fun parsePort(text: String): Int? {
	val port = text.trim().toIntOrNull() ?: return null
	if (port <= 0 || port > 65535) return null
	return port
}

internal fun isIpLiteral(value: Any?): Boolean {
	if (value !is String || value.isEmpty()) return false
	return parseInet4(value) || parseInet6(value)
}

internal fun parseInet4(text: String): Boolean {
	val parts = text.split(".")
	if (parts.size != 4) return false
	for (part in parts) {
		if (part.isEmpty() || part.length > 3) return false
		for (char in part) if (char !in '0'..'9') return false
		val number = part.toIntOrNull() ?: return false
		if (number < 0 || number > 255) return false
		if (part.length > 1 && part[0] == '0') return false
	}
	return true
}

// Rough IPv6 parsing (::, embedded IPv4, zone-id)
internal fun parseInet6(text: String): Boolean {
	if (text.isEmpty()) return false
	val core = text.substringBefore('%')
	if (core.isEmpty()) return false
	if (core == "::") return true
	val hasDoubleColon = core.contains("::")
	val tail = core.substringAfterLast(":")
	val embedded4 = tail.contains(".")
	// Split into groups around '::', folding any embedded IPv4
	val groupsRaw: List<String> = if (hasDoubleColon) {
		val (left, right) = core.split("::", limit = 2)
		val leftGroups = if (left.isEmpty()) emptyList() else left.split(":")
		val rightGroups = if (right.isEmpty()) emptyList() else right.split(":")
		leftGroups + rightGroups
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
		// Strictly fewer, not "no more than": "::" stands for one or more groups of zeros. A bad
		// dns.hosts address refuses the whole document, so it would cost the subscription.
		if (countWithoutDC >= expected) return false
	} else {
		if (countWithoutDC != expected) return false
	}
	for (group in groups) {
		if (group.isEmpty() || group.length > 4) return false
		for (char in group) {
			val isHex = char in '0'..'9' || char in 'a'..'f' || char in 'A'..'F'
			if (!isHex) return false
		}
	}
	return true
}

// The address a written form stands for, so two spellings of one compare equal: IPv4 as written,
// IPv6 as its eight groups in numbers, zone kept; null when the text is no address.
internal fun canonicalIp(text: String): String? {
	if (parseInet4(text)) return text
	if (!parseInet6(text)) return null
	val zone = text.substringAfter('%', "")
	var core = text.substringBefore('%')
	// An IPv4 tail is the last two groups written in another notation.
	val tail = core.substringAfterLast(':')
	if ('.' in tail) {
		val b = tail.split('.').map { it.toInt() }
		core = core.dropLast(tail.length) + "%x:%x".format(b[0] * 256 + b[1], b[2] * 256 + b[3])
	}
	val halves = core.split("::", limit = 2)
	val left = halves[0].split(':').filter { it.isNotEmpty() }
	val right = halves.getOrNull(1)?.split(':')?.filter { it.isNotEmpty() }.orEmpty()
	val groups = left + List(8 - left.size - right.size) { "0" } + right
	return groups.joinToString(":") { it.toInt(16).toString() } + if (zone.isEmpty()) "" else "%$zone"
}

private const val B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
private const val B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// Decodes base64 with the given alphabet. padded mirrors how Go tells the padded and raw encodings
// apart: true requires the "=" padding, false rejects it.
internal fun decodeBase64(input: String, urlSafe: Boolean, padded: Boolean): ByteArray? {
	val alphabet = if (urlSafe) B64_URL else B64_STD
	val text = input.trim()
	if (text.isEmpty()) return ByteArray(0)
	if (padded) {
		if (text.length % 4 != 0) return null
	} else {
		if (text.contains('=')) return null
		if (text.length % 4 == 1) return null
	}

	var body = text
	var padCount = 0
	while (body.endsWith("=")) {
		body = body.dropLast(1)
		padCount++
	}
	if (padCount > 2) return null

	val out = ByteArrayOutputStream(body.length * 3 / 4 + 3)
	var buffer = 0
	var bits = 0
	for (char in body) {
		val idx = alphabet.indexOf(char)
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

// Decodes standard or URL-safe base64, padded or not.
internal fun decodeBase64Any(text: String): ByteArray? {
	decodeBase64(text, urlSafe = false, padded = true)?.let { return it }
	decodeBase64(text, urlSafe = false, padded = false)?.let { return it }
	decodeBase64(text, urlSafe = true, padded = true)?.let { return it }
	decodeBase64(text, urlSafe = true, padded = false)?.let { return it }
	return null
}

// Decodes the unpadded URL-safe base64 that VLESS encryption keys use.
internal fun decodeBase64RawUrl(text: String): ByteArray? = decodeBase64(text, urlSafe = true, padded = false)

// Encodes bytes as padded standard base64.
internal fun encodeBase64Std(data: ByteArray): String {
	val out = StringBuilder((data.size + 2) / 3 * 4)
	var position = 0
	while (position + 2 < data.size) {
		val triple = ((data[position].toInt() and 0xFF) shl 16) or
			((data[position + 1].toInt() and 0xFF) shl 8) or
			(data[position + 2].toInt() and 0xFF)
		out.append(B64_STD[(triple shr 18) and 0x3F])
		out.append(B64_STD[(triple shr 12) and 0x3F])
		out.append(B64_STD[(triple shr 6) and 0x3F])
		out.append(B64_STD[triple and 0x3F])
		position += 3
	}
	when (data.size - position) {
		1 -> {
			val triple = (data[position].toInt() and 0xFF) shl 16
			out.append(B64_STD[(triple shr 18) and 0x3F])
			out.append(B64_STD[(triple shr 12) and 0x3F])
			out.append("==")
		}
		2 -> {
			val triple = ((data[position].toInt() and 0xFF) shl 16) or ((data[position +
				1].toInt() and 0xFF) shl 8)
			out.append(B64_STD[(triple shr 18) and 0x3F])
			out.append(B64_STD[(triple shr 12) and 0x3F])
			out.append(B64_STD[(triple shr 6) and 0x3F])
			out.append('=')
		}
	}
	return out.toString()
}

// Renders bytes as lowercase hex.
internal fun toHex(data: ByteArray): String {
	val out = StringBuilder(data.size * 2)
	for (byte in data) {
		val value = byte.toInt() and 0xFF
		out.append("0123456789abcdef"[value shr 4])
		out.append("0123456789abcdef"[value and 0x0F])
	}
	return out.toString()
}

// Decodes lowercase or uppercase hex, or null when the text is not hex.
internal fun fromHex(text: String): ByteArray? {
	if (text.length % 2 != 0) return null
	val out = ByteArray(text.length / 2)
	for (i in out.indices) {
		val high = Character.digit(text[i * 2], 16)
		val low = Character.digit(text[i * 2 + 1], 16)
		if (high < 0 || low < 0) return null
		out[i] = ((high shl 4) or low).toByte()
	}
	return out
}

// The alphabet a base64 text is written in. EITHER means it uses neither alphabet's two extra
// characters; null means it mixes both or holds something that is not base64. Whitespace inside
// counts as not base64 unless the caller allows it.
internal enum class Base64Alphabet { STANDARD, URL_SAFE, EITHER }

internal fun base64Alphabet(text: String, allowWhitespace: Boolean = false): Base64Alphabet? {
	var standard = false
	var urlSafe = false
	for (char in text) {
		when {
			char in 'A'..'Z' || char in 'a'..'z' || char in '0'..'9' || char == '=' -> {}
			char == '+' || char == '/' -> standard = true
			char == '-' || char == '_' -> urlSafe = true
			allowWhitespace && (char == ' ' || char == '\t' || char == '\r' || char == '\n') -> {}
			else -> return null
		}
	}
	if (standard && urlSafe) return null
	return when {
		standard -> Base64Alphabet.STANDARD
		urlSafe -> Base64Alphabet.URL_SAFE
		else -> Base64Alphabet.EITHER
	}
}

// The text with the padding its length calls for.
internal fun padBase64(text: String): String = when (text.length % 4) {
	2 -> "$text=="
	3 -> "$text="
	else -> text
}

// Decodes base64 the way the clients' own link decoders do: whitespace dropped, the URL-safe
// alphabet read as the standard one, padding restored, anything else outside the alphabet
// skipped by android.util.Base64. Only misplaced padding or a lone trailing character throws.
internal fun decodeBase64Lenient(text: String): ByteArray {
	val normalized = StringBuilder(text.length)
	for (char in text) {
		when (char) {
			' ', '\n', '\r', '\t' -> {}
			'-' -> normalized.append('+')
			'_' -> normalized.append('/')
			else -> normalized.append(char)
		}
	}
	val rem = normalized.length % 4
	if (rem != 0) repeat(4 - rem) { normalized.append('=') }
	return Base64.decode(normalized.toString(), Base64.DEFAULT)
}

// The android.util.Base64 flag for the alphabet the text is written in, or null when it is not
// base64 at all: nothing but padding and whitespace is not base64 either.
internal fun base64Flag(text: String): Int? {
	val hasBase64Chars = text.any {
		it.isLetterOrDigit() || it == '+' || it == '/' || it == '-' || it == '_'
	}
	if (!hasBase64Chars) return null
	val alphabet = base64Alphabet(text, allowWhitespace = true) ?: return null
	return if (alphabet == Base64Alphabet.URL_SAFE) Base64.URL_SAFE else Base64.DEFAULT
}

// Whether text holds DEL or a control character other than tab, LF and CR - the mark of binary.
internal fun hasBinaryControls(text: String): Boolean = text.any {
	val code = it.code
	code == 0x7f || (code < 0x20 && code != 0x09 && code != 0x0a && code != 0x0d)
}

// The bytes as UTF-8, or null when they are not well-formed UTF-8.
internal fun decodeStrictUtf8(bytes: ByteArray): String? {
	if (bytes.isEmpty()) return null
	return try {
		Charsets.UTF_8.newDecoder()
			.onMalformedInput(CodingErrorAction.REPORT)
			.onUnmappableCharacter(CodingErrorAction.REPORT)
			.decode(ByteBuffer.wrap(bytes)).toString()
	} catch (_: CharacterCodingException) {
		null
	}
}
