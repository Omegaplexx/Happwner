package android.net

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

// android.net.Uri, for tests only. Enough of the platform class for the link parsers: the parts
// they read off a share link, and the encoding and decoding they do to build one.
class Uri private constructor(private val raw: String) {

	val scheme: String?
		get() {
			val colon = raw.indexOf(':')
			if (colon <= 0) return null
			val scheme = raw.substring(0, colon)
			return if (scheme.all { it.isLetterOrDigit() || it == '+' || it == '-' ||
				it == '.' }) scheme else null
		}

	private val afterScheme: String
		get() {
			val colon = raw.indexOf(':')
			return if (colon < 0) raw else raw.substring(colon + 1)
		}

	val host: String?
		get() {
			val body = afterScheme
			if (!body.startsWith("//")) return null
			val rest = body.substring(2)
			val end = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }
			val authority = if (end < 0) rest else rest.substring(0, end)
			val hostPart = authority.substringAfterLast('@')
			return hostPart.substringBefore(':').ifEmpty { null }
		}

	val path: String?
		get() {
			var body = afterScheme
			if (body.startsWith("//")) {
				val rest = body.substring(2)
				val cut = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }
				body = if (cut < 0 || rest[cut] != '/') "" else rest.substring(cut)
			}
			return body.substringBefore('?').substringBefore('#')
		}

	val lastPathSegment: String?
		get() = path?.trim('/')?.substringAfterLast('/')?.ifEmpty { null }

	val pathSegments: List<String>
		get() = path?.split('/')?.filter { it.isNotEmpty() } ?: emptyList()

	val query: String?
		get() {
			val query = raw.substringAfter('?', "")
			if (query.isEmpty()) return null
			return query.substringBefore('#')
		}

	// Found as the platform finds it: by the name as it is encoded, the value decoded with a "+" in
	// it read as a space.
	fun getQueryParameter(key: String): String? {
		val queryText = query ?: return null
		val encodedKey = encode(key)
		var start = 0
		while (true) {
			val nextAmpersand = queryText.indexOf('&', start)
			val end = if (nextAmpersand >= 0) nextAmpersand else queryText.length
			var separator = queryText.indexOf('=', start)
			if (separator > end || separator < 0) separator = end
			if (separator - start == encodedKey.length &&
				queryText.regionMatches(start, encodedKey, 0, encodedKey.length)) {
				if (separator == end) return ""
				return decode(queryText.substring(separator + 1, end), true)
			}
			if (nextAmpersand < 0) return null
			start = nextAmpersand + 1
		}
	}

	override fun toString(): String = raw

	companion object {
		@JvmStatic
		fun parse(uriString: String): Uri = Uri(uriString)

		// Android declares these as platform types, so callers use them without null checks; the
		// shim has to be shaped the same way to compile the same sources.
		@JvmStatic
		fun decode(text: String): String = decode(text, false)

		// The platform's encoding: all but letters, digits and _-!.~'()* goes out as UTF-8 escapes,
		// a run of them at once so a surrogate pair stays one character.
		@JvmStatic
		fun encode(text: String): String {
			val out = StringBuilder(text.length)
			var current = 0
			while (current < text.length) {
				if (isUnreserved(text[current])) {
					out.append(text[current++])
					continue
				}
				var next = current + 1
				while (next < text.length && !isUnreserved(text[next])) next++
				for (byte in text.substring(current, next).toByteArray(Charsets.UTF_8)) {
					val bits = byte.toInt()
					out.append('%').append(HEX[bits shr 4 and 0xF]).append(HEX[bits and 0xF])
				}
				current = next
			}
			return out.toString()
		}

		private const val HEX = "0123456789ABCDEF"

		private fun isUnreserved(char: Char): Boolean =
			char in 'A'..'Z' || char in 'a'..'z' || char in '0'..'9' || char in "_-!.~'()*"

		// android.net.UriCodec's decoding, quirks kept: a broken escape turns into U+FFFD, the byte
		// half read behind it is kept too, and an escape the text ends inside ends the decoding.
		private fun decode(text: String, convertPlus: Boolean): String {
			val out = StringBuilder(text.length)
			val bytes = ByteBuffer.allocate(text.length)
			val decoder = Charsets.UTF_8.newDecoder()
				.onMalformedInput(CodingErrorAction.REPLACE)
				.replaceWith("\ufffd")
				.onUnmappableCharacter(CodingErrorAction.REPORT)
			fun flush() {
				if (bytes.position() == 0) return
				bytes.flip()
				try {
					out.append(decoder.decode(bytes))
				} catch (_: CharacterCodingException) {
					out.append('\ufffd')
				} finally {
					bytes.flip()
					bytes.limit(bytes.capacity())
				}
			}
			var index = 0
			while (index < text.length) {
				val char = text[index++]
				when (char) {
					'+' -> {
						flush()
						out.append(if (convertPlus) ' ' else '+')
					}
					'%' -> {
						var value = 0
						for (digitIndex in 0 until 2) {
							if (index >= text.length) {
								flush()
								out.append('\ufffd')
								return out.toString()
							}
							val digit = hexValue(text[index++])
							if (digit < 0) {
								flush()
								out.append('\ufffd')
								break
							}
							value = value * 16 + digit
						}
						bytes.put(value.toByte())
					}
					else -> {
						flush()
						out.append(char)
					}
				}
			}
			flush()
			return out.toString()
		}

		private fun hexValue(char: Char): Int = when (char) {
			in '0'..'9' -> char - '0'
			in 'a'..'f' -> char - 'a' + 10
			in 'A'..'F' -> char - 'A' + 10
			else -> -1
		}
	}
}
