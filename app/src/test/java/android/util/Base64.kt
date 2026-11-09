package android.util

import java.io.ByteArrayOutputStream
import java.util.Base64 as JavaBase64

// android.util.Base64 for tests only: every method in the android.jar stub throws "Stub!" when called,
// so without this the tests would exercise the stub rather than the converter.
object Base64 {
	const val DEFAULT = 0
	const val NO_PADDING = 1
	const val NO_WRAP = 2
	const val CRLF = 4
	const val URL_SAFE = 8
	const val NO_CLOSE = 16

	// Decodes the way the platform does: a character outside the alphabet is skipped, padding may
	// be left off but where given has to be whole, and a lone trailing character is refused.
	@JvmStatic
	fun decode(str: String, flags: Int): ByteArray {
		val urlSafe = flags and URL_SAFE != 0
		val out = ByteArrayOutputStream(str.length * 3 / 4)
		// 0 to 3: the characters read of the current group; 4: one "=" of two; 5: padding complete.
		var state = 0
		var value = 0
		for (char in str) {
			val digit = digitOf(char, urlSafe)
			if (digit >= 0) {
				if (state > 3) throw IllegalArgumentException("bad base-64")
				value = if (state == 0) digit else (value shl 6) or digit
				if (state < 3) {
					state++
				} else {
					out.write(value shr 16)
					out.write(value shr 8)
					out.write(value)
					state = 0
				}
			} else if (char == '=') {
				state = when (state) {
					2 -> {
						out.write(value shr 4)
						4
					}
					3 -> {
						out.write(value shr 10)
						out.write(value shr 2)
						5
					}
					4 -> 5
					else -> throw IllegalArgumentException("bad base-64")
				}
			}
		}
		when (state) {
			1, 4 -> throw IllegalArgumentException("bad base-64")
			2 -> out.write(value shr 4)
			3 -> {
				out.write(value shr 10)
				out.write(value shr 2)
			}
		}
		return out.toByteArray()
	}

	private fun digitOf(char: Char, urlSafe: Boolean): Int = when (char) {
		in 'A'..'Z' -> char - 'A'
		in 'a'..'z' -> char - 'a' + 26
		in '0'..'9' -> char - '0' + 52
		'+' -> if (urlSafe) -1 else 62
		'/' -> if (urlSafe) -1 else 63
		'-' -> if (urlSafe) 62 else -1
		'_' -> if (urlSafe) 63 else -1
		else -> -1
	}

	@JvmStatic
	fun encodeToString(input: ByteArray, flags: Int): String {
		val url = flags and URL_SAFE != 0
		val noPad = flags and NO_PADDING != 0
		val noWrap = flags and NO_WRAP != 0
		val crlf = flags and CRLF != 0
		var enc = if (url) JavaBase64.getUrlEncoder() else JavaBase64.getEncoder()
		if (noPad) enc = enc.withoutPadding()
		val encoded = enc.encodeToString(input)
		if (noWrap) return encoded
		val sep = if (crlf) "\r\n" else "\n"
		val out = StringBuilder()
		var position = 0
		while (position < encoded.length) {
			val end = minOf(position + 76, encoded.length)
			out.append(encoded, position, end).append(sep)
			position = end
		}
		return out.toString()
	}
}
