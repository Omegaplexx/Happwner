package com.happwner.text

import org.json.JSONTokener

// Nesting-depth gate for untrusted JSON, checked before org.json parses it.
internal object JsonDepth {

	// Deepest nesting accepted from untrusted input.
	const val MAX_DEPTH = 256

	// True when s nests deeper than limit containers at any point.
	fun exceedsMaxDepth(text: String, limit: Int = MAX_DEPTH): Boolean =
		maxNestingDepth(text, limit + 1) > limit

	// Deepest nesting in s, stopping once cap is reached. Mirrors JSONTokener's lexer rather than counting
	// brackets naively; the contract is one-sided - it may over-report depth but never under-reports.
	fun maxNestingDepth(text: String, cap: Int = Int.MAX_VALUE): Int {
		var depth = 0
		var max = 0
		var position = 0
		val textLength = text.length

		while (position < textLength) {
			when (val char = text[position]) {
				// Whitespace, exactly the set nextCleanInternal() skips.
				' ', '\t', '\n', '\r' -> position++

				'/' -> {
					val peek = if (position + 1 < textLength) text[position + 1] else '\u0000'
					when (peek) {
						'*' -> {
							val end = text.indexOf("*/", position + 2)
							// Unterminated: the parser throws, nothing more counts.
							if (end < 0) return max
							position = end + 2
						}
						'/' -> position = skipToEndOfLine(text, position + 2)
						// A lone slash ends a literal; the parser fails on it.
						else -> position++
					}
				}

				'#' -> position = skipToEndOfLine(text, position + 1)

				'"', '\'' -> position = skipQuoted(text, position + 1, char)

				'{', '[' -> {
					depth++
					if (depth > max) {
						max = depth
						if (max >= cap) return max
					}
					position++
				}

				// Clamped at zero so a stray closer can't buy extra depth later.
				'}', ']' -> {
					if (depth > 0) depth--
					position++
				}

				// Structural separators the parser consumes on their own.
				':', ',', ';', '=' -> position++

				// Can't begin a literal: the parser reads an empty one there and throws, so only the
				// character itself is consumed.
				'\\', '\u000c' -> position++

				// Anything else opens an unquoted literal; consuming the whole run keeps a quote
				// inside it from reading as a string opening, and nextToInternal() ends a literal
				// before it can swallow a bracket.
				else -> position = skipLiteral(text, position + 1)
			}
		}
		return max
	}

	private fun skipToEndOfLine(text: String, from: Int): Int {
		var position = from
		while (position < text.length) {
			val char = text[position]
			position++
			if (char == '\r' || char == '\n') break
		}
		return position
	}

	// Consumes a string body opened by quote, returning the index past the closing quote.
	private fun skipQuoted(text: String, from: Int, quote: Char): Int {
		var position = from
		while (position < text.length) {
			val char = text[position]
			if (char == '\\') {
				position += 2
				continue
			}
			position++
			if (char == quote) return position
		}
		// Unterminated: the parser throws, so the remainder can't add depth.
		return text.length
	}

	private fun skipLiteral(text: String, from: Int): Int {
		var position = from
		while (position < text.length) {
			val char = text[position]
			if (char == '\r' || char == '\n' || LITERAL_TERMINATORS.indexOf(char) >= 0) return position
			position++
		}
		return position
	}

	// The `excluded` set nextToInternal() is called with, plus space and tab.
	private const val LITERAL_TERMINATORS = "{}[]/\\:,=;# \t\u000c"
}

// True when the text is exactly one JSON value, and one the depth gate lets through.
internal fun isWholeJsonValue(text: String): Boolean = jsonProblem(text) == null

// Why a text that starts like JSON does not read as one, or null when it does. A key written twice
// is no problem: Android's reader takes the later value, as Xray's own does.
internal fun jsonProblem(text: String): String? {
	if (JsonDepth.exceedsMaxDepth(text)) return "it is nested deeper than a configuration ever is"
	return try {
		val tokener = JSONTokener(text)
		tokener.nextValue()
		if (tokener.nextClean().code == 0) null else "text follows the closing bracket"
	} catch (error: Exception) {
		val errorText = error.message ?: return "it is not valid JSON"
		"it is not valid JSON (${errorText.substringBefore(" at ")})"
	}
}
