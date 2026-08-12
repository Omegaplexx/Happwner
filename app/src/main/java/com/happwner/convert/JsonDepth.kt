package com.happwner.convert

// Nesting-depth gate for untrusted JSON, checked before org.json parses it.
internal object JsonDepth {

    // Deepest nesting accepted from untrusted input.
    const val MAX_DEPTH = 256

    // True when s nests deeper than limit containers at any point.
    fun exceedsMaxDepth(s: String, limit: Int = MAX_DEPTH): Boolean =
        maxNestingDepth(s, limit + 1) > limit

    // Deepest nesting in s, stopping once cap is reached. Mirrors JSONTokener's lexer rather than counting
    // brackets naively; the contract is one-sided - it may over-report depth but never under-reports.
    fun maxNestingDepth(s: String, cap: Int = Int.MAX_VALUE): Int {
        var depth = 0
        var max = 0
        var i = 0
        val n = s.length

        while (i < n) {
            when (val c = s[i]) {
                // Whitespace, exactly the set nextCleanInternal() skips.
                ' ', '\t', '\n', '\r' -> i++

                '/' -> {
                    val peek = if (i + 1 < n) s[i + 1] else '\u0000'
                    when (peek) {
                        '*' -> {
                            val end = s.indexOf("*/", i + 2)
                            // Unterminated: the parser throws, nothing more counts.
                            if (end < 0) return max
                            i = end + 2
                        }
                        '/' -> i = skipToEndOfLine(s, i + 2)
                        // A lone slash ends a literal; the parser fails on it.
                        else -> i++
                    }
                }

                '#' -> i = skipToEndOfLine(s, i + 1)

                '"', '\'' -> i = skipQuoted(s, i + 1, c)

                '{', '[' -> {
                    depth++
                    if (depth > max) {
                        max = depth
                        if (max >= cap) return max
                    }
                    i++
                }

                // Clamped at zero so a stray closer can't buy extra depth later.
                '}', ']' -> {
                    if (depth > 0) depth--
                    i++
                }

                // Structural separators the parser consumes on their own.
                ':', ',', ';', '=' -> i++

                // Can't begin a literal, so the parser reads an empty one and
                // throws; they still need a branch or skipLiteral() would spin.
                '\\', '\u000c' -> i++

                // Anything else opens an unquoted literal; consuming the whole run keeps a quote inside it from
                // reading as a string opening, and nextToInternal() ends a literal before it can swallow a bracket.
                else -> {
                    val next = skipLiteral(s, i)
                    i = if (next > i) next else i + 1
                }
            }
        }
        return max
    }

    private fun skipToEndOfLine(s: String, from: Int): Int {
        var i = from
        while (i < s.length) {
            val c = s[i]
            i++
            if (c == '\r' || c == '\n') break
        }
        return i
    }

    // Consumes a string body opened by quote, returning the index past the closing quote.
    private fun skipQuoted(s: String, from: Int, quote: Char): Int {
        var i = from
        while (i < s.length) {
            val c = s[i]
            if (c == '\\') {
                i += 2
                continue
            }
            i++
            if (c == quote) return i
        }
        // Unterminated: the parser throws, so the remainder can't add depth.
        return s.length
    }

    private fun skipLiteral(s: String, from: Int): Int {
        var i = from
        while (i < s.length) {
            val c = s[i]
            if (c == '\r' || c == '\n' || LITERAL_TERMINATORS.indexOf(c) >= 0) return i
            i++
        }
        return i
    }

    // The `excluded` set nextToInternal() is called with, plus space and tab.
    private const val LITERAL_TERMINATORS = "{}[]/\\:,=;# \t\u000c"
}
