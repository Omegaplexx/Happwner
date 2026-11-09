package com.happwner.client

import android.net.Uri

// Handler for INCY deep links (incy://add/<url>, incy://import/<base64>): mirrors INCY's own cg.h.b
// extraction
object IncyLinks {
	internal const val CRYPT_SCHEME_PREFIX = "incy://crypt"
	// Whether this is an incy://cryptN link.
	fun isCryptLink(link: String?): Boolean = link.trimmedStartsWith(CRYPT_SCHEME_PREFIX)

	private const val ADD_PREFIX = "incy://add/"
	private const val IMPORT_PREFIX = "incy://import/"
	private const val INCY_SCHEME = "incy://"

	private val SCHEMES = arrayOf(
		"http://", "https://", "vless://", "vmess://", "trojan://",
		"ss://", "hy2://", "hysteria2://", "socks://", "socks5://",
		"wireguard://", "wg://"
	)

	// Whether this is an incy://add/ or incy://import/ deep link.
	fun isIncyLink(link: String?): Boolean = link.trimmedStartsWith(ADD_PREFIX, IMPORT_PREFIX)

	// Strip incy://add/ or incy://import/ and unwrap (url-decode, then scheme-or-base64) to the inner link
	fun stripIncyPrefix(link: String?): String? {
		if (link == null) return null
		val trimmed = link.trim()
		val tail = when {
			trimmed.startsWith(ADD_PREFIX, ignoreCase = true) ->
				trimmed.substring(ADD_PREFIX.length)
			trimmed.startsWith(IMPORT_PREFIX, ignoreCase = true) ->
				trimmed.substring(IMPORT_PREFIX.length)
			else -> return null
		}.trim()
		if (tail.isEmpty()) return null

		val decoded = try { Uri.decode(tail) } catch (_: Throwable) { tail }
		if (startsWithKnownScheme(decoded)) return decoded

		return decodeBase64OrNull(decoded)
	}

	// Extract an incy://add/, incy://import/ or incy://crypt1/ link wrapped in http(s)
	fun extractEmbeddedIncyLink(raw: String?): String? =
		extractEmbeddedLink(raw, INCY_SCHEME) { isIncyLink(it) || isCryptLink(it) }

	// An incy:// wrapper carries a link of one of the schemes the clients import, not any scheme.
	private fun startsWithKnownScheme(text: String): Boolean =
		SCHEMES.any { text.startsWith(it, ignoreCase = true) }

	private fun decodeBase64OrNull(text: String): String? =
		decodeBase64Printable(text, minLength = 1)?.takeIf { startsWithKnownScheme(it) }
}
