package com.happwner.client

// The shapes a happ:// link takes: the cryptN/ modes with their payloads, the add/ wrapper, and a
// link embedded in an http(s) URL. Decrypting the payload is HappCrypto's.
object HappLinks {
	// ordinal: which built-in decoder reads the link - crypt=0 ... crypt5=4 - or null for a version
	// this build has no keys for, which only Happanion can open.
	internal data class HappInput(val ordinal: Int?, val modeName: String, val payload: String)

	// happ://cryptN/ for any N, a version this build does not know yet included.
	private val CRYPT_LINK =
		Regex("^happ://(crypt\\d*)/(.*)$", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
	private val BUILT_IN_MODES = listOf("crypt", "crypt2", "crypt3", "crypt4", "crypt5")

	// Splits a happ:// link into its mode and payload.
	internal fun parseInput(link: String): HappInput? {
		val match = CRYPT_LINK.matchEntire(link) ?: return null
		val mode = match.groupValues[1].lowercase()
		return HappInput(BUILT_IN_MODES.indexOf(mode).takeIf { it >= 0 }, mode, match.groupValues[2])
	}

	private const val HAPP_SCHEME = "happ://"

	// Extract a happ:// link wrapped in http(s), its scheme written as happ writes it
	fun extractEmbeddedHappLink(raw: String?): String? =
		extractEmbeddedLink(raw, HAPP_SCHEME) { hasPrefixAndMore(it, HAPP_SCHEME) }
			?.let { HAPP_SCHEME + it.substring(HAPP_SCHEME.length) }

	private const val ADD_PREFIX = "happ://add/"

	// The crypt mode a happ:// link names ("crypt", "crypt2" ...), including a version this build
	// has no keys for, or null when the link is not a happ crypt link.
	fun happLinkMode(link: String?): String? {
		if (link.isNullOrEmpty()) return null
		return parseInput(link.trim())?.modeName
	}

	// Whether this is an add/ or cryptN/ happ link.
	fun isOpenableHappLink(link: String?): Boolean =
		link.trimmedStartsWith(ADD_PREFIX) || happLinkMode(link) != null

	// Strip happ://add/ and unwrap (url-decode or base64) to the inner link
	fun stripAddPrefix(link: String?): String? {
		return unwrapAddLink(link, ADD_PREFIX)
	}
}
