package com.happwner.client

// The shapes a v2raytun:// link takes: the crypt/ payload, the import/ wrapper, and a link embedded
// in an http(s) URL. Decrypting the payload is V2RayTunCrypto's.
object V2RayTunLinks {
	internal const val V2RAY_SCHEME = "v2raytun://"
	internal const val CRYPT_PREFIX = "v2raytun://crypt/"
	// Whether this is a v2raytun://crypt/ link.
	fun isCryptLink(link: String?): Boolean = link.trimmedStartsWith(CRYPT_PREFIX)

	// Subscription/config import is path-style only: v2raytun://import/<URL or CONFIG_KEY>
	private const val IMPORT_PREFIX = "v2raytun://import/"

	// Whether this is a v2raytun://import/ deep link (subscription or config).
	fun isImportLink(link: String?): Boolean = link.trimmedStartsWith(IMPORT_PREFIX)

	// Strip v2raytun://import/ and unwrap (url-decode or base64) to the inner link
	fun stripImportPrefix(link: String?): String? {
		return unwrapAddLink(link, IMPORT_PREFIX)
	}

	// Extract a v2raytun:// link wrapped in http(s)
	fun extractEmbeddedV2RayLink(raw: String?): String? =
		extractEmbeddedLink(raw, V2RAY_SCHEME) { hasPrefixAndMore(it, V2RAY_SCHEME) }
}
