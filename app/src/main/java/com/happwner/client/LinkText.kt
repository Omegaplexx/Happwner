package com.happwner.client

import android.net.Uri
import android.util.Base64
import com.happwner.text.Base64Alphabet
import com.happwner.text.base64Alphabet
import com.happwner.text.padBase64
import java.security.PrivateKey
import java.security.interfaces.RSAKey
import javax.crypto.Cipher

// What the clients' own link decoders share: a scheme link's text and prefixes, the scheme's
// position in a wrapper and the link carried there, base64 that must decode to printable text,
// and RSA decrypted block by block.

private val SCHEME_LINK = Regex("^[A-Za-z][A-Za-z0-9+.\\-]*://")

// True when the text starts with a scheme, as every decrypted link does (https://, vless://, ...).
internal fun looksLikeSchemeLink(text: String): Boolean = SCHEME_LINK.containsMatchIn(text)

// Where "scheme" is followed by "://" or its percent-encoded "%3a" in the text, case-insensitive,
// or -1: the link may sit inside a wrapper that encoded its colon.
internal fun indexOfScheme(text: String, scheme: String): Int {
	val textLength = text.length
	var position = 0
	while (position < textLength) {
		if (position + scheme.length <= textLength && text.regionMatches(position, scheme, 0,
			scheme.length, ignoreCase = true)) {
			val rest = position + scheme.length
			if (rest + 3 <= textLength && text[rest] == ':' && text[rest + 1] == '/' && text[rest +
				2] == '/') return position
			if (rest + 3 <= textLength && text[rest] == '%' && text[rest + 1] == '3' &&
				(text[rest + 2] == 'a' || text[rest + 2] == 'A')) return position
		}
		position++
	}
	return -1
}

// Base64 that decodes to printable ASCII text at least minLength characters long, or null: the
// decoders read a wrapped link with it and reject a key that produced noise.
internal fun decodeBase64Printable(text: String, minLength: Int): String? {
	val cleaned = text.trim()
	if (cleaned.length < minLength) return null
	val alphabet = base64Alphabet(cleaned) ?: return null
	val flag = if (alphabet == Base64Alphabet.URL_SAFE) Base64.URL_SAFE else Base64.DEFAULT
	return try {
		val decodedBytes = Base64.decode(padBase64(cleaned), flag)
		if (decodedBytes.isEmpty()) return null
		for (byte in decodedBytes) {
			val value = byte.toInt() and 0xff
			if (!(value in 0x20..0x7e || value == 0x09 || value == 0x0a || value == 0x0d)) return null
		}
		String(decodedBytes, Charsets.UTF_8).trim()
	} catch (_: Throwable) {
		null
	}
}

// RSA/PKCS#1 v1.5 over a ciphertext of several key-sized blocks, decrypted one block at a time.
internal fun rsaDecryptBlocks(cipherBytes: ByteArray, key: PrivateKey, keySize: Int): ByteArray {
	val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
	cipher.init(Cipher.DECRYPT_MODE, key)
	val out = ByteArray(cipherBytes.size)
	var written = 0
	var off = 0
	while (off < cipherBytes.size) {
		val plain = cipher.doFinal(cipherBytes, off, keySize)
		System.arraycopy(plain, 0, out, written, plain.size)
		written += plain.size
		off += keySize
	}
	return out.copyOf(written)
}

// The link an "add"/"import" wrapper carries: the text after the prefix, percent-decoded when it
// was encoded, taken as a scheme link, or decoded from base64 when it is one, or as it stands.
internal fun unwrapAddLink(link: String?, prefix: String): String? {
	if (link == null) return null
	val trimmed = link.trim()
	if (!trimmed.startsWith(prefix, ignoreCase = true)) return null
	var rest = trimmed.substring(prefix.length).trim()
	if (rest.isEmpty()) return null
	if (rest.indexOf('%') >= 0) {
		val decoded = try { Uri.decode(rest) } catch (_: Throwable) { null }
		if (!decoded.isNullOrEmpty()) rest = decoded.trim()
	}
	if (looksLikeSchemeLink(rest)) return rest
	decodeBase64Printable(rest, minLength = 8)?.takeIf { looksLikeSchemeLink(it) }?.let { return it }
	return rest.ifEmpty { null }
}

// The RSA key's modulus size in bits, which is the ciphertext block size.
internal fun rsaModulusBitLength(key: PrivateKey): Int {
	val modulus = (key as? RSAKey)?.modulus
		?: throw IllegalStateException("PrivateKey is not RSAKey: ${key.javaClass}")
	return modulus.bitLength()
}

// True when the text, trimmed, starts with one of the prefixes in any case: how each client's links
// are told apart.
internal fun String?.trimmedStartsWith(vararg prefixes: String): Boolean {
	val trimmed = this?.trim() ?: return false
	return prefixes.any { trimmed.startsWith(it, ignoreCase = true) }
}

// True when the text starts with the prefix, in any case, and carries something after it.
internal fun hasPrefixAndMore(text: String, prefix: String): Boolean =
	text.length > prefix.length && text.startsWith(prefix, ignoreCase = true)

// How many times a wrapper is percent-decoded looking for the link inside it.
private const val EXTRACT_MAX_DEPTH = 2

// The characters a URL must escape: an unescaped one ends the link before it.
private const val LINK_DELIMITERS = " &#\"'`<>\\|^{}[]"

// A link of the scheme ("happ://", ...) carried inside an http(s) URL, found as it is or
// percent-encoded up to EXTRACT_MAX_DEPTH levels deep, and cut where a link cannot go on. Null when
// the URL carries none, or when accept turns the one it carries down.
internal fun extractEmbeddedLink(
	raw: String?,
	scheme: String,
	accept: (String) -> Boolean
): String? = extractEmbeddedLink(raw, scheme, accept, depth = 0)

private fun extractEmbeddedLink(
	raw: String?,
	scheme: String,
	accept: (String) -> Boolean,
	depth: Int
): String? {
	val trimmed = raw?.trim() ?: return null
	if (trimmed.isEmpty() || trimmed.startsWith(scheme, ignoreCase = true)) return null
	if (!trimmed.startsWith("http://", ignoreCase = true) &&
		!trimmed.startsWith("https://", ignoreCase = true)) return null

	val name = scheme.removeSuffix("://")
	val encoded = "$name%"
	val start = indexOfScheme(trimmed, name)
	if (start < 0) {
		// Not there as it is: the wrapper may have encoded it, so decode once and look again.
		if (depth < EXTRACT_MAX_DEPTH && trimmed.indexOf(encoded, ignoreCase = true) >= 0) {
			val once = try { Uri.decode(trimmed) } catch (_: Throwable) { null }
			if (once != null && once != trimmed) {
				return extractEmbeddedLink(once, scheme, accept, depth + 1)
			}
		}
		return null
	}

	val candidate = carveLink(trimmed, start)
	val decoded = try { Uri.decode(candidate) } catch (_: Throwable) { null }
	return (decoded ?: candidate).trim().takeIf(accept)
}

// Everything from start up to the first character a link cannot hold.
private fun carveLink(text: String, start: Int): String {
	var end = start
	while (end < text.length && !isLinkDelimiter(text[end])) end++
	return text.substring(start, end)
}

// A control or non-ASCII character ends a link, as does one a URL must escape.
private fun isLinkDelimiter(char: Char): Boolean =
	char.code !in 0x20..0x7e || char in LINK_DELIMITERS
