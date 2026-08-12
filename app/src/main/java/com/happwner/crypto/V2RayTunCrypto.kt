package com.happwner.crypto

import android.net.Uri
import android.util.Base64
import android.util.Log
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.interfaces.RSAKey
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.Cipher

// Decryptor for v2RayTun encrypted deep links (v2raytun://crypt/<base64>): RSA-4096 PKCS#1 v1.5
object V2RayTunCrypto {
    private const val TAG = "Happwner:V2RayTun"

    private const val CRYPT_PREFIX = "v2raytun://crypt/"
    private const val KEY_COUNT = 3

    sealed class Result {
        data class Decrypted(val plaintext: String) : Result()
        object NotCryptLink : Result()
        data class Error(val reason: String) : Result()
    }

    // Is this a v2raytun://crypt/ link?
    fun isCryptLink(link: String?): Boolean {
        if (link == null) return false
        val t = link.trim()
        return t.regionMatches(0, CRYPT_PREFIX, 0, CRYPT_PREFIX.length, ignoreCase = true)
    }

    // How many RSA blocks a link may carry: anyone can mint a crypt link of any length, and each block
    // costs ~8 ms on a desktop with no suspension point, so a megabyte would be minutes uninterruptible.
    private const val MAX_RSA_BLOCKS = 256

    // Decrypt a v2raytun://crypt/ link, trying every bundled key
    fun decryptCryptLink(link: String?): Result {
        if (link.isNullOrEmpty()) return Result.NotCryptLink
        val trimmed = link.trim()
        if (!trimmed.regionMatches(0, CRYPT_PREFIX, 0, CRYPT_PREFIX.length, ignoreCase = true)) {
            return Result.NotCryptLink
        }

        val payload = trimmed.substring(CRYPT_PREFIX.length).trim()
        if (payload.isEmpty()) return Result.Error("empty payload")

        val cipherBytes = try {
            b64DecodeFlexible(payload)
        } catch (_: IllegalArgumentException) {
            return Result.Error("payload is not valid base64")
        }
        if (cipherBytes.isEmpty()) return Result.Error("ciphertext is empty after base64 decode")

        var lastReason = "no bundled key could decrypt the link"
        for (ordinal in 0 until KEY_COUNT) {
            val key = try {
                loadKey(ordinal)
            } catch (_: Throwable) {
                lastReason = "bundled key #$ordinal is malformed"
                continue
            }

            val keySize = (rsaModulusBitLength(key) + 7) / 8
            if (cipherBytes.size % keySize != 0) {
                lastReason = "ciphertext length ${cipherBytes.size} not a multiple of RSA block $keySize"
                continue
            }
            val blocks = cipherBytes.size / keySize
            if (blocks > MAX_RSA_BLOCKS) {
                lastReason = "ciphertext is $blocks RSA blocks, more than the $MAX_RSA_BLOCKS a link can hold"
                continue
            }

            val plain = try {
                rsaDecryptBlocks(key, cipherBytes, keySize)
            } catch (_: Throwable) {
                // Wrong key: PKCS#1 unpadding throws. Try the next one.
                continue
            }

            val text = decodeStrictUtf8(plain) ?: continue
            val candidate = text.trim()
            if (looksLikeSchemeLink(candidate)) {
                Log.d(TAG, "Decrypted with key #$ordinal: ${cipherBytes.size}B -> ${plain.size}B")
                return Result.Decrypted(candidate)
            }
        }
        Log.w(TAG, "Decrypt failed: $lastReason")
        return Result.Error(lastReason)
    }

    // RSA/ECB/PKCS1: decrypt block by block by key size
    private fun rsaDecryptBlocks(key: PrivateKey, cipherBytes: ByteArray, keySize: Int): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, key)

        val out = ByteArray(cipherBytes.size)
        var written = 0
        var off = 0
        while (off < cipherBytes.size) {
            val part = cipher.doFinal(cipherBytes, off, keySize)
            System.arraycopy(part, 0, out, written, part.size)
            written += part.size
            off += keySize
        }
        return out.copyOf(written)
    }

    // Strict UTF-8 decode; null if not well-formed (a wrong key's random output almost never is)
    private fun decodeStrictUtf8(b: ByteArray): String? {
        if (b.isEmpty()) return null
        return try {
            val decoder = Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            decoder.decode(ByteBuffer.wrap(b)).toString()
        } catch (_: CharacterCodingException) {
            null
        }
    }

    // A decrypted crypt link is always a scheme link (https://, vless://, ...); confirms key, rejects garbage
    private val SCHEME_LINK_REGEX = Regex("^[A-Za-z][A-Za-z0-9+.\\-]*://")

    private fun looksLikeSchemeLink(s: String): Boolean = SCHEME_LINK_REGEX.containsMatchIn(s)

    private fun rsaModulusBitLength(key: PrivateKey): Int {
        val modulus = (key as? RSAKey)?.modulus
            ?: throw IllegalStateException("PrivateKey is not RSAKey: ${key.javaClass}")
        return modulus.bitLength()
    }

    // base64 with auto-normalization (url-safe to standard, strip whitespace, re-pad with =)
    private fun b64DecodeFlexible(s: String): ByteArray {
        val sb = StringBuilder(s.length)
        for (c in s) {
            when (c) {
                ' ', '\n', '\r', '\t' -> {}
                '-' -> sb.append('+')
                '_' -> sb.append('/')
                else -> sb.append(c)
            }
        }
        val rem = sb.length % 4
        if (rem != 0) repeat(4 - rem) { sb.append('=') }
        return Base64.decode(sb.toString(), Base64.DEFAULT)
    }

    private const val V2RAY_SCHEME = "v2raytun://"
    private const val EXTRACT_MAX_DEPTH = 2

    // Subscription/config import is path-style only: v2raytun://import/<URL or CONFIG_KEY>
    private const val IMPORT_PREFIX = "v2raytun://import/"

    // Is this a v2raytun://import/ deep link (subscription or config)?
    fun isImportLink(link: String?): Boolean {
        if (link == null) return false
        val t = link.trim()
        return t.regionMatches(0, IMPORT_PREFIX, 0, IMPORT_PREFIX.length, ignoreCase = true)
    }

    // Strip v2raytun://import/ and unwrap (url-decode or base64) to the inner link
    fun stripImportPrefix(link: String?): String? {
        if (link == null) return null
        val trimmed = link.trim()
        if (!trimmed.regionMatches(0, IMPORT_PREFIX, 0, IMPORT_PREFIX.length, ignoreCase = true)) return null
        var rest = trimmed.substring(IMPORT_PREFIX.length).trim()
        if (rest.isEmpty()) return null
        if (rest.indexOf('%') >= 0) {
            val decoded = try { Uri.decode(rest) } catch (_: Throwable) { null }
            if (!decoded.isNullOrEmpty()) rest = decoded.trim()
        }
        if (looksLikeSchemeLink(rest)) return rest
        val fromB64 = decodeBase64Link(rest)
        if (fromB64 != null) return fromB64
        return rest.ifEmpty { null }
    }

    // Extract a v2raytun:// link wrapped in http(s) (up to 2 levels of URL-decoding)
    fun extractEmbeddedV2RayLink(raw: String?): String? = extractEmbeddedV2RayLink(raw, 0)

    private fun extractEmbeddedV2RayLink(raw: String?, depth: Int): String? {
        if (raw == null) return null
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null

        if (trimmed.startsWith(V2RAY_SCHEME, ignoreCase = true)) return null
        if (!trimmed.startsWith("http://", ignoreCase = true) &&
            !trimmed.startsWith("https://", ignoreCase = true)) return null

        val start = indexOfV2RayScheme(trimmed)
        if (start < 0) {
            if (depth < EXTRACT_MAX_DEPTH && trimmed.indexOf("v2raytun%", ignoreCase = true) >= 0) {
                val once = try { Uri.decode(trimmed) } catch (_: Throwable) { null }
                if (once != null && once != trimmed) return extractEmbeddedV2RayLink(once, depth + 1)
            }
            return null
        }

        val candidate = carveV2RayCandidate(trimmed, start)
        val rawDecoded = try { Uri.decode(candidate) } catch (_: Throwable) { candidate }
        var decoded = (rawDecoded ?: candidate).trim()

        var guard = 0
        while (guard < EXTRACT_MAX_DEPTH && decoded.startsWith("v2raytun%", ignoreCase = true)) {
            val next = try { Uri.decode(decoded) } catch (_: Throwable) { null } ?: break
            val nextTrimmed = next.trim()
            if (nextTrimmed == decoded) break
            decoded = nextTrimmed
            guard++
        }

        if (!decoded.startsWith(V2RAY_SCHEME, ignoreCase = true)) return null
        if (decoded.length <= V2RAY_SCHEME.length) return null
        if (decoded == trimmed) return null
        return decoded
    }

    // Locate 'v2raytun' followed by :// or %3a (case-insensitive)
    private fun indexOfV2RayScheme(s: String): Int {
        val scheme = "v2raytun"
        val n = s.length
        var i = 0
        while (i < n) {
            if (i + scheme.length <= n && s.regionMatches(i, scheme, 0, scheme.length, ignoreCase = true)) {
                val rest = i + scheme.length
                if (rest + 3 <= n && s[rest] == ':' && s[rest + 1] == '/' && s[rest + 2] == '/') return i
                if (rest + 3 <= n && s[rest] == '%' && s[rest + 1] == '3' &&
                    (s[rest + 2] == 'a' || s[rest + 2] == 'A')) return i
            }
            i++
        }
        return -1
    }

    // Take everything up to the first delimiter
    private fun carveV2RayCandidate(s: String, start: Int): String {
        var end = start
        while (end < s.length && !isV2RayDelimiter(s[end])) end++
        return s.substring(start, end)
    }

    // Characters that terminate a v2raytun:// link
    private fun isV2RayDelimiter(c: Char): Boolean {
        val o = c.code
        if (o < 0x20 || o > 0x7e) return true
        return when (c) {
            ' ', '&', '#', '"', '\'', '`', '<', '>', '\\', '|', '^', '{', '}', '[', ']' -> true
            else -> false
        }
    }

    // Decode a base64 blob into a scheme link, if that's what it is
    private fun decodeBase64Link(s: String): String? {
        val cleaned = s.trim()
        if (cleaned.length < 8) return null
        var hasStd = false
        var hasUrl = false
        for (c in cleaned) {
            when {
                c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' -> {}
                c == '=' -> {}
                c == '+' || c == '/' -> hasStd = true
                c == '-' || c == '_' -> hasUrl = true
                else -> return null
            }
        }
        if (hasStd && hasUrl) return null
        val padded = when (cleaned.length % 4) {
            2 -> "$cleaned=="
            3 -> "$cleaned="
            else -> cleaned
        }
        val flag = if (hasUrl) Base64.URL_SAFE else Base64.DEFAULT
        return try {
            val data = Base64.decode(padded, flag)
            if (data.isEmpty()) return null
            for (b in data) {
                val v = b.toInt() and 0xff
                if (!(v in 0x20..0x7e || v == 0x09 || v == 0x0a || v == 0x0d)) return null
            }
            val decoded = String(data, Charsets.UTF_8).trim()
            if (looksLikeSchemeLink(decoded)) decoded else null
        } catch (_: Throwable) {
            null
        }
    }

    private val keyCache: Array<PrivateKey?> = arrayOfNulls(KEY_COUNT)
    private val keyLock = Any()

    // Cached PKCS#8 key by ordinal; all access under keyLock for safe publication
    private fun loadKey(ordinal: Int): PrivateKey {
        synchronized(keyLock) {
            keyCache[ordinal]?.let { return it }
            val der = Base64.decode(KEYS_B64[ordinal], Base64.DEFAULT)
            val key = try {
                KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(der))
            } catch (e: GeneralSecurityException) {
                throw IllegalStateException("bundled key #$ordinal is malformed: ${e.message}", e)
            }
            keyCache[ordinal] = key
            return key
        }
    }

    // RSA-4096 PKCS#8 keys bundled in v2RayTun: [0]=crypt3 (docs key), [1]=crypt4, [2]=key3
    private val KEYS_B64 = arrayOf(
        "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",
    )
}
