package com.happwner.data

import android.util.Base64
import android.util.Log
import com.happwner.text.base64Flag
import com.happwner.text.decodeStrictUtf8
import com.happwner.text.hasBinaryControls

// Happ's app-management parameters, in either shape a subscription may deliver them: a response
// header ("change-user-agent: xray") or a comment line in the body ("#change-user-agent: xray").
// The header wins when a provider sends both.
object HappParams {
	private const val TAG = "Happwner:Params"

	private const val CHANGE_USER_AGENT = "change-user-agent"

	// A value is one header line; anything longer is not one.
	private const val MAX_VALUE_LENGTH = 512

	// Announced base64, as the docs spell it. A bare value is taken literally - guessing would
	// turn "Happ/4.1.0" into noise.
	private const val BASE64_PREFIX = "base64:"

	// Past this a body is not worth decoding twice just to search it.
	private const val MAX_WRAPPED_BODY = 8 * 1024 * 1024

	// The User-Agent this subscription asks to be requested with. The body must already be
	// decrypted; base64 wrapping is undone here.
	fun changeUserAgent(headers: Map<String, List<String>>?, body: String?): String? =
		value(CHANGE_USER_AGENT, headers, body)

	// Each source is validated on its own, so one that carries an unusable value still leaves the
	// next its turn.
	private fun value(name: String, headers: Map<String, List<String>>?, body: String?): String? {
		if (headers != null) header(headers, name)?.let { raw -> normalize(raw)?.let { return it } }
		if (body.isNullOrEmpty()) return null
		bodyLine(body, name)?.let { raw -> normalize(raw)?.let { return it } }
		// A wrapped body hides its own parameter lines until it is unwrapped.
		val unwrapped = unwrapBase64(body) ?: return null
		return bodyLine(unwrapped, name)?.let { normalize(it) }
	}

	private fun header(headers: Map<String, List<String>>, name: String): String? {
		for ((key, values) in headers) {
			if (key.equals(name, ignoreCase = true)) {
				values.firstOrNull()?.takeIf { it.isNotBlank() }?.let { return it }
			}
		}
		return null
	}

	// Only a line beginning with '#' is a parameter line, which is what keeps a link's own "#title"
	// fragment out of this. Nothing is allocated until a line matches, so any body costs one pass.
	private fun bodyLine(body: String, name: String): String? {
		var position = 0
		while (position < body.length) {
			var eol = body.indexOf('\n', position)
			if (eol < 0) eol = body.length
			var end = eol
			if (end > position && body[end - 1] == '\r') end--
			if (end > position && body[position] == '#') matchParam(body, position + 1, end,
				name)?.let { return it }
			position = eol + 1
		}
		return null
	}

	// "<name>: <value>" within [start, end), or null when the line names another parameter.
	private fun matchParam(body: String, start: Int, end: Int, name: String): String? {
		var position = skipBlanks(body, start, end)
		if (position + name.length > end) return null
		if (!body.regionMatches(position, name, 0, name.length, ignoreCase = true)) return null
		position = skipBlanks(body, position + name.length, end)
		if (position >= end || body[position] != ':') return null
		return body.substring(position + 1, end)
	}

	private fun skipBlanks(body: String, from: Int, end: Int): Int {
		var position = from
		while (position < end && (body[position] == ' ' || body[position] == '\t')) position++
		return position
	}

	// What cannot go into a request header is not a value: a CR or LF splits the request, and a
	// character the connection cannot spell would reach the provider mangled anyway - which defeats
	// the check the parameter exists for.
	private fun normalize(raw: String): String? {
		var value = raw.trim()
		if (value.startsWith(BASE64_PREFIX, ignoreCase = true)) {
			value = decodeValue(value.substring(BASE64_PREFIX.length).trim())?.trim() ?: return null
		}
		if (value.isEmpty()) return null
		if (value.length > MAX_VALUE_LENGTH || value.any { it.code < 0x20 || it.code > 0x7e }) {
			Log.w(TAG, "Ignoring a parameter value that could not be sent as a header")
			return null
		}
		return value
	}

	private fun decodeValue(encoded: String): String? {
		val flag = base64Flag(encoded) ?: return null
		return try {
			String(Base64.decode(encoded, flag), Charsets.UTF_8)
		} catch (_: IllegalArgumentException) {
			null
		}
	}

	// A whole body wrapped in base64, decoded for reading only - deliberately more permissive than
	// the converter's own unwrapping, which also has to decide what it is looking at.
	private fun unwrapBase64(body: String): String? {
		if (body.length < 10 || body.length > MAX_WRAPPED_BODY) return null
		val cleaned = body.trim()
		val flag = base64Flag(cleaned) ?: return null

		val decodedBytes = try {
			Base64.decode(cleaned, flag)
		} catch (_: IllegalArgumentException) {
			return null
		}
		val decoded = decodeStrictUtf8(decodedBytes) ?: return null
		// Binary that happens to spell out base64 characters is not a subscription body.
		return if (hasBinaryControls(decoded)) null else decoded
	}
}
