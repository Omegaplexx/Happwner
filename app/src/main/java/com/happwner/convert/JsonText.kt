package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// JSON as the converters hand it out. Android's org.json writes every "/" as "\/" - valid JSON, but
// noise in a config and a difference from the same conversion on a desktop JVM.
internal fun jsonText(value: JSONObject, indent: Int = 0): String =
	withPlainSlashes(if (indent > 0) value.toString(indent) else value.toString())

internal fun jsonText(value: JSONArray, indent: Int = 0): String =
	withPlainSlashes(if (indent > 0) value.toString(indent) else value.toString())

// As jsonText, or null where Android's org.json cannot write the value: it reads 1e400 in a list as
// infinity, and writing that back out hands back null instead of text.
internal fun jsonTextOrNull(value: JSONObject): String? = plainOrNull(value.toString())

internal fun jsonTextOrNull(value: JSONArray): String? = plainOrNull(value.toString())

private fun plainOrNull(written: String?): String? = written?.let(::withPlainSlashes)

// A copy that shares nothing with the original, taken by walking it rather than writing it out:
// Android's org.json reads 1e400 in a list as infinity and cannot write that back to read it again.
internal fun jsonCopy(value: JSONObject): JSONObject {
	val copy = JSONObject()
	for (key in value.keys()) copy.put(key, copyOf(value.opt(key)))
	return copy
}

internal fun jsonCopy(value: JSONArray): JSONArray {
	val copy = JSONArray()
	for (i in 0 until value.length()) copy.put(copyOf(value.opt(i)))
	return copy
}

private fun copyOf(value: Any?): Any? = when (value) {
	is JSONObject -> jsonCopy(value)
	is JSONArray -> jsonCopy(value)
	else -> value
}

// Escapes are read pair by pair from the left, so only a "\/" pair itself turns into "/"; an escaped
// backslash before a slash stays as it was.
internal fun withPlainSlashes(json: String): String {
	if ('\\' !in json) return json
	val out = StringBuilder(json.length)
	var i = 0
	while (i < json.length) {
		val c = json[i]
		if (c == '\\' && i + 1 < json.length) {
			val next = json[i + 1]
			if (next == '/') out.append('/') else out.append(c).append(next)
			i += 2
		} else {
			out.append(c)
			i++
		}
	}
	return out.toString()
}
