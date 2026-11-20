package com.happwner.bridge

import java.net.HttpURLConnection

// What a request tells the provider about the device. A blank field sends no header of its own; only the
// User-Agent goes out empty, since the connection would add its own otherwise.
data class RequestIdentity(
	val hwid: String = "",
	val userAgent: String = "",
	val model: String = "",
	val os: String = "",
	val osVersion: String = "",
	val headers: List<Pair<String, String>> = emptyList()
) {
	internal fun applyTo(conn: HttpURLConnection) {
		conn.setRequestProperty(USER_AGENT, userAgent)
		listOf(HWID to hwid, DEVICE_MODEL to model, DEVICE_OS to os, OS_VERSION to osVersion)
			.forEach { (name, value) -> if (value.isNotEmpty()) conn.setRequestProperty(name, value) }
		headers.forEach { (name, value) -> conn.setRequestProperty(name, value) }
	}

	companion object {
		const val HWID = "x-hwid"
		const val USER_AGENT = "User-Agent"
		const val DEVICE_MODEL = "x-device-model"
		const val DEVICE_OS = "x-device-os"
		const val OS_VERSION = "x-ver-os"
	}
}

// Headers a person adds themselves. The fields own their five, and the connection owns the rest of the reserved ones.
object CustomHeaders {
	// Rows a person can add on the screen; a link may carry more.
	const val MAX_ON_SCREEN = 20

	const val MAX_FROM_LINK = 40

	private val RESERVED = setOf(
		RequestIdentity.HWID, RequestIdentity.USER_AGENT, RequestIdentity.DEVICE_MODEL,
		RequestIdentity.DEVICE_OS, RequestIdentity.OS_VERSION,
		"host", "content-length", "connection", "transfer-encoding"
	).map { it.lowercase() }.toSet()

	const val MAX_NAME_LENGTH = 64

	private const val NAME_PUNCTUATION = "!#\$%&'*+.^_`|~-"

	fun isNameChar(char: Char): Boolean =
		char in '0'..'9' || char in 'A'..'Z' || char in 'a'..'z' || char in NAME_PUNCTUATION

	fun isAllowedName(name: String): Boolean =
		name.length in 1..MAX_NAME_LENGTH && name.all(::isNameChar) && name.lowercase() !in RESERVED

	// The connection refuses anything but printable ASCII in a value, and a line break would end the header.
	fun isAllowedValue(value: String): Boolean =
		value.length <= 1024 && value.all { it in ' '..'~' }

	// A link's "Name:Value", or null when it is not an acceptable header.
	fun fromPair(text: String): Pair<String, String>? {
		val name = text.substringBefore(':').trim()
		val value = text.substringAfter(':', "").trim()
		return if (value.isNotEmpty() && isAllowedName(name) && isAllowedValue(value)) name to value else null
	}
}
