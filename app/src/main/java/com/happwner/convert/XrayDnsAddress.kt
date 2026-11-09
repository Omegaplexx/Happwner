package com.happwner.convert

import com.happwner.text.splitHostPort
// What an Xray DNS server address means. Both converters read the same schemes and must agree about them.
internal object XrayDnsAddress {

	// A resolver, read but not yet written in either core's dialect.
	internal sealed class Kind {
		// A server reached over the network. scheme is Xray's own name for the transport,
		// normalised: https, h3, tls, quic, tcp or udp.
		data class Remote(
			val scheme: String,
			val host: String,
			val port: Int?,
			// Xray's "+local" suffix: the query is dialed by the system rather than sent through
			// routing, so it never leaves by the proxy. sing-box says the same with a detour.
			val direct: Boolean,
			// The query path of an HTTPS or HTTP/3 resolver, without a leading slash.
			val path: String
		) : Kind()

		// dhcp://auto or dhcp://<interface>.
		data class Dhcp(val iface: String) : Kind()

		// "localhost": whatever the system resolves with.
		object Local : Kind()

		// "fakedns": answers from a fake address pool rather than a resolver.
		object FakeDns : Kind()

		// rcode:// and anything neither core can act on.
		object None : Kind()
	}

	// Why a server whose address reads as None is left out, worded alike in every pass: h2c is Xray's own
	// DoH in cleartext, which neither core has a resolver for; anything else Xray cannot use either.
	internal fun droppedReason(raw: String?): String {
		val text = raw.orEmpty().trim()
		val why = if ("://" in text && text.substringBefore("://").lowercase() == "h2c") {
			"is DNS over cleartext HTTP/2, which this core has no resolver for"
		} else {
			"names no resolver Xray can use"
		}
		return "dns server \"$text\" $why, so it was dropped"
	}

	private val HTTP3_SCHEMES = setOf("h3", "https+h3", "https3", "http3")
	private val PLAIN_SCHEMES = setOf("tls", "quic", "tcp", "udp")

	internal fun parse(raw: String?): Kind {
		if (raw.isNullOrEmpty()) return Kind.None
		val text = raw.trim()
		if (text.isEmpty()) return Kind.None
		if (text == "fakedns") return Kind.FakeDns
		if (text == "localhost") return Kind.Local
		if (text.startsWith("rcode://")) return Kind.None
		if (!text.contains("://")) {
			// A bare host[:port] is plain DNS over UDP, Xray's default when no scheme says otherwise.
			// One carrying URL syntax is a name Xray tries to resolve as it stands, and never can.
			if (text.any { it in "#/?" }) return Kind.None
			val hostPort = splitHostPort(text)
			return Kind.Remote("udp", hostPort.host, hostPort.port, false, "")
		}

		// Xray reads the address as a URL, whose fragment names no part of the resolver.
		val rest = text.substringAfter("://").substringBefore('#')
		// "+local" says Xray dials the resolver itself instead of routing the query, and "+udp"
		// only says which transport a DoH server falls back to.
		val rawScheme = text.substringBefore("://").lowercase()
		val direct = rawScheme.endsWith("+local")
		val scheme = rawScheme.replace("+local", "").replace("+udp", "")
		return when {
			scheme == "https" || scheme in HTTP3_SCHEMES -> {
				val slash = rest.indexOf('/')
				val hostPort = if (slash < 0) rest else rest.substring(0, slash)
				val path = if (slash < 0) "" else rest.substring(slash + 1)
				val split = splitHostPort(hostPort)
				Kind.Remote(if (scheme == "https") "https" else "h3", split.host, split.port,
					direct, path)
			}
			scheme in PLAIN_SCHEMES -> {
				// Only the host and port name such a server; Xray ignores a path or query after them.
				val hostPort = splitHostPort(rest.substringBefore('/').substringBefore('?'))
				Kind.Remote(scheme, hostPort.host, hostPort.port, direct, "")
			}
			scheme == "dhcp" -> Kind.Dhcp(if (rest == "auto") "" else rest)
			else -> Kind.None
		}
	}
}
