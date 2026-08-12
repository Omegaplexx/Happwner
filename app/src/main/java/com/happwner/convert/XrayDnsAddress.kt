package com.happwner.convert

// What an Xray DNS server address means. Both converters read the same schemes and must agree about
// them.
internal object XrayDnsAddress {

    // A resolver, read but not yet written in either core's dialect.
    internal sealed class Kind {
        // A server reached over the network. scheme is Xray's own name for the transport,
        // normalised: https, h3, tls, quic, tcp or udp.
        data class Remote(
            val scheme: String,
            val host: String,
            val port: Int?,
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

    private val HTTP3_SCHEMES = setOf("h3", "https+h3", "https3", "http3")
    private val PLAIN_SCHEMES = setOf("tls", "quic", "tcp", "udp")

    internal fun parse(raw: String?): Kind {
        if (raw.isNullOrEmpty()) return Kind.None
        val s = raw.trim()
        if (s.isEmpty()) return Kind.None
        if (s == "fakedns") return Kind.FakeDns
        if (s == "localhost") return Kind.Local
        if (s.startsWith("rcode://")) return Kind.None
        if (!s.contains("://")) {
            // A bare host[:port] is plain DNS over UDP, Xray's default when no
            // scheme says otherwise.
            val hp = SingBoxUtil.splitHostPort(s)
            return Kind.Remote("udp", hp.host, hp.port, "")
        }

        val rest = s.substringAfter("://")
        // "+local" and "+udp" describe how Xray reaches the resolver, not what
        // it speaks, and neither core has a field for it.
        val scheme = s.substringBefore("://").lowercase()
            .replace("+local", "").replace("+udp", "")
        return when {
            scheme == "https" || scheme in HTTP3_SCHEMES -> {
                val slash = rest.indexOf('/')
                val hostPort = if (slash < 0) rest else rest.substring(0, slash)
                val path = if (slash < 0) "" else rest.substring(slash + 1)
                val hp = SingBoxUtil.splitHostPort(hostPort)
                Kind.Remote(if (scheme == "https") "https" else "h3", hp.host, hp.port, path)
            }
            scheme in PLAIN_SCHEMES -> {
                val hp = SingBoxUtil.splitHostPort(rest)
                Kind.Remote(scheme, hp.host, hp.port, "")
            }
            scheme == "dhcp" -> Kind.Dhcp(if (rest == "auto") "" else rest)
            else -> Kind.None
        }
    }
}
