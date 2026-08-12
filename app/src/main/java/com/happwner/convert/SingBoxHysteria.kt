package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// Hysteria2, Hysteria v1 and TUIC as sing-box outbounds, which panels write in Xray-shaped configs.
// Checked against sing-box 1.13.15; TLS is never optional here - the core answers "TLS required".
internal object SingBoxHysteria {

    // What the core accepts; anything else refuses the whole document.
    private val TUIC_CONGESTION = setOf("cubic", "new_reno", "bbr")
    private val TUIC_RELAY_MODES = setOf("native", "quic")

    // Converts a hysteria2 outbound, or a hysteria one that turns out to be v2.
    internal fun convertHysteria2(o: JSONObject, notes: MutableList<String>): JSONObject? {
        val settings = o.xObj("settings") ?: JSONObject()
        val ss = o.xObj("streamSettings")

        val params = HysteriaParams(
            obfs = parsedObfsAnywhere(settings).first,
            obfsPassword = parsedObfsAnywhere(settings).second,
            hopInterval = hysteriaHopInterval(settings)
        )
        params.fromStream(notes, ss)

        val endpoints = hysteriaEndpoints(settings)
        val ep = endpoints.firstOrNull() ?: return null
        if (endpoints.size > 1) {
            notes.add(
                "the outbound lists ${endpoints.size} servers and a sing-box outbound holds one, " +
                    "so the first was used"
            )
        }

        var port = ep.port
        val ports = firstNonEmpty(ep.ports, params.ports)
        if (port == 0) firstPortOfRange(ports)?.let { port = it }
        if (ep.address.isEmpty()) return null
        if (port !in 1..65535) return null

        val sb = JSONObject()
        sb.put("type", "hysteria2")
        sb.put("server", ep.address)
        sb.put("server_port", port)

        // Port hopping: sing-box takes a list of "start:end" ranges, where Xray
        // and the Hysteria clients write "443-8443,9000".
        val hopRanges = portHopRanges(ports)
        if (hopRanges.isNotEmpty()) {
            sb.put("server_ports", JSONArray(hopRanges))
            val interval = firstNonEmpty(params.hopInterval, "")
            if (interval.isNotEmpty()) sb.put("hop_interval", durationSeconds(interval))
        }

        val password = firstNonEmpty(ep.password, params.password)
        if (password.isNotEmpty()) sb.put("password", password)

        // The core takes plain integers in Mbps; the source may spell them "100 Mbps", "100", or
        // leave them out entirely.
        for ((key, raw) in listOf(
            "up_mbps" to firstNonEmpty(ep.up, params.up),
            "down_mbps" to firstNonEmpty(ep.down, params.down)
        )) {
            if (raw.isBlank()) continue
            val n = mbpsNumber(raw)
            if (n != null) sb.put(key, n)
            else notes.add(
                "the rate \"$raw\" is not a whole number of Mbps and hysteria2 takes no other " +
                    "unit here, so it was left out and the core will pace itself"
            )
        }

        val obfsMode = firstNonEmpty(params.obfs, "")
        if (obfsMode.isNotEmpty()) {
            if (obfsMode.equals("salamander", ignoreCase = true)) {
                val ob = JSONObject()
                ob.put("type", "salamander")
                val op = params.obfsPassword
                if (op.isNotEmpty()) ob.put("password", op)
                sb.put("obfs", ob)
            } else {
                // gecko is a mihomo extension; sing-box only implements
                // salamander, and an unknown type is refused at load.
                notes.add("obfuscation \"$obfsMode\" has no sing-box equivalent and was dropped")
            }
        }

        sb.put("tls", hysteriaTlsBlock(settings, ss))
        return sb
    }

    // Converts a Hysteria v1 outbound.
    internal fun convertHysteria(o: JSONObject, notes: MutableList<String>): JSONObject? {
        val settings = o.xObj("settings") ?: JSONObject()
        val ss = o.xObj("streamSettings")

        val endpoints = hysteriaEndpoints(settings)
        val ep = endpoints.firstOrNull() ?: return null
        if (endpoints.size > 1) {
            notes.add(
                "the outbound lists ${endpoints.size} servers and a sing-box outbound holds one, " +
                    "so the first was used"
            )
        }
        if (ep.address.isEmpty()) return null
        if (ep.port !in 1..65535) return null

        val sb = JSONObject()
        sb.put("type", "hysteria")
        sb.put("server", ep.address)
        sb.put("server_port", ep.port)

        // Always auth_str, never auth.
        if (ep.password.isNotEmpty()) sb.put("auth_str", ep.password)

        // The core takes the rate either as a number of Mbps or as a string with a unit, and its
        // unit table is wider than Mbps alone.
        val upOk = putRate(sb, "up", "up_mbps", ep.up)
        val downOk = putRate(sb, "down", "down_mbps", ep.down)
        if (!upOk || !downOk) {
            // Both rates are mandatory in version 1; the core answers a missing
            // one with "missing upload speed" and refuses the outbound.
            notes.add("hysteria v1 needs both up and down rates")
            return null
        }

        // Port hopping is a version 1 feature too, and was going out only for
        // version 2.
        val ports = ep.ports
        val hopRanges = portHopRanges(ports)
        if (hopRanges.isNotEmpty()) {
            sb.put("server_ports", JSONArray(hopRanges))
            val interval = hysteriaHopInterval(settings)
            if (interval.isNotEmpty()) sb.put("hop_interval", durationSeconds(interval))
        }

        val (obfsMode, obfsPassword) = parsedObfsAnywhere(settings)
        // Version 1's obfuscator is a plain string, unlike version 2's object.
        val obfs = firstNonEmpty(obfsPassword, obfsMode)
        if (obfs.isNotEmpty()) sb.put("obfs", obfs)

        sb.put("tls", hysteriaTlsBlock(settings, ss))
        return sb
    }

    // Converts a TUIC outbound.
    internal fun convertTuic(o: JSONObject, notes: MutableList<String>): JSONObject? {
        val settings = o.xObj("settings") ?: JSONObject()
        val ss = o.xObj("streamSettings")

        val servers = settings.xObjList("servers")
        val src = servers.firstOrNull() ?: settings
        if (servers.size > 1) {
            notes.add(
                "the outbound lists ${servers.size} servers and a sing-box outbound holds one, " +
                    "so the first was used"
            )
        }

        val address = firstNonEmpty(src.xStr("address"), src.xStr("server"))
        val port = src.xInt("port")
        if (address.isEmpty() || port !in 1..65535) return null

        val uuid = firstNonEmpty(src.xStr("uuid"), settings.xStr("uuid"))
        if (uuid.isEmpty()) {
            // sing-box implements TUIC v5 only, which is uuid plus password.
            notes.add("sing-box implements TUIC v5, which needs a uuid; this outbound has none")
            return null
        }

        val sb = JSONObject()
        sb.put("type", "tuic")
        sb.put("server", address)
        sb.put("server_port", port)
        sb.put("uuid", uuid)
        val password = firstNonEmpty(src.xStrRaw("password"), settings.xStrRaw("password"))
        if (password.isNotEmpty()) sb.put("password", password)

        // The core validates this one and refuses the whole document over a value it does not know,
        // so an unfamiliar name is dropped here rather than taking the subscription down with it.
        val congestion = firstNonEmpty(
            settings.xStr("congestion_control"), settings.xStr("congestionController")
        )
        if (congestion.isNotEmpty()) {
            if (congestion in TUIC_CONGESTION) sb.put("congestion_control", congestion)
            else notes.add("congestion control \"$congestion\" is not one sing-box implements and was dropped")
        }
        val relay = firstNonEmpty(
            settings.xStr("udp_relay_mode"), settings.xStr("udpRelayMode")
        )
        if (relay.isNotEmpty()) {
            if (relay in TUIC_RELAY_MODES) sb.put("udp_relay_mode", relay)
            else notes.add("udp relay mode \"$relay\" is not one sing-box implements and was dropped")
        }
        if (settings.xBool("reduce_rtt") || settings.xBool("reduceRtt")) {
            sb.put("zero_rtt_handshake", true)
        }
        // heartbeat_interval is in MILLISECONDS - that is what the clients and mihomo's own
        // documentation say, and 10000 is the value they suggest.
        val heartbeatMs = settings.xInt("heartbeat_interval")
        if (heartbeatMs > 0) sb.put("heartbeat", "${heartbeatMs}ms")

        val tls = hysteriaTlsBlock(settings, ss)
        if (settings.xBool("disable_sni")) tls.put("disable_sni", true)
        sb.put("tls", tls)
        return sb
    }

    // The TLS block these three always carry - not conditional, since the core answers a missing
    // one with "TLS required" and rejects the whole document.
    private fun hysteriaTlsBlock(settings: JSONObject, ss: JSONObject?): JSONObject {
        val t = hysteriaTls(settings, ss)
        val tls = JSONObject()
        tls.put("enabled", true)
        if (t.sni.isNotEmpty()) tls.put("server_name", t.sni)
        if (t.insecure) tls.put("insecure", true)
        if (t.alpn.isNotEmpty()) tls.put("alpn", JSONArray(t.alpn))
        return tls
    }

    // Turns a "443-8443,9000" port list into the "443:8443" ranges sing-box takes. A single port
    // stays a single port, spelled as a one-wide range.
    internal fun portHopRanges(ports: String): List<String> {
        if (ports.isBlank()) return emptyList()
        val out = ArrayList<String>()
        for (raw in ports.split(",")) {
            val part = raw.trim()
            if (part.isEmpty()) continue
            val dash = part.indexOf('-')
            if (dash > 0) {
                val from = parsePort(part.substring(0, dash))
                val to = parsePort(part.substring(dash + 1))
                if (from != null && to != null) out.add("$from:$to")
            } else {
                parsePort(part)?.let { out.add("$it:$it") }
            }
        }
        return out
    }

    // Writes a rate under whichever of the two names fits it, and reports whether anything was
    // written at all.
    private fun putRate(sb: JSONObject, stringKey: String, numberKey: String, raw: String): Boolean {
        if (raw.isBlank()) return false
        mbpsNumber(raw)?.let { sb.put(numberKey, it); return true }
        if (isRateString(raw)) { sb.put(stringKey, raw.trim()); return true }
        return false
    }

    // Seconds, however the source spelled the interval.
    internal fun durationSeconds(v: String): String {
        val s = v.trim()
        if (s.isEmpty()) return "30s"
        if (s.all { it in '0'..'9' }) return "${s}s"
        return s
    }

    // Bits per second for the units the Hysteria clients accept, or null when the text is not a
    // rate.
    private fun bitsPerSecond(raw: String): Long? {
        val s = raw.trim()
        if (s.isEmpty()) return null
        val digits = s.takeWhile { it in '0'..'9' }
        if (digits.isEmpty()) return null
        val n = digits.toLongOrNull() ?: return null
        val unit = s.drop(digits.length).trim()
        val mult = when (unit) {
            "", "mbps", "Mbps", "m", "M" -> 1_000_000L
            "bps" -> 1L
            "Bps" -> 8L
            "Kbps" -> 1_000L
            "KBps" -> 8_000L
            "MBps" -> 8_000_000L
            "Gbps" -> 1_000_000_000L
            "GBps" -> 8_000_000_000L
            "Tbps" -> 1_000_000_000_000L
            "TBps" -> 8_000_000_000_000L
            else -> return null
        }
        return n * mult
    }

    // A rate in whole Mbps for the hysteria2 outbound, which takes up_mbps/down_mbps as numbers
    // only.
    internal fun mbpsNumber(raw: String): Int? {
        val bps = bitsPerSecond(raw) ?: return null
        if (bps <= 0 || bps % 1_000_000L != 0L) return null
        return (bps / 1_000_000L).toInt()
    }

    // True when the text is a rate the core would take verbatim in its string form.
    internal fun isRateString(raw: String): Boolean = bitsPerSecond(raw) != null
}
