package com.happwner.convert

import org.json.JSONObject

// The routing and DNS of an Xray configuration, written the way mihomo reads them.
internal object MihomoRouting {

    private const val NO_RESOLVE = ",no-resolve"

    // mihomo's own targets, which never name a proxy.
    private val BUILTIN_TARGETS = setOf("DIRECT", "REJECT", "REJECT-DROP", "PASS")

    // One Xray condition entry as a mihomo rule fragment, or null when mihomo has nothing that
    // matches it.
    private fun domainFragment(entry: String): String? =
        when (val n = XrayConditions.name(entry)) {
            is XrayConditions.Name.Exact -> "DOMAIN,${n.value}"
            is XrayConditions.Name.Suffix -> "DOMAIN-SUFFIX,${n.value}"
            is XrayConditions.Name.Keyword -> "DOMAIN-KEYWORD,${n.value}"
            is XrayConditions.Name.Pattern -> "DOMAIN-REGEX,${n.value}"
            is XrayConditions.Name.Geosite -> "GEOSITE,${n.value}"
            XrayConditions.Name.External, XrayConditions.Name.Unusable -> null
        }

    private fun ipFragment(entry: String, noResolve: Boolean): String? {
        val suffix = if (noResolve) NO_RESOLVE else ""
        return when (val a = XrayConditions.address(entry)) {
            is XrayConditions.Address.Cidr -> "IP-CIDR,${a.value}$suffix"
            is XrayConditions.Address.Country -> "GEOIP,${a.code}$suffix"
            is XrayConditions.Address.NotCountry -> "NOT,((GEOIP,${a.code}$suffix))"
            XrayConditions.Address.Private -> "GEOIP,private$suffix"
            XrayConditions.Address.External, XrayConditions.Address.Unusable -> null
        }
    }

    // "80,443,1000-2000" as mihomo writes a port list.
    private fun portList(value: Any?): String {
        val raw = when (value) {
            null -> ""
            is String -> value
            else -> value.toString()
        }
        val parts = raw.split(",").map { it.trim() }.filter { it.isNotEmpty() }
            .filter { tok ->
                // A port the core refuses costs the whole configuration.
                val bits = tok.split("-")
                bits.isNotEmpty() && bits.size <= 2 &&
                    bits.all { b -> b.toIntOrNull()?.let { SingBoxUtil.isUsablePort(it) } == true }
            }
        return parts.joinToString("/")
    }

    // Wraps the alternatives of one condition into a single fragment.
    private fun anyOf(fragments: List<String>): String? = when {
        fragments.isEmpty() -> null
        fragments.size == 1 -> fragments.first()
        else -> "OR,(" + fragments.joinToString(",") { "($it)" } + ")"
    }

    // Converts routing.rules.
    internal fun rules(
        routing: JSONObject?,
        targetOf: (String) -> String?,
        warn: (String) -> Unit
    ): List<String> {
        if (routing == null) return emptyList()
        val list = routing.xObjList("rules")
        if (list.isEmpty()) return emptyList()
        val noResolve = routing.xStr("domainStrategy").trim() == "AsIs" ||
            routing.xStr("domainStrategy").isEmpty()

        val out = ArrayList<String>()
        for ((i, r) in list.withIndex()) {
            val type = r.xStr("type")
            if (type.isNotEmpty() && type != "field") continue

            val tag = when {
                r.has("balancerTag") -> r.xStr("balancerTag")
                else -> r.xStr("outboundTag")
            }
            val target = targetOf(tag)
            if (target == null) {
                warn("routing.rules[$i] points at \"$tag\", which produced no proxy here; the rule was dropped")
                continue
            }

            // Each group is one Xray condition: its entries are alternatives,
            // and the groups themselves all have to hold at once.
            val groups = ArrayList<String>()
            var lostSomething = false
            // True when every condition the rule stated matches anything, so
            // the rule itself is a catch-all rather than something we failed at.
            var matchesEverything = true

            if (r.has("domain")) {
                matchesEverything = false
                val frags = r.xStrList("domain").mapNotNull {
                    val f = domainFragment(it)
                    if (f == null) lostSomething = true
                    f
                }
                anyOf(frags)?.let { groups.add(it) }
            }
            if (r.has("ip")) {
                matchesEverything = false
                val frags = r.xStrList("ip").mapNotNull {
                    val f = ipFragment(it, noResolve)
                    if (f == null) lostSomething = true
                    f
                }
                anyOf(frags)?.let { groups.add(it) }
            }
            if (r.has("port")) {
                matchesEverything = false
                val p = portList(r.opt("port"))
                if (p.isNotEmpty()) groups.add("DST-PORT,$p")
            }
            if (r.has("sourcePort")) {
                matchesEverything = false
                val p = portList(r.opt("sourcePort"))
                if (p.isNotEmpty()) groups.add("SRC-PORT,$p")
            }
            if (r.has("source")) {
                matchesEverything = false
                val frags = r.xStrList("source").mapNotNull {
                    val e = it.trim()
                    when {
                        e.isEmpty() -> null
                        e.startsWith("geoip:") -> "SRC-GEOIP,${e.removePrefix("geoip:")}"
                        else -> "SRC-IP-CIDR,$e"
                    }
                }
                anyOf(frags)?.let { groups.add(it) }
            }
            if (r.has("network")) {
                // Both networks named is every network there is; that leaves the
                // rule a catch-all rather than an unconvertible one.
                if (r.xStr("network").split(",").map { it.trim() }
                        .filter { it == "tcp" || it == "udp" }.size == 1) matchesEverything = false
                val nets = r.xStr("network").split(",").map { it.trim() }
                    .filter { it == "tcp" || it == "udp" }
                // Both named is every network there is, which is no condition.
                if (nets.size == 1) groups.add("NETWORK,${nets.first()}")
            }
            if (r.has("user")) {
                matchesEverything = false
                anyOf(r.xStrList("user").filter { it.isNotEmpty() }.map { "IN-USER,$it" })
                    ?.let { groups.add(it) }
            }
            if (r.has("inboundTag")) {
                matchesEverything = false
                anyOf(r.xStrList("inboundTag").filter { it.isNotEmpty() }.map { "IN-NAME,$it" })
                    ?.let { groups.add(it) }
            }
            if (r.has("protocol")) {
                warn(
                    "routing.rules[$i] matches on protocol, which mihomo has no rule for; " +
                        "the rest of the rule was kept"
                )
            }
            if (r.has("attrs")) {
                warn(
                    "routing.rules[$i] narrows by attrs, which mihomo has no rule for; " +
                        "the rule now matches without it"
                )
            }
            if (lostSomething) {
                warn(
                    "routing.rules[$i] holds an entry mihomo cannot use - an Xray data file, " +
                        "or a value it would refuse - and that entry was left out of the rule"
                )
            }

            when {
                groups.isEmpty() -> {
                    // A rule can legitimately have nothing left: naming both networks, or no
                    // condition at all, is how Xray writes "everything", which mihomo spells MATCH.
                    if (matchesEverything) out.add("MATCH,$target")
                    else warn("routing.rules[$i] had no condition mihomo can express and was dropped")
                }
                // A modifier belongs after the target, and inside the sub-rule when nested: mihomo reads
                // "IP-CIDR,cidr,no-resolve,DIRECT" as a rule pointing at a proxy called no-resolve and refuses the file.
                groups.size == 1 -> {
                    val g = groups.first()
                    if (g.endsWith(NO_RESOLVE) && !g.startsWith("OR,") && !g.startsWith("NOT,")) {
                        out.add(g.removeSuffix(NO_RESOLVE) + ",$target" + NO_RESOLVE)
                    } else {
                        out.add("$g,$target")
                    }
                }
                else -> out.add("AND,(" + groups.joinToString(",") { "($it)" } + "),$target")
            }
        }
        return out
    }

    // One Xray DNS address as mihomo spells it, or null when it has no form here.
    private fun dnsServer(address: String, warn: (String) -> Unit): String? =
        when (val k = XrayDnsAddress.parse(address)) {
            XrayDnsAddress.Kind.Local -> "system"
            XrayDnsAddress.Kind.FakeDns, XrayDnsAddress.Kind.None -> null
            is XrayDnsAddress.Kind.Dhcp -> "dhcp://" + k.iface.ifEmpty { "auto" }
            is XrayDnsAddress.Kind.Remote -> {
                val authority = k.host + (k.port?.let { ":$it" } ?: "")
                val path = if (k.path.isEmpty()) "" else "/" + k.path
                when (k.scheme) {
                    // mihomo answers h3 with "unsupport scheme"; the same
                    // resolver over HTTPS is the nearest thing it will take.
                    "h3" -> {
                        warn(
                            "dns server \"$address\" uses HTTP/3, which mihomo does not take; " +
                                "it was written as https"
                        )
                        "https://$authority$path"
                    }
                    "udp" -> authority
                    else -> "${k.scheme}://$authority$path"
                }
            }
        }

    // A domain condition as a nameserver-policy key.
    private fun policyKey(entry: String): String? {
        val e = entry.trim()
        return when {
            e.isEmpty() -> null
            e.startsWith("full:") -> e.removePrefix("full:")
            e.startsWith("domain:") -> "+." + e.removePrefix("domain:")
            e.startsWith("geosite:") -> "geosite:" + e.removePrefix("geosite:")
            e.startsWith("regexp:") || e.startsWith("ext:") -> null
            else -> "+.$e"
        }
    }

    // Converts the DNS block. Returns null when the configuration has none, so the caller keeps its
    // own default.
    internal fun dns(xray: JSONObject, warn: (String) -> Unit): YamlMap? {
        val d = xray.xObj("dns") ?: return null
        val servers = d.opt("servers")
        val plain = ArrayList<String>()
        val policy = LinkedHashMap<String, MutableList<String>>()
        var fakedns = false

        if (servers is org.json.JSONArray) {
            for (i in 0 until servers.length()) {
                val s = servers.opt(i)
                if (s is String) {
                    if (s.trim() == "fakedns") {
                        fakedns = true
                        continue
                    }
                    dnsServer(s, warn)?.let { plain.add(it) }
                    continue
                }
                val o = s as? JSONObject ?: continue
                val addr = o.xStr("address")
                if (addr == "fakedns") {
                    fakedns = true
                    continue
                }
                var server = dnsServer(addr, warn) ?: continue
                val port = o.xInt("port")
                if (port > 0 && !server.contains("://") && !server.contains(":")) {
                    server = "$server:$port"
                }
                val domains = o.xStrList("domains")
                if (domains.isEmpty()) {
                    plain.add(server)
                } else {
                    for (dom in domains) {
                        val key = policyKey(dom)
                        if (key == null) {
                            warn("dns domain \"$dom\" has no nameserver-policy form in mihomo and was left out")
                            continue
                        }
                        policy.getOrPut(key) { ArrayList() }.add(server)
                    }
                }
                if (o.xStrList("expectIPs").isNotEmpty()) {
                    warn("dns expectIPs has no mihomo equivalent and was left out")
                }
            }
        }

        val m = YamlMap()
        m.set("enable", true)
        when (d.xStr("queryStrategy")) {
            "UseIPv4" -> m.set("ipv6", false)
            "UseIPv6" -> m.set("ipv6", true)
            else -> m.set("ipv6", true)
        }
        // fakedns anywhere in the list is what turns fake-ip on here.
        val fakednsCfg = xray.opt("fakedns")
        if (fakedns || fakednsCfg != null) {
            m.set("enhanced-mode", "fake-ip")
            val pool = when (fakednsCfg) {
                is org.json.JSONArray -> fakednsCfg.optJSONObject(0)?.xStr("ipPool") ?: ""
                is JSONObject -> fakednsCfg.xStr("ipPool")
                else -> ""
            }
            m.set("fake-ip-range", pool.ifEmpty { "198.18.0.1/16" })
        } else {
            m.set("enhanced-mode", "redir-host")
        }
        if (plain.isEmpty()) plain.add("system")
        m.set("nameserver", YamlFlowSeq(plain))
        if (policy.isNotEmpty()) {
            val pm = YamlMap()
            for ((k, v) in policy) pm.set(k, YamlFlowSeq(v))
            m.set("nameserver-policy", pm)
        }
        return m
    }

    // Xray's hosts block, in mihomo's spelling.
    internal fun hosts(xray: JSONObject): YamlMap? {
        val h = xray.xObj("dns")?.xObj("hosts") ?: return null
        val m = YamlMap()
        var any = false
        for (key in h.keys()) {
            val mapped = when {
                key.startsWith("domain:") -> "+." + key.removePrefix("domain:")
                key.startsWith("full:") -> key.removePrefix("full:")
                key.startsWith("regexp:") -> null
                else -> key
            } ?: continue
            when (val v = h.opt(key)) {
                is String -> {
                    m.set(mapped, v); any = true
                }
                is org.json.JSONArray -> {
                    val vals = (0 until v.length()).mapNotNull { v.opt(it) as? String }
                    if (vals.size == 1) m.set(mapped, vals.first())
                    else if (vals.isNotEmpty()) m.set(mapped, YamlFlowSeq(vals))
                    any = true
                }
            }
        }
        return if (any) m else null
    }
}
