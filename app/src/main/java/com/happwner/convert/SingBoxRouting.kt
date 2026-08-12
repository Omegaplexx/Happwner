package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// Everything that is not a proxy server: inbounds, routing rules, DNS.
internal object SingBoxRouting {
    internal val QUERY_STRATEGY_MAP = mapOf(
        "UseIPv4" to "ipv4_only",
        "UseIPv4v6" to "prefer_ipv4",
        "UseIPv6" to "ipv6_only",
        "UseIPv6v4" to "prefer_ipv6",
        "UseIP" to "prefer_ipv4",
        "UseSystem" to "prefer_ipv4"
    )

    internal val REMOTE_DNS_TYPES = setOf("https", "h3", "tls", "quic", "tcp", "udp")

    // The Xray domain strategies that let an address rule match a domain destination, by resolving
    // it first. "AsIs" deliberately does not.
    internal val RESOLVING_DOMAIN_STRATEGIES = setOf("IPIfNonMatch", "IPOnDemand")

    // True when a converted rule decides by address rather than by name. Looks inside a conjunction
    // or disjunction too, since regrouping moves the address conditions of a mixed rule into one.
    internal fun matchesByAddress(rule: JSONObject): Boolean {
        if (rule.has("ip_cidr") || rule.has("ip_is_private")) return true
        rule.optJSONArray("rule_set")?.let { sets ->
            for (i in 0 until sets.length()) {
                if (sets.optString(i, "").startsWith("geoip-")) return true
            }
        }
        rule.optJSONArray("rules")?.let { nested ->
            for (i in 0 until nested.length()) {
                val n = nested.optJSONObject(i) ?: continue
                if (matchesByAddress(n)) return true
            }
        }
        return false
    }

    internal val ENCRYPTED_DNS_TYPES = setOf("https", "h3", "tls", "quic", "tcp")

    internal data class PortLists(val ports: List<Int>, val ranges: List<String>)

    internal fun parsePortList(value: Any?): PortLists {
        val ports = mutableListOf<Int>()
        val ranges = mutableListOf<String>()
        if (value == null || value === JSONObject.NULL) return PortLists(ports, ranges)

        val items = mutableListOf<String>()
        if (value is JSONArray) {
            for (i in 0 until value.length()) {
                val v = value.opt(i) ?: continue
                items.addAll(v.toString().split(","))
            }
        } else {
            items.addAll(value.toString().split(","))
        }
        for (raw in items) {
            val tok = raw.trim()
            if (tok.isEmpty()) continue
            when {
                tok.contains("-") -> ranges.add(tok.replace("-", ":"))
                tok.all { it in '0'..'9' } ->
                    tok.toIntOrNull()?.takeIf { SingBoxUtil.isUsablePort(it) }?.let { ports.add(it) }
            }
        }
        return PortLists(ports, ranges)
    }

    internal fun parseListenPort(p: Any?): Int? {
        if (p == null || p === JSONObject.NULL) return null
        if (p is Boolean) return null
        if (p is Int) return p
        if (p is Long) return p.toInt()
        if (p is Number) return p.toInt()
        if (p is String) {
            val s = p.trim()
            if (s.isEmpty()) return null
            if (s.all { it in '0'..'9' }) return s.toIntOrNull()
            return null
        }
        if (p is JSONArray && p.length() >= 1) return parseListenPort(p.opt(0))
        return null
    }

    internal data class DomainSplit(
        val domain: List<String>,
        val domainSuffix: List<String>,
        val domainKeyword: List<String>,
        val domainRegex: List<String>,
        val geosite: List<String>
    )

    internal fun splitDomains(domains: List<Any?>, dropped: MutableList<String> = mutableListOf()): DomainSplit {
        val full = mutableListOf<String>()
        val suffix = mutableListOf<String>()
        val keyword = mutableListOf<String>()
        val regex = mutableListOf<String>()
        val geosite = mutableListOf<String>()
        for (raw in domains) {
            val d = (raw as? String) ?: continue
            when (val n = XrayConditions.name(d)) {
                is XrayConditions.Name.Exact -> full.add(n.value)
                is XrayConditions.Name.Suffix -> suffix.add(n.value)
                is XrayConditions.Name.Keyword -> keyword.add(n.value)
                is XrayConditions.Name.Pattern -> regex.add(n.value)
                is XrayConditions.Name.Geosite -> geosite.add(n.value)
                XrayConditions.Name.External -> dropped.add(d)
                XrayConditions.Name.Unusable -> if (d.isNotBlank()) dropped.add(d)
            }
        }
        return DomainSplit(full, suffix, keyword, regex, geosite)
    }

    internal data class IpSplit(
        val ipCidr: List<String>,
        val geoip: List<String>,
        val ipIsPrivate: Boolean,
        // The "geoip:!xx" entries, which need a rule of their own to invert.
        val geoipNot: List<String> = emptyList()
    )

    internal fun splitIps(ips: List<Any?>, dropped: MutableList<String> = mutableListOf()): IpSplit {
        val cidr = mutableListOf<String>()
        val geoip = mutableListOf<String>()
        val geoipNot = mutableListOf<String>()
        var isPrivate = false
        for (raw in ips) {
            val i = (raw as? String) ?: continue
            when (val a = XrayConditions.address(i)) {
                is XrayConditions.Address.Cidr -> cidr.add(a.value)
                is XrayConditions.Address.Country -> geoip.add(a.code)
                // "geoip:!cn" is "anywhere but cn". The core inverts a whole rule rather than one
                // field, so it becomes an alternative of its own where the rule is assembled.
                is XrayConditions.Address.NotCountry -> geoipNot.add(a.code)
                XrayConditions.Address.Private -> isPrivate = true
                XrayConditions.Address.External -> dropped.add(i)
                XrayConditions.Address.Unusable -> if (i.isNotBlank()) dropped.add(i)
            }
        }
        return IpSplit(cidr, geoip, isPrivate, geoipNot)
    }

    // Destination-name fields; the core treats these as alternatives.
    private val DOMAIN_KEYS = setOf("domain", "domain_suffix", "domain_keyword", "domain_regex")

    // Destination-address fields; likewise alternatives among themselves.
    private val IP_KEYS = setOf("ip_cidr", "ip_is_private")

    // Rebuilds a rule so that it means what the Xray rule meant.
    internal fun regroupRule(sb: JSONObject, invertedSets: List<String>): JSONObject {
        val domainObj = JSONObject()
        val ipObj = JSONObject()
        val otherObj = JSONObject()
        var outbound: String? = null
        var action: String? = null
        val keys = sb.keys().asSequence().toList()
        for (k in keys) {
            val v = sb.opt(k)
            when {
                k == "outbound" -> outbound = v as? String
                k == "action" -> action = v as? String
                k in DOMAIN_KEYS -> domainObj.put(k, v)
                k in IP_KEYS -> ipObj.put(k, v)
                k == "rule_set" -> {
                    val arr = v as? JSONArray ?: continue
                    val geosite = JSONArray()
                    val geoip = JSONArray()
                    for (i in 0 until arr.length()) {
                        val t = arr.optString(i, "")
                        if (t.startsWith("geoip-")) geoip.put(t) else geosite.put(t)
                    }
                    if (geosite.length() > 0) domainObj.put("rule_set", geosite)
                    if (geoip.length() > 0) ipObj.put("rule_set", geoip)
                }
                else -> otherObj.put(k, v)
            }
        }

        val hasDomain = domainObj.length() > 0
        val hasIp = ipObj.length() > 0 || invertedSets.isNotEmpty()
        // One kind of destination condition and no negation is what the core
        // already reads correctly, so leave that rule exactly as it was.
        if (!(hasDomain && hasIp) && invertedSets.isEmpty()) return sb

        val ipPart: JSONObject? = when {
            !hasIp -> null
            invertedSets.isEmpty() -> ipObj
            else -> {
                val alts = JSONArray()
                if (ipObj.length() > 0) alts.put(ipObj)
                for (tag in invertedSets) {
                    // An inverted rule matches whenever the plain one doesn't, and an address rule-set doesn't match a
                    // name - so alone it swallowed every domain. The match-any address keeps it to known addresses.
                    alts.put(
                        JSONObject()
                            .put("type", "logical")
                            .put("mode", "and")
                            .put(
                                "rules",
                                JSONArray()
                                    .put(
                                        JSONObject().put(
                                            "ip_cidr",
                                            JSONArray().put("0.0.0.0/0").put("::/0")
                                        )
                                    )
                                    .put(
                                        JSONObject()
                                            .put("rule_set", JSONArray().put(tag))
                                            .put("invert", true)
                                    )
                            )
                    )
                }
                if (alts.length() == 1) {
                    alts.getJSONObject(0)
                } else {
                    JSONObject().put("type", "logical").put("mode", "or").put("rules", alts)
                }
            }
        }

        val parts = JSONArray()
        if (hasDomain) parts.put(domainObj)
        if (ipPart != null) parts.put(ipPart)
        if (otherObj.length() > 0) parts.put(otherObj)
        if (parts.length() == 1) {
            val only = parts.getJSONObject(0)
            outbound?.let { only.put("outbound", it) }
            action?.let { only.put("action", it) }
            return only
        }
        val out = JSONObject()
        out.put("type", "logical")
        out.put("mode", "and")
        out.put("rules", parts)
        outbound?.let { out.put("outbound", it) }
        action?.let { out.put("action", it) }
        return out
    }

    internal fun addRuleSetTags(rule: JSONObject, tags: List<String>) {
        if (tags.isEmpty()) return
        val existing = mutableListOf<String>()
        val arr = rule.optJSONArray("rule_set")
        if (arr != null) for (i in 0 until arr.length()) existing.add(arr.optString(i))
        for (t in tags) if (t !in existing) existing.add(t)
        rule.put("rule_set", JSONArray(existing))
    }

    internal fun applyDomainSplit(rule: JSONObject, split: DomainSplit, ruleSets: MutableSet<String>) {
        if (split.domain.isNotEmpty()) rule.put("domain", JSONArray(split.domain))
        if (split.domainSuffix.isNotEmpty()) rule.put("domain_suffix", JSONArray(split.domainSuffix))
        if (split.domainKeyword.isNotEmpty()) rule.put("domain_keyword", JSONArray(split.domainKeyword))
        if (split.domainRegex.isNotEmpty()) rule.put("domain_regex", JSONArray(split.domainRegex))
        if (split.geosite.isNotEmpty()) {
            val tags = split.geosite.map { "geosite-${it.lowercase()}" }
            ruleSets.addAll(tags)
            addRuleSetTags(rule, tags)
        }
    }

    internal fun applyGeoipToRuleSet(rule: JSONObject, geoip: List<String>, ruleSets: MutableSet<String>) {
        if (geoip.isEmpty()) return
        val tags = geoip.map { "geoip-${it.lowercase()}" }
        ruleSets.addAll(tags)
        addRuleSetTags(rule, tags)
    }

    internal data class InboundResult(
        val sb: JSONObject?,
        val sniffEnabled: Boolean,
        val sniffResolves: Boolean
    )

    // Xray inbound to sing-box inbound (socks/http/mixed/dokodemo)
    internal fun convInbound(inb: JSONObject): InboundResult {
        val proto = inb.xStr("protocol")
        val sniff = inb.optJSONObject("sniffing") ?: JSONObject()
        val sniffEnabled = sniff.xBool("enabled")
        val destOverride = sniff.optJSONArray("destOverride")
        val hasDestOverride = destOverride != null && destOverride.length() > 0
        val routeOnly = sniff.xBool("routeOnly")
        val sniffResolves = sniffEnabled && hasDestOverride && !routeOnly

        val listenPort = parseListenPort(inb.opt("port"))

        // dokodemo-door -> a direct inbound
        if (proto == "dokodemo-door") {
            val ds = inb.optJSONObject("settings") ?: JSONObject()
            val sb = JSONObject()
            sb.put("type", "direct")
            sb.put("tag", inb.optString("tag", "direct-in"))
            sb.put("listen", inb.optString("listen", "0.0.0.0"))
            if (listenPort != null) sb.put("listen_port", listenPort) else sb.put("listen_port", JSONObject.NULL)
            val net = ds.optString("network", "tcp")
            if (net == "tcp" || net == "udp") sb.put("network", net)
            val addr = ds.opt("address")
            if (SingBoxUtil.isTruthy(addr)) sb.put("override_address", ds.xStr("address"))
            val port = parseListenPort(ds.opt("port"))
            if (port != null) sb.put("override_port", port)
            return InboundResult(sb, sniffEnabled, sniffResolves)
        }

        // Server-side inbounds aren't supported here; only socks/http/mixed
        if (proto in setOf("vmess", "vless", "trojan", "shadowsocks")) {
            return InboundResult(null, false, false)
        }
        if (proto !in setOf("socks", "http", "mixed")) {
            return InboundResult(null, false, false)
        }
        if (listenPort == null) {
            return InboundResult(null, false, false)
        }

        // socks/http/mixed with optional accounts
        val sb = JSONObject()
        sb.put("type", proto)
        sb.put("tag", inb.optString("tag", proto))
        sb.put("listen", inb.optString("listen", "127.0.0.1"))
        sb.put("listen_port", listenPort)
        val settings = inb.optJSONObject("settings")
        val accounts = settings?.optJSONArray("accounts")
        if (accounts != null && accounts.length() > 0) {
            val users = JSONArray()
            for (i in 0 until accounts.length()) {
                val a = accounts.optJSONObject(i) ?: continue
                val u = JSONObject()
                u.put("username", a.optString("user", ""))
                u.put("password", a.optString("pass", ""))
                users.put(u)
            }
            sb.put("users", users)
        }
        return InboundResult(sb, sniffEnabled, sniffResolves)
    }

    // Xray routing.rules to sing-box route.rules (domains/ip to rule_set, balancers, special actions)
    internal fun convRouteRules(
        routing: JSONObject,
        balancerMap: Map<String, String>,
        specialRemap: Map<String, Pair<String, JSONObject?>>,
        specialTagDrop: Set<String>,
        ruleSets: MutableSet<String>,
        notes: MutableList<String>? = null
    ): List<JSONObject> {
        val out = mutableListOf<JSONObject>()
        val rules = routing.optJSONArray("rules") ?: return out
        for (i in 0 until rules.length()) {
            val r = rules.optJSONObject(i) ?: continue
            val typeField = r.optString("type", "")
            if (typeField.isNotEmpty() && typeField != "field") continue
            val sb = JSONObject()
            // Negated countries collected while reading this rule; they become
            // alternatives inside it rather than rules of their own.
            val invertedSets = mutableListOf<String>()
            // Target: balancer tag, special action (reject/hijack-dns), or plain outbound
            when {
                r.has("balancerTag") -> {
                    val bt = r.optString("balancerTag", "")
                    if (bt in specialTagDrop) continue
                    sb.put("outbound", balancerMap[bt] ?: bt)
                }
                r.has("outboundTag") -> {
                    val tgt = r.optString("outboundTag", "")
                    if (tgt in specialTagDrop) continue
                    val rem = specialRemap[tgt]
                    if (rem != null) {
                        sb.put("action", rem.first)
                        rem.second?.let { extra ->
                            val keys = extra.keys()
                            while (keys.hasNext()) {
                                val k = keys.next()
                                sb.put(k, extra.opt(k))
                            }
                        }
                    } else {
                        sb.put("outbound", tgt)
                    }
                }
                else -> continue
            }

            // Match conditions: inbound/protocol/network/port/source/domain/ip/user/process
            val inTags = SingBoxUtil.asStringList(r.opt("inboundTag"))
            if (inTags.isNotEmpty()) sb.put("inbound", JSONArray(inTags))

            if (r.has("protocol")) {
                val protos = SingBoxUtil.asStringList(r.opt("protocol"))
                sb.put("protocol", JSONArray(protos))
            }
            if (r.has("network")) {
                val netRaw = r.opt("network")
                val nets = mutableListOf<String>()
                val src = if (netRaw is String) netRaw.split(",") else SingBoxUtil.asStringList(netRaw)
                for (n in src) {
                    val t = n.trim()
                    if (t == "tcp" || t == "udp") nets.add(t)
                }
                if (nets.isNotEmpty()) sb.put("network", JSONArray(nets))
            }
            if (r.has("port")) {
                val pl = parsePortList(r.opt("port"))
                if (pl.ports.isNotEmpty()) sb.put("port", JSONArray(pl.ports))
                if (pl.ranges.isNotEmpty()) sb.put("port_range", JSONArray(pl.ranges))
            }
            if (r.has("sourcePort")) {
                val sp = parsePortList(r.opt("sourcePort"))
                if (sp.ports.isNotEmpty()) sb.put("source_port", JSONArray(sp.ports))
                if (sp.ranges.isNotEmpty()) sb.put("source_port_range", JSONArray(sp.ranges))
            }
            if (r.has("source")) {
                val ipSplit = splitIps(SingBoxUtil.asList(r.opt("source")))
                if (ipSplit.ipCidr.isNotEmpty()) sb.put("source_ip_cidr", JSONArray(ipSplit.ipCidr))
                if (ipSplit.ipIsPrivate) sb.put("source_ip_is_private", true)
            }
            if (r.has("domain")) {
                val droppedDom = mutableListOf<String>()
                val d = splitDomains(SingBoxUtil.asList(r.opt("domain")), droppedDom)
                if (droppedDom.isNotEmpty()) notes?.add(
                    "routing.rules[$i]: ${droppedDom.joinToString(", ")} is not a name condition " +
                        "the core can read and was left out of the rule"
                )
                applyDomainSplit(sb, d, ruleSets)
            }
            if (r.has("ip")) {
                val droppedIp = mutableListOf<String>()
                val ipSplit = splitIps(SingBoxUtil.asList(r.opt("ip")), droppedIp)
                if (droppedIp.isNotEmpty()) notes?.add(
                    "routing.rules[$i]: ${droppedIp.joinToString(", ")} is not an address the core " +
                        "can read (or names an Xray data file) and was left out of the rule"
                )
                if (ipSplit.ipCidr.isNotEmpty()) sb.put("ip_cidr", JSONArray(ipSplit.ipCidr))
                if (ipSplit.ipIsPrivate) sb.put("ip_is_private", true)
                applyGeoipToRuleSet(sb, ipSplit.geoip, ruleSets)
                for (code in ipSplit.geoipNot) {
                    val tag = "geoip-${code.lowercase()}"
                    ruleSets.add(tag)
                    invertedSets.add(tag)
                }
            }
            if (r.has("attrs")) {
                // Xray narrows a rule by HTTP attributes; sing-box has no
                // equivalent, so the rule stays but matches more than it did.
                notes?.add(
                    "routing.rules[$i]: the attrs condition has no sing-box equivalent, " +
                        "so the rule now matches without it"
                )
            }
            if (r.has("user")) {
                sb.put("auth_user", JSONArray(SingBoxUtil.asStringList(r.opt("user"))))
            }
            if (r.has("process")) {
                sb.put("process_name", JSONArray(SingBoxUtil.asStringList(r.opt("process"))))
            }

            out.add(regroupRule(sb, invertedSets))
        }
        return out
    }

    internal data class DnsAddr(val type: String?, val fields: JSONObject)

    // Xray DNS address to a sing-box type + fields (https/h3/tls/quic/tcp/udp/dhcp/fakedns)
    internal fun parseDnsAddress(addrRaw: String?): DnsAddr =
        when (val k = XrayDnsAddress.parse(addrRaw)) {
            XrayDnsAddress.Kind.FakeDns -> DnsAddr("fakeip", JSONObject())
            XrayDnsAddress.Kind.Local -> DnsAddr("local", JSONObject())
            XrayDnsAddress.Kind.None -> DnsAddr(null, JSONObject())
            is XrayDnsAddress.Kind.Dhcp -> DnsAddr(
                "dhcp",
                JSONObject().apply { if (k.iface.isNotEmpty()) put("interface", k.iface) }
            )
            is XrayDnsAddress.Kind.Remote -> DnsAddr(
                // The core spells the HTTP/3 transport "h3" and answers "http3" with "unknown transport type",
                // refusing the whole document. Checked against sing-box 1.13.18.
                k.scheme,
                JSONObject().apply {
                    put("server", k.host)
                    k.port?.let { put("server_port", it) }
                    if (k.path.isNotEmpty()) put("path", "/" + k.path)
                }
            )
        }

    internal fun makeDnsRule(obj: JSONObject, serverTag: String, ruleSets: MutableSet<String>): JSONObject? {
        val domains = SingBoxUtil.asList(obj.opt("domains"))
        if (domains.isEmpty()) return null
        val rule = JSONObject()
        rule.put("server", serverTag)
        val ds = splitDomains(domains)
        applyDomainSplit(rule, ds, ruleSets)
        return rule
    }

    internal fun fakeipRanges(fakednsObj: Any?): Pair<String, String> {
        if (fakednsObj == null || fakednsObj === JSONObject.NULL) {
            return "198.18.0.0/15" to "fc00::/18"
        }
        val pools: List<JSONObject> = when (fakednsObj) {
            is JSONArray -> (0 until fakednsObj.length()).mapNotNull { fakednsObj.optJSONObject(it) }
            is JSONObject -> listOf(fakednsObj)
            else -> emptyList()
        }
        var v4 = "198.18.0.0/15"
        var v6 = "fc00::/18"
        for (p in pools) {
            val pool = p.optString("ipPool", "")
            if (pool.contains(".") && !pool.contains(":")) v4 = pool
            else if (pool.contains(":")) v6 = pool
        }
        return v4 to v6
    }

    // Xray dns to sing-box dns (servers, rules, hosts, fakeip, final) notes collects anything
    // dropped on the way, so the caller can report it the same way it reports a dropped outbound.
    internal fun convDns(
        xrayDns: JSONObject?,
        fakednsObj: Any?,
        dnsDetour: String?,
        ruleSets: MutableSet<String>,
        notes: MutableList<String>
    ): JSONObject {
        val out = JSONObject()
        out.put("servers", JSONArray())
        out.put("rules", JSONArray())
        val cs = xrayDns?.optString("clientIp", "")
        if (!cs.isNullOrEmpty()) out.put("client_subnet", cs)

        val seenTags = mutableSetOf<String>()
        var hasLocal = false
        var hasFakeip = false
        var fakeipTag: String? = null
        var n = 0

        val serversArr = xrayDns?.optJSONArray("servers") ?: JSONArray()
        val outServers = out.getJSONArray("servers")
        val outRules = out.getJSONArray("rules")

        // Each Xray DNS server -> a typed sing-box server (+ a domain rule)
        for (i in 0 until serversArr.length()) {
            val raw = serversArr.opt(i)
            val addrRaw: String
            val obj: JSONObject
            if (raw is String) {
                addrRaw = raw
                obj = JSONObject()
            } else if (raw is JSONObject) {
                addrRaw = raw.optString("address", "")
                obj = raw
            } else continue

            val parsed = parseDnsAddress(addrRaw)
            val st = parsed.type ?: continue

            val srv = JSONObject()
            srv.put("type", st)
            var tag = obj.optString("tag", "")
            if (st == "local") tag = "local"
            if (tag.isEmpty()) {
                tag = "dns-$n"; n++
            }
            while (tag in seenTags) {
                tag = "$tag-$n"; n++
            }
            seenTags.add(tag)
            srv.put("tag", tag)

            val keys = parsed.fields.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                srv.put(k, parsed.fields.opt(k))
            }
            if (!srv.has("server_port")) {
                val v = obj.opt("port")
                if (SingBoxUtil.isTruthy(v)) {
                    val p = when (v) {
                        is Number -> v.toInt()
                        is String -> v.toIntOrNull()
                        else -> null
                    }
                    if (p != null) srv.put("server_port", p)
                }
            }

            val sqs = obj.optString("queryStrategy", "")
            if (sqs.isNotEmpty() && QUERY_STRATEGY_MAP.containsKey(sqs)) {
                // Not domain_strategy: on a new-format server that is a dial field replacing the old
                // address_strategy - it resolves the server's own name, not what the queries return.
                notes.add(
                    "dns.servers[].queryStrategy asks which address types the queries return, which " +
                        "a sing-box server has no field for; the document-level queryStrategy is carried"
                )
            }
            // Xray's per-server clientIP is EDNS Client Subnet, but sing-box has client_subnet on dns and
            // dns.rules only (measured on 1.13.15), so it is carried below onto the rule built for this server.
            val sci = obj.optString("clientIP", "")

            when {
                st in ENCRYPTED_DNS_TYPES -> {
                    if (dnsDetour != null) srv.put("detour", dnsDetour)
                    srv.put("domain_resolver", "local")
                }
                st == "udp" -> {
                    if (dnsDetour != null) srv.put("detour", dnsDetour)
                }
                st == "local" -> hasLocal = true
                st == "fakeip" -> {
                    val ranges = fakeipRanges(fakednsObj)
                    srv.put("inet4_range", ranges.first)
                    srv.put("inet6_range", ranges.second)
                    hasFakeip = true
                    fakeipTag = tag
                }
            }
            outServers.put(srv)

            // Xray narrows a DNS server by the addresses it is allowed to answer with; a rule here
            // decides by the question, before any answer exists, so there is nowhere to put it.
            if (obj.optJSONArray("expectIPs") != null || obj.optJSONArray("unexpectedIPs") != null) {
                notes.add(
                    "dns server \"$addrRaw\": expectIPs/unexpectedIPs filter the answer, " +
                        "and a sing-box DNS rule decides by the question, so it was left out"
                )
            }

            val rule = makeDnsRule(obj, tag, ruleSets)
            if (rule != null) {
                if (st == "fakeip" && !rule.has("query_type")) {
                    rule.put("query_type", JSONArray().put("A").put("AAAA"))
                }
                // The rule is what sends these queries to this server, so it is also where their
                // client subnet belongs.
                if (sci.isNotEmpty()) rule.put("client_subnet", sci)
                outRules.put(rule)
            } else if (sci.isNotEmpty()) {
                // No domains, so no rule carries queries here and there is nowhere to scope the
                // subnet to.
                notes.add(
                    "skipped: dns.servers[$i].clientIP: sing-box scopes the client subnet to a " +
                        "DNS rule, and this server has no domains to build one from"
                )
            }
        }

        // Static hosts -> a 'hosts' server in front, with a matching rule
        val hosts = xrayDns?.optJSONObject("hosts")
        if (hosts != null && hosts.length() > 0) {
            val predefined = JSONObject()
            val hk = hosts.keys()
            while (hk.hasNext()) {
                val host = hk.next()
                val v = hosts.opt(host)
                val ipsList = when (v) {
                    is String -> listOf(v as Any?)
                    is JSONArray -> (0 until v.length()).map { v.opt(it) as Any? }
                    else -> emptyList()
                }
                val ipsOnly = ipsList.filter { SingBoxUtil.isIpLiteral(it) }.map { it as String }
                if (ipsOnly.isNotEmpty()) {
                    predefined.put(host, JSONArray(ipsOnly))
                }
            }
            if (predefined.length() > 0) {
                val hostsSrv = JSONObject()
                hostsSrv.put("type", "hosts")
                hostsSrv.put("tag", "hosts")
                hostsSrv.put("predefined", predefined)
                val newServers = JSONArray()
                newServers.put(hostsSrv)
                for (i in 0 until outServers.length()) newServers.put(outServers.opt(i))
                out.put("servers", newServers)

                val hostKeys = JSONArray()
                val hk2 = predefined.keys()
                while (hk2.hasNext()) hostKeys.put(hk2.next())
                val rule = JSONObject()
                rule.put("domain", hostKeys)
                rule.put("server", "hosts")
                val newRules = JSONArray()
                newRules.put(rule)
                for (i in 0 until outRules.length()) newRules.put(outRules.opt(i))
                out.put("rules", newRules)
            }
        }

        val finalServersArr = out.getJSONArray("servers")
        if (!hasLocal) {
            val local = JSONObject()
            local.put("type", "local")
            local.put("tag", "local")
            finalServersArr.put(local)
        }

        if (hasFakeip && fakeipTag != null) {
            var hasFakeipRule = false
            val rulesNow = out.getJSONArray("rules")
            for (i in 0 until rulesNow.length()) {
                if (rulesNow.optJSONObject(i)?.optString("server", "") == fakeipTag) {
                    hasFakeipRule = true; break
                }
            }
            if (!hasFakeipRule) {
                val rule = JSONObject()
                rule.put("query_type", JSONArray().put("A").put("AAAA"))
                rule.put("server", fakeipTag)
                rulesNow.put(rule)
            }
        }

        // Pick the default (final) DNS server: the first remote one
        var finalTag: String? = null
        for (i in 0 until finalServersArr.length()) {
            val s = finalServersArr.optJSONObject(i) ?: continue
            if (s.optString("type", "") !in REMOTE_DNS_TYPES) continue
            if (dnsDetour == null || s.optString("detour", "") == dnsDetour) {
                finalTag = s.optString("tag", "")
                break
            }
        }
        if (finalTag == null) {
            for (i in 0 until finalServersArr.length()) {
                val s = finalServersArr.optJSONObject(i) ?: continue
                if (s.optString("type", "") in REMOTE_DNS_TYPES) {
                    finalTag = s.optString("tag", ""); break
                }
            }
        }
        // A fakeip server answers every query from its pool, so the core refuses to let it be the
        // default ("default server cannot be fakeip") and rejects the document with it.
        if (finalTag == null && finalServersArr.length() > 0) {
            for (i in 0 until finalServersArr.length()) {
                val s = finalServersArr.optJSONObject(i) ?: continue
                if (s.optString("type", "") == "fakeip") continue
                finalTag = s.optString("tag", "")
                break
            }
        }
        if (!finalTag.isNullOrEmpty()) out.put("final", finalTag)

        return out
    }
}
