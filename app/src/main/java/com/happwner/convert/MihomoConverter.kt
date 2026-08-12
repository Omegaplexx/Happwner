package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

// Turns Xray Core JSON configurations into a mihomo (Clash Meta) YAML configuration.
object MihomoConverter {

    sealed class Result {
        // A converted configuration, with a count of what was dropped.
        data class Ok(
            val yaml: String,
            val converted: Int,
            val skipped: Int,
            val notes: List<String>
        ) : Result()

        // The input is not an Xray configuration; leave it alone.
        object NotXray : Result()

        // The input is Xray, but nothing in it could be converted. Carries the same per-outbound
        // reasons as Ok, so a total failure explains itself as partial ones already did.
        data class Unsupported(val notes: List<String> = emptyList()) : Result()
    }

    // Converts every Xray configuration in input into one mihomo document.
    fun convert(input: String): Result = run(input, proxiesOnly = false)

    // Converts input into a proxies list only, the proxy-provider format.
    fun convertProxies(input: String): Result = run(input, proxiesOnly = true)

    private fun run(input: String, proxiesOnly: Boolean): Result {
        // Backstop against a bug in parseConfigs itself (it already returns null for merely-
        // malformed input).
        val configs = try {
            parseConfigs(input)
        } catch (_: Exception) {
            null
        } ?: return Result.NotXray

        if (configs.isEmpty()) return Result.NotXray

        return try {
            val conv = MihomoConv(MihomoOptions())
            conv.convertAll(configs)
            if (conv.proxies.isEmpty()) return Result.Unsupported(conv.diagnostics.map { it.render() })
            val doc = buildMihomoDocument(
                conv.proxies, conv.groups, conv.selectable(),
                MihomoDocumentOptions(proxiesOnly = proxiesOnly),
                conv.routingRules, conv.dnsBlock, conv.hostsBlock
            )
            Result.Ok(
                yaml = encodeYaml(doc),
                converted = conv.converted,
                skipped = conv.skipped,
                notes = conv.diagnostics.map { it.render() }
            )
        } catch (e: Exception) {
            // Per-outbound failures are already caught inside convertAll(), so reaching here means
            // buildMihomoDocument or encodeYaml broke - a bug in the converter, not an unsupported
            Result.Unsupported(
                listOf("skipped: document assembly: internal error (${e.javaClass.simpleName}): ${e.message ?: "no message"}")
            )
        }
    }

    // Reads the converter's input: a JSON array of Xray configurations, or any of the looser shapes
    // tools produce (a single config, a bare outbound array, a lone outbound).
    internal fun parseConfigs(input: String): List<JSONObject>? {
        if (input.isBlank()) return null
        val trimmed = stripJsonComments(input).trim()
        if (trimmed.isEmpty()) return null
        if (!trimmed.startsWith("[") && !trimmed.startsWith("{")) return null
        // Refused before parsing: Android's parser recurses per nesting level with no limit of its
        // own, and the resulting StackOverflowError is an Error, so the catch below would not stop
        if (JsonDepth.exceedsMaxDepth(trimmed)) return null
        if (!isWholeJsonValue(trimmed)) return null

        // JSONTokener throwing here just means the text isn't valid JSON - the normal way to learn
        // that.
        val value = try {
            JSONTokener(trimmed).nextValue()
        } catch (_: Exception) {
            return null
        }

        val items: List<JSONObject> = when (value) {
            is JSONArray -> (0 until value.length()).mapNotNull { value.opt(it) as? JSONObject }
            is JSONObject -> listOf(value)
            else -> return null
        }
        if (items.isEmpty()) return null

        val configs = ArrayList<JSONObject>(items.size)
        var anyXray = false
        for (item in items) {
            val cfg = normaliseConfig(item) ?: continue
            if (cfg.xObjList("outbounds").any { it.xHas("protocol") }) anyXray = true
            configs.add(cfg)
        }
        if (!anyXray) return null
        return configs
    }

    // Accepts either a full configuration or a single outbound, returning a configuration whose
    // "outbounds" array is always present.
    private fun normaliseConfig(item: JSONObject): JSONObject? {
        if (item.xArr("outbounds") != null) return item
        // Some tools emit a single outbound at the top level instead of a list.
        val single = item.xObj("outbound")
        if (single != null) {
            val cfg = JSONObject(item.toString())
            cfg.remove("outbound")
            cfg.put("outbounds", JSONArray().put(single))
            return cfg
        }
        // No "outbounds" key: this may be a bare outbound object.
        if (item.xHas("protocol")) {
            val cfg = JSONObject()
            cfg.put("outbounds", JSONArray().put(item))
            return cfg
        }
        return null
    }

    // True when the whole string is one valid JSON value, with no trailing junk.
    private fun isWholeJsonValue(s: String): Boolean {
        if (JsonDepth.exceedsMaxDepth(s)) return false
        return try {
            val t = JSONTokener(s)
            t.nextValue()
            t.nextClean().code == 0
        } catch (_: Exception) {
            false
        }
    }
}

// Controls how outbounds are converted.
internal data class MihomoOptions(
    // Sets "udp: true" on protocols that can relay UDP.
    val udp: Boolean = true,
    // Forces certificate verification off on every node.
    val skipCertVerify: Boolean = false,
    // The uTLS fingerprint applied to TLS nodes that do not specify one.
    val clientFingerprint: String = "",
    // Prepended to every generated proxy name.
    val namePrefix: String = "",
    // The mihomo group type an Xray balancer becomes.
    val balancerGroupType: String = "url-test"
)

// A note about one outbound.
internal class MihomoDiagnostic(val source: String, val message: String, val fatal: Boolean) {
    fun render(): String = "${if (fatal) "skipped" else "warning"}: $source: $message"
}

// A proxy group emitted ahead of the generated ones - how an Xray balancer is represented: its
// nodes become members, and only the group is selectable.
internal class MihomoGroup(
    val name: String,
    val type: String,
    val members: List<String>,
    val strategy: String = "",
    val note: String = ""
)

// Raised when an outbound has no mihomo equivalent, so the node is dropped.
internal class MihomoUnsupported(message: String) : Exception(message)

// Carries the state shared by one conversion run.
internal class MihomoConv(val opts: MihomoOptions) {
    val proxies = ArrayList<YamlMap>()
    val groups = ArrayList<MihomoGroup>()
    // routing.rules as mihomo lines, when the source had any.
    val routingRules = ArrayList<String>()
    // The converted dns block and hosts, when the source had them.
    var dnsBlock: YamlMap? = null
    var hostsBlock: YamlMap? = null

    // Whether the "only the first one's routing" note has already been made.
    private var routingSourceReported = false
    val diagnostics = ArrayList<MihomoDiagnostic>()
    var converted = 0
    var skipped = 0

    // Proxy names a balancer claimed, offered through their group instead.
    private val balanced = HashSet<String>()

    // Counts how often each proxy name has been handed out, pre-loading the generated group names and
    // built-in targets: mihomo shares one namespace and rejects the whole config on a collision.
    private val used = HashMap<String, Int>().apply {
        put(MIHOMO_SELECT_GROUP, 1)
        put(MIHOMO_AUTO_GROUP, 1)
        // mihomo resolves these itself; a proxy carrying one of these names
        // would shadow the built-in target inside every group.
        put("DIRECT", 1)
        put("REJECT", 1)
        put("REJECT-DROP", 1)
        put("PASS", 1)
        put("COMPATIBLE", 1)
        put("GLOBAL", 1)
    }

    // Identifies the outbound currently being converted, for diagnostics.
    var src: String = ""

    fun warn(message: String) {
        diagnostics.add(MihomoDiagnostic(src, message, fatal = false))
    }

    fun skip(message: String) {
        diagnostics.add(MihomoDiagnostic(src, message, fatal = true))
        skipped++
    }

    // Takes the routing and DNS of one configuration, once.
    private fun captureRoutingAndDns(cfg: JSONObject, ci: Int, tagNames: Map<String, List<String>>) {
        val routing = cfg.xObj("routing")
        val dns = cfg.xObj("dns")
        if (routing == null && dns == null) return
        if (routingRules.isNotEmpty() || dnsBlock != null) {
            // Said once, however many follow.
            if (!routingSourceReported) {
                routingSourceReported = true
                src = "config[$ci]"
                warn(
                    "routing and DNS were taken from the first configuration; " +
                        "the ones in the configurations after it were left out"
                )
            }
            return
        }
        src = "config[$ci].routing"
        val auxTargets = HashMap<String, String>()
        for (ob in cfg.xObjList("outbounds")) {
            val tag = ob.xStr("tag")
            if (tag.isEmpty()) continue
            when (ob.xStr("protocol").lowercase()) {
                "freedom" -> auxTargets[tag] = "DIRECT"
                "blackhole" -> auxTargets[tag] = "REJECT"
            }
        }
        if (routing != null) {
            routingRules.addAll(
                MihomoRouting.rules(routing, { tag -> targetForTag(tag, tagNames, auxTargets) }) { warn(it) }
            )
        }
        if (dns != null) {
            src = "config[$ci].dns"
            dnsBlock = MihomoRouting.dns(cfg) { m -> warn(m) }
            hostsBlock = MihomoRouting.hosts(cfg)
        }
    }

    // What an Xray outbound or balancer tag became, or null when nothing of it survived.
    private fun targetForTag(
        tag: String,
        tagNames: Map<String, List<String>>,
        auxTargets: Map<String, String>
    ): String? {
        if (tag.isEmpty()) return null
        return auxTargets[tag]
            ?: tagNames[tag]?.firstOrNull()
            ?: groups.firstOrNull { it.name == tag }?.name
            ?: groups.firstOrNull { it.note.contains("\"$tag\"") }?.name
    }

    // Converts every outbound of every configuration, and every balancer.
    fun convertAll(configs: List<JSONObject>) {
        for ((ci, cfg) in configs.withIndex()) {
            val label = configLabel(cfg)
            val balancers = configBalancers(cfg)
            val outbounds = cfg.xObjList("outbounds")
            // A configuration label only names a node unambiguously when the file holds a single
            // proxy outbound, which is the usual shape of a generated per-node config.
            val proxyOutbounds = outbounds.count { !isNonProxyProtocol(it.xStr("protocol").lowercase()) }

            // The tag of each outbound, mapped to the proxies it produced, so
            // the balancers below can find the nodes their selectors cover.
            val tagNames = LinkedHashMap<String, MutableList<String>>()

            for ((oi, ob) in outbounds.withIndex()) {
                val proto = ob.xStr("protocol").lowercase()
                if (isNonProxyProtocol(proto)) continue
                src = "config[$ci].outbounds[$oi] (${if (proto.isEmpty()) "no protocol" else proto})"

                val preferred = if (proxyOutbounds == 1 && balancers.isEmpty()) label else ""
                val made = try {
                    convertOutbound(ob, proto, preferred)
                } catch (e: MihomoUnsupported) {
                    // Expected: this specific feature has no mihomo equivalent.
                    skip(e.message ?: "the outbound could not be converted")
                    continue
                } catch (e: Exception) {
                    // Unexpected: a bug in the converter for this one outbound, not a known
                    // limitation.
                    skip("internal error (${e.javaClass.simpleName}): ${e.message ?: "no message"}")
                    continue
                }
                for (p in made) {
                    proxies.add(p)
                    converted++
                    val tag = ob.xStr("tag")
                    if (tag.isNotEmpty()) {
                        (p.get("name") as? String)?.let {
                            tagNames.getOrPut(tag) { ArrayList() }.add(it)
                        }
                    }
                }
            }

            balanced.addAll(buildBalancers(cfg, ci, tagNames))
            // Routing and DNS travel with the first configuration that has them.
            captureRoutingAndDns(cfg, ci, tagNames)
        }

        // Dropped nodes are reported before degraded ones.
        val fatalFirst = diagnostics.filter { it.fatal } + diagnostics.filter { !it.fatal }
        diagnostics.clear()
        diagnostics.addAll(fatalFirst)
    }

    // Every proxy name, in output order.
    fun names(): List<String> = proxies.mapNotNull { it.get("name") as? String }

    // The entries to offer the user: one name per balancer group, plus every proxy no balancer
    // claimed.
    fun selectable(): List<String> {
        val inner = HashSet<String>()
        for (g in groups) inner.addAll(g.members)
        val out = ArrayList<String>(groups.size + proxies.size)
        // A group that only exists to be wrapped by another one is not offered.
        for (g in groups) if (g.name !in inner) out.add(g.name)
        for (name in names()) if (name !in balanced) out.add(name)
        return out
    }

    // Dispatches on the outbound protocol.
    private fun convertOutbound(ob: JSONObject, proto: String, preferred: String): List<YamlMap> =
        when (proto) {
            "vless" -> convertVless(ob, preferred)
            "vmess" -> convertVmess(ob, preferred)
            "trojan" -> convertTrojan(ob, preferred)
            "shadowsocks", "ss" -> convertShadowsocks(ob, preferred)
            "socks", "socks5" -> convertSocks(ob, preferred)
            "http", "https" -> convertHttp(ob, preferred)
            "wireguard" -> convertWireGuard(ob, preferred)
            "hysteria2", "hy2" -> convertHysteria2(ob, preferred)
            "hysteria", "hy" -> convertHysteria(ob, preferred)
            "tuic" -> convertTuic(ob, preferred)
            "vlite" -> throw MihomoUnsupported("the VLITE protocol has no mihomo equivalent")
            "mtproto" -> throw MihomoUnsupported("the MTProto protocol has no mihomo equivalent")
            else -> throw MihomoUnsupported("unsupported protocol \"$proto\"")
        }

    // Builds a unique proxy name, preferring the configuration label, then the outbound tag, and
    // falling back to protocol/host/port.
    fun name(preferred: String, tag: String, proto: String, host: String, port: Int): String {
        var candidate = preferred.trim()
        if (candidate.isEmpty()) candidate = meaningfulTag(tag)
        if (candidate.isEmpty()) {
            val bare = stripBrackets(host)
            val shown = if (bare.contains(":")) "[$bare]" else bare
            candidate = "$proto-$shown:$port"
        }
        if (opts.namePrefix.isNotEmpty()) candidate = opts.namePrefix + candidate
        return uniqueName(sanitizeName(candidate))
    }

    // Reserves a name against everything already handed out, because mihomo needs proxies and
    // groups to be distinct from one another.
    fun uniqueName(candidate: String): String {
        // The name is free: take it and say so.
        val taken = used[candidate] ?: run {
            used[candidate] = 1
            return candidate
        }
        // Otherwise walk the suffixes until one is free.
        var n = taken
        while (true) {
            n++
            val next = "$candidate #$n"
            if (!used.containsKey(next)) {
                used[candidate] = n
                used[next] = 1
                return next
            }
        }
    }

    // Builds the common head of a proxy entry.
    fun base(name: String, type: String, server: String, port: Int): YamlMap {
        val addr = server.trim()
        if (addr.isEmpty()) throw MihomoUnsupported("the outbound has no server address")
        if (port <= 0 || port > 65535) throw MihomoUnsupported("invalid server port $port")
        val m = YamlMap()
        m.set("name", name)
        m.set("type", type)
        m.set("server", stripBrackets(addr))
        m.set("port", port)
        return m
    }

    // Sets "udp: true" when the options ask for it.
    fun udpFlag(m: YamlMap) {
        if (opts.udp) m.set("udp", true)
    }

    // sockopt options mihomo has no per-proxy field for. The sing-box converter reports the same
    // set, so one configuration reads the same whichever mode produced it.
    private val SOCKOPT_WITHOUT_MIHOMO_EQUIVALENT = listOf(
        "tcpNoDelay", "tcpUserTimeout", "tcpWindowClamp", "tcpMaxSeg",
        "V6Only", "penetrate", "addressPortStrategy", "happyEyeballs"
    )

    // Maps Xray's sockopt onto mihomo's per-proxy dialer options.
    fun applyDialer(m: YamlMap, ob: JSONObject) {
        // sendThrough picks the local address one outbound leaves from; mihomo binds by interface
        // for the whole client, so a node pinned to one address would silently use another.
        if (ob.xBindsLocalAddress()) {
            warn("sendThrough is set per outbound, which mihomo has no place for, and was dropped")
        }
        val so = ob.xObj("streamSettings").xObj("sockopt")
        if (so != null) {
            m.setBoolTrue("tfo", so.xBool("tcpFastOpen"))
            m.setBoolTrue("mptcp", so.xBool("tcpMptcp"))
            m.setStr("interface-name", so.xStr("interface"))
            m.setInt("routing-mark", so.xInt("mark"))

            when (so.xStr("domainStrategy").lowercase()) {
                "useip4", "useipv4", "forceip4", "forceipv4" -> m.set("ip-version", "ipv4")
                "useip6", "useipv6", "forceip6", "forceipv6" -> m.set("ip-version", "ipv6")
            }
            val dp = so.xStr("dialerProxy")
            if (dp.isNotEmpty()) {
                // mihomo resolves dialer-proxy by proxy name; the Xray tag only
                // matches if a proxy with that name exists in the output.
                m.set("dialer-proxy", dp)
                warn("sockopt.dialerProxy \"$dp\" was mapped to dialer-proxy; it only works if a proxy with that exact name exists")
            }
            val tp = so.xStr("tproxy")
            if (tp.isNotEmpty() && tp != "off") {
                warn("sockopt.tproxy is an inbound-side option and was dropped")
            }
            // The rest of sockopt has no per-proxy home in mihomo: each is small alone, together
            // they are the difference between a node behaving as tuned and quietly not.
            if (so.xAsksForKeepAlive()) {
                warn(
                    "sockopt.tcpKeepAliveIdle / tcpKeepAliveInterval have no mihomo " +
                        "equivalent and were dropped"
                )
            }
            if (so.xStr("tcpcongestion").isNotEmpty()) {
                warn("sockopt.tcpcongestion has no mihomo equivalent and was dropped")
            }
            // The sing-box side names these one by one; saying nothing here would answer the same
            // config two different ways depending on which mode the person picked.
            for (f in SOCKOPT_WITHOUT_MIHOMO_EQUIVALENT) {
                if (SingBoxUtil.isTruthy(so.opt(f))) warn("sockopt.$f has no mihomo equivalent and was dropped")
            }
            if (SingBoxUtil.isTruthy(so.opt("customSockopt"))) {
                warn("sockopt.customSockopt sets raw socket options, which mihomo cannot express")
            }
        }

        // proxySettings chains this outbound through another one by tag, which
        // is the same idea as mihomo's dialer-proxy.
        val chained = ob.xObj("proxySettings").xStr("tag")
        if (chained.isNotEmpty() && !m.has("dialer-proxy")) {
            m.set("dialer-proxy", chained)
            warn("proxySettings.tag \"$chained\" was mapped to dialer-proxy; it only works if a proxy with that exact name exists")
        }
    }

    // Maps Xray's mux.cool settings. Mihomo does not implement mux.cool, but the XUDP fields still
    // describe how UDP is packed.
    fun applyMux(m: YamlMap, ob: JSONObject, proto: String) {
        val mux = ob.xObj("mux") ?: return
        if (!mux.xBool("enabled")) return
        when (proto) {
            "vless", "vmess" -> {
                if (mux.xInt("xudpConcurrency") != 0) m.set("packet-encoding", "xudp")
                warn("mux.cool is enabled but mihomo does not implement it; only the XUDP packet encoding was carried over")
            }
            else -> warn("mux.cool is enabled but mihomo does not implement it; it was dropped")
        }
    }

    // ------------------------------------------------------- balancers ----

    // Turns one configuration's balancers into proxy groups.
    private fun buildBalancers(
        cfg: JSONObject,
        ci: Int,
        tagNames: Map<String, List<String>>
    ): Set<String> {
        val balancers = configBalancers(cfg)
        if (balancers.isEmpty()) return emptySet()

        val claimed = HashSet<String>()
        val label = configLabel(cfg)
        val routing = cfg.xObj("routing")
        val rules = routing.xObjList("rules")
        val hasRules = rules.isNotEmpty()
        val routed = rules.map { it.xStr("balancerTag") }.filter { it.isNotEmpty() }.toSet()

        for ((bi, b) in balancers.withIndex()) {
            val tag = b.xStr("tag")
            src = "config[$ci].routing.balancers[$bi] ($tag)"

            val members = balancerMembers(b, tagNames)
            if (members.isEmpty()) {
                warn("the balancer \"$tag\" selected no node that could be converted; it was dropped")
                continue
            }

            val groupName = balancerGroupName(b, label, balancers.size)
            val groupType = groupTypeFor(b)
            val strategy = if (groupType == "load-balance") loadBalanceStrategy(strategyName(b)) else ""

            groups.add(
                MihomoGroup(
                    name = groupName,
                    type = groupType,
                    members = members,
                    strategy = strategy,
                    note = "Xray balancer \"$tag\", strategy ${strategyDisplay(b)}"
                )
            )

            // A balancer that no rule routes to is inert in Xray. It still becomes a group here, since the nodes
            // have to go somewhere, but saying so explains a group the panel never uses.
            if (hasRules && tag !in routed) {
                warn("no routing rule uses the balancer \"$tag\"; its nodes were grouped anyway")
            }

            claimed.addAll(members)
            applyFallbackTag(b, tagNames, claimed)
        }
        return claimed
    }

    // Resolves the proxy names a balancer covers.
    private fun balancerMembers(b: JSONObject, tagNames: Map<String, List<String>>): List<String> {
        val selectors = b.xStrList("selector")
        // Xray sorts the selected tags, so the member order is reproducible.
        val tags = tagNames.keys
            .filter { tag -> selectors.any { tag.startsWith(it) } }
            .sorted()
        return tags.flatMap { tagNames[it].orEmpty() }
    }

    // Wraps the balancer group in a fallback group when the balancer names a spare outbound.
    private fun applyFallbackTag(
        b: JSONObject,
        tagNames: Map<String, List<String>>,
        claimed: MutableSet<String>
    ) {
        val fallbackTag = b.xStr("fallbackTag")
        if (fallbackTag.isEmpty()) return
        val spares = tagNames[fallbackTag].orEmpty()
        if (spares.isEmpty()) {
            warn("fallbackTag \"$fallbackTag\" does not name a converted outbound; it was dropped")
            return
        }

        // The balancer group was just appended, so it is the last one.
        val inner = groups.removeAt(groups.size - 1)
        val outerName = inner.name
        // The two groups need distinct names; the outer one keeps the plain
        // name because that is what the user selects.
        val innerName = uniqueName("$outerName pool")
        groups.add(MihomoGroup(innerName, inner.type, inner.members, inner.strategy, inner.note))
        groups.add(
            MihomoGroup(
                name = outerName,
                type = "fallback",
                members = listOf(innerName) + spares,
                note = "Xray balancer fallbackTag \"$fallbackTag\""
            )
        )

        // The spare is reachable through the group, so it does not need its own
        // entry in the top-level lists either.
        claimed.addAll(spares)
    }

    // Picks a name for the balancer's group, from the configuration's label ("remarks") since that
    // describes the location to a person.
    private fun balancerGroupName(b: JSONObject, label: String, balancerCount: Int): String {
        val tag = b.xStr("tag")
        var candidate = when {
            label.isEmpty() -> tag
            // Several balancers share one label, so the tag tells them apart
            // while the label still leads the name.
            balancerCount > 1 -> "$label ($tag)"
            else -> label
        }
        if (opts.namePrefix.isNotEmpty()) candidate = opts.namePrefix + candidate
        return uniqueName(sanitizeName(candidate))
    }

    // Decides which mihomo group type stands in for the balancer.
    private fun groupTypeFor(b: JSONObject): String {
        var requested = opts.balancerGroupType.trim().lowercase()
        if (requested.isEmpty() || requested !in BALANCER_GROUP_TYPES) requested = "url-test"

        // url-test picks the fastest node, which is what leastPing and leastLoad ask for.
        if (requested == "url-test") {
            when (val s = strategyName(b)) {
                "random", "roundrobin" ->
                    warn(
                        "the balancer uses the $s strategy, which spreads traffic; " +
                            "it became a url-test group that picks the fastest node"
                    )
            }
        }
        return requested
    }
}

private val BALANCER_GROUP_TYPES = setOf("url-test", "load-balance", "fallback", "select")

// Maps an Xray strategy onto mihomo's load-balance ones.
private fun loadBalanceStrategy(strategy: String): String = when (strategy) {
    "roundrobin" -> "round-robin"
    // mihomo's default spreads by hashing the destination, which keeps a
    // connection on one node without pinning all traffic to it.
    else -> "consistent-hashing"
}

// The strategy in Xray's normalised spelling; unset means "random".
private fun strategyName(b: JSONObject): String {
    val s = b.xObj("strategy").xStr("type").lowercase()
    return s.ifEmpty { "random" }
}

// The strategy as the configuration spelled it, for messages a person reads.
private fun strategyDisplay(b: JSONObject): String {
    val s = b.xObj("strategy").xStr("type")
    return s.ifEmpty { "random" }
}

// The configuration's load balancers, skipping the ones Xray itself refuses.
internal fun configBalancers(cfg: JSONObject): List<JSONObject> =
    cfg.xObj("routing").xObjList("balancers")
        .filter { it.xStr("tag").isNotEmpty() && it.xStrList("selector").isNotEmpty() }

// The human-readable name of a configuration, if it carries one.
internal fun configLabel(cfg: JSONObject): String =
    cfg.xStrOf("remarks", "remark", "name", "ps", "tag")

// Whether the outbound is a local action rather than a remote server. These become mihomo's
// DIRECT/REJECT targets and never appear in the proxies list.
internal fun isNonProxyProtocol(proto: String): Boolean =
    proto in setOf("freedom", "blackhole", "dns", "loopback", "")

// Outbound tags that describe a role rather than a server, so they make poor proxy names.
private val GENERIC_TAGS = setOf(
    "proxy", "proxies", "out", "outbound", "default",
    "direct", "block", "blocked", "agentout", "main", "node"
)

internal fun meaningfulTag(tag: String): String {
    val t = tag.trim()
    if (t.isEmpty() || t.lowercase() in GENERIC_TAGS) return ""
    return t
}

// Strips characters that break mihomo's proxy references or make a name unusable in a group.
internal fun sanitizeName(raw: String): String {
    var s = raw.trim()
    // Control characters and line breaks cannot appear in a name.
    s = s.filter { it.code >= 0x20 && it.code != 0x7f }.trim()
    // A comma cannot appear either: a rule line is comma-separated, so a node called "US, LA" would
    // be read as a rule pointing at a proxy called "US" and mihomo refuses the whole configuration
    if (s.contains(',')) {
        s = s.replace(',', ' ').replace(Regex(" {2,}"), " ").trim()
    }
    if (s.isEmpty()) return "proxy"
    val maxNameLen = 120
    if (s.length > maxNameLen) {
        var end = maxNameLen
        // Do not split a surrogate pair, which would leave invalid text.
        if (Character.isHighSurrogate(s[end - 1])) end--
        s = s.substring(0, end).trim()
        if (s.isEmpty()) return "proxy"
    }
    return s
}

// Reads an outbound's settings object, which every protocol needs.
internal fun outboundSettings(ob: JSONObject): JSONObject =
    ob.xObj("settings") ?: throw MihomoUnsupported("the outbound has no settings")
