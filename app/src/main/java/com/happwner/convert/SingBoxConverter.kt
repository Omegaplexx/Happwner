package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// Converts an Xray config into a sing-box one.
object SingBoxConverter {

    private val DOMAIN_STRATEGY_MAP = mapOf(
        "AsIs" to "",
        "UseIP" to "prefer_ipv4",
        "UseIPv4" to "ipv4_only",
        "UseIPv4v6" to "prefer_ipv4",
        "UseIPv6" to "ipv6_only",
        "UseIPv6v4" to "prefer_ipv6",
        "IPIfNonMatch" to "prefer_ipv4",
        "IPOnDemand" to "prefer_ipv4"
    )

    private val LOG_LEVEL_MAP = mapOf(
        "debug" to "debug",
        "info" to "info",
        "warning" to "warn",
        "warn" to "warn",
        "error" to "error",
        "none" to "fatal"
    )

    private val SINGBOX_OUTBOUND_TYPES = setOf(
        "vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2",
        "tuic", "wireguard", "anytls", "ssh", "naive", "shadowtls",
        "selector", "urltest", "direct", "block", "dns", "socks", "http"
    )

    // Pull rule-sets (.srs) from SagerNet repositories
    private const val GEOSITE_URL_TEMPLATE = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/{name}.srs"
    private const val GEOIP_URL_TEMPLATE = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/{name}.srs"

    sealed class Result {
        // notes: one line per proxy outbound dropped, e.g. "skipped: outbounds[2] (vless): vless
        // flow "..." has no sing-box equivalent".
        data class Ok(val config: JSONObject, val notes: List<String> = emptyList()) : Result()
        object NotXray : Result()
        // Carries notes too: when every outbound in a config is unsupported the config is dropped whole, and
        // without this the reason vanished - the skipped counter went up with nothing in the log.
        data class Unsupported(val notes: List<String> = emptyList()) : Result()
    }

    sealed class OutboundsResult {
        // See Result.Ok.notes above - same idea, one line per dropped outbound.
        data class Ok(val outbounds: List<JSONObject>, val notes: List<String> = emptyList()) : OutboundsResult()
        object NotXray : OutboundsResult()
        data class Unsupported(val notes: List<String> = emptyList()) : OutboundsResult()
    }

    // The tag of the DNS server convDns always emits; see applySockopt.
    private const val LOCAL_DNS_TAG = "local"

    // Delegates. LinkConverter calls both, and no caller should have to know
    // which file the implementation moved to.
    internal fun normalizeFlow(flow: String?): String = SingBoxProtocols.normalizeFlow(flow)

    fun mergeUnified(fullConfigs: List<JSONObject>): JSONObject? =
        SingBoxMerge.mergeUnified(fullConfigs)

    // Full Xray config to a full sing-box config
    fun convert(input: String, nameFallback: String = ""): Result {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return Result.NotXray
        if (!trimmed.startsWith("{")) return Result.NotXray
        // Android's parser recurses per nesting level with no depth limit of its
        // own, so this has to be refused before parsing rather than caught after.
        if (JsonDepth.exceedsMaxDepth(trimmed)) return Result.NotXray

        // JSONObject throwing here just means the text isn't valid JSON - the normal way to learn
        // that.
        val xray = try {
            JSONObject(trimmed)
        } catch (_: Exception) {
            return Result.NotXray
        }

        if (isSingbox(xray)) return Result.NotXray
        if (!looksLikeXray(xray)) return Result.NotXray

        return try {
            val built = convertObject(xray, nameFallback) ?: return Result.Unsupported()
            // convertObject signals "nothing convertible" with an empty config
            // object, carrying the per-outbound reasons for the log.
            if (built.config.length() == 0) return Result.Unsupported(built.notes)
            Result.Ok(built.config, built.notes)
        } catch (_: Exception) {
            // A bug in convertObject for this input rather than an unsupported
            // profile; no per-outbound reasons exist in that case.
            Result.Unsupported()
        }
    }

    // Xray to just the list of sing-box outbounds (no wrapper)
    fun convertToOutbounds(input: String, nameFallback: String = ""): OutboundsResult {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return OutboundsResult.NotXray
        if (!trimmed.startsWith("{")) return OutboundsResult.NotXray
        // See convert() above.
        if (JsonDepth.exceedsMaxDepth(trimmed)) return OutboundsResult.NotXray

        val xray = try {
            JSONObject(trimmed)
        } catch (_: Exception) {
            return OutboundsResult.NotXray
        }

        if (isSingbox(xray)) return OutboundsResult.NotXray
        if (!looksLikeXray(xray)) return OutboundsResult.NotXray

        return try {
            val extracted = extractProxyOutbounds(xray, nameFallback) ?: return OutboundsResult.Unsupported()
            if (extracted.outbounds.isEmpty()) OutboundsResult.Unsupported(extracted.notes)
            else OutboundsResult.Ok(extracted.outbounds, extracted.notes)
        } catch (_: Exception) {
            OutboundsResult.Unsupported()
        }
    }

    // Extract only supported proxy outbounds; take names from remarks
    private data class ProxyExtraction(val outbounds: List<JSONObject>, val notes: List<String>)

    private fun extractProxyOutbounds(xray: JSONObject, nameFallback: String): ProxyExtraction? {
        val remarks = (xray.optString("remarks", "").ifEmpty {
            xray.optString("name", "").ifEmpty { nameFallback }
        }).trim()

        val outsRaw = xray.optJSONArray("outbounds") ?: return null

        val supportedProxies = mutableListOf<JSONObject>()
        val notes = mutableListOf<String>()
        for (i in 0 until outsRaw.length()) {
            val o = outsRaw.optJSONObject(i) ?: continue
            val proto = o.xStr("protocol")
            // Aux outbounds are not proxies and there is nothing to report about them.
            if (proto in SingBoxProtocols.XRAY_PROTOCOLS_AUX) {
                // Nothing to convert, but one detail of blackhole does get lost: it can answer with
                // a canned HTTP reply, where sing-box only closes the connection.
                if (proto == "blackhole" &&
                    o.optJSONObject("settings")?.optJSONObject("response")
                        ?.optString("type", "") == "http"
                ) {
                    notes.add(
                        "outbounds[$i] (blackhole): the canned HTTP response has no sing-box " +
                            "equivalent; the connection is closed instead"
                    )
                }
                continue
            }
            val reason = SingBoxProtocols.unsupportedReason(o)
            if (reason != null) {
                val label = proto.ifEmpty { "no protocol" }
                notes.add("skipped: outbounds[$i] ($label): $reason")
                continue
            }
            supportedProxies.add(o)
        }

        // Every proxy in the config was rejected. Still return the reasons - the caller turns this
        // into Unsupported, and without carrying them the drop would be invisible in the log.
        if (supportedProxies.isEmpty()) {
            // A configuration of nothing but freedom/blackhole/dns has no proxy to convert.
            if (notes.isEmpty()) {
                notes.add("no proxy outbound in this configuration; there was nothing to convert")
            }
            return ProxyExtraction(emptyList(), notes)
        }

        val results = mutableListOf<JSONObject>()
        val singleProxy = supportedProxies.size == 1

        // Convert each, naming from remarks (with #tag suffix when there are several)
        for (o in supportedProxies) {
            val r = SingBoxProtocols.convOutbound(o)
            // Reported whether or not the outbound survived: a node dropped
            // with nothing said about it is the failure these notes exist for.
            for (n in r.notes) {
                notes.add("outbounds[${o.optString("tag", o.xStr("protocol"))}]: $n")
            }
            val sb = r.sb ?: continue
            if (r.kind == "aux") continue

            sb.remove("detour")

            val originalTag = o.optString("tag", "").trim()
            val newTag = when {
                remarks.isEmpty() -> originalTag.ifEmpty { "proxy" }
                singleProxy -> remarks
                else -> if (originalTag.isEmpty()) remarks else "$remarks #$originalTag"
            }
            sb.put("tag", newTag)
            results.add(sb)
        }

        return ProxyExtraction(results, notes)
    }

    // Heuristic for "this is Xray": outbounds carry a protocol field
    private fun looksLikeXray(d: JSONObject): Boolean {
        val outs = d.optJSONArray("outbounds") ?: return false
        if (outs.length() == 0) return false
        for (i in 0 until outs.length()) {
            val o = outs.optJSONObject(i) ?: continue
            if (o.has("protocol")) return true
        }
        return false
    }

    // Heuristic for "already sing-box": route present + the first outbound's type is a sing-box one
    private fun isSingbox(d: JSONObject): Boolean {
        if (!d.has("route") || !d.has("outbounds")) return false
        val outs = d.optJSONArray("outbounds") ?: return false
        if (outs.length() == 0) return false
        val first = outs.optJSONObject(0) ?: return false
        return first.optString("type", "") in SINGBOX_OUTBOUND_TYPES
    }

    private fun dedupeByTag(items: List<JSONObject>, used: MutableSet<String>): List<JSONObject> {
        val out = mutableListOf<JSONObject>()
        for (it in items) {
            val t = it.optString("tag", "")
            if (t.isEmpty() || t in used) continue
            used.add(t)
            out.add(it)
        }
        return out
    }

    // See Result.Ok.notes above - same idea, for the merged-config path.
    private data class ConvertResult(val config: JSONObject, val notes: List<String>)

    // Main assembly: inbounds + outbounds + selector/urltest + route + dns + experimental
    private fun convertObject(xray: JSONObject, nameFallback: String): ConvertResult? {
        val inbounds = mutableListOf<JSONObject>()
        val usedInbTags = mutableSetOf<String>()
        val resolveInbounds = mutableListOf<String>()
        val notes = mutableListOf<String>()

        // Convert inbounds (collecting sniff-resolve tags)
        val xrayInbounds = xray.optJSONArray("inbounds")
        if (xrayInbounds != null) {
            for (i in 0 until xrayInbounds.length()) {
                val inb = xrayInbounds.optJSONObject(i) ?: continue
                val result = SingBoxRouting.convInbound(inb)
                val sbInb = result.sb ?: continue
                val base = sbInb.optString("tag", "").ifEmpty { sbInb.optString("type", "in") }
                val tag = SingBoxUtil.makeUniqueTag(base, usedInbTags)
                sbInb.put("tag", tag)
                usedInbTags.add(tag)
                inbounds.add(sbInb)
                if (result.sniffResolves) resolveInbounds.add(tag)
            }
        }

        val remarks = (xray.optString("remarks", "").ifEmpty {
            xray.optString("name", "").ifEmpty { nameFallback }
        }).trim()

        // Find the supported proxy outbounds (used for naming)
        val xrayProxies = mutableListOf<JSONObject>()
        val outsRaw = xray.optJSONArray("outbounds")
        if (outsRaw != null) {
            for (i in 0 until outsRaw.length()) {
                val o = outsRaw.optJSONObject(i) ?: continue
                if (o.xStr("protocol") in SingBoxProtocols.XRAY_PROTOCOLS_PROXY && SingBoxProtocols.isOutboundSupported(o)) {
                    xrayProxies.add(o)
                }
            }
        }

        // Plan tag renames from remarks
        val rename = mutableMapOf<String, String>()
        if (remarks.isNotEmpty()) {
            if (xrayProxies.size == 1) {
                val onlyTag = xrayProxies[0].optString("tag", "").trim()
                rename[onlyTag] = remarks
            } else if (xrayProxies.size > 1) {
                for (p in xrayProxies) {
                    val origTag = p.optString("tag", "").trim()
                    val newTag = if (origTag.isEmpty()) remarks else "$remarks #$origTag"
                    rename[origTag] = newTag
                }
            }
        }

        val proxyOuts = mutableListOf<JSONObject>()
        val proxyTags = mutableListOf<String>()
        val auxOuts = mutableListOf<JSONObject>()
        val endpoints = mutableListOf<JSONObject>()
        val specialRemap = mutableMapOf<String, Pair<String, JSONObject?>>()
        val specialTagDrop = mutableSetOf<String>()

        // Convert every outbound: proxy / endpoint / aux, mapping the special tags
        if (outsRaw != null) {
            for (i in 0 until outsRaw.length()) {
                val o = outsRaw.optJSONObject(i) ?: continue
                val otag = o.optString("tag", "")
                val proto = o.xStr("protocol")
                when (proto) {
                    "blackhole" -> {
                        specialRemap[otag] = "reject" to null
                        // The rule action closes the connection; blackhole can also answer with a
                        // canned HTTP reply, and that part has nowhere to go.
                        if (o.optJSONObject("settings")?.optJSONObject("response")
                                ?.optString("type", "") == "http"
                        ) {
                            notes.add(
                                "outbounds[$i] (blackhole): the canned HTTP response has no " +
                                    "sing-box equivalent; the connection is closed instead"
                            )
                        }
                        continue
                    }
                    "dns" -> {
                        specialRemap[otag] = "hijack-dns" to null
                        continue
                    }
                    "loopback" -> {
                        specialTagDrop.add(otag)
                        continue
                    }
                }
                // Asked of every outbound reaching here, not only known proxies: guarding on XRAY_PROTOCOLS_PROXY
                // meant hysteria2 and tuic were dropped without a word, the very case the reason exists for.
                val reason = SingBoxProtocols.unsupportedReason(o)
                if (reason != null) {
                    specialTagDrop.add(otag)
                    notes.add("skipped: outbounds[$i] (${proto.ifEmpty { "no protocol" }}): $reason")
                    continue
                }
                // "local" is the DNS server convDns always emits, so an outbound may point
                // domain_resolver at it.
                val r = SingBoxProtocols.convOutbound(o, LOCAL_DNS_TAG)
                for (n in r.notes) notes.add("outbounds[$i] ($proto): $n")
                val c = r.sb ?: continue
                when (r.kind) {
                    "wireguard" -> {
                        val cTag = c.optString("tag", "")
                        val newTag = rename[cTag] ?: cTag
                        c.put("tag", newTag)
                        endpoints.add(c)
                        proxyTags.add(newTag)
                    }
                    "aux" -> auxOuts.add(c)
                    else -> {
                        val cTag = c.optString("tag", "")
                        val newTag = rename[cTag] ?: cTag
                        c.put("tag", newTag)
                        proxyOuts.add(c)
                        proxyTags.add(newTag)
                    }
                }
            }
        }

        // Nothing convertible in this config. Hand the reasons back anyway
        // (empty config + notes) so convert() can attach them to Unsupported.
        if (proxyOuts.isEmpty() && endpoints.isEmpty()) {
            // A configuration of nothing but freedom/blackhole/dns has no proxy to convert.
            if (notes.isEmpty()) {
                notes.add("no proxy outbound in this configuration; there was nothing to convert")
            }
            return ConvertResult(JSONObject(), notes)
        }

        // Ensure a 'direct' outbound exists
        val hasDirect = auxOuts.any { it.optString("type", "") == "direct" && it.optString("tag", "") == "direct" }
        if (!hasDirect) {
            val direct = JSONObject()
            direct.put("type", "direct")
            direct.put("tag", "direct")
            auxOuts.add(direct)
        }

        for (o in (proxyOuts + endpoints + auxOuts)) {
            val d = o.optString("detour", "")
            if (d.isNotEmpty()) {
                if (d in specialTagDrop || d in specialRemap) {
                    o.remove("detour")
                } else if (rename.containsKey(d)) {
                    o.put("detour", rename[d])
                }
            }
        }

        val routing = xray.optJSONObject("routing") ?: JSONObject()
        val obs = xray.optJSONObject("burstObservatory")
            ?: xray.optJSONObject("observatory") ?: JSONObject()
        val pingCfg = obs.optJSONObject("pingConfig") ?: JSONObject()
        val testUrl = pingCfg.optString("destination", "")
        val testInterval = pingCfg.optString("interval", "")

        // Build Xray balancers into urltest outbounds
        val balancerOuts = mutableListOf<JSONObject>()
        val balancerMap = mutableMapOf<String, String>()
        var primaryBalancer: String? = null
        val balancers = routing.optJSONArray("balancers")
        if (balancers != null) {
            for (i in 0 until balancers.length()) {
                val b = balancers.optJSONObject(i) ?: continue
                val btag = b.optString("tag", "")
                if (btag.isEmpty()) continue
                val prefixesArr = b.optJSONArray("selector")
                val prefixes = mutableListOf<String>()
                if (prefixesArr != null) {
                    for (j in 0 until prefixesArr.length()) {
                        val item = prefixesArr.opt(j)
                        if (item is String) prefixes.add(item)
                    }
                }
                val origMatch: List<String> = if (prefixes.isNotEmpty()) {
                    xrayProxies.mapNotNull { p ->
                        val t = p.optString("tag", "")
                        if (t.isNotEmpty() && prefixes.any { pf -> t.startsWith(pf) }) t else null
                    }
                } else {
                    xrayProxies.mapNotNull { p ->
                        val t = p.optString("tag", "")
                        if (t.isNotEmpty()) t else null
                    }
                }
                var members = origMatch.map { rename[it] ?: it }
                if (members.isEmpty()) members = proxyTags.toList()
                if (members.isEmpty()) {
                    specialTagDrop.add(btag)
                    continue
                }

                val bb = JSONObject()
                bb.put("type", "urltest")
                bb.put("tag", btag)
                bb.put("outbounds", JSONArray(members))
                if (testUrl.isNotEmpty()) bb.put("url", testUrl)
                if (testInterval.isNotEmpty()) bb.put("interval", testInterval)
                balancerOuts.add(bb)
                balancerMap[btag] = btag
                if (primaryBalancer == null) primaryBalancer = btag
            }
        }

        // Build the top-level selector over proxies + balancers
        var selectorTag = if (remarks.isNotEmpty()) remarks else "select"
        val existingTags = HashSet<String>(proxyTags)
        for (b in balancerOuts) existingTags.add(b.optString("tag", ""))
        for (a in auxOuts) existingTags.add(a.optString("tag", ""))
        while (selectorTag in existingTags) selectorTag += " \u2299"

        var selector: JSONObject? = null
        val needSelector = proxyTags.size > 1 || balancerOuts.isNotEmpty()
        if (proxyTags.isNotEmpty() && needSelector) {
            selector = JSONObject()
            selector.put("type", "selector")
            selector.put("tag", selectorTag)
            val outs = JSONArray()
            for (b in balancerOuts) outs.put(b.optString("tag", ""))
            for (t in proxyTags) outs.put(t)
            selector.put("outbounds", outs)
            selector.put("default", if (balancerOuts.isNotEmpty()) balancerOuts[0].optString("tag", "") else proxyTags[0])
        }

        // Assemble and dedupe the outbound / endpoint lists
        var sbOutbounds = mutableListOf<JSONObject>()
        if (selector != null) sbOutbounds.add(selector)
        sbOutbounds.addAll(balancerOuts)
        sbOutbounds.addAll(proxyOuts)
        sbOutbounds.addAll(auxOuts)

        val usedOutTags = mutableSetOf<String>()
        sbOutbounds = dedupeByTag(sbOutbounds, usedOutTags).toMutableList()
        val endpointsDedup = dedupeByTag(endpoints, usedOutTags)

        val finalTag = when {
            selector != null -> selectorTag
            primaryBalancer != null -> primaryBalancer
            else -> proxyTags.firstOrNull { it.isNotEmpty() } ?: "direct"
        }

        val dnsDetour: String? = proxyTags.firstOrNull { it.isNotEmpty() }
        val ruleSetDownloadDetour = "direct"
        val requiredRuleSets = mutableSetOf<String>()

        // Convert routing rules; prepend the built-in pre-rules (sniff/hijack-dns/resolve)
        val routeRules = SingBoxRouting.convRouteRules(routing, balancerMap, specialRemap, specialTagDrop, requiredRuleSets, notes).toMutableList()
        for (r in routeRules) {
            val ob = r.optString("outbound", "")
            if (ob.isNotEmpty() && rename.containsKey(ob)) r.put("outbound", rename[ob])
        }

        val preRules = mutableListOf<JSONObject>()
        preRules.add(JSONObject().put("action", "sniff"))
        preRules.add(JSONObject().put("protocol", "dns").put("action", "hijack-dns"))
        preRules.add(JSONObject().put("port", JSONArray().put(53)).put("action", "hijack-dns"))
        if (resolveInbounds.isNotEmpty()) {
            val r = JSONObject()
            r.put("inbound", JSONArray(resolveInbounds))
            r.put("action", "resolve")
            preRules.add(r)
        } else {
            // IPIfNonMatch/IPOnDemand let an address rule match a domain destination, but only where a resolve
            // action says to. Placed before the first address rule, not at the head; verified against 1.13.18.
            val wantsResolve = SingBoxRouting.RESOLVING_DOMAIN_STRATEGIES.contains(
                routing.optString("domainStrategy", "").trim()
            )
            if (wantsResolve) {
                val at = routeRules.indexOfFirst { SingBoxRouting.matchesByAddress(it) }
                if (at >= 0) routeRules.add(at, JSONObject().put("action", "resolve"))
            }
        }

        // Assemble route (rules + final + default DNS resolver)
        val route = JSONObject()
        val allRules = JSONArray()
        for (r in preRules) allRules.put(r)
        for (r in routeRules) allRules.put(r)
        route.put("rules", allRules)
        route.put("auto_detect_interface", true)
        route.put("final", finalTag)
        val ddr = JSONObject()
        ddr.put("server", "local")
        val ds = routing.optString("domainStrategy", "").trim()
        val dsMapped = DOMAIN_STRATEGY_MAP[ds] ?: ""
        if (dsMapped.isNotEmpty()) {
            ddr.put("strategy", dsMapped)
        } else {
            val xrayDnsObj = xray.optJSONObject("dns")
            val qs = xrayDnsObj?.optString("queryStrategy", "")
            if (!qs.isNullOrEmpty() && SingBoxRouting.QUERY_STRATEGY_MAP.containsKey(qs)) {
                ddr.put("strategy", SingBoxRouting.QUERY_STRATEGY_MAP[qs])
            }
        }
        route.put("default_domain_resolver", ddr)

        // Convert DNS and attach the remote geosite/geoip rule-sets
        var fakednsObj: Any? = xray.opt("fakedns")
        if (fakednsObj == null || fakednsObj === JSONObject.NULL) {
            fakednsObj = xray.optJSONObject("dns")?.opt("fakedns")
        }
        val sbDns = SingBoxRouting.convDns(xray.optJSONObject("dns"), fakednsObj, dnsDetour, requiredRuleSets, notes)

        if (requiredRuleSets.isNotEmpty()) {
            val rsArr = JSONArray()
            for (tag in requiredRuleSets.sorted()) {
                val rs = JSONObject()
                rs.put("type", "remote")
                rs.put("tag", tag)
                rs.put("format", "binary")
                val url = when {
                    // the .srs name carries a geosite-/geoip- prefix
                    tag.startsWith("geosite-") -> GEOSITE_URL_TEMPLATE.replace("{name}", tag)
                    tag.startsWith("geoip-") -> GEOIP_URL_TEMPLATE.replace("{name}", tag)
                    else -> continue
                }
                rs.put("url", url)
                rs.put("download_detour", ruleSetDownloadDetour)
                rs.put("update_interval", "1d")
                rsArr.put(rs)
            }
            route.put("rule_set", rsArr)
        }

        val xlog = xray.optJSONObject("log")?.optString("loglevel", "warning") ?: "warning"
        val sbLogLevel = LOG_LEVEL_MAP[xlog] ?: "warn"

        // Final config: log/dns/inbounds/outbounds/route/experimental/endpoints
        val config = JSONObject()
        val logObj = JSONObject()
        logObj.put("level", sbLogLevel)
        logObj.put("timestamp", true)
        config.put("log", logObj)
        config.put("dns", sbDns)
        config.put("inbounds", JSONArray(inbounds))
        config.put("outbounds", JSONArray(sbOutbounds))
        config.put("route", route)
        val experimental = JSONObject()
        val cacheFile = JSONObject()
        cacheFile.put("enabled", true)
        experimental.put("cache_file", cacheFile)
        config.put("experimental", experimental)
        if (endpointsDedup.isNotEmpty()) config.put("endpoints", JSONArray(endpointsDedup))
        return ConvertResult(config, notes)
    }
}
