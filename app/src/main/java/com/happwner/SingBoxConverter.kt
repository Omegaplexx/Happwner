package com.happwner

import org.json.JSONArray
import org.json.JSONObject

object SingBoxConverter {

    private val UTLS_FP = setOf(
        "chrome", "firefox", "edge", "safari", "360", "qq",
        "ios", "android", "random", "randomized"
    )

    private val XRAY_TRANSPORTS_OK = setOf(
        "tcp", "raw", "", "ws", "grpc", "http", "h2", "httpupgrade", "quic"
    )
    private val XRAY_SECURITY_OK = setOf("", "none", "tls", "reality")
    private val XRAY_PROTOCOLS_PROXY = setOf(
        "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard"
    )
    private val XRAY_PROTOCOLS_AUX = setOf("freedom", "blackhole", "dns", "loopback")

    private val VLESS_FLOW_OK = setOf("", "xtls-rprx-vision")
    private val VLESS_FLOW_MAP = mapOf("xtls-rprx-vision-udp443" to "xtls-rprx-vision")

    private val VMESS_SECURITY_OK = setOf(
        "auto", "none", "zero", "aes-128-gcm",
        "chacha20-poly1305", "aes-128-ctr"
    )

    private val SS_METHODS_OK = setOf(
        "none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
        "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
        "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
        "rc4-md5", "chacha20-ietf", "xchacha20"
    )
    private val SS_METHOD_ALIAS = mapOf(
        "chacha20-poly1305" to "chacha20-ietf-poly1305",
        "xchacha20-poly1305" to "xchacha20-ietf-poly1305",
        "plain" to "none"
    )
    private val SS_PLUGINS_OK = setOf("", "obfs-local", "v2ray-plugin")

    private val QUERY_STRATEGY_MAP = mapOf(
        "UseIPv4" to "ipv4_only",
        "UseIPv4v6" to "prefer_ipv4",
        "UseIPv6" to "ipv6_only",
        "UseIPv6v4" to "prefer_ipv6",
        "UseIP" to "prefer_ipv4",
        "UseSystem" to "prefer_ipv4"
    )

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

    private val REMOTE_DNS_TYPES = setOf("https", "http3", "tls", "quic", "tcp", "udp")
    private val ENCRYPTED_DNS_TYPES = setOf("https", "http3", "tls", "quic", "tcp")

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
        data class Ok(val config: JSONObject) : Result()
        object NotXray : Result()
        object Unsupported : Result()
    }

    sealed class OutboundsResult {
        data class Ok(val outbounds: List<JSONObject>) : OutboundsResult()
        object NotXray : OutboundsResult()
        object Unsupported : OutboundsResult()
    }

    // Full Xray config to a full sing-box config
    fun convert(input: String, nameFallback: String = ""): Result {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return Result.NotXray
        if (!trimmed.startsWith("{")) return Result.NotXray

        val xray = try {
            JSONObject(trimmed)
        } catch (_: Throwable) {
            return Result.NotXray
        }

        if (isSingbox(xray)) return Result.NotXray
        if (!looksLikeXray(xray)) return Result.NotXray

        return try {
            val sb = convertObject(xray, nameFallback) ?: return Result.Unsupported
            Result.Ok(sb)
        } catch (_: Throwable) {
            Result.Unsupported
        }
    }

    // Xray to just the list of sing-box outbounds (no wrapper)
    fun convertToOutbounds(input: String, nameFallback: String = ""): OutboundsResult {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return OutboundsResult.NotXray
        if (!trimmed.startsWith("{")) return OutboundsResult.NotXray

        val xray = try {
            JSONObject(trimmed)
        } catch (_: Throwable) {
            return OutboundsResult.NotXray
        }

        if (isSingbox(xray)) return OutboundsResult.NotXray
        if (!looksLikeXray(xray)) return OutboundsResult.NotXray

        return try {
            val list = extractProxyOutbounds(xray, nameFallback) ?: return OutboundsResult.Unsupported
            if (list.isEmpty()) OutboundsResult.Unsupported else OutboundsResult.Ok(list)
        } catch (_: Throwable) {
            OutboundsResult.Unsupported
        }
    }

    // Merge several sing-box configs into one: rename tags, shared selector/urltest
    fun mergeUnified(fullConfigs: List<JSONObject>): JSONObject? {
        if (fullConfigs.isEmpty()) return null
        if (fullConfigs.size == 1) {
            val single = deepCopyObj(fullConfigs[0])
            stripForkOnlyFields(single)
            return single
        }

        val usedOutTags = mutableSetOf<String>()
        val usedDnsTags = mutableSetOf<String>()
        val usedRuleSetTags = mutableSetOf<String>()
        usedOutTags.addAll(setOf("proxy", "auto", "direct", "mixed-in"))
        usedDnsTags.add("local")

        val outRenames = mutableListOf<MutableMap<String, String>>()
        val dnsRenames = mutableListOf<MutableMap<String, String>>()

        // Pass 1: plan tag renames per config (proxies, endpoints, DNS)
        for (cfg in fullConfigs) {
            val outRename = mutableMapOf<String, String>()
            val dnsRename = mutableMapOf<String, String>()

            val outbounds = cfg.optJSONArray("outbounds")
            if (outbounds != null) {
                for (i in 0 until outbounds.length()) {
                    val o = outbounds.optJSONObject(i) ?: continue
                    val origTag = o.optString("tag", "")
                    val type = o.optString("type", "")
                    if (origTag.isEmpty()) continue
                    if (type == "selector" || type == "urltest") {
                        outRename[origTag] = "proxy"
                        continue
                    }
                    if (type == "direct") {
                        outRename[origTag] = "direct"
                        continue
                    }
                    val newTag = makeUniqueTag(origTag, usedOutTags)
                    usedOutTags.add(newTag)
                    outRename[origTag] = newTag
                }
            }
            val endpoints = cfg.optJSONArray("endpoints")
            if (endpoints != null) {
                for (i in 0 until endpoints.length()) {
                    val o = endpoints.optJSONObject(i) ?: continue
                    val origTag = o.optString("tag", "")
                    if (origTag.isEmpty()) continue
                    val newTag = makeUniqueTag(origTag, usedOutTags)
                    usedOutTags.add(newTag)
                    outRename[origTag] = newTag
                }
            }
            val dns = cfg.optJSONObject("dns")
            if (dns != null) {
                val dnsServers = dns.optJSONArray("servers")
                if (dnsServers != null) {
                    for (i in 0 until dnsServers.length()) {
                        val s = dnsServers.optJSONObject(i) ?: continue
                        val origTag = s.optString("tag", "")
                        if (origTag.isEmpty()) continue
                        if (origTag == "local" && s.optString("type") == "local") {
                            dnsRename[origTag] = "local"
                            continue
                        }
                        val newTag = makeUniqueTag(origTag, usedDnsTags)
                        usedDnsTags.add(newTag)
                        dnsRename[origTag] = newTag
                    }
                }
            }
            outRenames.add(outRename)
            dnsRenames.add(dnsRename)
        }

        val leafOutbounds = mutableListOf<JSONObject>()
        val leafOutboundTags = mutableListOf<String>()
        val mergedEndpoints = mutableListOf<JSONObject>()
        val mergedEndpointTags = mutableListOf<String>()
        val mergedDnsServers = mutableListOf<JSONObject>()
        val mergedDnsRules = mutableListOf<JSONObject>()
        val mergedRouteRules = mutableListOf<JSONObject>()
        val mergedRuleSet = mutableListOf<JSONObject>()
        var hasDirect = false
        var hasLocal = false

        // Pass 2: copy outbounds/endpoints/dns/route in, rewriting tags
        for ((idx, cfg) in fullConfigs.withIndex()) {
            val outR = outRenames[idx]
            val dnsR = dnsRenames[idx]

            val obs = cfg.optJSONArray("outbounds")
            if (obs != null) {
                for (i in 0 until obs.length()) {
                    val o = obs.optJSONObject(i) ?: continue
                    val type = o.optString("type", "")
                    if (type == "selector" || type == "urltest") continue
                    val obCopy = deepCopyObj(o)
                    rewriteOutbound(obCopy, outR, dnsR)
                    if (obCopy.optString("type") == "direct" && obCopy.optString("tag") == "direct") {
                        if (hasDirect) continue
                        hasDirect = true
                        leafOutbounds.add(obCopy)
                        continue
                    }
                    leafOutboundTags.add(obCopy.optString("tag"))
                    leafOutbounds.add(obCopy)
                }
            }
            val eps = cfg.optJSONArray("endpoints")
            if (eps != null) {
                for (i in 0 until eps.length()) {
                    val o = eps.optJSONObject(i) ?: continue
                    val obCopy = deepCopyObj(o)
                    rewriteOutbound(obCopy, outR, dnsR)
                    mergedEndpoints.add(obCopy)
                    mergedEndpointTags.add(obCopy.optString("tag"))
                }
            }

            val dns = cfg.optJSONObject("dns")
            if (dns != null) {
                val servers = dns.optJSONArray("servers")
                if (servers != null) {
                    for (i in 0 until servers.length()) {
                        val s = servers.optJSONObject(i) ?: continue
                        val sCopy = deepCopyObj(s)
                        rewriteDnsServer(sCopy, outR, dnsR)
                        if (sCopy.optString("type") == "local" && sCopy.optString("tag") == "local") {
                            if (hasLocal) continue
                            hasLocal = true
                        }
                        mergedDnsServers.add(sCopy)
                    }
                }
                val drules = dns.optJSONArray("rules")
                if (drules != null) {
                    for (i in 0 until drules.length()) {
                        val r = drules.optJSONObject(i) ?: continue
                        val rCopy = deepCopyObj(r)
                        rewriteDnsRule(rCopy, outR, dnsR)
                        mergedDnsRules.add(rCopy)
                    }
                }
            }

            val route = cfg.optJSONObject("route")
            if (route != null) {
                val rules = route.optJSONArray("rules")
                if (rules != null) {
                    for (i in 0 until rules.length()) {
                        val r = rules.optJSONObject(i) ?: continue
                        if (idx > 0 && isPreRule(r)) continue
                        val rCopy = deepCopyObj(r)
                        rewriteRouteRule(rCopy, outR, dnsR)
                        mergedRouteRules.add(rCopy)
                    }
                }
                val ruleSet = route.optJSONArray("rule_set")
                if (ruleSet != null) {
                    for (i in 0 until ruleSet.length()) {
                        val rs = ruleSet.optJSONObject(i) ?: continue
                        val tag = rs.optString("tag", "")
                        if (tag.isEmpty() || tag in usedRuleSetTags) continue
                        usedRuleSetTags.add(tag)
                        mergedRuleSet.add(deepCopyObj(rs))
                    }
                }
            }
        }

        // Build the shared selector + urltest over all leaf outbounds
        val allLeafTags = leafOutboundTags + mergedEndpointTags
        if (allLeafTags.isEmpty()) return null

        if (!hasLocal) {
            val localSrv = JSONObject()
            localSrv.put("type", "local")
            localSrv.put("tag", "local")
            mergedDnsServers.add(0, localSrv)
        }
        if (!hasDirect) {
            val direct = JSONObject()
            direct.put("type", "direct")
            direct.put("tag", "direct")
            leafOutbounds.add(direct)
        }

        val selector = JSONObject()
        selector.put("type", "selector")
        selector.put("tag", "proxy")
        val selectorOuts = JSONArray()
        selectorOuts.put("auto")
        for (t in allLeafTags) selectorOuts.put(t)
        selectorOuts.put("direct")
        selector.put("outbounds", selectorOuts)
        selector.put("default", "auto")

        val urltest = JSONObject()
        urltest.put("type", "urltest")
        urltest.put("tag", "auto")
        val urltestOuts = JSONArray()
        for (t in allLeafTags) urltestOuts.put(t)
        urltest.put("outbounds", urltestOuts)
        urltest.put("url", "https://www.gstatic.com/generate_204")
        urltest.put("interval", "5m")

        // Assemble the merged config (log/dns/inbounds/outbounds/route/experimental)
        val merged = JSONObject()
        val firstLog = fullConfigs[0].optJSONObject("log")
        if (firstLog != null) merged.put("log", deepCopyObj(firstLog))

        val dnsObj = JSONObject()
        dnsObj.put("servers", JSONArray(mergedDnsServers))
        if (mergedDnsRules.isNotEmpty()) dnsObj.put("rules", JSONArray(mergedDnsRules))
        val firstDns = fullConfigs[0].optJSONObject("dns")
        if (firstDns != null) {
            val cs = firstDns.optString("client_subnet", "")
            if (cs.isNotEmpty()) dnsObj.put("client_subnet", cs)
            val df = firstDns.optString("final", "")
            if (df.isNotEmpty()) {
                val mapped = dnsRenames[0][df] ?: df
                dnsObj.put("final", mapped)
            }
        }
        merged.put("dns", dnsObj)

        val firstInbounds = fullConfigs[0].optJSONArray("inbounds")
        if (firstInbounds != null && firstInbounds.length() > 0) {
            merged.put("inbounds", deepCopyArr(firstInbounds))
        } else {
            val inbounds = JSONArray()
            val mixedIn = JSONObject()
            mixedIn.put("type", "mixed")
            mixedIn.put("tag", "mixed-in")
            mixedIn.put("listen", "127.0.0.1")
            mixedIn.put("listen_port", 2080)
            inbounds.put(mixedIn)
            merged.put("inbounds", inbounds)
        }

        val outArr = JSONArray()
        outArr.put(selector)
        outArr.put(urltest)
        for (o in leafOutbounds) outArr.put(o)
        merged.put("outbounds", outArr)

        if (mergedEndpoints.isNotEmpty()) merged.put("endpoints", JSONArray(mergedEndpoints))

        val routeObj = JSONObject()
        if (mergedRouteRules.isNotEmpty()) routeObj.put("rules", JSONArray(mergedRouteRules))
        if (mergedRuleSet.isNotEmpty()) routeObj.put("rule_set", JSONArray(mergedRuleSet))
        routeObj.put("auto_detect_interface", true)
        routeObj.put("final", "proxy")
        val ddr = JSONObject()
        ddr.put("server", "local")
        routeObj.put("default_domain_resolver", ddr)
        merged.put("route", routeObj)

        val firstExp = fullConfigs[0].optJSONObject("experimental")
        if (firstExp != null) {
            val expCopy = deepCopyObj(firstExp)
            stripForkOnlyFields(expCopy)
            merged.put("experimental", expCopy)
        }

        return merged
    }

    // Strip fields that only sing-box forks understand
    private fun stripForkOnlyFields(cfg: JSONObject) {
        val exp = cfg.optJSONObject("experimental") ?: return
        val cf = exp.optJSONObject("cache_file") ?: return
        cf.remove("store_dns")
    }

    private fun deepCopyObj(obj: JSONObject): JSONObject = JSONObject(obj.toString())
    private fun deepCopyArr(arr: JSONArray): JSONArray = JSONArray(arr.toString())

    // Built-in pre-rules (sniff/hijack-dns/resolve): we add our own and skip duplicates
    private fun isPreRule(r: JSONObject): Boolean {
        val action = r.optString("action", "")
        if (action == "sniff" && r.length() == 1) return true
        if (action == "hijack-dns" && (r.has("protocol") || r.has("port"))) return true
        if (action == "resolve" && r.has("inbound")) return true
        return false
    }

    private fun renameString(obj: JSONObject, key: String, rename: Map<String, String>) {
        val v = obj.opt(key)
        if (v !is String || v.isEmpty()) return
        val mapped = rename[v] ?: return
        if (mapped != v) obj.put(key, mapped)
    }

    private fun renameStringArray(obj: JSONObject, key: String, rename: Map<String, String>) {
        val arr = obj.optJSONArray(key) ?: return
        var changed = false
        val newArr = JSONArray()
        for (i in 0 until arr.length()) {
            val item = arr.opt(i)
            if (item is String) {
                val mapped = rename[item]
                if (mapped != null && mapped != item) {
                    newArr.put(mapped); changed = true
                } else {
                    newArr.put(item)
                }
            } else {
                newArr.put(item)
            }
        }
        if (changed) obj.put(key, newArr)
    }

    private fun rewriteOutbound(o: JSONObject, outRename: Map<String, String>, dnsRename: Map<String, String>) {
        renameString(o, "tag", outRename)
        renameString(o, "detour", outRename)
        renameStringArray(o, "outbounds", outRename)
        renameString(o, "default", outRename)
        val drRaw = o.opt("domain_resolver")
        if (drRaw is String && drRaw.isNotEmpty()) {
            val mapped = dnsRename[drRaw]
            if (mapped != null && mapped != drRaw) o.put("domain_resolver", mapped)
        } else if (drRaw is JSONObject) {
            renameString(drRaw, "server", dnsRename)
        }
    }

    private fun rewriteDnsServer(s: JSONObject, outRename: Map<String, String>, dnsRename: Map<String, String>) {
        renameString(s, "tag", dnsRename)
        renameString(s, "detour", outRename)
        val drRaw = s.opt("domain_resolver")
        if (drRaw is String && drRaw.isNotEmpty()) {
            val mapped = dnsRename[drRaw]
            if (mapped != null && mapped != drRaw) s.put("domain_resolver", mapped)
        } else if (drRaw is JSONObject) {
            renameString(drRaw, "server", dnsRename)
        }
    }

    private fun rewriteDnsRule(r: JSONObject, outRename: Map<String, String>, dnsRename: Map<String, String>) {
        renameString(r, "server", dnsRename)
        renameString(r, "outbound", outRename)
    }

    private fun rewriteRouteRule(r: JSONObject, outRename: Map<String, String>, dnsRename: Map<String, String>) {
        renameString(r, "outbound", outRename)
        renameString(r, "server", dnsRename)
    }

    // Extract only supported proxy outbounds; take names from remarks
    private fun extractProxyOutbounds(xray: JSONObject, nameFallback: String): List<JSONObject>? {
        val remarks = (xray.optString("remarks", "").ifEmpty {
            xray.optString("name", "").ifEmpty { nameFallback }
        }).trim()

        val outsRaw = xray.optJSONArray("outbounds") ?: return null

        val supportedProxies = mutableListOf<JSONObject>()
        for (i in 0 until outsRaw.length()) {
            val o = outsRaw.optJSONObject(i) ?: continue
            val proto = o.optString("protocol", "")
            if (proto !in XRAY_PROTOCOLS_PROXY) continue
            if (!isOutboundSupported(o)) continue
            supportedProxies.add(o)
        }

        if (supportedProxies.isEmpty()) return null

        val results = mutableListOf<JSONObject>()
        val singleProxy = supportedProxies.size == 1

        // Convert each, naming from remarks (with #tag suffix when there are several)
        for (o in supportedProxies) {
            val r = convOutbound(o)
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

        return if (results.isEmpty()) null else results
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

    private fun isTruthy(v: Any?): Boolean {
        if (v == null || v === JSONObject.NULL) return false
        return when (v) {
            is Boolean -> v
            is Number -> v.toDouble() != 0.0
            is String -> v.isNotEmpty()
            is JSONArray -> v.length() > 0
            is JSONObject -> v.length() > 0
            else -> true
        }
    }

    private fun utlsFp(fp: Any?): String {
        if (fp is String && fp in UTLS_FP) return fp
        return "chrome"
    }

    private fun asList(v: Any?): List<Any?> {
        if (v == null || v === JSONObject.NULL) return emptyList()
        if (v is JSONArray) {
            val out = ArrayList<Any?>(v.length())
            for (i in 0 until v.length()) out.add(v.opt(i))
            return out
        }
        return listOf(v)
    }

    private fun asStringList(v: Any?): List<String> {
        return asList(v).mapNotNull {
            when (it) {
                null, JSONObject.NULL -> null
                is String -> it
                else -> it.toString()
            }
        }
    }

    private fun isIpLiteral(s: Any?): Boolean {
        if (s !is String || s.isEmpty()) return false
        return parseInet4(s) || parseInet6(s)
    }

    private fun parseInet4(s: String): Boolean {
        val parts = s.split(".")
        if (parts.size != 4) return false
        for (p in parts) {
            if (p.isEmpty() || p.length > 3) return false
            for (c in p) if (c !in '0'..'9') return false
            val n = p.toIntOrNull() ?: return false
            if (n < 0 || n > 255) return false
            if (p.length > 1 && p[0] == '0') return false
        }
        return true
    }

    // Rough IPv6 parsing (::, embedded IPv4, zone-id)
    private fun parseInet6(s: String): Boolean {
        if (s.isEmpty()) return false
        val core = s.substringBefore('%')
        if (core.isEmpty()) return false
        if (core == "::") return true
        val hasDoubleColon = core.contains("::")
        val tail = core.substringAfterLast(":")
        val embedded4 = tail.contains(".")
        // Split into groups around '::', folding any embedded IPv4
        val groupsRaw: List<String> = if (hasDoubleColon) {
            val (left, right) = core.split("::", limit = 2)
            val l = if (left.isEmpty()) emptyList() else left.split(":")
            val r = if (right.isEmpty()) emptyList() else right.split(":")
            l + r
        } else {
            core.split(":")
        }
        val groups = groupsRaw.toMutableList()
        if (embedded4) {
            val last = groups.removeAt(groups.size - 1)
            if (!parseInet4(last)) return false
            groups.add("0")
            groups.add("0")
        }
        val expected = 8
        val countWithoutDC = groups.size
        if (hasDoubleColon) {
            if (countWithoutDC > expected) return false
        } else {
            if (countWithoutDC != expected) return false
        }
        for (g in groups) {
            if (g.isEmpty() || g.length > 4) return false
            for (c in g) {
                val ok = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'
                if (!ok) return false
            }
        }
        return true
    }

    private data class PortLists(val ports: List<Int>, val ranges: List<String>)

    private fun parsePortList(value: Any?): PortLists {
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
                tok.all { it in '0'..'9' } -> tok.toIntOrNull()?.let { ports.add(it) }
            }
        }
        return PortLists(ports, ranges)
    }

    private fun parseListenPort(p: Any?): Int? {
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

    private fun toDuration(v: Any?): String? {
        if (v == null || v === JSONObject.NULL) return null
        if (v is Boolean) return null
        if (v is Int || v is Long) return "${(v as Number).toInt()}s"
        if (v is Double || v is Float) return "${(v as Number).toInt()}s"
        if (v is String) {
            val s = v.trim()
            if (s.isEmpty()) return null
            if (s.all { it in '0'..'9' }) return "${s}s"
            return s
        }
        return null
    }

    private data class HostPort(val host: String, val port: Int?)

    private fun splitHostPort(s: String?): HostPort {
        if (s.isNullOrEmpty()) return HostPort(s ?: "", null)
        if (s.startsWith("[")) {
            val rb = s.indexOf("]")
            if (rb < 0) return HostPort(s, null)
            val host = s.substring(1, rb)
            val rest = s.substring(rb + 1)
            if (rest.startsWith(":") && rest.substring(1).all { it in '0'..'9' }) {
                return HostPort(host, rest.substring(1).toIntOrNull())
            }
            return HostPort(host, null)
        }
        if (s.count { it == ':' } == 1) {
            val idx = s.indexOf(':')
            val host = s.substring(0, idx)
            val port = s.substring(idx + 1)
            if (port.isNotEmpty() && port.all { it in '0'..'9' }) return HostPort(host, port.toIntOrNull())
        }
        return HostPort(s, null)
    }

    private fun normalizeFlow(flow: String?): String {
        if (flow.isNullOrEmpty()) return ""
        return VLESS_FLOW_MAP[flow] ?: flow
    }

    private data class WsPath(val path: String, val earlyData: Int?)

    private fun parseWsPath(path: Any?): WsPath {
        if (path !is String || !path.contains("?") || !path.contains("ed=")) {
            return WsPath(path as? String ?: "", null)
        }
        val qIdx = path.indexOf("?")
        val base = path.substring(0, qIdx)
        val query = path.substring(qIdx + 1)
        val kept = mutableListOf<String>()
        var edValue: Int? = null
        for (pair in query.split("&")) {
            if (pair.isEmpty()) continue
            if (pair.startsWith("ed=")) {
                val n = pair.substring(3).toIntOrNull()
                if (n != null) edValue = n else kept.add(pair)
            } else {
                kept.add(pair)
            }
        }
        val newQuery = kept.joinToString("&")
        val newPath = if (newQuery.isEmpty()) base else "$base?$newQuery"
        return WsPath(newPath, edValue)
    }

    private fun normalizeHeadersV2ray(headers: JSONObject?, singleValue: Boolean): JSONObject {
        val out = JSONObject()
        if (headers == null) return out
        val keys = headers.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            val v = headers.opt(k) ?: continue
            if (v === JSONObject.NULL) continue
            if (singleValue) {
                if (v is JSONArray) {
                    if (v.length() > 0) out.put(k, v.opt(0)?.toString() ?: "") else out.put(k, "")
                } else {
                    out.put(k, v.toString())
                }
            } else {
                if (v is JSONArray) {
                    out.put(k, v)
                } else {
                    out.put(k, JSONArray().put(v.toString()))
                }
            }
        }
        return out
    }

    private fun serializePluginOpts(opts: Any?): String {
        if (opts == null || opts === JSONObject.NULL) return ""
        if (opts is String) return opts
        if (opts is JSONObject) {
            val parts = mutableListOf<String>()
            val keys = opts.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                val v = opts.opt(k)
                if (v is Boolean) {
                    parts.add(if (v) k else "$k=0")
                } else {
                    parts.add("$k=$v")
                }
            }
            return parts.joinToString(";")
        }
        return ""
    }

    private fun getTcpHttpRequest(stream: JSONObject): JSONObject? {
        val net = stream.optString("network", "tcp").ifEmpty { "tcp" }
        if (net !in setOf("tcp", "raw", "")) return null
        val ts = stream.optJSONObject("tcpSettings")
            ?: stream.optJSONObject("rawSettings")
            ?: return null
        val hdr = ts.optJSONObject("header") ?: return null
        if (hdr.optString("type", "none").ifEmpty { "none" } != "http") return null
        return hdr.optJSONObject("request") ?: JSONObject()
    }

    // Heuristic for "already sing-box": route present + the first outbound's type is a sing-box one
    private fun isSingbox(d: JSONObject): Boolean {
        if (!d.has("route") || !d.has("outbounds")) return false
        val outs = d.optJSONArray("outbounds") ?: return false
        if (outs.length() == 0) return false
        val first = outs.optJSONObject(0) ?: return false
        return first.optString("type", "") in SINGBOX_OUTBOUND_TYPES
    }

    // Whether an outbound is supported (protocol/transport/security/flow/method)
    private fun isOutboundSupported(o: JSONObject): Boolean {
        val proto = o.optString("protocol", "")
        if (proto !in XRAY_PROTOCOLS_PROXY && proto !in XRAY_PROTOCOLS_AUX) return false
        if (proto in XRAY_PROTOCOLS_AUX || proto == "wireguard") return true
        val stream = o.optJSONObject("streamSettings") ?: JSONObject()
        val net = stream.optString("network", "tcp").ifEmpty { "tcp" }
        if (net !in XRAY_TRANSPORTS_OK) return false
        if (net == "tcp" || net == "raw") {
            val ts = stream.optJSONObject("tcpSettings") ?: stream.optJSONObject("rawSettings")
            val hdrType = ts?.optJSONObject("header")?.optString("type", "none")?.ifEmpty { "none" }
            if (hdrType != null && hdrType != "none" && hdrType != "http") return false
        }
        if (net == "quic") {
            val qs = stream.optJSONObject("quicSettings") ?: JSONObject()
            val qsec = qs.optString("security", "none").lowercase().ifEmpty { "none" }
            if (qsec != "none" && qsec != "") return false
            val qhdr = (qs.optJSONObject("header")?.optString("type", "none")
                ?: "none").lowercase().ifEmpty { "none" }
            if (qhdr != "none" && qhdr != "") return false
        }
        val sec = stream.optString("security", "")
        if (sec !in XRAY_SECURITY_OK) return false
        if (proto == "vless") {
            val user = firstUser(o)
            val flowRaw = user?.optString("flow", "") ?: ""
            val flow = normalizeFlow(flowRaw)
            if (flow !in VLESS_FLOW_OK) return false
            val enc = (user?.optString("encryption", "none") ?: "none").trim()
            if (enc.isNotEmpty() && enc != "none") return false
        }
        if (proto == "vmess") {
            val user = firstUser(o)
            val vsec = (user?.optString("security", "auto") ?: "auto").ifEmpty { "auto" }
            if (vsec !in VMESS_SECURITY_OK) return false
        }
        if (proto == "shadowsocks") {
            val srv = firstServer(o)
            val rawMethod = srv?.optString("method", "aes-256-gcm") ?: "aes-256-gcm"
            val method = SS_METHOD_ALIAS[rawMethod] ?: rawMethod
            if (method !in SS_METHODS_OK) return false
            val plugin = srv?.optString("plugin", "") ?: ""
            if (plugin.isNotEmpty() && plugin !in SS_PLUGINS_OK) return false
        }
        return true
    }

    private fun firstUser(o: JSONObject): JSONObject? {
        val settings = o.optJSONObject("settings") ?: return null
        val vnext = settings.optJSONArray("vnext") ?: return null
        val first = vnext.optJSONObject(0) ?: return null
        val users = first.optJSONArray("users") ?: return null
        return users.optJSONObject(0)
    }

    private fun firstServer(o: JSONObject): JSONObject? {
        val settings = o.optJSONObject("settings") ?: return null
        val servers = settings.optJSONArray("servers") ?: return null
        return servers.optJSONObject(0)
    }

    private data class DomainSplit(
        val domain: List<String>,
        val domainSuffix: List<String>,
        val domainKeyword: List<String>,
        val domainRegex: List<String>,
        val geosite: List<String>
    )

    private fun splitDomains(domains: List<Any?>): DomainSplit {
        val full = mutableListOf<String>()
        val suffix = mutableListOf<String>()
        val keyword = mutableListOf<String>()
        val regex = mutableListOf<String>()
        val geosite = mutableListOf<String>()
        for (raw in domains) {
            val d = (raw as? String) ?: continue
            if (d.startsWith("!")) continue
            when {
                d.startsWith("geosite:") -> geosite.add(d.substringAfter(":"))
                d.startsWith("domain:") -> suffix.add(d.substringAfter(":"))
                d.startsWith("full:") -> full.add(d.substringAfter(":"))
                d.startsWith("regexp:") -> regex.add(d.substringAfter(":"))
                d.startsWith("keyword:") -> keyword.add(d.substringAfter(":"))
                d.startsWith("ext:") || d.startsWith("ext-domain:") -> {
                }
                else -> suffix.add(d)
            }
        }
        return DomainSplit(full, suffix, keyword, regex, geosite)
    }

    private data class IpSplit(
        val ipCidr: List<String>,
        val geoip: List<String>,
        val ipIsPrivate: Boolean
    )

    private fun splitIps(ips: List<Any?>): IpSplit {
        val cidr = mutableListOf<String>()
        val geoip = mutableListOf<String>()
        var isPrivate = false
        for (raw in ips) {
            val i = (raw as? String) ?: continue
            if (i.startsWith("!")) continue
            when {
                i == "geoip:private" -> isPrivate = true
                i.startsWith("geoip:") -> geoip.add(i.substringAfter(":"))
                i.startsWith("ext:") || i.startsWith("ext-ip:") -> {
                }
                else -> cidr.add(i)
            }
        }
        return IpSplit(cidr, geoip, isPrivate)
    }

    private fun addRuleSetTags(rule: JSONObject, tags: List<String>) {
        if (tags.isEmpty()) return
        val existing = mutableListOf<String>()
        val arr = rule.optJSONArray("rule_set")
        if (arr != null) for (i in 0 until arr.length()) existing.add(arr.optString(i))
        for (t in tags) if (t !in existing) existing.add(t)
        rule.put("rule_set", JSONArray(existing))
    }

    private fun applyDomainSplit(rule: JSONObject, split: DomainSplit, ruleSets: MutableSet<String>) {
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

    private fun applyGeoipToRuleSet(rule: JSONObject, geoip: List<String>, ruleSets: MutableSet<String>) {
        if (geoip.isEmpty()) return
        val tags = geoip.map { "geoip-${it.lowercase()}" }
        ruleSets.addAll(tags)
        addRuleSetTags(rule, tags)
    }

    private data class InboundResult(
        val sb: JSONObject?,
        val sniffEnabled: Boolean,
        val sniffResolves: Boolean
    )

    // Xray inbound to sing-box inbound (socks/http/mixed/dokodemo)
    private fun convInbound(inb: JSONObject): InboundResult {
        val proto = inb.optString("protocol", "")
        val sniff = inb.optJSONObject("sniffing") ?: JSONObject()
        val sniffEnabled = sniff.optBoolean("enabled", false)
        val destOverride = sniff.optJSONArray("destOverride")
        val hasDestOverride = destOverride != null && destOverride.length() > 0
        val routeOnly = sniff.optBoolean("routeOnly", false)
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
            if (isTruthy(addr)) sb.put("override_address", addr)
            val port = ds.opt("port")
            if (isTruthy(port)) sb.put("override_port", port)
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

    // streamSettings to the tls block (including reality/utls/ech)
    private fun convTls(stream: JSONObject): JSONObject? {
        val sec = stream.optString("security", "")
        if (sec != "tls" && sec != "reality") return null
        val tls = JSONObject()
        tls.put("enabled", true)

        // Reality: utls fingerprint + public key / short id
        if (sec == "reality") {
            val rs = stream.optJSONObject("realitySettings") ?: JSONObject()
            val sn = rs.optString("serverName", "")
            if (sn.isNotEmpty()) tls.put("server_name", sn)
            val utls = JSONObject()
            utls.put("enabled", true)
            utls.put("fingerprint", utlsFp(rs.opt("fingerprint")))
            tls.put("utls", utls)
            val reality = JSONObject()
            reality.put("enabled", true)
            reality.put("public_key", rs.optString("publicKey", ""))
            reality.put("short_id", rs.optString("shortId", ""))
            tls.put("reality", reality)
            return tls
        }

        // Plain TLS: sni, alpn, versions, utls, certs, ECH
        val ts = stream.optJSONObject("tlsSettings") ?: JSONObject()
        val sn = ts.optString("serverName", "")
        if (sn.isNotEmpty()) tls.put("server_name", sn)
        if (ts.optBoolean("allowInsecure", false)) tls.put("insecure", true)
        val alpn = ts.opt("alpn")
        if (alpn != null && alpn !== JSONObject.NULL) {
            if (alpn is JSONArray) {
                if (alpn.length() > 0) tls.put("alpn", alpn)
            } else {
                tls.put("alpn", JSONArray().put(alpn.toString()))
            }
        }
        if (ts.has("minVersion") && !ts.isNull("minVersion")) {
            val v = ts.optString("minVersion", "")
            if (v.isNotEmpty()) tls.put("min_version", v)
        }
        if (ts.has("maxVersion") && !ts.isNull("maxVersion")) {
            val v = ts.optString("maxVersion", "")
            if (v.isNotEmpty()) tls.put("max_version", v)
        }
        val fp = ts.optString("fingerprint", "")
        if (fp.isNotEmpty()) {
            val utls = JSONObject()
            utls.put("enabled", true)
            utls.put("fingerprint", utlsFp(fp))
            tls.put("utls", utls)
        }
        val certs = ts.optJSONArray("certificates")
        if (certs != null && certs.length() > 0) {
            val cert = certs.optJSONObject(0) ?: JSONObject()
            val certFile = cert.optString("certificateFile", "")
            if (certFile.isNotEmpty()) {
                tls.put("certificate_path", certFile)
            } else if (cert.has("certificate") && !cert.isNull("certificate")) {
                val cval = cert.opt("certificate")
                if (cval is JSONArray) {
                    val parts = mutableListOf<String>()
                    for (i in 0 until cval.length()) {
                        parts.add(cval.opt(i)?.toString() ?: "")
                    }
                    tls.put("certificate", parts.joinToString("\n"))
                } else if (cval is String) {
                    tls.put("certificate", cval)
                }
            }
        }
        var ech: Any? = ts.opt("echConfigList")
        if (ech == null || ech === JSONObject.NULL ||
            (ech is JSONArray && ech.length() == 0) ||
            (ech is String && ech.isEmpty())) {
            ech = ts.opt("ech")
        }
        if (ech != null && ech !== JSONObject.NULL &&
            !(ech is JSONArray && ech.length() == 0) &&
            !(ech is String && ech.isEmpty())) {
            val echObj = JSONObject()
            echObj.put("enabled", true)
            when (ech) {
                is JSONArray -> echObj.put("config", ech)
                is String -> echObj.put("config_path", ech)
            }
            tls.put("ech", echObj)
        }
        return tls
    }

    // streamSettings to the transport block (ws/grpc/http/httpupgrade/quic/tcp-http)
    private fun convTransport(stream: JSONObject): JSONObject? {
        var net = stream.optString("network", "tcp").ifEmpty { "tcp" }
        if (net == "raw") net = "tcp"

        // tcp + http header -> http transport
        if (net == "tcp") {
            val req = getTcpHttpRequest(stream) ?: return null
            val tr = JSONObject()
            tr.put("type", "http")
            val pathRaw = req.opt("path")
            when (pathRaw) {
                is JSONArray -> if (pathRaw.length() > 0) tr.put("path", pathRaw.opt(0))
                is String -> if (pathRaw.isNotEmpty()) tr.put("path", pathRaw)
            }
            val method = req.optString("method", "")
            if (method.isNotEmpty()) tr.put("method", method)
            val headersIn = req.optJSONObject("headers")
            val workingHeaders = if (headersIn != null) {
                val copy = JSONObject()
                val keys = headersIn.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    copy.put(k, headersIn.opt(k))
                }
                copy
            } else null
            var hostVals: Any? = null
            if (workingHeaders != null) {
                if (workingHeaders.has("Host")) {
                    hostVals = workingHeaders.opt("Host"); workingHeaders.remove("Host")
                } else if (workingHeaders.has("host")) {
                    hostVals = workingHeaders.opt("host"); workingHeaders.remove("host")
                }
            }
            if (hostVals != null && hostVals !== JSONObject.NULL) {
                if (hostVals is JSONArray) {
                    tr.put("host", hostVals)
                } else {
                    tr.put("host", JSONArray().put(hostVals.toString()))
                }
            }
            if (workingHeaders != null && workingHeaders.length() > 0) {
                tr.put("headers", normalizeHeadersV2ray(workingHeaders, singleValue = false))
            }
            return tr
        }

        // WebSocket: path, headers, early-data
        if (net == "ws") {
            val ws = stream.optJSONObject("wsSettings") ?: JSONObject()
            val tr = JSONObject()
            tr.put("type", "ws")
            val rawPath = ws.optString("path", "")
            val parsed = parseWsPath(rawPath)
            if (parsed.path.isNotEmpty()) tr.put("path", parsed.path)
            val headers = normalizeHeadersV2ray(ws.optJSONObject("headers"), singleValue = true)
            if (headers.length() > 0) tr.put("headers", headers)
            var earlyData = parsed.earlyData
            if (earlyData == null && ws.has("maxEarlyData") && !ws.isNull("maxEarlyData")) {
                val v = ws.opt("maxEarlyData")
                earlyData = when (v) {
                    is Int -> v
                    is Long -> v.toInt()
                    is Number -> v.toInt()
                    is String -> v.toIntOrNull()
                    else -> null
                }
            }
            if (earlyData != null && earlyData != 0) {
                tr.put("max_early_data", earlyData)
                tr.put(
                    "early_data_header_name",
                    ws.optString("earlyDataHeaderName", "").ifEmpty { "Sec-WebSocket-Protocol" }
                )
            } else {
                val edh = ws.optString("earlyDataHeaderName", "")
                if (edh.isNotEmpty()) tr.put("early_data_header_name", edh)
            }
            return tr
        }

        // gRPC: service name and timeouts
        if (net == "grpc") {
            val g = stream.optJSONObject("grpcSettings") ?: JSONObject()
            var sn = g.optString("serviceName", "")
            if (sn.startsWith("/")) sn = sn.trimStart('/')
            val tr = JSONObject()
            tr.put("type", "grpc")
            tr.put("service_name", sn)
            val idle = toDuration(g.opt("idle_timeout"))
            if (idle != null) tr.put("idle_timeout", idle)
            val hct = toDuration(g.opt("health_check_timeout"))
            if (hct != null) tr.put("ping_timeout", hct)
            if (g.optBoolean("permit_without_stream", false)) tr.put("permit_without_stream", true)
            return tr
        }

        // HTTP/2: host/path/headers/timeouts
        if (net == "http" || net == "h2") {
            val h = stream.optJSONObject("httpSettings") ?: JSONObject()
            val tr = JSONObject()
            tr.put("type", "http")
            val path = h.optString("path", "")
            if (path.isNotEmpty()) tr.put("path", path)
            val host = h.opt("host")
            if (host != null && host !== JSONObject.NULL) {
                if (host is JSONArray) {
                    if (host.length() > 0) tr.put("host", host)
                } else if (host is String) {
                    if (host.isNotEmpty()) tr.put("host", JSONArray().put(host))
                } else {
                    val hs = host.toString()
                    if (hs.isNotEmpty()) tr.put("host", JSONArray().put(hs))
                }
            }
            val method = h.optString("method", "")
            if (method.isNotEmpty()) tr.put("method", method)
            val headers = h.optJSONObject("headers")
            if (headers != null && headers.length() > 0) {
                tr.put("headers", normalizeHeadersV2ray(headers, singleValue = false))
            }
            val idle = toDuration(h.opt("read_idle_timeout"))
            if (idle != null) tr.put("idle_timeout", idle)
            val hct = toDuration(h.opt("health_check_timeout"))
            if (hct != null) tr.put("ping_timeout", hct)
            return tr
        }

        // HTTPUpgrade: host (top-level or from the headers)
        if (net == "httpupgrade") {
            val hu = stream.optJSONObject("httpupgradeSettings") ?: JSONObject()
            val tr = JSONObject()
            tr.put("type", "httpupgrade")
            val path = hu.optString("path", "")
            if (path.isNotEmpty()) tr.put("path", path)
            var hostTop = hu.optString("host", "")
            val headers = normalizeHeadersV2ray(hu.optJSONObject("headers"), singleValue = true)
            var hostFromHeaders: String? = null
            val hk = headers.keys()
            val toRemove = mutableListOf<String>()
            while (hk.hasNext()) {
                val k = hk.next()
                if (k.lowercase() == "host") {
                    hostFromHeaders = headers.opt(k)?.toString()
                    toRemove.add(k)
                }
            }
            for (k in toRemove) headers.remove(k)
            if (hostTop.isEmpty() && !hostFromHeaders.isNullOrEmpty()) hostTop = hostFromHeaders
            if (hostTop.isNotEmpty()) tr.put("host", hostTop)
            if (headers.length() > 0) tr.put("headers", headers)
            return tr
        }

        if (net == "quic") {
            val tr = JSONObject()
            tr.put("type", "quic")
            return tr
        }

        return null
    }

    // packetEncoding (xudp/packetaddr), protocol-aware
    private fun convPacketEncoding(o: JSONObject, proto: String): String? {
        val settings = o.optJSONObject("settings") ?: JSONObject()
        var v: Any? = settings.opt("packetEncoding")
        if (v == null || v === JSONObject.NULL) {
            val vnext = settings.optJSONArray("vnext")?.optJSONObject(0)
            val user = vnext?.optJSONArray("users")?.optJSONObject(0)
            v = user?.opt("packetEncoding")
        }
        if (v == null || v === JSONObject.NULL) return null
        val s = v.toString().lowercase()
        return when (s) {
            "packet" -> "packetaddr"
            "xudp" -> if (proto == "vless") null else "xudp"
            "none", "" -> if (proto == "vless") "" else null
            else -> null
        }
    }

    private fun applyProxySettings(sb: JSONObject, o: JSONObject) {
        var chainTag = o.optJSONObject("proxySettings")?.optString("tag", "") ?: ""
        if (chainTag.isEmpty()) {
            val ss = o.optJSONObject("streamSettings") ?: JSONObject()
            chainTag = ss.optString("dialerProxy", "")
            if (chainTag.isEmpty()) {
                chainTag = ss.optJSONObject("sockopt")?.optString("dialerProxy", "") ?: ""
            }
        }
        if (chainTag.isNotEmpty()) sb.put("detour", chainTag)
    }

    private val FREEDOM_STRATEGY_MAP = mapOf(
        "AsIs" to "",
        "UseIP" to "prefer_ipv4",
        "UseIPv4" to "ipv4_only",
        "UseIPv4v6" to "prefer_ipv4",
        "UseIPv6" to "ipv6_only",
        "UseIPv6v4" to "prefer_ipv6",
        "ForceIP" to "prefer_ipv4",
        "ForceIPv4" to "ipv4_only",
        "ForceIPv4v6" to "prefer_ipv4",
        "ForceIPv6" to "ipv6_only",
        "ForceIPv6v4" to "prefer_ipv6"
    )

    private fun applySockopt(sb: JSONObject, stream: JSONObject?) {
        val sock = stream?.optJSONObject("sockopt") ?: return
        val ds = sock.optString("domainStrategy", "").trim()
        val strat = FREEDOM_STRATEGY_MAP[ds] ?: ""
        if (strat.isNotEmpty() && !sb.has("domain_strategy")) {
            sb.put("domain_strategy", strat)
        }
        val tfo = sock.opt("tcpFastOpen")
        if (tfo is Boolean) sb.put("tcp_fast_open", tfo)
        val kaiRaw = sock.opt("tcpKeepAliveInterval")
        if (kaiRaw is Number) {
            val kai = kaiRaw.toInt()
            if (kai > 0) sb.put("tcp_keep_alive_interval", "${kai}s")
        }
    }

    private data class OutboundResult(val sb: JSONObject?, val kind: String?)

    // One Xray outbound to one sing-box outbound
    private fun convOutbound(o: JSONObject): OutboundResult {
        val proto = o.optString("protocol", "")
        val tag = o.optString("tag", proto)

        // freedom -> direct
        if (proto == "freedom") {
            val sb = JSONObject()
            sb.put("type", "direct")
            sb.put("tag", tag)
            val settings = o.optJSONObject("settings") ?: JSONObject()
            val ds = settings.optString("domainStrategy", "").trim()
            val strat = FREEDOM_STRATEGY_MAP[ds] ?: ""
            if (strat.isNotEmpty()) {
                sb.put("domain_strategy", strat)
            }
            applyProxySettings(sb, o)
            return OutboundResult(sb, "aux")
        }

        if (proto == "blackhole" || proto == "dns") return OutboundResult(null, "aux")
        if (proto == "loopback") return OutboundResult(null, "aux")

        val stream = o.optJSONObject("streamSettings") ?: JSONObject()
        val settings = o.optJSONObject("settings") ?: JSONObject()

        if (proto == "wireguard") {
            return OutboundResult(convWireguard(o, settings, tag), "wireguard")
        }

        // VLESS / VMess: server/uuid + flow or vmess security, tls, transport
        if (proto == "vless" || proto == "vmess") {
            val vnext = settings.optJSONArray("vnext")?.optJSONObject(0) ?: JSONObject()
            val user = vnext.optJSONArray("users")?.optJSONObject(0) ?: JSONObject()
            val sb = JSONObject()
            sb.put("type", proto)
            sb.put("tag", tag)
            sb.put("server", vnext.opt("address") ?: JSONObject.NULL)
            sb.put("server_port", vnext.opt("port") ?: JSONObject.NULL)
            sb.put("uuid", user.opt("id") ?: JSONObject.NULL)
            if (proto == "vless") {
                val flowRaw = user.optString("flow", "")
                val flow = normalizeFlow(flowRaw)
                if (flow.isNotEmpty()) sb.put("flow", flow)
            } else {
                sb.put("security", user.optString("security", "auto"))
                val aid = user.opt("alterId")
                sb.put("alter_id", if (aid == null || aid === JSONObject.NULL) 0 else aid)
                var gp: Any? = user.opt("global_padding")
                if (gp == null || gp === JSONObject.NULL) gp = user.opt("globalPadding")
                if (gp == null || gp === JSONObject.NULL) {
                    sb.put("global_padding", true)
                } else if (gp is Boolean) {
                    sb.put("global_padding", gp)
                } else {
                    sb.put("global_padding", gp.toString().lowercase() == "true")
                }
                var al: Any? = user.opt("authenticated_length")
                if (al == null || al === JSONObject.NULL) al = user.opt("authenticatedLength")
                if (al is Boolean && !al) sb.put("authenticated_length", false)
            }
            val pe = convPacketEncoding(o, proto)
            if (pe != null) sb.put("packet_encoding", pe)
            val tls = convTls(stream)
            if (tls != null) sb.put("tls", tls)
            val tr = convTransport(stream)
            if (tr != null) sb.put("transport", tr)
            applyProxySettings(sb, o)
            applySockopt(sb, stream)
            return OutboundResult(sb, "proxy")
        }

        // Trojan
        if (proto == "trojan") {
            val srv = settings.optJSONArray("servers")?.optJSONObject(0) ?: JSONObject()
            val sb = JSONObject()
            sb.put("type", "trojan")
            sb.put("tag", tag)
            sb.put("server", srv.opt("address") ?: JSONObject.NULL)
            sb.put("server_port", srv.opt("port") ?: JSONObject.NULL)
            sb.put("password", srv.opt("password") ?: JSONObject.NULL)
            val tls = convTls(stream)
            if (tls != null) sb.put("tls", tls)
            val tr = convTransport(stream)
            if (tr != null) sb.put("transport", tr)
            applyProxySettings(sb, o)
            applySockopt(sb, stream)
            return OutboundResult(sb, "proxy")
        }

        // Shadowsocks (+ plugin / udp-over-tcp)
        if (proto == "shadowsocks") {
            val srv = settings.optJSONArray("servers")?.optJSONObject(0) ?: JSONObject()
            val rawMethod = srv.optString("method", "aes-256-gcm").ifEmpty { "aes-256-gcm" }
            val method = SS_METHOD_ALIAS[rawMethod] ?: rawMethod
            val sb = JSONObject()
            sb.put("type", "shadowsocks")
            sb.put("tag", tag)
            sb.put("server", srv.opt("address") ?: JSONObject.NULL)
            sb.put("server_port", srv.opt("port") ?: JSONObject.NULL)
            sb.put("method", method)
            sb.put("password", srv.opt("password") ?: JSONObject.NULL)
            val plugin = srv.optString("plugin", "")
            if (plugin.isNotEmpty()) sb.put("plugin", plugin)
            var po: Any? = srv.opt("plugin_opts")
            if (po == null || po === JSONObject.NULL) po = srv.opt("pluginOpts")
            if (po != null && po !== JSONObject.NULL) {
                val ser = serializePluginOpts(po)
                if (ser.isNotEmpty()) sb.put("plugin_opts", ser)
            }
            if (srv.optBoolean("uot", false)) {
                val v = srv.opt("UoTVersion")
                val ver = when (v) {
                    null, JSONObject.NULL -> 1
                    is Number -> v.toInt()
                    is String -> v.toIntOrNull() ?: 1
                    else -> 1
                }
                val uot = JSONObject()
                uot.put("enabled", true)
                uot.put("version", ver)
                sb.put("udp_over_tcp", uot)
            }
            applyProxySettings(sb, o)
            applySockopt(sb, stream)
            return OutboundResult(sb, "proxy")
        }

        // SOCKS
        if (proto == "socks") {
            val srv = settings.optJSONArray("servers")?.optJSONObject(0) ?: JSONObject()
            val sb = JSONObject()
            sb.put("type", "socks")
            sb.put("tag", tag)
            sb.put("server", srv.opt("address") ?: JSONObject.NULL)
            sb.put("server_port", srv.opt("port") ?: JSONObject.NULL)
            val users = srv.optJSONArray("users")
            if (users != null && users.length() > 0) {
                val u0 = users.optJSONObject(0) ?: JSONObject()
                sb.put("username", u0.optString("user", ""))
                sb.put("password", u0.optString("pass", ""))
            }
            val ver = srv.opt("version")
            if (ver != null && ver !== JSONObject.NULL) {
                val v = ver.toString().replace("socks", "")
                if (v == "4" || v == "4a" || v == "5") sb.put("version", v)
            }
            if (srv.optBoolean("uot", false)) {
                val uot = JSONObject()
                uot.put("enabled", true)
                sb.put("udp_over_tcp", uot)
            }
            applyProxySettings(sb, o)
            applySockopt(sb, stream)
            return OutboundResult(sb, "proxy")
        }

        // HTTP proxy
        if (proto == "http") {
            val srv = settings.optJSONArray("servers")?.optJSONObject(0) ?: JSONObject()
            val sb = JSONObject()
            sb.put("type", "http")
            sb.put("tag", tag)
            sb.put("server", srv.opt("address") ?: JSONObject.NULL)
            sb.put("server_port", srv.opt("port") ?: JSONObject.NULL)
            val users = srv.optJSONArray("users")
            if (users != null && users.length() > 0) {
                val u0 = users.optJSONObject(0) ?: JSONObject()
                sb.put("username", u0.optString("user", ""))
                sb.put("password", u0.optString("pass", ""))
            }
            val tls = convTls(stream)
            if (tls != null) sb.put("tls", tls)
            applyProxySettings(sb, o)
            applySockopt(sb, stream)
            return OutboundResult(sb, "proxy")
        }

        return OutboundResult(null, null)
    }

    // WireGuard to a sing-box endpoint
    private fun convWireguard(o: JSONObject, settings: JSONObject, tag: String): JSONObject {
        val addressesAny = settings.opt("address")
        val addresses = JSONArray()
        when (addressesAny) {
            is JSONArray -> for (i in 0 until addressesAny.length()) {
                addressesAny.opt(i)?.let { addresses.put(it) }
            }
            is String -> if (addressesAny.isNotEmpty()) addresses.put(addressesAny)
        }
        val ep = JSONObject()
        ep.put("type", "wireguard")
        ep.put("tag", tag)
        if (addresses.length() > 0) {
            ep.put("address", addresses)
        } else {
            val fallback = JSONArray()
            fallback.put("10.0.0.2/32")
            ep.put("address", fallback)
        }
        ep.put("private_key", settings.optString("secretKey", ""))
        val mtuVal = settings.opt("mtu")
        if (isTruthy(mtuVal)) {
            val mtu = when (mtuVal) {
                is Number -> mtuVal.toInt()
                is String -> mtuVal.toIntOrNull()
                else -> null
            }
            if (mtu != null) ep.put("mtu", mtu)
        }
        val workersVal = settings.opt("workers")
        if (isTruthy(workersVal)) {
            val w = when (workersVal) {
                is Number -> workersVal.toInt()
                is String -> workersVal.toIntOrNull()
                else -> null
            }
            if (w != null) ep.put("workers", w)
        }
        val reservedVal = settings.opt("reserved")
        if (isTruthy(reservedVal)) {
            ep.put("reserved", reservedVal)
        }
        // Map each peer (endpoint, keys, allowed-ips, keepalive)
        val peers = JSONArray()
        val peerArr = settings.optJSONArray("peers")
        if (peerArr != null) {
            for (i in 0 until peerArr.length()) {
                val p = peerArr.optJSONObject(i) ?: continue
                val endpoint = p.optString("endpoint", "")
                val hp = splitHostPort(endpoint)
                val peer = JSONObject()
                peer.put("address", hp.host)
                peer.put("port", hp.port ?: 0)
                peer.put("public_key", p.optString("publicKey", ""))
                val allowed = p.optJSONArray("allowedIPs")
                if (allowed != null && allowed.length() > 0) {
                    peer.put("allowed_ips", allowed)
                } else {
                    val def = JSONArray()
                    def.put("0.0.0.0/0")
                    def.put("::/0")
                    peer.put("allowed_ips", def)
                }
                val psk = p.optString("preSharedKey", "")
                if (psk.isNotEmpty()) peer.put("pre_shared_key", psk)
                val ka = p.opt("keepAlive")
                if (isTruthy(ka)) {
                    val v = when (ka) {
                        is Number -> ka.toInt()
                        is String -> ka.toIntOrNull()
                        else -> null
                    }
                    if (v != null) peer.put("persistent_keepalive_interval", v)
                }
                val peerReserved = p.opt("reserved")
                if (isTruthy(peerReserved)) {
                    peer.put("reserved", peerReserved)
                }
                peers.put(peer)
            }
        }
        if (peers.length() > 0) ep.put("peers", peers)
        applyProxySettings(ep, o)
        applySockopt(ep, o.optJSONObject("streamSettings"))
        return ep
    }

    // Xray routing.rules to sing-box route.rules (domains/ip to rule_set, balancers, special actions)
    private fun convRouteRules(
        routing: JSONObject,
        balancerMap: Map<String, String>,
        specialRemap: Map<String, Pair<String, JSONObject?>>,
        specialTagDrop: Set<String>,
        ruleSets: MutableSet<String>
    ): List<JSONObject> {
        val out = mutableListOf<JSONObject>()
        val rules = routing.optJSONArray("rules") ?: return out
        for (i in 0 until rules.length()) {
            val r = rules.optJSONObject(i) ?: continue
            val typeField = r.optString("type", "")
            if (typeField.isNotEmpty() && typeField != "field") continue
            val sb = JSONObject()
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
            val inTags = asStringList(r.opt("inboundTag"))
            if (inTags.isNotEmpty()) sb.put("inbound", JSONArray(inTags))

            if (r.has("protocol")) {
                val protos = asStringList(r.opt("protocol"))
                sb.put("protocol", JSONArray(protos))
            }
            if (r.has("network")) {
                val netRaw = r.opt("network")
                val nets = mutableListOf<String>()
                val src = if (netRaw is String) netRaw.split(",") else asStringList(netRaw)
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
                val ipSplit = splitIps(asList(r.opt("source")))
                if (ipSplit.ipCidr.isNotEmpty()) sb.put("source_ip_cidr", JSONArray(ipSplit.ipCidr))
                if (ipSplit.ipIsPrivate) sb.put("source_ip_is_private", true)
            }
            if (r.has("domain")) {
                val d = splitDomains(asList(r.opt("domain")))
                applyDomainSplit(sb, d, ruleSets)
            }
            if (r.has("ip")) {
                val ipSplit = splitIps(asList(r.opt("ip")))
                if (ipSplit.ipCidr.isNotEmpty()) sb.put("ip_cidr", JSONArray(ipSplit.ipCidr))
                if (ipSplit.ipIsPrivate) sb.put("ip_is_private", true)
                applyGeoipToRuleSet(sb, ipSplit.geoip, ruleSets)
            }
            if (r.has("user")) {
                sb.put("auth_user", JSONArray(asStringList(r.opt("user"))))
            }
            if (r.has("process")) {
                sb.put("process_name", JSONArray(asStringList(r.opt("process"))))
            }

            out.add(sb)
        }
        return out
    }

    private data class DnsAddr(val type: String?, val fields: JSONObject)

    // Xray DNS address to a sing-box type + fields (https/h3/tls/quic/tcp/udp/dhcp/fakedns)
    private fun parseDnsAddress(addrRaw: String?): DnsAddr {
        if (addrRaw.isNullOrEmpty()) return DnsAddr(null, JSONObject())
        val s = addrRaw.trim()

        if (s == "fakedns") return DnsAddr("fakeip", JSONObject())
        if (s == "localhost") return DnsAddr("local", JSONObject())

        if (s.startsWith("rcode://")) return DnsAddr(null, JSONObject())

        // scheme:// form -> https / h3 / tls / quic / tcp / udp / dhcp
        if (s.contains("://")) {
            val schemeRaw = s.substringBefore("://")
            val rest = s.substringAfter("://")
            val scheme = schemeRaw.lowercase().replace("+local", "").replace("+udp", "")
            if (scheme == "https") {
                val slashIdx = rest.indexOf("/")
                val hostPort = if (slashIdx < 0) rest else rest.substring(0, slashIdx)
                val path = if (slashIdx < 0) "" else rest.substring(slashIdx + 1)
                val hp = splitHostPort(hostPort)
                val f = JSONObject()
                f.put("server", hp.host)
                if (hp.port != null) f.put("server_port", hp.port)
                if (path.isNotEmpty()) f.put("path", "/$path")
                return DnsAddr("https", f)
            }
            if (scheme in setOf("h3", "https+h3", "https3", "http3")) {
                val slashIdx = rest.indexOf("/")
                val hostPort = if (slashIdx < 0) rest else rest.substring(0, slashIdx)
                val path = if (slashIdx < 0) "" else rest.substring(slashIdx + 1)
                val hp = splitHostPort(hostPort)
                val f = JSONObject()
                f.put("server", hp.host)
                if (hp.port != null) f.put("server_port", hp.port)
                if (path.isNotEmpty()) f.put("path", "/$path")
                return DnsAddr("http3", f)
            }
            if (scheme in setOf("tls", "quic", "tcp", "udp")) {
                val hp = splitHostPort(rest)
                val f = JSONObject()
                f.put("server", hp.host)
                if (hp.port != null) f.put("server_port", hp.port)
                return DnsAddr(scheme, f)
            }
            if (scheme == "dhcp") {
                val f = JSONObject()
                if (rest.isNotEmpty() && rest != "auto") f.put("interface", rest)
                return DnsAddr("dhcp", f)
            }
            return DnsAddr(null, JSONObject())
        }

        // Bare host[:port] -> udp
        val hp = splitHostPort(s)
        val f = JSONObject()
        f.put("server", hp.host)
        if (hp.port != null) f.put("server_port", hp.port)
        return DnsAddr("udp", f)
    }

    private fun makeDnsRule(obj: JSONObject, serverTag: String, ruleSets: MutableSet<String>): JSONObject? {
        val domains = asList(obj.opt("domains"))
        if (domains.isEmpty()) return null
        val rule = JSONObject()
        rule.put("server", serverTag)
        val ds = splitDomains(domains)
        applyDomainSplit(rule, ds, ruleSets)
        return rule
    }

    private fun fakeipRanges(fakednsObj: Any?): Pair<String, String> {
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

    // Xray dns to sing-box dns (servers, rules, hosts, fakeip, final)
    private fun convDns(xrayDns: JSONObject?, fakednsObj: Any?, dnsDetour: String?, ruleSets: MutableSet<String>): JSONObject {
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
                if (isTruthy(v)) {
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
                srv.put("strategy", QUERY_STRATEGY_MAP[sqs])
            }
            val sci = obj.optString("clientIP", "")
            if (sci.isNotEmpty()) srv.put("client_subnet", sci)

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

            val rule = makeDnsRule(obj, tag, ruleSets)
            if (rule != null) {
                if (st == "fakeip" && !rule.has("query_type")) {
                    rule.put("query_type", JSONArray().put("A").put("AAAA"))
                }
                outRules.put(rule)
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
                val ipsOnly = ipsList.filter { isIpLiteral(it) }.map { it as String }
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
        if (finalTag == null && finalServersArr.length() > 0) {
            finalTag = finalServersArr.optJSONObject(0)?.optString("tag", "")
        }
        if (!finalTag.isNullOrEmpty()) out.put("final", finalTag)

        return out
    }

    // Make the tag unique: base, "base (2)", "base (3)", and so on
    private fun makeUniqueTag(base: String, used: MutableSet<String>): String {
        if (base !in used) return base
        var i = 2
        while ("$base ($i)" in used) i++
        return "$base ($i)"
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

    // Main assembly: inbounds + outbounds + selector/urltest + route + dns + experimental
    private fun convertObject(xray: JSONObject, nameFallback: String): JSONObject? {
        val inbounds = mutableListOf<JSONObject>()
        val usedInbTags = mutableSetOf<String>()
        val resolveInbounds = mutableListOf<String>()

        // Convert inbounds (collecting sniff-resolve tags)
        val xrayInbounds = xray.optJSONArray("inbounds")
        if (xrayInbounds != null) {
            for (i in 0 until xrayInbounds.length()) {
                val inb = xrayInbounds.optJSONObject(i) ?: continue
                val result = convInbound(inb)
                val sbInb = result.sb ?: continue
                val base = sbInb.optString("tag", "").ifEmpty { sbInb.optString("type", "in") }
                val tag = makeUniqueTag(base, usedInbTags)
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
                if (o.optString("protocol", "") in XRAY_PROTOCOLS_PROXY && isOutboundSupported(o)) {
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
                val proto = o.optString("protocol", "")
                when (proto) {
                    "blackhole" -> {
                        specialRemap[otag] = "reject" to null
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
                if (proto in XRAY_PROTOCOLS_PROXY && !isOutboundSupported(o)) {
                    specialTagDrop.add(otag)
                    continue
                }
                val r = convOutbound(o)
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

        if (proxyOuts.isEmpty() && endpoints.isEmpty()) return null

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
        while (selectorTag in existingTags) selectorTag += " ⊙"

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
        val routeRules = convRouteRules(routing, balancerMap, specialRemap, specialTagDrop, requiredRuleSets).toMutableList()
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
            if (!qs.isNullOrEmpty() && QUERY_STRATEGY_MAP.containsKey(qs)) {
                ddr.put("strategy", QUERY_STRATEGY_MAP[qs])
            }
        }
        route.put("default_domain_resolver", ddr)

        // Convert DNS and attach the remote geosite/geoip rule-sets
        var fakednsObj: Any? = xray.opt("fakedns")
        if (fakednsObj == null || fakednsObj === JSONObject.NULL) {
            fakednsObj = xray.optJSONObject("dns")?.opt("fakedns")
        }
        val sbDns = convDns(xray.optJSONObject("dns"), fakednsObj, dnsDetour, requiredRuleSets)

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
        return config
    }
}
