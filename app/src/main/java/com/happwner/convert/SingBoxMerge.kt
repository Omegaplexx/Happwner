package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// Folds several converted sing-box configs into one runnable config: a selector over a url-test
// group, tags deduplicated, one inbound added.
internal object SingBoxMerge {
    // Merge several sing-box configs into one: rename tags, shared selector/urltest
    internal fun mergeUnified(fullConfigs: List<JSONObject>): JSONObject? {
        if (fullConfigs.isEmpty()) return null
        if (fullConfigs.size == 1) {
            val single = SingBoxUtil.deepCopyObj(fullConfigs[0])
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
                    val newTag = SingBoxUtil.makeUniqueTag(origTag, usedOutTags)
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
                    val newTag = SingBoxUtil.makeUniqueTag(origTag, usedOutTags)
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
                        val newTag = SingBoxUtil.makeUniqueTag(origTag, usedDnsTags)
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
                    val obCopy = SingBoxUtil.deepCopyObj(o)
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
                    val obCopy = SingBoxUtil.deepCopyObj(o)
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
                        val sCopy = SingBoxUtil.deepCopyObj(s)
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
                        val rCopy = SingBoxUtil.deepCopyObj(r)
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
                        val rCopy = SingBoxUtil.deepCopyObj(r)
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
                        mergedRuleSet.add(SingBoxUtil.deepCopyObj(rs))
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
        if (firstLog != null) merged.put("log", SingBoxUtil.deepCopyObj(firstLog))

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
            merged.put("inbounds", SingBoxUtil.deepCopyArr(firstInbounds))
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
            val expCopy = SingBoxUtil.deepCopyObj(firstExp)
            stripForkOnlyFields(expCopy)
            merged.put("experimental", expCopy)
        }

        return merged
    }

    // Strip fields that only sing-box forks understand
    internal fun stripForkOnlyFields(cfg: JSONObject) {
        val exp = cfg.optJSONObject("experimental") ?: return
        val cf = exp.optJSONObject("cache_file") ?: return
        cf.remove("store_dns")
    }

    // Built-in pre-rules (sniff/hijack-dns/resolve): we add our own and skip duplicates
    internal fun isPreRule(r: JSONObject): Boolean {
        val action = r.optString("action", "")
        if (action == "sniff" && r.length() == 1) return true
        if (action == "hijack-dns" && (r.has("protocol") || r.has("port"))) return true
        if (action == "resolve" && r.has("inbound")) return true
        return false
    }

    internal fun renameString(obj: JSONObject, key: String, rename: Map<String, String>) {
        val v = obj.opt(key)
        if (v !is String || v.isEmpty()) return
        val mapped = rename[v] ?: return
        if (mapped != v) obj.put(key, mapped)
    }

    internal fun renameStringArray(obj: JSONObject, key: String, rename: Map<String, String>) {
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

    internal fun rewriteOutbound(o: JSONObject, outRename: Map<String, String>, dnsRename: Map<String, String>) {
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

    internal fun rewriteDnsServer(s: JSONObject, outRename: Map<String, String>, dnsRename: Map<String, String>) {
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

    internal fun rewriteDnsRule(r: JSONObject, outRename: Map<String, String>, dnsRename: Map<String, String>) {
        renameString(r, "server", dnsRename)
        renameString(r, "outbound", outRename)
    }

    internal fun rewriteRouteRule(r: JSONObject, outRename: Map<String, String>, dnsRename: Map<String, String>) {
        renameString(r, "outbound", outRename)
        renameString(r, "server", dnsRename)
    }
}
