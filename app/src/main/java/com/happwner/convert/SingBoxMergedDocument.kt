package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// One merge of several sing-box documents, each assembled by SingBoxDocument and so holding every
// block it always writes: tags are planned first, each document's outbounds, endpoints, DNS and route
// copied in under them, then the shared selector and urltest built over every leaf and assembled.
internal class SingBoxMergedDocument(private val fullConfigs: List<JSONObject>,
	private val notes: MutableList<String>) {
	// Each configuration is written as though it were the only one; these two remember what has
	// already been said about that - the closing rules once for all of them, each conflict once.
	private var catchAllSaid = false
	private val conflictsReported = mutableSetOf<String>()
	private val usedOutTags = mutableSetOf("proxy", "auto", "direct", "mixed-in")
	private val usedDnsTags = mutableSetOf("local")
	private val usedRuleSetTags = mutableSetOf<String>()
	private val outRenames = mutableListOf<MutableMap<String, String>>()
	private val dnsRenames = mutableListOf<MutableMap<String, String>>()
	private val leafOutbounds = mutableListOf<JSONObject>()
	private val leafOutboundTags = mutableListOf<String>()
	private val mergedEndpoints = mutableListOf<JSONObject>()
	private val mergedEndpointTags = mutableListOf<String>()
	private val mergedDnsServers = mutableListOf<JSONObject>()
	// The same resolver written in several configurations is one resolver: its first copy is kept
	// and every later configuration's tag for it points at that copy.
	private val dnsServerByContent = HashMap<String, String>()
	private val mergedDnsRules = mutableListOf<JSONObject>()
	private val mergedRouteRules = mutableListOf<JSONObject>()
	private val mergedRuleSet = mutableListOf<JSONObject>()
	private var hasLocal = false
	private var hasDirect = false

	fun build(): JSONObject? {
		for (cfg in fullConfigs) planTags(cfg)
		for ((idx, cfg) in fullConfigs.withIndex()) {
			val outR = outRenames[idx]
			val dnsR = dnsRenames[idx]
			copyOutbounds(cfg, outR, dnsR)
			copyEndpoints(cfg, outR, dnsR)
			copyDns(cfg, outR, dnsR)
			copyRoute(cfg, idx, outR, dnsR)
		}
		val allLeafTags = leafOutboundTags + mergedEndpointTags
		if (allLeafTags.isEmpty()) return null
		return assemble(allLeafTags)
	}

	// Pass 1: the tag every proxy, endpoint and resolver will carry, unique across the document.
	private fun planTags(cfg: JSONObject) {
		val outRename = mutableMapOf<String, String>()
		val dnsRename = mutableMapOf<String, String>()

		val outbounds = cfg.getJSONArray("outbounds")
		for (i in 0 until outbounds.length()) {
			val outbound = outbounds.getJSONObject(i)
			val origTag = outbound.optString("tag", "")
			val type = outbound.optString("type", "")
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
		val endpoints = cfg.optJSONArray("endpoints")
		if (endpoints != null) {
			for (i in 0 until endpoints.length()) {
				val endpoint = endpoints.getJSONObject(i)
				val origTag = endpoint.optString("tag", "")
				if (origTag.isEmpty()) continue
				val newTag = SingBoxUtil.makeUniqueTag(origTag, usedOutTags)
				usedOutTags.add(newTag)
				outRename[origTag] = newTag
			}
		}
		val dnsServers = cfg.getJSONObject("dns").getJSONArray("servers")
		for (i in 0 until dnsServers.length()) {
			val server = dnsServers.getJSONObject(i)
			val origTag = server.optString("tag", "")
			if (origTag == "local" && server.optString("type") == "local") {
				dnsRename[origTag] = "local"
				continue
			}
			val newTag = SingBoxUtil.makeUniqueTag(origTag, usedDnsTags)
			usedDnsTags.add(newTag)
			dnsRename[origTag] = newTag
		}
		outRenames.add(outRename)
		dnsRenames.add(dnsRename)
	}

	private fun copyOutbounds(cfg: JSONObject, outR: Map<String, String>, dnsR: Map<String, String>) {
		val obs = cfg.getJSONArray("outbounds")
		for (i in 0 until obs.length()) {
			val outbound = obs.getJSONObject(i)
			val type = outbound.optString("type", "")
			if (type == "selector" || type == "urltest") continue
			val obCopy = jsonCopy(outbound)
			SingBoxMerge.rewriteOutbound(obCopy, outR, dnsR)
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

	private fun copyEndpoints(cfg: JSONObject, outR: Map<String, String>, dnsR: Map<String, String>) {
		val endpoints = cfg.optJSONArray("endpoints")
		if (endpoints != null) {
			for (i in 0 until endpoints.length()) {
				val endpoint = endpoints.getJSONObject(i)
				val obCopy = jsonCopy(endpoint)
				SingBoxMerge.rewriteOutbound(obCopy, outR, dnsR)
				mergedEndpoints.add(obCopy)
				mergedEndpointTags.add(obCopy.optString("tag"))
			}
		}
	}

	private fun copyDns(cfg: JSONObject, outR: Map<String, String>, dnsR: MutableMap<String, String>) {
		val dns = cfg.getJSONObject("dns")
		val servers = dns.getJSONArray("servers")
		for (i in 0 until servers.length()) {
			val server = servers.getJSONObject(i)
			val sCopy = jsonCopy(server)
			SingBoxMerge.rewriteDnsServer(sCopy, outR, dnsR)
			// Alone, a configuration sends its DNS through its proxy; merged, "its proxy"
			// is whichever the person selects - the "proxy" selector built below. It also
			// makes one server of the same resolver written by every configuration.
			val detour = sCopy.optString("detour", "")
			if (detour.isNotEmpty() && detour != "direct") sCopy.put("detour", "proxy")
			if (sCopy.optString("type") == "local" && sCopy.optString("tag") == "local") {
				if (hasLocal) continue
				hasLocal = true
			}
			val content = SingBoxMerge.dnsServerContent(sCopy)
			val kept = dnsServerByContent[content]
			if (kept != null) {
				// Point this configuration's name for the resolver at the copy kept.
				dnsR[server.optString("tag", "")] = kept
				continue
			}
			dnsServerByContent[content] = sCopy.optString("tag", "")
			mergedDnsServers.add(sCopy)
		}
		val drules = dns.getJSONArray("rules")
		for (i in 0 until drules.length()) {
			val rule = drules.getJSONObject(i)
			val rCopy = jsonCopy(rule)
			SingBoxMerge.rewriteDnsRule(rCopy, outR, dnsR)
			// The same DNS rule from several configurations is read once; the first is
			// the one that decides, as with the route rules.
			if (mergedDnsRules.none { SingBoxMerge.sameRule(it, rCopy) }) mergedDnsRules.add(rCopy)
		}
	}

	private fun copyRoute(cfg: JSONObject, idx: Int, outR: Map<String, String>, dnsR: Map<String, String>) {
		val route = cfg.getJSONObject("route")
		val rules = route.getJSONArray("rules")
		for (i in 0 until rules.length()) {
			val rule = rules.getJSONObject(i)
			if (idx > 0 && SingBoxMerge.isPreRule(rule)) continue
			val rCopy = jsonCopy(rule)
			SingBoxMerge.rewriteRouteRule(rCopy, outR, dnsR)
			// A configuration's closing rule - "everything else through me" - holds for it
			// alone. Among several it would pin every connection to the first one's servers
			// and leave every rule under it unreachable; route.final decides here.
			if (SingBoxMerge.reachesEverything(rCopy)) {
				if (!catchAllSaid) {
					catchAllSaid = true
					notes.add(
						"each configuration's rule for everything else was dropped, so that " +
							"the selected outbound decides where that traffic goes"
					)
				}
				continue
			}
			// The same rule in several configurations decides the same traffic the same way,
			// and the first is the one the core reads. One that decides differently can never
			// be read, and saying so is how somebody learns their configurations disagree.
			val earlier = mergedRouteRules.firstOrNull { SingBoxMerge.sameCondition(it, rCopy) }
			if (earlier != null) {
				if (!SingBoxMerge.sameRule(earlier, rCopy) &&
					conflictsReported.add(SingBoxMerge.conditionOf(rCopy).toString())
				) {
					val first = SingBoxMerge.decisionOf(earlier)
					val other = SingBoxMerge.decisionOf(rCopy)
					notes.add(
						"two configurations route the same traffic to different " +
							"places (\"$first\" and \"$other\"); the first one decides " +
							"and the other was dropped"
					)
				}
				continue
			}
			mergedRouteRules.add(rCopy)
		}
		val ruleSet = route.optJSONArray("rule_set")
		if (ruleSet != null) {
			for (i in 0 until ruleSet.length()) {
				val ruleSetEntry = ruleSet.getJSONObject(i)
				val tag = ruleSetEntry.optString("tag", "")
				if (tag.isEmpty() || tag in usedRuleSetTags) continue
				usedRuleSetTags.add(tag)
				val rsCopy = jsonCopy(ruleSetEntry)
				// Each configuration fetched its rule sets through its own proxy; merged,
				// that is whichever the person selects.
				if (rsCopy.optString("download_detour", "").let { it.isNotEmpty() && it != "direct" }) {
					rsCopy.put("download_detour", "proxy")
				}
				mergedRuleSet.add(rsCopy)
			}
		}
	}

	// The shared selector and urltest over every leaf, and the document around them.
	private fun assemble(allLeafTags: List<String>): JSONObject {
		// A configuration's direct is gone when it dialed through something that produced nothing,
		// while the selector below still names direct - so one is added when none was kept.
		if (!hasDirect) {
			leafOutbounds.add(SingBoxUtil.directOutbound())
		}

		val selector = JSONObject()
		selector.put("type", "selector")
		selector.put("tag", "proxy")
		val selectorOuts = JSONArray()
		selectorOuts.put("auto")
		for (tag in allLeafTags) selectorOuts.put(tag)
		selectorOuts.put("direct")
		selector.put("outbounds", selectorOuts)
		selector.put("default", "auto")

		val urltest = JSONObject()
		urltest.put("type", "urltest")
		urltest.put("tag", "auto")
		val urltestOuts = JSONArray()
		for (tag in allLeafTags) urltestOuts.put(tag)
		urltest.put("outbounds", urltestOuts)
		urltest.put("url", "https://www.gstatic.com/generate_204")
		urltest.put("interval", "5m")
		// Assemble the merged config (log/dns/inbounds/outbounds/route/experimental)
		val merged = JSONObject()
		merged.put("log", jsonCopy(fullConfigs[0].getJSONObject("log")))

		val dnsObj = JSONObject()
		dnsObj.put("servers", JSONArray(mergedDnsServers))
		if (mergedDnsRules.isNotEmpty()) dnsObj.put("rules", JSONArray(mergedDnsRules))
		val firstDns = fullConfigs[0].getJSONObject("dns")
		val clientSubnet = firstDns.optString("client_subnet", "")
		if (clientSubnet.isNotEmpty()) dnsObj.put("client_subnet", clientSubnet)
		val dnsFinal = firstDns.optString("final", "")
		if (dnsFinal.isNotEmpty()) {
			val mapped = dnsRenames[0][dnsFinal] ?: dnsFinal
			dnsObj.put("final", mapped)
		}
		merged.put("dns", dnsObj)

		val firstInbounds = fullConfigs[0].getJSONArray("inbounds")
		if (firstInbounds.length() > 0) {
			merged.put("inbounds", jsonCopy(firstInbounds))
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
		for (outbound in leafOutbounds) outArr.put(outbound)
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

		merged.put("experimental", jsonCopy(fullConfigs[0].getJSONObject("experimental")))
		SingBoxUtil.dropEmptyDirectDetours(merged)
		return merged
	}
}
