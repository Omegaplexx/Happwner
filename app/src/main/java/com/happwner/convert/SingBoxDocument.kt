package com.happwner.convert

import java.util.Collections
import java.util.IdentityHashMap
import org.json.JSONArray
import org.json.JSONObject

// One conversion of an Xray configuration into a sing-box document, section by section in the
// order the sections depend on each other: inbounds, names, outbounds, chains, balancers, the
// selector, the outbound list, the route, DNS, and the document itself.
internal class SingBoxConversion(private val xray: JSONObject, nameFallback: String) {
	private val notes = mutableListOf<String>()
	private val inbounds = mutableListOf<JSONObject>()
	private val resolveInbounds = mutableListOf<String>()
	// Whether any inbound of the source asked to sniff. Xray does not sniff unless told to, and a
	// document that sniffs anyway lets domain rules match traffic Xray would have routed by address.
	private var anyInboundSniffs = false
	// Every spelling a generator writes a name in, read the same way the other two passes read
	// it, so a configuration named under any of them is named here too.
	private val remarks = configLabel(xray).ifEmpty { nameFallback.trim() }
	private val outsRaw = xray.optJSONArray("outbounds")
	private val xrayProxies = mutableListOf<JSONObject>()
	private val rename = mutableMapOf<String, String>()
	private val proxyOuts = mutableListOf<JSONObject>()
	private val proxyTags = mutableListOf<String>()
	private val auxOuts = mutableListOf<JSONObject>()
	private val endpoints = mutableListOf<JSONObject>()
	// Every proxy and endpoint tag given out, so no two nodes share one: sing-box takes no two
	// outbounds of one tag, and the second would otherwise be lost without a word.
	private val tagNames = UniqueNames()
	private val specialRemap = mutableMapOf<String, String>()
	private val specialTagDrop = mutableSetOf<String>()
	private val routing = xray.optJSONObject("routing") ?: JSONObject()
	private val probe = xrayProbe(xray)
	private val testUrl = probe.url
	private val testInterval = probe.intervalSeconds?.let { "${it}s" } ?: ""
	private val balancerOuts = mutableListOf<JSONObject>()
	private val balancerMap = mutableMapOf<String, String>()
	private var primaryBalancer: String? = null
	private var selectorTag = if (remarks.isNotEmpty()) remarks else "select"
	private var selector: JSONObject? = null
	private var sbOutbounds = mutableListOf<JSONObject>()
	private var endpointsDedup: List<JSONObject> = emptyList()
	private var finalTag = ""
	private val requiredRuleSets = mutableSetOf<String>()
	private var ruleSetDownloadDetour = ""
	private var dnsDetour: String? = null
	private var routeRules = mutableListOf<JSONObject>()
	// Which Xray rule each converted one came from, so a rule dropped later is named by it.
	private val ruleOrigins = IdentityHashMap<JSONObject, Int>()

	// Which Xray outbound each converted one came from, so a node dropped later is named by it.
	private val outboundOrigins = IdentityHashMap<JSONObject, String>()
	// The fragment settings of each freedom outbound by its tag, for the nodes that dial through one.
	private val freedomFragments = mutableMapOf<String, JSONObject>()
	private val route = JSONObject()

	fun run(): SingBoxConverter.ConvertedDocument {
		readInbounds()
		planNames()
		convertOutbounds()
		if (proxyOuts.isEmpty() && endpoints.isEmpty()) return nothingToConvert()
		ensureDirect()
		resolveChains()
		// Chains can take the last node with them, and then there is nothing to convert after all.
		if (proxyOuts.isEmpty() && endpoints.isEmpty()) return nothingToConvert()
		buildBalancers()
		buildSelector()
		assembleOutbounds()
		buildRoute()
		val sbDns = buildDnsAndRuleSets()
		return assembleDocument(sbDns)
	}

	private fun readInbounds() {
		val usedInbTags = mutableSetOf<String>()
		val xrayInbounds = xray.optJSONArray("inbounds")
		if (xrayInbounds != null) {
			for (i in 0 until xrayInbounds.length()) {
				val inb = xrayInbounds.optJSONObject(i) ?: continue
				val inboundNotes = mutableListOf<String>()
				val result = SingBoxRouting.buildInbound(inb, inboundNotes)
				inboundNotes.mapTo(notes) { "inbounds[$i]: $it" }
				if (result.inbound == null) {
					result.refusal?.let { notes.add("inbounds[$i]: $it") }
					continue
				}
				val sbInb = result.inbound
				val base = sbInb.optString("tag", "").ifEmpty { sbInb.optString("type", "in") }
				val tag = SingBoxUtil.makeUniqueTag(base, usedInbTags)
				sbInb.put("tag", tag)
				usedInbTags.add(tag)
				inbounds.add(sbInb)
				if (result.sniffResolves) resolveInbounds.add(tag)
				if (result.sniffEnabled) anyInboundSniffs = true
			}
		}
	}

	private fun planNames() {
		// The proxy outbounds sing-box carries: those renamed from remarks, and those balancers select -
		// each read as convertOutbounds reads it, server by server.
		if (outsRaw != null) {
			for (i in 0 until outsRaw.length()) {
				val outbound = outsRaw.optJSONObject(i) ?: continue
				if (outbound.xrayProtocol() in SingBoxProtocols.XRAY_PROTOCOLS_PROXY &&
					expandOutboundEndpoints(outbound).any { SingBoxProtocols.isOutboundSupported(it) }
				) {
					xrayProxies.add(outbound)
				}
			}
		}

		// Plan tag renames from remarks
		if (remarks.isNotEmpty()) {
			// Named by what the file holds, as the other passes name it: a node whose neighbour
			// sing-box cannot carry is still one of several.
			if (proxyOutboundCount(outsRaw) == 1 && xrayProxies.size == 1) {
				val onlyTag = xrayProxies[0].optString("tag", "").trim()
				rename[onlyTag] = remarks
			} else if (xrayProxies.isNotEmpty()) {
				for (proxy in xrayProxies) {
					val origTag = proxy.optString("tag", "").trim()
					val newTag = if (origTag.isEmpty()) remarks else "$remarks #$origTag"
					rename[origTag] = newTag
				}
			}
		}
	}

	private fun convertOutbounds() {
		// Convert every outbound: proxy / endpoint / aux, mapping the special tags
		if (outsRaw != null) {
			// Tags a rule can name come first, so a node named by what it is never takes one of them;
			// a tag written twice gives its second node a name of its own.
			val claimed = HashMap<Int, String>()
			for (i in 0 until outsRaw.length()) {
				val outbound = outsRaw.optJSONObject(i) ?: continue
				val tag = outbound.optString("tag", "")
				if (tag.isNotEmpty() && outbound.xrayProtocol() in SingBoxProtocols.XRAY_PROTOCOLS_PROXY) {
					claimed[i] = tagNames.take(rename[tag] ?: tag)
				}
			}
			for (i in 0 until outsRaw.length()) {
				val outbound = outsRaw.optJSONObject(i) ?: continue
				val otag = outbound.optString("tag", "")
				val proto = outbound.xrayProtocol()
				if (proto == "freedom") {
					outbound.xObj("settings").xObj("fragment")?.let { freedomFragments[otag] = it }
				}
				when (proto) {
					"blackhole" -> {
						specialRemap[otag] = "reject"
						// The rule action closes the connection; blackhole can also answer with a
						// canned HTTP reply, and that part has nowhere to go.
						SingBoxProtocols.blackholeResponseNote(outbound, i)?.let { notes.add(it) }
						continue
					}
					"dns" -> {
						specialRemap[otag] = "hijack-dns"
						dnsOutboundSettingsNote(outbound)?.let { notes.add("outbounds[$i] (dns): $it") }
						continue
					}
					"loopback" -> {
						specialTagDrop.add(otag)
						continue
					}
				}
				// An outbound naming several servers spreads over them in Xray. Each server becomes an
				// outbound and, when there is more than one, a urltest group under the original tag stands
				// for the whole, so a rule or balancer naming that tag still reaches every server.
				val expanded = expandOutboundEndpoints(outbound)
				ignoredServerListNote(outbound)?.let {
					notes.add("outbounds[$i] (${proto.ifEmpty { "no protocol" }}): $it")
				}
				// Asked of every outbound reaching here, so that a hysteria2 or tuic node is refused with a
				// reason rather than dropped without a word - and of each server, so one server's flaw
				// neither takes down the rest nor slips through behind a sound first one.
				val reasons = expanded.map { SingBoxProtocols.unsupportedReason(it) }
				if (reasons.all { it != null }) {
					specialTagDrop.add(otag)
					val label = proto.ifEmpty { "no protocol" }
					notes.add("skipped: outbounds[$i] ($label): ${reasons.first()}")
					continue
				}
				val own = claimed[i]
				val memberTags = mutableListOf<String>()
				for ((one, reason) in expanded.zip(reasons)) {
					if (reason != null) {
						notes.add("skipped: outbounds[$i] ($proto): $reason")
						continue
					}
					// "local" is the DNS server buildDns always emits, so an outbound may point
					// domain_resolver at it.
					val result = SingBoxProtocols.buildOutbound(one, SingBoxConverter.LOCAL_DNS_TAG)
					// A node left out gives its reason last, which reads as the skip it is.
					for ((k, note) in result.notes.withIndex()) {
						val skip = result.outbound == null && k == result.notes.lastIndex
						notes.add("${if (skip) "skipped: " else ""}outbounds[$i] ($proto): $note")
					}
					val converted = result.outbound ?: continue
					outboundOrigins[converted] = "outbounds[$i] ($proto)"
					if (result.kind == "aux") {
						val cTag = converted.optString("tag", "")
						converted.put("tag", rename[cTag] ?: cTag)
						auxOuts.add(converted)
						continue
					}
					// The members of a split outbound are told apart by their server; the original
					// tag is kept for the group that stands for all of them.
					val newTag = when {
						own == null -> tagNames.take(unnamed(proto, converted))
						expanded.size == 1 -> own
						else -> {
							val host = converted.optString("server", "")
							tagNames.take("$own $host:${converted.optInt("server_port")}")
						}
					}
					converted.put("tag", newTag)
					if (result.kind == "wireguard") endpoints.add(converted) else proxyOuts.add(converted)
					memberTags.add(newTag)
				}
				// A node with no tag of its own stands alone: no rule can name it, so it needs no group.
				if (own != null && memberTags.size > 1) {
					val group = JSONObject()
					group.put("type", "urltest")
					group.put("tag", own)
					group.put("outbounds", JSONArray(memberTags))
					proxyOuts.add(group)
					proxyTags.add(own)
				} else {
					proxyTags.addAll(memberTags)
				}
			}
		}
	}

	// What a node with no tag of its own is called: the configuration's name for its untagged nodes,
	// else what it is - an endpoint by its first peer - as the other passes name it.
	private fun unnamed(proto: String, node: JSONObject): String {
		rename[""]?.let { return it }
		val peer = node.optJSONArray("peers")?.optJSONObject(0)
		return if (peer != null) addressName(proto, peer.optString("address", ""), peer.optInt("port"))
		else addressName(proto, node.optString("server", ""), node.optInt("server_port"))
	}

	// A configuration of nothing but freedom/blackhole/dns has no proxy to convert; the reasons go
	// back so convert() can attach them to Unsupported.
	private fun nothingToConvert(): SingBoxConverter.ConvertedDocument {
		if (notes.isEmpty()) notes.add("no proxy outbound in this configuration; there was nothing to " +
			"convert")
		return SingBoxConverter.ConvertedDocument(JSONObject(), notes)
	}

	private fun ensureDirect() {
		val hasDirect = auxOuts.any { it.optString("type", "") == "direct" && it.optString("tag",
			"") == "direct" }
		if (!hasDirect) {
			auxOuts.add(SingBoxUtil.directOutbound())
		}
	}

	private fun resolveChains() {
		// A detour names the outbound this one dials through: through freedom the direct it became or what
		// it dials through, through a proxy that proxy's name. Any other target (blackhole: Xray never
		// connects) produced no outbound and takes the node with it - sing-box refuses a dangling detour.
		val detours = IdentityHashMap<JSONObject, String>()
		for (outbound in (proxyOuts + endpoints + auxOuts)) {
			outbound.optString("detour", "").takeIf { it.isNotEmpty() }?.let { detours[outbound] = it }
		}
		val written = (proxyOuts + endpoints + auxOuts).map { it.optString("tag", "") }.toSet()
		// One left out leaves out whatever dials through it too, so this runs until nothing more falls.
		// A circle of detours goes too: Xray never connects one, and sing-box will not start with it.
		while (true) {
			val byTag = (proxyOuts + endpoints + auxOuts).associateBy { it.optString("tag", "") }
			val fallen = (proxyOuts + endpoints + auxOuts).filter { outbound ->
				detours[outbound]?.let { (rename[it] ?: it) !in byTag } == true
			}
			val circling = if (fallen.isNotEmpty()) emptyList()
			else byTag.values.filter { leadsBackTo(it, detours, byTag) }
			if (fallen.isEmpty() && circling.isEmpty()) break
			for (outbound in circling) {
				val place = outboundOrigins[outbound] ?: "\"${outbound.optString("tag", "")}\""
				val detour = detours[outbound]
				notes.add("skipped: $place: dials through \"$detour\", which leads back to it in a circle")
				proxyOuts.remove(outbound); endpoints.remove(outbound); auxOuts.remove(outbound)
				proxyTags.remove(outbound.optString("tag", ""))
			}
			for (outbound in fallen) {
				val detour = detours.getValue(outbound)
				val place = outboundOrigins[outbound] ?: "\"${outbound.optString("tag", "")}\""
				val target = rename[detour] ?: detour
				val why = if (target in written) "was left out itself" else "produced no outbound here"
				notes.add("skipped: $place: dials through \"$detour\", which $why")
				proxyOuts.remove(outbound); endpoints.remove(outbound); auxOuts.remove(outbound)
				proxyTags.remove(outbound.optString("tag", ""))
			}
		}
		// A freedom dialing through another outbound sends through it whatever goes to it, so that outbound
		// takes the freedom's traffic here: sing-box refuses the whole document over a direct with a detour.
		val chainedDirects = auxOuts.filter { it.optString("type") == "direct" && it in detours }
		val aliases = chainedDirects.associate { it.optString("tag", "") to detours.getValue(it) }
		for (direct in chainedDirects) {
			val tag = direct.optString("tag", "")
			var target = tag
			val seen = HashSet<String>()
			while (seen.add(target)) target = aliases[target]?.let { rename[it] ?: it } ?: break
			rename[tag] = target
			auxOuts.remove(direct)
			detours.remove(direct)
			val place = outboundOrigins[direct] ?: "\"$tag\""
			val strategy = if (direct.has("domain_resolver")) ", without the freedom's domainStrategy" else ""
			notes.add(
				"$place: dials through \"${aliases.getValue(tag)}\", and a sing-box direct outbound dials " +
					"through nothing, so \"$target\" takes what goes to it$strategy"
			)
		}
		// In the order the outbounds stand, so the notes come out alike on every run.
		for (outbound in (proxyOuts + endpoints + auxOuts).filter { detours.containsKey(it) }) {
			val detour = detours.getValue(outbound)
			val fragment = freedomFragments[detour]
			val split = fragment != null && !SingBoxStream.sendsOverUdp(outbound)
			if (split && proxyOuts.any { it === outbound }) {
				val place = outboundOrigins[outbound] ?: "\"${outbound.optString("tag", "")}\""
				val through = "$place: dials through freedom \"$detour\""
				notes.add(
					if (SingBoxStream.applyTlsFragment(outbound, fragment)) {
						"$through with its fragment: ${SingBoxStream.TLS_FRAGMENT_NOTE}"
					} else {
						"$through without its fragment, which sing-box does only to the Client Hello - the " +
							"first packet - of its own TLS naming a server, not REALITY's"
					}
				)
			}
			outbound.put("detour", rename[detour] ?: detour)
		}
	}

	// Whether following detours from this outbound comes back to it.
	private fun leadsBackTo(
		start: JSONObject, detours: Map<JSONObject, String>, byTag: Map<String, JSONObject>
	): Boolean {
		val seen = Collections.newSetFromMap(IdentityHashMap<JSONObject, Boolean>())
		var current = start
		while (true) {
			val detour = detours[current] ?: return false
			val next = byTag[rename[detour] ?: detour] ?: return false
			if (next === start) return true
			if (!seen.add(next)) return false
			current = next
		}
	}

	private fun buildBalancers() {
		// Build Xray balancers into urltest outbounds
		val balancers = routing.optJSONArray("balancers")
		if (balancers != null) {
			for (i in 0 until balancers.length()) {
				val balancer = balancers.optJSONObject(i) ?: continue
				val btag = balancer.optString("tag", "")
				if (btag.isEmpty()) continue
				// Named where the mihomo pass names it, so one balancer reads the same in both.
				val at = "routing.balancers[$i] ($btag): the balancer"
				val prefixesArr = balancer.optJSONArray("selector")
				val prefixes = mutableListOf<String>()
				if (prefixesArr != null) {
					for (j in 0 until prefixesArr.length()) {
						val item = prefixesArr.opt(j)
						if (item is String) prefixes.add(item)
					}
				}
				// Xray picks members by tag prefix, and a selector matching nothing leaves a balancer
				// with no outbound - dropped, as in the mihomo pass, with its rules. Only outbounds that
				// were written count: sing-box refuses to start over a member that does not exist.
				val origMatch = xrayProxies.mapNotNull { proxy ->
					val tag = proxy.optString("tag", "")
					if (tag.isNotEmpty() && prefixes.any { prefix -> tag.startsWith(prefix) }) tag else null
				}.sorted()
				val members = origMatch.map { rename[it] ?: it }.filter { it in proxyTags }
				if (members.isEmpty()) {
					notes.add(
						"$at selects no outbound written here by its prefixes $prefixes, so it was dropped"
					)
					specialTagDrop.add(btag)
					continue
				}
				// Xray falls back to fallbackTag when no member is healthy; sing-box's urltest has
				// no spare of its own, so the fallback is named as lost rather than folded in.
				val fallbackTag = balancer.optString("fallbackTag", "")
				if (fallbackTag.isNotEmpty()) {
					notes.add(
						"$at names \"$fallbackTag\" as its fallback, which a sing-box urltest group " +
							"has no field for, so the fallback was dropped"
					)
				}
				balancerStrategyNote(balancer, "sing-box", "urltest")?.let { notes.add("$at $it") }

				val balancerOutbound = JSONObject()
				balancerOutbound.put("type", "urltest")
				balancerOutbound.put("tag", btag)
				balancerOutbound.put("outbounds", JSONArray(members))
				if (testUrl.isNotEmpty()) balancerOutbound.put("url", testUrl)
				if (testInterval.isNotEmpty()) balancerOutbound.put("interval", testInterval)
				balancerOuts.add(balancerOutbound)
				balancerMap[btag] = btag
				if (primaryBalancer == null) primaryBalancer = btag
			}
		}
	}

	private fun buildSelector() {
		// Build the top-level selector over proxies + balancers
		val existingTags = HashSet<String>(proxyTags)
		for (balancer in balancerOuts) existingTags.add(balancer.optString("tag", ""))
		for (aux in auxOuts) existingTags.add(aux.optString("tag", ""))
		while (selectorTag in existingTags) selectorTag += " \u2299"

		val needSelector = proxyTags.size > 1 || balancerOuts.isNotEmpty()
		if (proxyTags.isNotEmpty() && needSelector) {
			val built = JSONObject()
			built.put("type", "selector")
			built.put("tag", selectorTag)
			val outs = JSONArray()
			for (balancer in balancerOuts) outs.put(balancer.optString("tag", ""))
			for (tag in proxyTags) outs.put(tag)
			built.put("outbounds", outs)
			built.put("default",
				if (balancerOuts.isNotEmpty()) balancerOuts[0].optString("tag", "") else proxyTags[0])
			selector = built
		}
	}

	private fun assembleOutbounds() {
		// Assemble and dedupe the outbound / endpoint lists
		selector?.let { sbOutbounds.add(it) }
		sbOutbounds.addAll(balancerOuts)
		sbOutbounds.addAll(proxyOuts)
		sbOutbounds.addAll(auxOuts)

		val usedOutTags = mutableSetOf<String>()
		sbOutbounds = SingBoxConverter.dedupeByTag(sbOutbounds, usedOutTags).toMutableList()
		endpointsDedup = SingBoxConverter.dedupeByTag(endpoints, usedOutTags)

		val balancer = primaryBalancer
		finalTag = when {
			selector != null -> selectorTag
			balancer != null -> balancer
			else -> proxyTags.firstOrNull { it.isNotEmpty() } ?: "direct"
		}
		// The rule sets come from raw.githubusercontent.com, which the people this is for cannot always
		// reach directly; fetched through the proxy they load once it is up and are cached. The proxy's
		// own connection is not routed by a rule set, so nothing is circular.
		ruleSetDownloadDetour = finalTag
		dnsDetour = proxyTags.firstOrNull { it.isNotEmpty() }
	}

	private fun buildRoute() {
		// Convert routing rules; prepend the built-in pre-rules (sniff/hijack-dns/resolve)
		routeRules = SingBoxRouting.buildRouteRules(routing, balancerMap, specialRemap, specialTagDrop,
			requiredRuleSets, notes, ruleOrigins).toMutableList()
		for (rule in routeRules) {
			val target = rule.optString("outbound", "")
			if (target.isNotEmpty() && rename.containsKey(target)) rule.put("outbound", rename[target])
		}
		val preRules = mutableListOf<JSONObject>()
		// A configuration that declares inbounds and asks none of them to sniff is read as written:
		// sniffing would let domain rules match what Xray routed by address. One with no inbounds
		// says nothing about it, and the client brings its own - so sniffing stays.
		val sniffs = anyInboundSniffs || xray.optJSONArray("inbounds").let { it == null || it.length() == 0 }
		if (sniffs) preRules.add(JSONObject().put("action", "sniff"))
		else notes.add(
			"no inbound written into the document asks to sniff, so the document does not either; " +
				"rules that name domains match only what a name is known for"
		)
		preRules.add(JSONObject().put("protocol", "dns").put("action", "hijack-dns"))
		preRules.add(JSONObject().put("port", JSONArray().put(53)).put("action", "hijack-dns"))
		if (resolveInbounds.isNotEmpty()) {
			val rule = JSONObject()
			rule.put("inbound", JSONArray(resolveInbounds))
			rule.put("action", "resolve")
			preRules.add(rule)
		} else {
			// IPIfNonMatch/IPOnDemand let an address rule match a domain destination, but only
			// where a resolve action says to. It is placed before the first address rule, not at the head.
			val wantsResolve = xrayRoutingResolves(routing.optString("domainStrategy", ""))
			if (wantsResolve) {
				val firstAddressRule = routeRules.indexOfFirst { SingBoxRouting.matchesByAddress(it) }
				if (firstAddressRule >= 0) routeRules.add(firstAddressRule,
					JSONObject().put("action", "resolve"))
			}
		}

		// Assemble route (rules + final + default DNS resolver)
		val allRules = JSONArray()
		// A rule repeating one before it decides nothing - sing-box takes the first that matches - so
		// only the first is kept; one converted from the routing often repeats a built-in one.
		val written = HashSet<String>()
		for (rule in preRules + routeRules) if (written.add(canonicalJson(rule))) allRules.put(rule)
		route.put("rules", allRules)
		route.put("auto_detect_interface", true)
		route.put("final", finalTag)
		val ddr = JSONObject()
		ddr.put("server", "local")
		// Routing reads only its own two names and every other one as AsIs, which sets no strategy.
		val domainStrategy = xrayDomainStrategyName(routing.optString("domainStrategy", ""))
		val dsMapped =
			if (xrayRoutingResolves(domainStrategy)) XRAY_DOMAIN_STRATEGY[domainStrategy] ?: "" else ""
		if (dsMapped.isNotEmpty()) {
			ddr.put("strategy", dsMapped)
		} else {
			val xrayDnsObj = xray.optJSONObject("dns")
			val queryStrategy = normalizeQueryStrategy(xrayDnsObj?.optString("queryStrategy", "") ?: "")
			if (!queryStrategy.isNullOrEmpty() &&
				SingBoxRouting.QUERY_STRATEGY_MAP.containsKey(queryStrategy)) {
				ddr.put("strategy", SingBoxRouting.QUERY_STRATEGY_MAP[queryStrategy])
			}
		}
		route.put("default_domain_resolver", ddr)
	}

	private fun buildDnsAndRuleSets(): JSONObject {
		// Convert DNS and attach the remote geosite/geoip rule-sets
		var fakednsObj: Any? = xray.opt("fakedns")
		if (fakednsObj == null || fakednsObj === JSONObject.NULL) {
			fakednsObj = xray.optJSONObject("dns")?.opt("fakedns")
		}
		val sbDns = SingBoxRouting.buildDns(xray.optJSONObject("dns"), fakednsObj, dnsDetour,
			requiredRuleSets, notes)

		if (requiredRuleSets.isNotEmpty()) {
			val rsArr = JSONArray()
			for (tag in requiredRuleSets.sorted()) {
				val ruleSet = JSONObject()
				ruleSet.put("type", "remote")
				ruleSet.put("tag", tag)
				ruleSet.put("format", "binary")
				val url = when {
					// the .srs name carries a geosite-/geoip- prefix
					tag.startsWith("geosite-") -> SingBoxConverter.GEOSITE_URL_TEMPLATE.replace("{name}", tag)
					tag.startsWith("geoip-") -> SingBoxConverter.GEOIP_URL_TEMPLATE.replace("{name}", tag)
					else -> continue
				}
				ruleSet.put("url", url)
				ruleSet.put("download_detour", ruleSetDownloadDetour)
				ruleSet.put("update_interval", "1d")
				rsArr.put(ruleSet)
			}
			route.put("rule_set", rsArr)
		}
		return sbDns
	}

	// Blocks of a configuration that no client-side document holds. Named rather than passed over,
	// because a person reading the answer cannot see what was in the file it came from.
	private fun reportDocumentBlocks() {
		// Xray removed the global transport block and now refuses a configuration carrying one, so
		// whatever it asked for never took effect there either.
		if (xray.xHas("transport")) {
			notes.add(
				"the global transport block was removed from Xray, which refuses a configuration " +
					"carrying it, so nothing here was taken from it"
			)
		}
		if (xray.xHas("reverse")) {
			notes.add(
				"reverse builds a tunnel back through this client, which sing-box has no form " +
					"for, so the reverse block was dropped"
			)
		}
		if (xray.xHas("policy")) {
			notes.add(
				"policy sets Xray's own timeouts and buffers per user level, which sing-box " +
					"decides for itself, so the policy block was dropped"
			)
		}
	}

	private fun assembleDocument(sbDns: JSONObject): SingBoxConverter.ConvertedDocument {
		reportDocumentBlocks()
		val xlog = xray.optJSONObject("log")?.optString("loglevel", "warning") ?: "warning"
		val sbLogLevel = SingBoxConverter.LOG_LEVEL_MAP[xlog] ?: "warn"

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

		// A rule naming an outbound the document does not hold is one sing-box refuses the whole
		// file over, so the subscription would not start at all. Checked here, where every tag the
		// document ended up with is known - a hand-written list of the usual names is not that.
		val documentTags = sbOutbounds.map { it.optString("tag") }.toMutableSet()
		documentTags.addAll(endpointsDedup.map { it.optString("tag") })
		val keptRules = JSONArray()
		val routeRulesOut = route.optJSONArray("rules") ?: JSONArray()
		for (i in 0 until routeRulesOut.length()) {
			val rule = routeRulesOut.getJSONObject(i)
			val target = rule.optString("outbound", "")
			if (target.isNotEmpty() && target !in documentTags) {
				val where = ruleOrigins[rule]?.let { "routing.rules[$it]" } ?: "a routing rule"
				notes.add(
					"$where points at \"$target\", which produced no outbound here; the rule was dropped"
				)
				continue
			}
			keptRules.put(rule)
		}
		route.put("rules", keptRules)
		val routeFinal = route.optString("final", "")
		if (routeFinal.isNotEmpty() && routeFinal !in documentTags) route.remove("final")
		val experimental = JSONObject()
		val cacheFile = JSONObject()
		cacheFile.put("enabled", true)
		experimental.put("cache_file", cacheFile)
		config.put("experimental", experimental)
		if (endpointsDedup.isNotEmpty()) config.put("endpoints", JSONArray(endpointsDedup))
		SingBoxUtil.dropEmptyDirectDetours(config)
		return SingBoxConverter.ConvertedDocument(config, notes)
	}
}

// A JSON value with every object's keys in order, so two values that say the same compare equal.
private fun canonicalJson(value: Any?): String = when (value) {
	is JSONObject -> value.keys().asSequence().sorted()
		.joinToString(",", "{", "}") { JSONObject.quote(it) + ":" + canonicalJson(value.opt(it)) }
	is JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { canonicalJson(value.opt(it)) }
	is String -> JSONObject.quote(value)
	else -> value.toString()
}
