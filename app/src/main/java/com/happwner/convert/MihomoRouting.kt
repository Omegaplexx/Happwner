package com.happwner.convert

import com.happwner.text.isIpLiteral
import org.json.JSONArray
import org.json.JSONObject

// The routing and DNS of an Xray configuration, written the way mihomo reads them.
internal object MihomoRouting {

	private const val NO_RESOLVE = ",no-resolve"

	// One Xray condition entry as a mihomo rule fragment, or null when mihomo has nothing that matches it.
	private fun domainFragment(entry: String): String? =
		when (val nameCondition = XrayConditions.name(entry)) {
			is XrayConditions.Name.Exact -> "DOMAIN,${nameCondition.value}"
			is XrayConditions.Name.Suffix -> "DOMAIN-SUFFIX,${nameCondition.value}"
			is XrayConditions.Name.Keyword -> "DOMAIN-KEYWORD,${nameCondition.value}"
			is XrayConditions.Name.Pattern -> mihomoRegex(nameCondition.value)?.let { "DOMAIN-REGEX,$it" }
			is XrayConditions.Name.Geosite -> "GEOSITE,${nameCondition.value}"
			XrayConditions.Name.External, XrayConditions.Name.Unusable -> null
		}

	// A sniffing exclusion in the form mihomo's skip lists take, read as Xray reads the entry: a name, a
	// name with its subdomains (+.), geosite, geoip, address ranges, and a bare name, which Xray finds
	// inside others too, as itself alone. Null where none fits - a keyword, pattern or negation.
	private fun skippedName(entry: String): String? = when (val name = XrayConditions.name(entry)) {
		is XrayConditions.Name.Exact -> name.value
		is XrayConditions.Name.Suffix -> "+.${name.value}"
		is XrayConditions.Name.Geosite -> "geosite:${name.value}"
		is XrayConditions.Name.Keyword -> name.value.takeUnless { entry.trim().startsWith("keyword:") }
		else -> null
	}

	private fun skippedAddress(entry: String): String? {
		return when (val address = XrayConditions.address(entry)) {
			is XrayConditions.Address.Cidr -> address.value
			is XrayConditions.Address.Country -> "geoip:${address.code}"
			XrayConditions.Address.Private -> "geoip:private"
			else -> null
		}
	}

	private fun ipFragment(entry: String, noResolve: Boolean): String? {
		val suffix = if (noResolve) NO_RESOLVE else ""
		return when (val target = XrayConditions.address(entry)) {
			is XrayConditions.Address.Cidr -> "IP-CIDR,${target.value}$suffix"
			is XrayConditions.Address.Country -> "GEOIP,${target.code}$suffix"
			is XrayConditions.Address.NotCountry ->
				knownAddressesOnly("NOT,((GEOIP,${target.code}$suffix))", suffix)
			XrayConditions.Address.Private -> "GEOIP,private$suffix"
			XrayConditions.Address.NotPrivate -> knownAddressesOnly("NOT,((GEOIP,private$suffix))", suffix)
			XrayConditions.Address.External, XrayConditions.Address.Unusable -> null
		}
	}

	// Where names are not resolved, a negation matches every name too - measured: mihomo takes one
	// past NOT,((IP-CIDR,...,no-resolve)) as an address outside the set. Held to known addresses, it
	// means what Xray means; a source always has its address, so no source negation needs this.
	private fun knownAddressesOnly(negation: String, suffix: String): String =
		if (suffix.isEmpty()) negation
		else "AND,((OR,((IP-CIDR,0.0.0.0/0$suffix),(IP-CIDR6,::/0$suffix))),($negation))"

	// A pool mihomo takes as a fake-IP range: room for fakeip.New, which hands addresses out from four
	// past the network one up to the last - eight addresses at least.
	private fun isFakeIpRange(pool: String, ipv6: Boolean): Boolean =
		fakeIpPoolBits(pool, ipv6)?.let { it <= (if (ipv6) 128 else 32) - 3 } == true

	// One address of a rule's source as mihomo writes it, read as the destination ones are.
	private fun sourceFragment(entry: String): String? = when (val source = XrayConditions.address(entry)) {
		is XrayConditions.Address.Cidr -> "SRC-IP-CIDR,${source.value}"
		is XrayConditions.Address.Country -> "SRC-GEOIP,${source.code}"
		is XrayConditions.Address.NotCountry -> "NOT,((SRC-GEOIP,${source.code}))"
		XrayConditions.Address.Private -> "SRC-GEOIP,private"
		XrayConditions.Address.NotPrivate -> "NOT,((SRC-GEOIP,private))"
		XrayConditions.Address.External, XrayConditions.Address.Unusable -> null
	}

	// A pattern as mihomo compiles DOMAIN-REGEX - with regexp2, not Go's RE2: a named group is
	// spelled "(?<name>" there and \Q...\E is written out escaped, meaning what they did; "\C" has
	// no form, so the pattern goes, named with whatever else the rule could not take.
	private fun mihomoRegex(pattern: String): String? {
		val out = StringBuilder()
		var i = 0
		while (i < pattern.length) {
			when {
				pattern.startsWith("\\Q", i) -> {
					val end = pattern.indexOf("\\E", i + 2).let { if (it < 0) pattern.length else it }
					for (ch in pattern.substring(i + 2, end)) {
						if (!ch.isLetterOrDigit()) out.append('\\')
						out.append(ch)
					}
					i = minOf(end + 2, pattern.length)
				}
				pattern.startsWith("\\C", i) -> return null
				pattern[i] == '\\' && i + 1 < pattern.length -> {
					out.append(pattern, i, i + 2)
					i += 2
				}
				pattern.startsWith("(?P<", i) -> {
					out.append("(?<")
					i += 4
				}
				else -> out.append(pattern[i++])
			}
		}
		return out.toString()
	}

	// "80/443/1000-2000" as mihomo writes a port list, from the ports the shared reader kept; a
	// token it dropped is named, since the core would refuse the whole configuration over it.
	private fun portList(value: Any?, key: String, warn: (String) -> Unit): String {
		val ports = XrayConditions.rulePorts(value)
		for (tok in ports.dropped) warn("$key \"$tok\" is not a port or a port range, so it was dropped")
		return (ports.singles.map { it.toString() } + ports.ranges.map { "${it.first}-${it.second}" })
			.joinToString("/")
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
		val noResolve = !xrayRoutingResolves(routing.xStr("domainStrategy"))

		val out = ArrayList<String>()
		for ((index, rule) in list.withIndex()) {
			val type = rule.xStr("type")
			if (type.isNotEmpty() && type != "field") continue

			// A rule names either; when it names both, Xray takes the outbound and ignores the
			// balancer, and so does this.
			val tag = rule.xStr("outboundTag").ifEmpty { rule.xStr("balancerTag") }
			val target = targetOf(tag)
			if (target == null) {
				warn(
					"routing.rules[$index] points at \"$tag\", which produced no proxy here; the rule " +
						"was dropped"
				)
				continue
			}

			// Each group is one Xray condition: its entries are alternatives,
			// and the groups themselves all have to hold at once.
			val groups = ArrayList<String>()
			var lostSomething = false
			// True when every condition the rule stated matches anything, so
			// the rule itself is a catch-all rather than something we failed at.
			var matchesEverything = true
			// True when a whole condition cannot be said in mihomo's terms. Losing one alternative narrows a
			// rule, which is safe; losing a condition widens it, which is worse than no rule at all.
			var lostAWholeCondition = false

			// A stated condition that produced nothing mihomo can say is a whole condition lost, whatever its
			// entries were: the rule would reach traffic the source never routed here.
			fun condition(field: String, fragment: String?) {
				matchesEverything = false
				if (fragment != null) {
					groups.add(fragment)
				} else {
					lostAWholeCondition = true
					warn(
						"routing.rules[$index] narrows by $field with nothing mihomo can express, so " +
							"the rule was dropped rather than applied to traffic it was not meant for"
					)
				}
			}

			// Xray adds "domains" to "domain" as one condition.
			if (rule.has("domain") || xrayConditionStated("domains", rule.opt("domains"))) {
				condition("domain", anyOf((rule.xStrList("domain") + rule.xStrList("domains")).mapNotNull {
					val fragment = domainFragment(it)
					if (fragment == null) lostSomething = true
					fragment
				}))
			}
			if (rule.has("ip")) {
				condition("ip", anyOf(rule.xStrList("ip").mapNotNull {
					val fragment = ipFragment(it, noResolve)
					if (fragment == null) lostSomething = true
					fragment
				}))
			}
			if (rule.has("port")) {
				condition("port", portList(rule.opt("port"), "port",
					warn).ifEmpty { null }?.let { "DST-PORT,$it" })
			}
			if (rule.has("sourcePort")) {
				condition("sourcePort",
					portList(rule.opt("sourcePort"), "sourcePort",
						warn).ifEmpty { null }?.let { "SRC-PORT,$it" })
			}
			// Xray reads "sourceIP", and "source" only when that is absent or null.
			val sourceKey = if (rule.isNull("sourceIP")) "source" else "sourceIP"
			if (rule.has(sourceKey)) {
				condition(sourceKey, anyOf(rule.xStrList(sourceKey).mapNotNull {
					val fragment = sourceFragment(it)
					if (fragment == null) lostSomething = true
					fragment
				}))
			}
			if (rule.has("network")) {
				val nets = rule.xStr("network").split(",").map { it.trim() }
					.filter { it == "tcp" || it == "udp" }.distinct()
				when (nets.size) {
					// Both named is every network there is, which is no condition at all.
					2 -> {}
					1 -> condition("network", "NETWORK,${nets.first()}")
					// Named, but neither tcp nor udp: a condition that says nothing mihomo reads.
					else -> condition("network", null)
				}
			}
			if (rule.has("user")) {
				condition("user",
					anyOf(rule.xStrList("user").filter { it.isNotEmpty() }.map { "IN-USER,$it" }))
			}
			if (rule.has("inboundTag")) {
				condition("inboundTag",
					anyOf(rule.xStrList("inboundTag").filter { it.isNotEmpty() }.map { "IN-NAME,$it" }))
			}
			if (rule.has("protocol")) {
				lostAWholeCondition = true
				warn(
					"routing.rules[$index] matches on protocol, which mihomo has no rule for, so the " +
						"rule was dropped rather than applied to traffic it was not meant for"
				)
			}
			if (rule.has("attrs")) {
				lostAWholeCondition = true
				warn(
					"routing.rules[$index] narrows by attrs, which mihomo has no rule for, so the " +
						"rule was dropped rather than applied to traffic it was not meant for"
				)
			}
			// Written, these keep a rule naming nothing else from being a catch-all even where Xray reads
			// them as no condition - Xray refuses such a rule; both networks say "everything" regardless.
			val named = listOf("domains", "sourceIP", "process", "vlessRoute", "localIP", "localPort")
			if (!rule.has("network") && named.any(rule::has)) matchesEverything = false
			for (field in listOf("process", "vlessRoute", "localIP", "localPort")) {
				if (!xrayConditionStated(field, rule.opt(field))) continue
				lostAWholeCondition = true
				warn(
					"routing.rules[$index] narrows by $field, which is not carried into mihomo, so the " +
						"rule was dropped rather than applied to traffic it was not meant for"
				)
			}
			if (xrayWebhookStated(rule)) {
				warn("routing.rules[$index] has a webhook, which mihomo has no equivalent for")
			}
			if (lostSomething) {
				warn(
					"routing.rules[$index] holds an entry mihomo cannot use - an Xray data file, " +
						"or a value it would refuse - and that entry was dropped from the rule, " +
						"which now matches the rest of what it listed"
				)
			}
			// A rule missing a whole condition would reach traffic the source never sent here.
			if (lostAWholeCondition) continue
			ruleLine(groups, target, matchesEverything, index, warn)?.let { out.add(it) }
		}
		return out
	}

	// A rule's condition groups as one mihomo line: MATCH for a catch-all, one group alone, or an
	// AND of them all. Null, with a warning, for a rule left with nothing it can match on.
	private fun ruleLine(groups: List<String>, target: String, matchesEverything: Boolean, index: Int,
		warn: (String) -> Unit): String? = when {
		groups.isEmpty() -> {
			// Only a rule that narrowed on nothing is a catch-all: both networks, or no
			// condition, is how Xray writes "everything", which mihomo spells MATCH. A rule
			// emptied by a condition it could not say is not that, and never becomes one.
			if (matchesEverything) "MATCH,$target"
			else {
				warn("routing.rules[$index] had no condition mihomo can express and was dropped")
				null
			}
		}
		// A modifier belongs after the target, and inside the sub-rule when nested: mihomo reads
		// "IP-CIDR,cidr,no-resolve,DIRECT" as a rule pointing at a proxy called no-resolve
		// and refuses the file.
		groups.size == 1 -> {
			val group = groups.first()
			if (group.endsWith(NO_RESOLVE) && !group.startsWith("OR,") && !group.startsWith("NOT,")) {
				group.removeSuffix(NO_RESOLVE) + ",$target" + NO_RESOLVE
			} else {
				"$group,$target"
			}
		}
		else -> "AND,(" + groups.joinToString(",") { "($it)" } + "),$target"
	}

	// The sniffer block from what the source's inbounds asked for, or null when none sniffs. Xray
	// sniffs on every port, so each protocol gets the whole range; destOverride is override-destination,
	// routeOnly lets only the rules see the name; fakedns is not a sniffer in mihomo and names nothing.
	internal fun sniffer(config: JSONObject, warn: (String) -> Unit): YamlMap? {
		val asked = config.xObjList("inbounds").filter { it.xObj("sniffing").xBool("enabled") }
		if (asked.isEmpty()) return null
		val protocols = LinkedHashSet<String>()
		var overrideDestination = false
		val skipNames = LinkedHashSet<String>()
		val skipAddresses = LinkedHashSet<String>()
		val unskippable = LinkedHashSet<String>()
		val narrowed = LinkedHashSet<String>()
		for (inbound in asked) {
			val sniffing = inbound.xObj("sniffing")
			for (name in sniffing.xStrList("destOverride")) {
				when (name.lowercase()) {
					"http" -> protocols.add("HTTP")
					"tls" -> protocols.add("TLS")
					"quic" -> protocols.add("QUIC")
					"fakedns" -> {}
					else -> warn(
						"sniffing.destOverride \"$name\" is not a protocol mihomo sniffs, so it was dropped")
				}
			}
			if (!sniffing.xBool("routeOnly")) overrideDestination = true
			if (sniffing.xBool("metadataOnly")) {
				warn(
					"sniffing.metadataOnly reads only the connection's own metadata, which mihomo " +
						"has no field for, so it was dropped"
				)
			}
			for (entry in sniffing.xStrList("domainsExcluded")) {
				val skipped = skippedName(entry)
				if (skipped == null) unskippable.add(entry) else skipNames.add(skipped)
				val bare = XrayConditions.name(entry) is XrayConditions.Name.Keyword
				if (skipped != null && bare) narrowed.add(entry)
			}
			for (entry in sniffing.xStrList("ipsExcluded")) {
				skippedAddress(entry)?.let { skipAddresses.add(it) } ?: unskippable.add(entry)
			}
		}
		if (protocols.isEmpty()) return null
		val sniff = YamlMap()
		for (protocol in protocols) sniff.set(protocol, YamlMap().apply { set("ports",
			YamlFlowSeq(listOf("1-65535"))) })
		val block = YamlMap()
		block.set("enable", true)
		block.set("override-destination", overrideDestination)
		block.set("sniff", sniff)
		if (skipNames.isNotEmpty()) block.set("skip-domain", YamlFlowSeq(skipNames.toList()))
		if (skipAddresses.isNotEmpty()) block.set("skip-dst-address", YamlFlowSeq(skipAddresses.toList()))
		if (narrowed.isNotEmpty()) {
			val quoted = narrowed.joinToString(", ") { "\"$it\"" }
			warn("sniffing excludes $quoted wherever Xray finds it inside a name; mihomo skips the " +
				"name alone")
		}
		if (unskippable.isNotEmpty()) {
			val which = if (unskippable.size == 1) "it was" else "they were"
			val quoted = unskippable.joinToString(", ") { "\"$it\"" }
			warn("sniffing excludes $quoted, which mihomo's sniffer has no form for, so $which dropped")
		}
		return block
	}

	// Whether Xray dials this resolver itself instead of routing the query ("+local").
	private fun isDirectResolver(address: String): Boolean =
		(XrayDnsAddress.parse(address) as? XrayDnsAddress.Kind.Remote)?.direct == true

	// A server's address with the client subnet Xray would send it. The system's resolver and DHCP's are
	// not servers on the network and send none.
	private fun withEcs(server: String, subnet: String?): String {
		if (subnet == null || server == "system" || server.startsWith("dhcp://")) return server
		val joiner = if ('#' in server) "&" else "#"
		return "$server${joiner}ecs=$subnet&ecs-override=true"
	}

	// One Xray DNS address as mihomo spells it, or null when it has no form here. A port written
	// beside the address in a server object applies when the address itself names none.
	private fun dnsServer(address: String, portBeside: Int? = null, warn: (String) -> Unit): String? =
		when (val kind = XrayDnsAddress.parse(address)) {
			XrayDnsAddress.Kind.Local -> "system"
			XrayDnsAddress.Kind.FakeDns -> null
			XrayDnsAddress.Kind.None -> {
				warn(XrayDnsAddress.droppedReason(address))
				null
			}
			is XrayDnsAddress.Kind.Dhcp -> "dhcp://" + kind.iface.ifEmpty { "auto" }
			is XrayDnsAddress.Kind.Remote -> {
				val port = kind.port ?: portBeside?.takeIf { it > 0 }
				// An IPv6 address is bracketed wherever a port follows it or a scheme precedes it;
				// bare, mihomo reads it as it stands.
				val ipv6 = kind.host.contains(':')
				val host = if (ipv6 && (port != null || kind.scheme != "udp")) "[${kind.host}]" else kind.host
				val authority = host + (port?.let { ":$it" } ?: "")
				val path = if (kind.path.isEmpty()) "" else "/" + kind.path
				when (kind.scheme) {
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
					else -> "${kind.scheme}://$authority$path"
				}
			}
		}

	// A domain condition as a nameserver-policy key.
	private fun policyKey(entry: String): String? {
		val trimmedEntry = entry.trim()
		return when {
			trimmedEntry.isEmpty() -> null
			trimmedEntry.startsWith("full:") -> trimmedEntry.removePrefix("full:")
			trimmedEntry.startsWith("domain:") -> "+." + trimmedEntry.removePrefix("domain:")
			trimmedEntry.startsWith("geosite:") -> "geosite:" + trimmedEntry.removePrefix("geosite:")
			trimmedEntry.startsWith("regexp:") || trimmedEntry.startsWith("ext:") ||
				trimmedEntry.startsWith("keyword:") -> null
			else -> "+.$trimmedEntry"
		}
	}

	// Converts the DNS block. Returns null when the configuration has none, so the caller keeps its
	// own default.
	internal fun dns(xray: JSONObject, warn: (String) -> Unit): YamlMap? {
		val dns = xray.xObj("dns") ?: return null
		// Xray asks its first server alone at times, moving on from it to none: no filter can hand over.
		val firstAlone = xrayAsksFirstAlone(dns)
		// The client subnet Xray sends every server, unless the server names its own.
		val globalRaw = dns.xStr("clientIp")
		val globalSubnet = if (globalRaw.isEmpty()) null else xrayClientSubnet(globalRaw)
		if (globalRaw.isNotEmpty() && globalSubnet == null) {
			warn(unreadableClientIp("dns.clientIp", globalRaw))
		}
		val nameservers = Nameservers(firstAlone, globalSubnet, warn)
		nameservers.read(dns.opt("servers"))

		val dnsMap = YamlMap()
		dnsMap.set("enable", true)
		when (normalizeQueryStrategy(dns.xStr("queryStrategy"))) {
			"UseIPv4" -> dnsMap.set("ipv6", false)
			"UseIPv6" -> dnsMap.set("ipv6", true)
			else -> dnsMap.set("ipv6", true)
		}
		if (dns.xHas("disableCache")) {
			warn("dns disableCache has no mihomo equivalent and was dropped; mihomo caches answers")
		}
		// fakedns anywhere in the list is what turns fake-ip on here.
		val fakednsCfg = xray.opt("fakedns")
		if (nameservers.fakedns || fakednsCfg != null) {
			dnsMap.set("enhanced-mode", "fake-ip")
			// Each pool goes to the range of its family, and only one mihomo reads as one: fake-ip-range only
			// as an IPv4 prefix, and fake-ip-range6 wherever it sees IPv6 - always on an Android that hides
			// interfaces from it - refusing the document over a bad one.
			val pools = when (fakednsCfg) {
				is JSONArray -> (0 until fakednsCfg.length())
					.mapNotNull { fakednsCfg.optJSONObject(it)?.xStr("ipPool") }
				is JSONObject -> listOf(fakednsCfg.xStr("ipPool"))
				else -> emptyList()
			}
			pools.filter { !isFakeIpRange(it, ipv6 = false) && !isFakeIpRange(it, ipv6 = true) }
				.forEach { warn(fakeIpPoolDroppedNote(it)) }
			val ipv4Pool = pools.firstOrNull { isFakeIpRange(it, ipv6 = false) }
			dnsMap.set("fake-ip-range", ipv4Pool ?: "198.18.0.1/16")
			dnsMap.setString("fake-ip-range6", pools.firstOrNull { isFakeIpRange(it, ipv6 = true) })
		} else {
			dnsMap.set("enhanced-mode", "redir-host")
		}
		nameservers.writeTo(dnsMap, dns)
		return dnsMap
	}

	// Xray's servers in its order, sorted into mihomo's nameserver lists as they are read.
	private class Nameservers(
		private val firstAlone: Boolean,
		private val globalSubnet: String?,
		private val warn: (String) -> Unit
	) {
		private val plain = ArrayList<String>()
		// Xray dials a "+local" resolver itself, so its queries never leave by the proxy; mihomo
		// keeps such resolvers in direct-nameserver, which is asked outside the tunnel as well.
		private val direct = ArrayList<String>()
		private val policy = LinkedHashMap<String, MutableList<String>>()
		// Every server Xray could ask about other names, with what sing-box weighs its default by:
		// kept out of the fallback order, dialled outside the tunnel, narrowed to some names.
		private val candidates = ArrayList<Pair<List<Boolean>, String>>()
		// Beside plain: the one country each server's expectIPs keeps, "" for none, null for one
		// that cannot carry - mihomo's fallback-filter judges an answer by a single geoip-code.
		private val plainCountry = ArrayList<String?>()
		private val plainAddress = ArrayList<String>()
		// Beside plain: whether Xray stops at the server (finalQuery), asking none after it.
		private val plainFinal = ArrayList<Boolean>()
		// The server Xray lists first, as mihomo spells it - the one it asks alone at times.
		private var firstServer: String? = null
		var fakedns = false
			private set

		fun read(servers: Any?) {
			if (servers !is JSONArray) return
			for (i in 0 until servers.length()) {
				val serverValue = servers.opt(i)
				if (serverValue is String) {
					if (serverValue.trim() == "fakedns") {
						fakedns = true
						continue
					}
					dnsServer(serverValue, warn = warn)?.let { withEcs(it, globalSubnet) }?.let {
						if (i == 0) firstServer = it
						if (isDirectResolver(serverValue)) {
							direct.add(it)
						} else {
							plain.add(it)
							plainCountry.add("")
							plainAddress.add(serverValue.trim())
							plainFinal.add(false)
						}
						candidates.add(listOf(false, isDirectResolver(serverValue), false) to it)
					}
					continue
				}
				val serverObject = serverValue as? JSONObject ?: continue
				val addr = serverObject.xStr("address")
				if (addr == "fakedns") {
					fakedns = true
					continue
				}
				val ownRaw = serverObject.xStr("clientIp")
				val ownSubnet = if (ownRaw.isEmpty()) null else xrayClientSubnet(ownRaw)
				if (ownRaw.isNotEmpty() && ownSubnet == null) {
					warn(unreadableClientIp("dns.servers[$i].clientIP", ownRaw))
				}
				val server = dnsServer(addr, serverObject.xInt("port"), warn)
					?.let { withEcs(it, ownSubnet ?: globalSubnet) } ?: continue
				if (i == 0) firstServer = server
				val domains = serverObject.xStrList("domains")
				val skipsFallback = serverObject.optBoolean("skipFallback", false)
				candidates.add(listOf(skipsFallback, isDirectResolver(addr), domains.isNotEmpty()) to server)
				val filtered = serverObject.xExpectedIps().isNotEmpty() ||
					serverObject.xStrList("unexpectedIPs").isNotEmpty()
				val country = when {
					!filtered -> ""
					firstAlone || serverObject.xBool("finalQuery") -> null
					else -> answerCountry(serverObject)
				}
				if (domains.isEmpty()) {
					// Narrowed to no names and out of the fallback order, it is one Xray never asks.
					if (!skipsFallback) {
						if (isDirectResolver(addr)) {
							direct.add(server)
						} else {
							plain.add(server)
							plainCountry.add(country)
							plainAddress.add(addr)
							plainFinal.add(serverObject.xBool("finalQuery"))
						}
					}
				} else {
					for (dom in domains) {
						val key = policyKey(dom)
						if (key == null) {
							warn(
								"dns domain \"$dom\" has no nameserver-policy form" +
									" in mihomo and was dropped"
							)
							continue
						}
						policy.getOrPut(key) { ArrayList() }.add(server)
					}
				}
				val why = when {
					!filtered -> null
					firstAlone -> firstAloneFilterReason(i == 0)
					serverObject.xBool("finalQuery") -> FINAL_QUERY_FILTER_REASON
					country == null -> "only one country carries - fallback-filter takes a single geoip-code"
					domains.isNotEmpty() -> "mihomo filters answers only between nameserver and fallback"
					skipsFallback || isDirectResolver(addr) -> "the server is outside Xray's fallback order"
					else -> null
				}
				if (why != null) warn(droppedAnswerFilter(addr, why))
			}
		}

		// What was read, as mihomo's lists: nameserver, the fallback behind the leading country's
		// filter, direct-nameserver and nameserver-policy.
		fun writeTo(dnsMap: YamlMap, dns: JSONObject) {
			// Nothing left for every name: the server Xray asks about them first, chosen as sing-box
			// chooses its default, rather than a system resolver the subscription never named.
			if (plain.isEmpty()) {
				val preference = compareBy<Pair<List<Boolean>, String>>(
					{ it.first[0] }, { it.first[1] }, { it.first[2] }
				)
				plain.add(candidates.minWithOrNull(preference)?.second ?: "system")
			}
			// The servers leading Xray's order with one country's filter are asked first; an answer
			// from elsewhere goes to the rest, as Xray moves on to them.
			val code = plainCountry.firstOrNull().orEmpty()
			val lead = if (code.isEmpty()) 0 else plainCountry.takeWhile { it == code }.size
			// Xray asks none past a finalQuery server, so the fallback ends with the first one.
			val stop = (lead until plain.size).firstOrNull { plainFinal.getOrElse(it) { false } }
				?.plus(1) ?: plain.size
			val fallback =
				if (lead in 1 until plain.size) plain.subList(lead, stop).toList() else emptyList()
			plainCountry.forEachIndexed { i, country ->
				if (country.isNullOrEmpty() || (i < lead && fallback.isNotEmpty())) {
					return@forEachIndexed
				}
				// What ends the leading run decides why: a server without a filter answers every name
				// first; one filtering otherwise leaves a country the single geoip-code cannot also take.
				val why = when {
					i < lead -> "no server comes after it for mihomo to fall back to"
					plainCountry[lead] == "" ->
						"a server Xray asks before it answers every name, so it never decides"
					else -> "mihomo's fallback-filter takes only the country leading Xray's order"
				}
				warn(droppedAnswerFilter(plainAddress[i], why))
			}
			// Xray asks its first server alone about a name no domains match: it is the whole list, and
			// connections leaving directly resolve through it too rather than through servers never asked.
			val first = firstServer
			if (firstAlone && first == null) warn(firstServerNotDefault(xrayFirstServer(dns)))
			if (firstAlone && first != null) direct.clear()
			val nameserver = when {
				firstAlone && first != null -> listOf(first)
				fallback.isEmpty() -> plain
				else -> plain.subList(0, lead).toList()
			}
			dnsMap.set("nameserver", YamlFlowSeq(nameserver))
			if (fallback.isNotEmpty()) {
				dnsMap.set("fallback", YamlFlowSeq(fallback))
				val filter = YamlMap()
				filter.set("geoip", true)
				filter.set("geoip-code", code.uppercase())
				dnsMap.set("fallback-filter", filter)
			}
			if (direct.isNotEmpty()) dnsMap.set("direct-nameserver", YamlFlowSeq(direct))
			if (policy.isNotEmpty()) {
				val policyMap = YamlMap()
				for ((domain, value) in policy) policyMap.set(domain, YamlFlowSeq(value))
				dnsMap.set("nameserver-policy", policyMap)
			}
		}
	}

	// The one country a server's expectIPs keeps, or null when it names anything else: subnets,
	// private or negated addresses, several countries, or unexpectedIPs.
	private fun answerCountry(server: JSONObject): String? {
		if (server.xStrList("unexpectedIPs").isNotEmpty()) return null
		val codes = server.xExpectedIps()
			.map { (XrayConditions.address(it) as? XrayConditions.Address.Country)?.code }
		if (codes.isEmpty() || null in codes) return null
		return codes.distinct().singleOrNull()
	}

	private fun droppedAnswerFilter(server: String, why: String) =
		"dns server \"$server\": the answer filter (expectIPs/unexpectedIPs) was dropped - $why"

	// An address as mihomo's hosts reads one - netip.ParseAddr, which takes a zone but not an empty one.
	private fun isHostAddress(value: String) = isIpLiteral(value) && !value.endsWith("%")

	// A name as mihomo's hosts reads one: two labels at least once the dots around it are trimmed.
	private fun isHostName(value: String) = value.trim('.').split('.').size >= 2

	// Xray's hosts block, in mihomo's spelling. A key is a name, a suffix (+.) or a wildcard;
	// Xray's keyword, regexp and geosite forms have no hosts spelling in mihomo, and written as
	// they stand they would be names nothing ever asks for.
	internal fun hosts(xray: JSONObject, warn: (String) -> Unit): YamlMap? {
		val hosts = xray.xObj("dns")?.xObj("hosts") ?: return null
		val hostsMap = YamlMap()
		var any = false
		for (key in hosts.keys()) {
			val mapped = when {
				key.startsWith("domain:") -> "+." + key.removePrefix("domain:")
				key.startsWith("full:") -> key.removePrefix("full:")
				key.startsWith("keyword:") || key.startsWith("regexp:") ||
					key.startsWith("geosite:") || key.startsWith("ext:") -> {
					warn("dns.hosts entry \"$key\" has no hosts form in mihomo and was dropped")
					null
				}
				else -> key
			} ?: continue
			val vals = when (val value = hosts.opt(key)) {
				is String -> listOf(value)
				is JSONArray -> (0 until value.length()).mapNotNull { value.opt(it) as? String }
				else -> continue
			}
			// mihomo takes one address or name, or a list of addresses, and refuses the whole file
			// over anything else - a name in a list, or one of a single label such as "" or "localhost" -
			// so that goes, as the sing-box pass drops what it cannot carry.
			val single = vals.size <= 1
			val kept = vals.filter { isHostAddress(it) || single && isHostName(it) }
			if (kept.size < vals.size) warn(
				if (single) "dns.hosts entry \"$key\" maps to \"${vals.first()}\", which is neither an " +
					"address nor a name mihomo takes, so it was dropped"
				else "dns.hosts entry \"$key\" maps to a name among its addresses, which a mihomo hosts " +
					"list has no form for, so that part was dropped"
			)
			if (kept.size == 1) hostsMap.set(mapped, kept.first())
			else if (kept.isNotEmpty()) hostsMap.set(mapped, YamlFlowSeq(kept))
			any = true
		}
		return if (any) hostsMap else null
	}
}
