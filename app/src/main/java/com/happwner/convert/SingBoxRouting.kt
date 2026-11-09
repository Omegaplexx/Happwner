package com.happwner.convert

import com.happwner.text.isIpLiteral
import org.json.JSONArray
import org.json.JSONObject

// Everything that is not a proxy server: inbounds, routing rules, DNS.
internal object SingBoxRouting {
	// The four strategies Xray has, in sing-box's words. Read through normalizeQueryStrategy, so
	// every spelling Xray takes arrives here as one of these.
	internal val QUERY_STRATEGY_MAP = mapOf(
		"UseIPv4" to "ipv4_only",
		"UseIPv6" to "ipv6_only",
		"UseIP" to "prefer_ipv4",
		"UseSystem" to "prefer_ipv4"
	)

	internal val REMOTE_DNS_TYPES = setOf("https", "h3", "tls", "quic", "tcp", "udp")

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
				val nestedRule = nested.optJSONObject(i) ?: continue
				if (matchesByAddress(nestedRule)) return true
			}
		}
		return false
	}

	internal val ENCRYPTED_DNS_TYPES = setOf("https", "h3", "tls", "quic", "tcp")

	// The ports of a rule as sing-box writes them, from the ports the shared reader kept; a token
	// it dropped is named, since the core would refuse the whole document over it.
	internal data class PortLists(val ports: List<Int>, val ranges: List<String>)

	internal fun parsePortList(value: Any?, key: String, notes: MutableList<String>): PortLists {
		val ports = XrayConditions.rulePorts(value)
		for (tok in ports.dropped) {
			notes.add("routing $key \"$tok\" is not a port or a port range, so it was dropped")
		}
		return PortLists(ports.singles, ports.ranges.map { "${it.first}:${it.second}" })
	}

	// A port to listen on, as sing-box takes one: a whole number from 1 to 65535. Anything else - a
	// fraction, a number past the range, which a cast would wrap - fails the whole document there.
	internal fun parseListenPort(raw: Any?): Int? {
		val port: Long? = when (raw) {
			is Int -> raw.toLong()
			is Long -> raw
			is Number -> raw.toDouble().takeIf { it % 1.0 == 0.0 && it in 1.0..65535.0 }?.toLong()
			is String -> raw.trim().takeIf { text ->
				text.isNotEmpty() && text.length <= 5 && text.all { it in '0'..'9' }
			}?.toLong()
			is JSONArray -> return if (raw.length() >= 1) parseListenPort(raw.opt(0)) else null
			else -> null
		}
		return port?.takeIf { it in 1..65535 }?.toInt()
	}

	internal data class DomainSplit(
		val domain: List<String>,
		val domainSuffix: List<String>,
		val domainKeyword: List<String>,
		val domainRegex: List<String>,
		val geosite: List<String>
	)

	internal fun splitDomains(domains: List<Any?>,
		dropped: MutableList<String> = mutableListOf()): DomainSplit {
		val full = mutableListOf<String>()
		val suffix = mutableListOf<String>()
		val keyword = mutableListOf<String>()
		val regex = mutableListOf<String>()
		val geosite = mutableListOf<String>()
		for (raw in domains) {
			val domain = (raw as? String) ?: continue
			when (val nameCondition = XrayConditions.name(domain)) {
				is XrayConditions.Name.Exact -> full.add(nameCondition.value)
				is XrayConditions.Name.Suffix -> suffix.add(nameCondition.value)
				is XrayConditions.Name.Keyword -> keyword.add(nameCondition.value)
				is XrayConditions.Name.Pattern -> regex.add(nameCondition.value)
				is XrayConditions.Name.Geosite -> geosite.add(nameCondition.value)
				XrayConditions.Name.External -> dropped.add(domain)
				XrayConditions.Name.Unusable -> if (domain.isNotBlank()) dropped.add(domain)
			}
		}
		return DomainSplit(full, suffix, keyword, regex, geosite)
	}

	internal data class IpSplit(
		val ipCidr: List<String>,
		val geoip: List<String>,
		val ipIsPrivate: Boolean,
		// The "geoip:!xx" entries, which the core inverts only as an alternative of their own.
		val geoipNot: List<String>,
		// "geoip:!private": the core knows the private ranges itself, so this is an inverted
		// is-private alternative rather than a country set it would have to fetch.
		val ipIsNotPrivate: Boolean
	)

	internal fun splitIps(ips: List<Any?>, dropped: MutableList<String>): IpSplit {
		val cidr = mutableListOf<String>()
		val geoip = mutableListOf<String>()
		val geoipNot = mutableListOf<String>()
		var isPrivate = false
		var isNotPrivate = false
		for (raw in ips) {
			val entry = (raw as? String) ?: continue
			when (val addressCondition = XrayConditions.address(entry)) {
				is XrayConditions.Address.Cidr -> cidr.add(addressCondition.value)
				is XrayConditions.Address.Country -> geoip.add(addressCondition.code)
				// "geoip:!cn" is "anywhere but cn". The core inverts a whole rule rather than one
				// field, so it becomes an alternative of its own where the rule is assembled.
				is XrayConditions.Address.NotCountry -> geoipNot.add(addressCondition.code)
				XrayConditions.Address.Private -> isPrivate = true
				XrayConditions.Address.NotPrivate -> isNotPrivate = true
				XrayConditions.Address.External -> dropped.add(entry)
				XrayConditions.Address.Unusable -> if (entry.isNotBlank()) dropped.add(entry)
			}
		}
		return IpSplit(cidr, geoip, isPrivate, geoipNot, isNotPrivate)
	}

	// Destination-name fields; the core treats these as alternatives.
	private val DOMAIN_KEYS = setOf("domain", "domain_suffix", "domain_keyword", "domain_regex")

	// Destination-address fields; likewise alternatives among themselves.
	private val IP_KEYS = setOf("ip_cidr", "ip_is_private")

	// Source-address fields, alternatives among themselves and to the source countries.
	private val SOURCE_IP_KEYS = setOf("source_ip_cidr", "source_ip_is_private")

	// What reading one rule sets aside to join it in regroupRule: the negated countries of the
	// destination, and the countries of the source, plain and negated.
	internal class Deferred {
		val invertedSets = mutableListOf<String>()
		val sourceSets = mutableListOf<String>()
		val invertedSourceSets = mutableListOf<String>()
		// "not private" on either side: an alternative of its own, like the inverted sets.
		var notPrivate: Boolean = false
		var notPrivateSource: Boolean = false
		val size: Int
			get() = invertedSets.size + sourceSets.size + invertedSourceSets.size +
				(if (notPrivate) 1 else 0) + (if (notPrivateSource) 1 else 0)
		val hasSource: Boolean
			get() = sourceSets.isNotEmpty() || invertedSourceSets.isNotEmpty() || notPrivateSource
	}

	// Rebuilds a rule so that it means what the Xray rule meant.
	internal fun regroupRule(rule: JSONObject, deferred: Deferred): JSONObject {
		val invertedSets = deferred.invertedSets
		val domainObj = JSONObject()
		val ipObj = JSONObject()
		val sourceObj = JSONObject()
		val otherObj = JSONObject()
		var outbound: String? = null
		var action: String? = null
		val keys = rule.keys().asSequence().toList()
		for (key in keys) {
			val value = rule.opt(key)
			when {
				key == "outbound" -> outbound = value as? String
				key == "action" -> action = value as? String
				key in DOMAIN_KEYS -> domainObj.put(key, value)
				key in IP_KEYS -> ipObj.put(key, value)
				key in SOURCE_IP_KEYS && deferred.hasSource -> sourceObj.put(key, value)
				key == "rule_set" -> {
					val entries = value as? JSONArray ?: continue
					val geosite = JSONArray()
					val geoip = JSONArray()
					for (i in 0 until entries.length()) {
						val entry = entries.optString(i, "")
						if (entry.startsWith("geoip-")) geoip.put(entry) else geosite.put(entry)
					}
					if (geosite.length() > 0) domainObj.put("rule_set", geosite)
					if (geoip.length() > 0) ipObj.put("rule_set", geoip)
				}
				else -> otherObj.put(key, value)
			}
		}

		val hasDomain = domainObj.length() > 0
		val hasIp = ipObj.length() > 0 || invertedSets.isNotEmpty() || deferred.notPrivate
		// One kind of destination condition, no negation and no source country is what the core
		// already reads correctly, so leave that rule exactly as it was.
		if (!(hasDomain && hasIp) && invertedSets.isEmpty() && !deferred.notPrivate &&
			!deferred.hasSource
		) {
			return rule
		}

		val ipPart: JSONObject? = when {
			!hasIp -> null
			invertedSets.isEmpty() && !deferred.notPrivate -> ipObj
			else -> {
				val alts = JSONArray()
				if (ipObj.length() > 0) alts.put(ipObj)
				if (deferred.notPrivate) {
					val notPrivate = JSONObject().put("ip_is_private", true).put("invert", true)
					alts.put(knownAddressesOnly(notPrivate))
				}
				for (tag in invertedSets) {
					val notInSet = JSONObject().put("rule_set", JSONArray().put(tag)).put("invert", true)
					alts.put(knownAddressesOnly(notInSet))
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
		if (deferred.hasSource) parts.put(sourcePart(sourceObj, deferred))
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

	// An inverted destination condition matches whatever the plain one does not, a name included -
	// measured on 1.12 to 1.14. Held to known addresses, it means what Xray means; a source always
	// has its address, so no source condition needs this.
	private fun knownAddressesOnly(inverted: JSONObject): JSONObject =
		JSONObject().put("type", "logical").put("mode", "and").put(
			"rules",
			JSONArray()
				.put(JSONObject().put("ip_cidr", JSONArray().put("0.0.0.0/0").put("::/0")))
				.put(inverted)
		)

	// The source with its countries: their rule-sets turned to the source address, each part an
	// alternative of its own - the switch would turn destination countries too, and 1.12 requires
	// the source's own addresses beside such a rule-set. A negated country is its set inverted.
	private fun sourcePart(sourceObj: JSONObject, deferred: Deferred): JSONObject {
		val alts = JSONArray()
		if (sourceObj.length() > 0) alts.put(sourceObj)
		if (deferred.notPrivateSource) {
			alts.put(JSONObject().put("source_ip_is_private", true).put("invert", true))
		}
		if (deferred.sourceSets.isNotEmpty()) {
			alts.put(
				JSONObject().put("rule_set", JSONArray(deferred.sourceSets))
					.put("rule_set_ip_cidr_match_source", true)
			)
		}
		for (tag in deferred.invertedSourceSets) {
			alts.put(
				JSONObject().put("rule_set", JSONArray().put(tag))
					.put("rule_set_ip_cidr_match_source", true).put("invert", true)
			)
		}
		return if (alts.length() == 1) alts.getJSONObject(0)
		else JSONObject().put("type", "logical").put("mode", "or").put("rules", alts)
	}

	internal fun addRuleSetTags(rule: JSONObject, tags: List<String>) {
		if (tags.isEmpty()) return
		val existing = mutableListOf<String>()
		val ruleSetTags = rule.optJSONArray("rule_set")
		if (ruleSetTags != null) {
			for (i in 0 until ruleSetTags.length()) existing.add(ruleSetTags.optString(i))
		}
		for (tag in tags) if (tag !in existing) existing.add(tag)
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
		addRuleSetTags(rule, geoip.map { countrySet(it, ruleSets) })
	}

	// The rule-set of a country, registered for the document to fetch.
	private fun countrySet(code: String, ruleSets: MutableSet<String>): String =
		"geoip-${code.lowercase()}".also { ruleSets.add(it) }

	internal data class InboundResult(
		val inbound: JSONObject?,
		val sniffEnabled: Boolean,
		val sniffResolves: Boolean,
		// Why nothing was written, when nothing was: an inbound dropped in silence leaves a
		// document a client listens on nothing with, and the person is left guessing.
		val refusal: String? = null
	)

	// The address an inbound listens on, as sing-box takes one: an IP literal, without brackets. None
	// written is the fallback; anything else - a name, a socket path - would fail the whole document,
	// so it falls back too, and the note says so.
	private fun listenAddress(inb: JSONObject, fallback: String, notes: MutableList<String>): String {
		val written = inb.opt("listen")
		if (written == null || written == JSONObject.NULL) return fallback
		val text = written.toString().trim().removeSurrounding("[", "]")
		if (text.isEmpty()) return fallback
		if (isIpLiteral(text)) return text
		notes.add("inbound listen \"$written\" is no address sing-box can listen on, so $fallback was used")
		return fallback
	}

	// Xray inbound to sing-box inbound (socks/http/mixed/dokodemo)
	internal fun buildInbound(inb: JSONObject, notes: MutableList<String>): InboundResult {
		val proto = inb.xrayProtocol()
		val sniff = inb.optJSONObject("sniffing") ?: JSONObject()
		val sniffEnabled = sniff.xBool("enabled")
		val destOverride = sniff.optJSONArray("destOverride")
		val hasDestOverride = destOverride != null && destOverride.length() > 0
		val routeOnly = sniff.xBool("routeOnly")
		val sniffResolves = sniffEnabled && hasDestOverride && !routeOnly
		if (sniffEnabled) {
			// What the sniffer was told to do beyond looking: sing-box sniffs what it knows and
			// has no field for either of these, and a person who excluded a domain from sniffing
			// had a reason for it.
			if (sniff.xBool("metadataOnly")) {
				notes.add(
					"sniffing.metadataOnly reads only the connection's own metadata, which " +
						"sing-box has no field for, so it was dropped"
				)
			}
			val excluded = sniff.xStrList("domainsExcluded")
			if (excluded.isNotEmpty()) {
				notes.add(
					"sniffing.domainsExcluded keeps ${excluded.size} name(s) out of sniffing, " +
						"which sing-box has no field for, so they were dropped"
				)
			}
			val excludedIps = sniff.xStrList("ipsExcluded")
			if (excludedIps.isNotEmpty()) {
				notes.add(
					"sniffing.ipsExcluded keeps ${excludedIps.size} address(es) out of sniffing, " +
						"which sing-box has no field for, so they were dropped"
				)
			}
		}

		val listenPort = parseListenPort(inb.opt("port"))

		// dokodemo-door -> a direct inbound
		if (proto == "dokodemo-door") {
			val inboundSettings = inb.optJSONObject("settings") ?: JSONObject()
			val inbound = JSONObject()
			inbound.put("type", "direct")
			inbound.put("tag", inb.optString("tag", "direct-in"))
			inbound.put("listen", listenAddress(inb, "0.0.0.0", notes))
			if (listenPort != null) inbound.put("listen_port", listenPort) else inbound.put("listen_port",
				JSONObject.NULL)
			val net = inboundSettings.optString("network", "tcp")
			if (net == "tcp" || net == "udp") inbound.put("network", net)
			val addr = inboundSettings.opt("address")
			if (isTruthy(addr)) inbound.put("override_address", inboundSettings.xStr("address"))
			val port = parseListenPort(inboundSettings.opt("port"))
			if (port != null) inbound.put("override_port", port)
			return InboundResult(inbound, sniffEnabled, sniffResolves)
		}

		// Server-side inbounds aren't supported here; only socks/http/mixed
		if (proto in setOf("vmess", "vless", "trojan", "shadowsocks")) {
			return InboundResult(null, false, false,
				"a $proto inbound listens for other clients, which this converts nothing for, " +
					"so it was dropped")
		}
		if (proto !in setOf("socks", "http", "mixed")) {
			val named = proto.ifEmpty { "unnamed" }
			return InboundResult(null, false, false,
				"the $named inbound has no form here, which carries socks, http and mixed, " +
					"so it was dropped")
		}
		if (listenPort == null) {
			return InboundResult(null, false, false,
				"the $proto inbound names no single port to listen on, which is the only form " +
					"sing-box takes, so it was dropped")
		}

		// socks/http/mixed with optional accounts
		val inbound = JSONObject()
		inbound.put("type", proto)
		inbound.put("tag", inb.optString("tag", proto))
		inbound.put("listen", listenAddress(inb, "127.0.0.1", notes))
		inbound.put("listen_port", listenPort)
		val settings = inb.optJSONObject("settings")
		// Xray takes "accounts" whenever it is written, an empty list too, and "users" otherwise; one read
		// alone would bring a login written as the other to sing-box as no login at all.
		val accounts = settings?.let {
			val written = it.has("accounts") && !it.isNull("accounts")
			it.optJSONArray(if (written) "accounts" else "users")
		}
		if (accounts != null && accounts.length() > 0) {
			val users = JSONArray()
			for (i in 0 until accounts.length()) {
				val account = accounts.optJSONObject(i) ?: continue
				val user = JSONObject()
				user.put("username", account.optString("user", ""))
				user.put("password", account.optString("pass", ""))
				users.put(user)
			}
			inbound.put("users", users)
		}
		return InboundResult(inbound, sniffEnabled, sniffResolves)
	}

	// Xray routing.rules to sing-box route.rules (domains/ip to rule_set, balancers, special actions)
	internal fun buildRouteRules(
		routing: JSONObject,
		balancerMap: Map<String, String>,
		specialRemap: Map<String, String>,
		specialTagDrop: Set<String>,
		ruleSets: MutableSet<String>,
		notes: MutableList<String>,
		origins: MutableMap<JSONObject, Int>
	): List<JSONObject> {
		val out = mutableListOf<JSONObject>()
		val rules = routing.optJSONArray("rules") ?: return out
		for (i in 0 until rules.length()) {
			val xrayRule = rules.optJSONObject(i) ?: continue
			val typeField = xrayRule.optString("type", "")
			if (typeField.isNotEmpty() && typeField != "field") continue
			val rule = ruleTarget(xrayRule, balancerMap, specialRemap, specialTagDrop) ?: continue
			val deferred = Deferred()
			val lostAWholeCondition = applyConditions(xrayRule, i, rule, ruleSets, deferred, notes)

			// Only a rule that stated no condition at all is a catch-all. One left with nothing
			// because its conditions could not be said is not, and never becomes one.
			val namedACondition = xrayRule.keys().asSequence().any { it in RULE_CONDITIONS }
			// A condition set aside joins the rule in regroupRule below, so it counts as one even
			// though it is not in the rule yet.
			val conditions = rule.keys().asSequence().count { it !in RULE_ACTION_KEYS } + deferred.size
			if (lostAWholeCondition || (namedACondition && conditions == 0)) {
				if (!lostAWholeCondition) {
					notes.add(
						"routing.rules[$i]: nothing in its condition could be said in sing-box's " +
							"terms, so the rule was dropped rather than applied to everything"
					)
				}
				continue
			}
			out.add(regroupRule(rule, deferred).also { origins.put(it, i) })
		}
		return out
	}

	// The rule with its target only: a plain outbound or a special action (reject/hijack-dns),
	// else the balancer; null for a rule pointing at nothing written. A rule naming both is read
	// the way Xray reads it: the outbound takes effect, the balancer is ignored.
	private fun ruleTarget(
		xrayRule: JSONObject,
		balancerMap: Map<String, String>,
		specialRemap: Map<String, String>,
		specialTagDrop: Set<String>
	): JSONObject? {
		val rule = JSONObject()
		when {
			xrayRule.optString("outboundTag", "").isEmpty() && xrayRule.has("balancerTag") -> {
				val balancerTag = xrayRule.optString("balancerTag", "")
				if (balancerTag in specialTagDrop) return null
				rule.put("outbound", balancerMap[balancerTag] ?: balancerTag)
			}
			xrayRule.has("outboundTag") -> {
				val tgt = xrayRule.optString("outboundTag", "")
				if (tgt in specialTagDrop) return null
				val action = specialRemap[tgt]
				if (action != null) {
					rule.put("action", action)
				} else {
					rule.put("outbound", tgt)
				}
			}
			else -> return null
		}
		return rule
	}

	// Puts the rule's conditions into the sing-box rule. True when a whole condition could not be
	// said in sing-box's terms: a rule that keeps its action and loses what narrowed it does not
	// match less - it matches everything, and takes every rule under it out of the file.
	private fun applyConditions(
		xrayRule: JSONObject,
		index: Int,
		rule: JSONObject,
		ruleSets: MutableSet<String>,
		deferred: Deferred,
		notes: MutableList<String>
	): Boolean {
		var lostAWholeCondition = false

		// A stated condition that put nothing into the rule is a whole condition lost, whatever its
		// entries: the rule would reach traffic the source never routed here. Losing some
		// alternatives only narrows it.
		fun shape() = Triple(rule.length(), rule.optJSONArray("rule_set")?.length() ?: 0, deferred.size)
		fun stated(field: String, before: Triple<Int, Int, Int>) {
			if (shape() == before) {
				lostAWholeCondition = true
				notes.add(
					"routing.rules[$index]: narrows by $field with nothing the core can express, " +
						"so the rule was dropped rather than applied to traffic it was not meant for"
				)
			}
		}

		if (xrayRule.has("inboundTag")) {
			val before = shape()
			val inTags = SingBoxUtil.asStringList(xrayRule.opt("inboundTag"))
			if (inTags.isNotEmpty()) rule.put("inbound", JSONArray(inTags))
			stated("inboundTag", before)
		}
		if (xrayRule.has("protocol")) {
			val before = shape()
			val protos = SingBoxUtil.asStringList(xrayRule.opt("protocol"))
			if (protos.isNotEmpty()) rule.put("protocol", JSONArray(protos))
			stated("protocol", before)
		}
		if (xrayRule.has("network")) {
			val before = shape()
			val netRaw = xrayRule.opt("network")
			val nets = mutableListOf<String>()
			val src = if (netRaw is String) netRaw.split(",") else SingBoxUtil.asStringList(netRaw)
			for (networkName in src) {
				val trimmed = networkName.trim()
				if (trimmed == "tcp" || trimmed == "udp") nets.add(trimmed)
			}
			if (nets.isNotEmpty()) rule.put("network", JSONArray(nets))
			stated("network", before)
		}
		if (xrayRule.has("port")) {
			val before = shape()
			val portLists = parsePortList(xrayRule.opt("port"), "port", notes)
			if (portLists.ports.isNotEmpty()) rule.put("port", JSONArray(portLists.ports))
			if (portLists.ranges.isNotEmpty()) rule.put("port_range", JSONArray(portLists.ranges))
			stated("port", before)
		}
		if (xrayRule.has("sourcePort")) {
			val before = shape()
			val sourcePorts = parsePortList(xrayRule.opt("sourcePort"), "sourcePort", notes)
			if (sourcePorts.ports.isNotEmpty()) rule.put("source_port", JSONArray(sourcePorts.ports))
			if (sourcePorts.ranges.isNotEmpty()) rule.put("source_port_range", JSONArray(sourcePorts.ranges))
			stated("sourcePort", before)
		}
		// Xray reads "sourceIP", and "source" only when that is absent or null.
		val sourceKey = if (xrayRule.isNull("sourceIP")) "source" else "sourceIP"
		if (xrayRule.has(sourceKey)) {
			val before = shape()
			val droppedSrc = mutableListOf<String>()
			val ipSplit = splitIps(SingBoxUtil.asList(xrayRule.opt(sourceKey)), droppedSrc)
			if (droppedSrc.isNotEmpty()) notes.add(
				"routing.rules[$index]: ${droppedSrc.joinToString(", ")} is not an address the core " +
					"can read (or names an Xray data file) and was dropped from the rule"
			)
			if (ipSplit.ipCidr.isNotEmpty()) rule.put("source_ip_cidr", JSONArray(ipSplit.ipCidr))
			if (ipSplit.ipIsPrivate) rule.put("source_ip_is_private", true)
			if (ipSplit.ipIsNotPrivate) deferred.notPrivateSource = true
			for (code in ipSplit.geoip) deferred.sourceSets.add(countrySet(code, ruleSets))
			for (code in ipSplit.geoipNot) deferred.invertedSourceSets.add(countrySet(code, ruleSets))
			stated(sourceKey, before)
		}
		// Xray adds "domains" to "domain" as one condition.
		if (xrayRule.has("domain") || xrayConditionStated("domains", xrayRule.opt("domains"))) {
			val before = shape()
			val droppedDom = mutableListOf<String>()
			val written = SingBoxUtil.asList(xrayRule.opt("domain")) +
				SingBoxUtil.asList(xrayRule.opt("domains"))
			val domains = splitDomains(written, droppedDom)
			if (droppedDom.isNotEmpty()) notes.add(
				"routing.rules[$index]: ${droppedDom.joinToString(", ")} is not a name condition " +
					"the core can read and was dropped from the rule"
			)
			applyDomainSplit(rule, domains, ruleSets)
			stated("domain", before)
		}
		if (xrayRule.has("ip")) {
			val before = shape()
			val droppedIp = mutableListOf<String>()
			val ipSplit = splitIps(SingBoxUtil.asList(xrayRule.opt("ip")), droppedIp)
			if (droppedIp.isNotEmpty()) notes.add(
				"routing.rules[$index]: ${droppedIp.joinToString(", ")} is not an address the core " +
					"can read (or names an Xray data file) and was dropped from the rule"
			)
			if (ipSplit.ipCidr.isNotEmpty()) rule.put("ip_cidr", JSONArray(ipSplit.ipCidr))
			if (ipSplit.ipIsPrivate) rule.put("ip_is_private", true)
			if (ipSplit.ipIsNotPrivate) deferred.notPrivate = true
			applyGeoipToRuleSet(rule, ipSplit.geoip, ruleSets)
			for (code in ipSplit.geoipNot) deferred.invertedSets.add(countrySet(code, ruleSets))
			stated("ip", before)
		}
		if (xrayRule.has("attrs")) {
			// Xray narrows a rule by HTTP attributes and sing-box has no equivalent. Kept, the
			// rule would act on traffic the source never sent here - and with nothing else to
			// narrow it, on all of it.
			lostAWholeCondition = true
			notes.add(
				"routing.rules[$index]: the attrs condition has no sing-box equivalent, so the " +
					"rule was dropped rather than applied to traffic it was not meant for"
			)
		}
		for (field in listOf("vlessRoute", "localIP", "localPort")) {
			if (!xrayConditionStated(field, xrayRule.opt(field))) continue
			lostAWholeCondition = true
			notes.add(
				"routing.rules[$index]: the $field condition has no sing-box equivalent, so the " +
					"rule was dropped rather than applied to traffic it was not meant for"
			)
		}
		if (xrayWebhookStated(xrayRule)) {
			notes.add("routing.rules[$index]: its webhook has no sing-box equivalent and was dropped")
		}
		if (xrayRule.has("user")) {
			val before = shape()
			val users = SingBoxUtil.asStringList(xrayRule.opt("user"))
			if (users.isNotEmpty()) rule.put("auth_user", JSONArray(users))
			stated("user", before)
		}
		// An empty list is no condition to Xray, and a rule left with none is dropped by the caller;
		// a list of nulls is one nothing matches, said here by dropping the rule.
		if (xrayConditionStated("process", xrayRule.opt("process"))) {
			val before = shape()
			val names = SingBoxUtil.asStringList(xrayRule.opt("process"))
			if (names.isNotEmpty()) rule.put("process_name", JSONArray(names))
			stated("process", before)
		}
		return lostAWholeCondition
	}

	// What an Xray rule states to narrow itself, and what a sing-box rule says to act rather than
	// to match. A rule holding only the second matches every connection there is.
	private val RULE_CONDITIONS = setOf(
		"domain", "ip", "port", "sourcePort", "network", "source", "user", "inboundTag",
		"protocol", "attrs", "process", "domains", "sourceIP", "vlessRoute", "localIP", "localPort"
	)
	private val RULE_ACTION_KEYS = setOf("outbound", "action", "invert", "server", "strategy")

	// direct: Xray dials this resolver itself ("+local"), so its queries never leave by the proxy.
	internal data class DnsAddr(val type: String?, val fields: JSONObject, val direct: Boolean = false)

	// Xray DNS address to a sing-box type + fields (https/h3/tls/quic/tcp/udp/dhcp/fakedns)
	internal fun parseDnsAddress(addrRaw: String?): DnsAddr =
		when (val kind = XrayDnsAddress.parse(addrRaw)) {
			XrayDnsAddress.Kind.FakeDns -> DnsAddr("fakeip", JSONObject())
			XrayDnsAddress.Kind.Local -> DnsAddr("local", JSONObject())
			XrayDnsAddress.Kind.None -> DnsAddr(null, JSONObject())
			is XrayDnsAddress.Kind.Dhcp -> DnsAddr(
				"dhcp",
				JSONObject().apply { if (kind.iface.isNotEmpty()) put("interface", kind.iface) }
			)
			is XrayDnsAddress.Kind.Remote -> DnsAddr(
				// The core spells the HTTP/3 transport "h3" and answers "http3" with "unknown
				// transport type", refusing the whole document.
				kind.scheme,
				JSONObject().apply {
					put("server", kind.host)
					kind.port?.let { put("server_port", it) }
					if (kind.path.isNotEmpty()) put("path", "/" + kind.path)
				},
				kind.direct
			)
		}

	internal fun makeDnsRule(obj: JSONObject, serverTag: String, ruleSets: MutableSet<String>): JSONObject? {
		val domains = SingBoxUtil.asList(obj.opt("domains"))
		if (domains.isEmpty()) return null
		val rule = JSONObject()
		rule.put("server", serverTag)
		val domainSplit = splitDomains(domains)
		applyDomainSplit(rule, domainSplit, ruleSets)
		return rule
	}

	internal fun fakeipRanges(fakednsObj: Any?, notes: MutableList<String>): Pair<String, String> {
		if (fakednsObj == null || fakednsObj === JSONObject.NULL) {
			return "198.18.0.0/15" to "fc00::/18"
		}
		val pools: List<JSONObject> = when (fakednsObj) {
			is JSONArray -> (0 until fakednsObj.length()).mapNotNull { fakednsObj.optJSONObject(it) }
			is JSONObject -> listOf(fakednsObj)
			else -> emptyList()
		}
		var ipv4Pool = "198.18.0.0/15"
		var ipv6Pool = "fc00::/18"
		for (poolEntry in pools) {
			val pool = poolEntry.optString("ipPool", "")
			when {
				fakeIpPoolBits(pool, ipv6 = false) != null -> ipv4Pool = pool
				fakeIpPoolBits(pool, ipv6 = true) != null -> ipv6Pool = pool
				else -> notes.add(fakeIpPoolDroppedNote(pool))
			}
		}
		return ipv4Pool to ipv6Pool
	}

	// Xray dns to sing-box dns (servers, rules, hosts, fakeip, final) notes collects anything
	// dropped on the way, so the caller can report it the same way it reports a dropped outbound.
	internal fun buildDns(
		xrayDns: JSONObject?,
		fakednsObj: Any?,
		dnsDetour: String?,
		ruleSets: MutableSet<String>,
		notes: MutableList<String>
	): JSONObject = DnsBuilder(xrayDns, fakednsObj, dnsDetour, ruleSets, notes).build()

	// One DNS block, built in the order its parts depend on each other: the servers and their
	// rules, the hosts server in front of them, the final server, and the flags.
	private class DnsBuilder(
		private val xrayDns: JSONObject?,
		private val fakednsObj: Any?,
		private val dnsDetour: String?,
		private val ruleSets: MutableSet<String>,
		private val notes: MutableList<String>
	) {
		private val out = JSONObject().put("servers", JSONArray()).put("rules", JSONArray())
		private val seenTags = mutableSetOf<String>()
		private var hasLocal = false
		private var hasFakeip = false
		private var fakeipTag: String? = null
		// Servers a rule narrows to certain names, which may answer nothing else, and servers
		// skipFallback keeps out of the order Xray asks about every other name.
		private val scopedTags = mutableSetOf<String>()
		private val noFallbackTags = mutableSetOf<String>()
		private var n = 0
		private val serversArr = xrayDns?.optJSONArray("servers") ?: JSONArray()
		private val outServers = out.getJSONArray("servers")
		private val outRules = out.getJSONArray("rules")
		// Read from the document each time: addHosts replaces the servers array to put the hosts
		// server in front, and anything appended to the old array would be lost with it.
		private val servers: JSONArray get() = out.getJSONArray("servers")
		// The answer filters of the servers every name falls to, by server tag - the address as written,
		// the rule, and its countries, whose rule-sets are fetched only for a filter that is placed.
		private val answerFilters = LinkedHashMap<String, Triple<String, JSONObject, List<String>>>()
		// The tag of the server Xray lists first, once it became one here.
		private var firstTag: String? = null
		// A 1.14 core refuses an answer filter in a DNS block whose rules name query types, as the
		// fakeip server's rule does.
		private val hasFakeipServer = (0 until serversArr.length()).any { i ->
			val raw = serversArr.opt(i)
			val address = (raw as? JSONObject)?.optString("address", "") ?: (raw as? String).orEmpty()
			parseDnsAddress(address).type == "fakeip"
		}

		fun build(): JSONObject {
			applyClientSubnet()
			addServers()
			placeAnswerFilters()
			addHosts()
			pickFinal()
			applyFlags()
			return out
		}

		private fun applyClientSubnet() {
			// Every case of the key arrives spelled clientIp: XrayKeys brings it to that.
			val clientSubnet = xrayDns?.optString("clientIp", "")
			if (clientSubnet.isNullOrEmpty()) return
			val subnet = xrayClientSubnet(clientSubnet)
			if (subnet != null) {
				out.put("client_subnet", subnet)
			} else {
				notes.add(unreadableClientIp("dns.clientIp", clientSubnet))
			}
		}

		private fun addServers() {
			// Each Xray DNS server -> a typed sing-box server (+ a domain rule)
			for (i in 0 until serversArr.length()) {
				val raw = serversArr.opt(i)
				val addrRaw: String
				val serverObject: JSONObject
				if (raw is String) {
					addrRaw = raw
					serverObject = JSONObject()
				} else if (raw is JSONObject) {
					addrRaw = raw.optString("address", "")
					serverObject = raw
				} else continue

				val parsed = parseDnsAddress(addrRaw)
				val serverType = parsed.type
				if (serverType == null) {
					notes.add(XrayDnsAddress.droppedReason(addrRaw))
					continue
				}

				// sing-box runs one fakeip server and refuses a second ("multiple fakeip server are not
				// supported"); a repeat answers from the same pool in Xray, so it is the first one again.
				val sameFakeip = fakeipTag.takeIf { serverType == "fakeip" }
				val srv = JSONObject()
				srv.put("type", serverType)
				var tag = sameFakeip ?: serverObject.optString("tag", "")
				if (sameFakeip == null) {
					if (serverType == "local") tag = "local"
					if (tag.isEmpty()) {
						tag = "dns-$n"; n++
					}
					while (tag in seenTags) {
						tag = "$tag-$n"; n++
					}
					seenTags.add(tag)
				}
				srv.put("tag", tag)
				if (i == 0) firstTag = tag

				val keys = parsed.fields.keys()
				while (keys.hasNext()) {
					val key = keys.next()
					srv.put(key, parsed.fields.opt(key))
				}
				if (!srv.has("server_port")) {
					val portValue = serverObject.opt("port")
					if (isTruthy(portValue)) {
						val port = when (portValue) {
							is Number -> portValue.toInt()
							is String -> portValue.toIntOrNull()
							else -> null
						}
						if (port != null) srv.put("server_port", port)
					}
				}

				val sqs = normalizeQueryStrategy(serverObject.optString("queryStrategy", ""))
				if (sqs.isNotEmpty() && QUERY_STRATEGY_MAP.containsKey(sqs)) {
					// Not domain_strategy: on a new-format server that is a dial field replacing the old
					// address_strategy - it resolves the server's own name, not what the queries return.
					notes.add(
						"dns.servers[].queryStrategy asks which address types the queries return, which " +
							"a sing-box server has no field for; the document-level queryStrategy is carried"
					)
				}
				// Xray's per-server clientIP is EDNS Client Subnet, but sing-box has client_subnet on dns and
				// dns.rules only, so it is carried below onto the rule built for this server.
				val sci = serverObject.optString("clientIp", "")

				// Xray dials a "+local" resolver itself, so its queries do not leave by the proxy;
				// the direct outbound is where sing-box says the same thing. Without this the
				// person's own resolver would be asked through the tunnel it was kept out of.
				val serverDetour = if (parsed.direct) "direct" else dnsDetour
				when {
					serverType in ENCRYPTED_DNS_TYPES -> {
						if (serverDetour != null) srv.put("detour", serverDetour)
						srv.put("domain_resolver", "local")
					}
					serverType == "udp" -> {
						if (serverDetour != null) srv.put("detour", serverDetour)
					}
					serverType == "local" -> hasLocal = true
					serverType == "fakeip" && sameFakeip == null -> {
						val ranges = fakeipRanges(fakednsObj, notes)
						srv.put("inet4_range", ranges.first)
						srv.put("inet6_range", ranges.second)
						hasFakeip = true
						fakeipTag = tag
					}
				}
				if (sameFakeip == null) outServers.put(srv)
				if (serverObject.optBoolean("skipFallback", false)) noFallbackTags.add(tag)

				val rule = makeDnsRule(serverObject, tag, ruleSets)
				val filtered = serverObject.xExpectedIps().isNotEmpty() ||
					serverObject.xStrList("unexpectedIPs").isNotEmpty()
				if (filtered) {
					readAnswerFilter(serverObject, addrRaw, tag, narrowed = rule != null, first = i == 0)
				}
				if (rule != null) {
					scopedTags.add(tag)
					if (serverType == "fakeip" && !rule.has("query_type")) {
						rule.put("query_type", JSONArray().put("A").put("AAAA"))
					}
					// The rule is what sends these queries to this server, so it is also where their
					// client subnet belongs.
					if (sci.isNotEmpty()) {
						val subnet = xrayClientSubnet(sci)
						if (subnet != null) {
							rule.put("client_subnet", subnet)
						} else {
							notes.add(unreadableClientIp("dns.servers[$i].clientIP", sci))
						}
					}
					outRules.put(rule)
				} else if (sci.isNotEmpty()) {
					// No domains, so no rule carries queries here and there is nowhere to scope the
					// subnet to.
					notes.add(
						"dns.servers[$i].clientIP: sing-box scopes the client subnet to a DNS rule, and " +
							"this server has no domains to build one from, so it was dropped"
					)
				}
			}
		}

		// Xray passes over a server whose answer holds none of its expectIPs and asks the next; a
		// sing-box rule filtered on the answer's addresses is skipped the same way. Only a plain
		// list of addresses and countries carries - a negation or unexpectedIPs has no such filter.
		private fun readAnswerFilter(
			server: JSONObject,
			addrRaw: String,
			tag: String,
			narrowed: Boolean,
			first: Boolean
		) {
			val dropped = mutableListOf<String>()
			val split = splitIps(server.xExpectedIps(), dropped)
			val why = when {
				xrayAsksFirstAlone(xrayDns) -> firstAloneFilterReason(first)
				server.xBool("finalQuery") -> FINAL_QUERY_FILTER_REASON
				server.xStrList("unexpectedIPs").isNotEmpty() || dropped.isNotEmpty() ||
					split.geoipNot.isNotEmpty() || split.ipIsNotPrivate ->
					"a negated or unreadable entry, or an unexpectedIPs list, has no sing-box answer filter"
				hasFakeipServer -> "a 1.14 core refuses it beside the query types of the fakeip server's rule"
				narrowed -> "on a server narrowed to domains it would share one rule with them"
				else -> null
			}
			if (why != null) {
				notes.add(droppedAnswerFilter(addrRaw, why))
				return
			}
			val rule = JSONObject()
			if (split.ipCidr.isNotEmpty()) rule.put("ip_cidr", JSONArray(split.ipCidr))
			if (split.ipIsPrivate) rule.put("ip_is_private", true)
			if (rule.length() == 0 && split.geoip.isEmpty()) return
			answerFilters[tag] = Triple(addrRaw, rule.put("server", tag), split.geoip)
		}

		// The servers every name falls to, in Xray's order: the filtered ones leading it become rules,
		// so the default is the first after them - Xray's next. A filter with no server after it, or
		// behind one that answers every name first, never decides.
		private fun placeAnswerFilters() {
			if (answerFilters.isEmpty()) return
			val order = (0 until outServers.length()).mapNotNull { outServers.optJSONObject(it) }
				.filter { it.optString("type", "") in REMOTE_DNS_TYPES }
				.map { it.optString("tag", "") }
				.filter { it !in noFallbackTags && it !in scopedTags }
			val lead = order.takeWhile { it in answerFilters }
			val placed = if (lead.size < order.size) lead else lead.dropLast(1)
			for (tag in placed) {
				val (_, rule, countries) = answerFilters.getValue(tag)
				if (countries.isNotEmpty()) {
					rule.put("rule_set", JSONArray(countries.map { countrySet(it, ruleSets) }))
				}
				outRules.put(rule)
				scopedTags.add(tag)
			}
			for ((tag, filter) in answerFilters) {
				if (tag in placed) continue
				val why = if (tag in lead) {
					"no server comes after it for sing-box to move on to"
				} else {
					"a server Xray asks before it answers every name, so it never decides"
				}
				notes.add(droppedAnswerFilter(filter.first, why))
			}
		}

		private fun droppedAnswerFilter(addrRaw: String, why: String) =
			"dns server \"$addrRaw\": the answer filter (expectIPs/unexpectedIPs) was dropped - $why"

		private fun addHosts() {
			// Static hosts -> a 'hosts' server in front, with a matching rule
			val hosts = xrayDns?.optJSONObject("hosts")
			if (hosts != null && hosts.length() > 0) {
				val predefined = JSONObject()
				// A "domain:" key is its name and every name under it; the hosts server matches whole
				// names alone, so the name itself is carried, after the exact keys that outrank it.
				val hostNames = hosts.keys().asSequence().sortedBy { it.startsWith("domain:") }
				for (host in hostNames) {
					val value = hosts.opt(host)
					// sing-box's hosts server maps exact names to addresses. A keyword, regexp or
					// geosite key has no such form and, written as it stands, would be a name nothing
					// ever asks for; a value that is another name has no place in it either.
					val name = when {
						host.startsWith("full:") -> host.removePrefix("full:")
						host.startsWith("domain:") -> host.removePrefix("domain:")
						host.contains(':') && host.substringBefore(':') in setOf("keyword", "regexp",
							"geosite", "ext") -> {
							notes.add("dns.hosts entry \"$host\" has no hosts form in sing-box and was " +
								"dropped")
							continue
						}
						else -> host
					}
					val ipsList = when (value) {
						is String -> listOf(value as Any?)
						is JSONArray -> (0 until value.length()).map { value.opt(it) as Any? }
						else -> emptyList()
					}
					val ipsOnly = ipsList.filter { isIpLiteral(it) }.map { it as String }
					if (ipsOnly.size < ipsList.size) {
						notes.add("dns.hosts entry \"$host\" maps to a name rather than an address, " +
							"which sing-box's hosts server has no form for, so that part was dropped")
					}
					if (ipsOnly.isEmpty()) continue
					if (!host.startsWith("domain:")) {
						predefined.put(name, JSONArray(ipsOnly))
						continue
					}
					val carried = if (predefined.has(name)) {
						"\"$name\" keeps its own entry"
					} else {
						predefined.put(name, JSONArray(ipsOnly))
						"\"$name\" is carried"
					}
					notes.add(
						"dns.hosts entry \"$host\": sing-box's hosts server matches whole names, so " +
							"$carried and the names under it resolve as usual"
					)
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

			if (!hasLocal) {
				val local = JSONObject()
				local.put("type", "local")
				local.put("tag", "local")
				servers.put(local)
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
		}

		private fun pickFinal() {
			val all = (0 until servers.length()).mapNotNull { servers.optJSONObject(it) }
			val remote = all.filter { it.optString("type", "") in REMOTE_DNS_TYPES }
			// Xray asks its first server alone about such names - the default, when it can be one.
			val firstAlone = xrayAsksFirstAlone(xrayDns)
			if (firstAlone) {
				val first = all.firstOrNull { it.optString("tag", "") == firstTag }
				if (first != null && first.optString("type", "") !in setOf("fakeip", "hosts")) {
					out.put("final", firstTag)
					return
				}
				notes.add(firstServerNotDefault(xrayFirstServer(xrayDns)))
			}
			val inFallback = { s: JSONObject -> s.optString("tag", "") !in noFallbackTags }
			val unnarrowed = { s: JSONObject -> s.optString("tag", "") !in scopedTags }
			val onDetour = { s: JSONObject ->
				dnsDetour == null || s.optString("detour", "") == dnsDetour
			}
			// sing-box asks its default server and stops where Xray moves on to the next: the
			// default is one Xray asks about any name, on the DNS route, narrowed by no rule -
			// weighed in that order, a tie going to the one listed first.
			val preference =
				compareBy<JSONObject>({ !inFallback(it) }, { !onDetour(it) }, { !unnarrowed(it) })
			val finalTag = remote.minWithOrNull(preference)?.optString("tag", "")
				// A fakeip server answers every query from its pool, so the core refuses it as the
				// default ("default server cannot be fakeip"); the hosts server answers only the
				// names it was given, so it cannot be the default either.
				?: all.firstOrNull { it.optString("type", "") !in setOf("fakeip", "hosts") }
					?.optString("tag", "")
			if (!finalTag.isNullOrEmpty()) out.put("final", finalTag)
			// The spare resolvers Xray would have moved on to: after the default and fed by no
			// rule, so carried but never asked.
			val spare = remote.count {
				inFallback(it) && unnarrowed(it) && it.optString("tag", "") != finalTag
			}
			if (spare > 0 && !firstAlone) {
				val rest = if (spare == 1) {
					"the server Xray would have asked next is carried but never reached"
				} else {
					"the $spare servers Xray would have asked next are carried but never reached"
				}
				notes.add("dns.servers: sing-box asks its default server and stops, so $rest")
			}
		}

		private fun applyFlags() {
			// sing-box has the same switch, under its own name.
			if (xrayDns?.optBoolean("disableCache", false) == true) out.put("disable_cache", true)
		}
	}
}
