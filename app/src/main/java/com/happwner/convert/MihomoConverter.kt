package com.happwner.convert

import com.happwner.text.JsonDepth
import com.happwner.text.isWholeJsonValue
import com.happwner.text.stripBrackets
import com.happwner.text.stripJsonComments
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

// Turns Xray Core JSON configurations into a mihomo (Clash Meta) YAML configuration.
object MihomoConverter {

	sealed class Result {
		data class Ok(
			val yaml: String,
			val converted: Int,
			val skipped: Int,
			val notes: List<String>
		) : Result()

		object NotXray : Result()

		// Xray, but nothing in it could be converted - carries the same per-outbound reasons as Ok.
		data class Unsupported(val notes: List<String> = emptyList(), val skipped: Int = 0) : Result()
	}

	// What mihomo makes of an input.
	enum class Verdict { CARRIED, UNSUPPORTED, NOT_XRAY }

	data class Check(val verdict: Verdict, val notes: List<String> = emptyList())

	// parseConfigs with a backstop: a bug in it reads as "not Xray" (malformed input already returns null).
	private fun parseConfigsOrNull(input: String) =
		try { parseConfigs(input) } catch (_: Exception) { null }

	// Answers without building the document - same question convertToOutbounds asks on the sing-box side.
	fun check(input: String): Check {
		val configs = parseConfigsOrNull(input) ?: return Check(Verdict.NOT_XRAY)

		return try {
			val conv = MihomoConversion()
			conv.convertAll(configs)
			val notes = conv.diagnostics.map { it.render() }
			Check(if (conv.proxies.isEmpty()) Verdict.UNSUPPORTED else Verdict.CARRIED, notes)
		} catch (error: Exception) {
			Check(
				Verdict.UNSUPPORTED,
				listOf(
					"skipped: conversion: internal error " +
						"(${error.javaClass.simpleName}): ${error.message ?: "no message"}"
				)
			)
		}
	}

	// Converts every Xray configuration in input into one mihomo document.
	fun convert(input: String): Result {
		val configs = parseConfigsOrNull(input) ?: return Result.NotXray

		return try {
			val conv = MihomoConversion()
			conv.convertAll(configs)
			if (conv.proxies.isEmpty()) {
				return Result.Unsupported(conv.diagnostics.map { it.render() }, conv.skipped)
			}
			// The probe URL/interval come from the first configuration naming them, like the DNS
			// block: the groups belong to the document, not to one configuration.
			val probe = configs.asSequence().map { xrayProbe(it) }
				.firstOrNull { it.url.isNotEmpty() || it.intervalSeconds != null }
			val standard = MihomoHealthCheck()
			val doc = buildMihomoDocument(
				conv.proxies, conv.groups, conv.selectable(),
				MihomoHealthCheck(
					url = probe?.url.orEmpty().ifEmpty { standard.url },
					interval = probe?.intervalSeconds?.takeIf { it > 0 } ?: standard.interval
				),
				conv.routingRules, conv.dnsBlock, conv.hostsBlock, conv.snifferBlock, conv.trustedCertificates
			)
			Result.Ok(
				yaml = encodeYaml(doc),
				converted = conv.converted,
				skipped = conv.skipped,
				notes = conv.diagnostics.map { it.render() }
			)
		} catch (error: Exception) {
			// Per-outbound failures are already caught in convertAll(), so this means
			// buildMihomoDocument/encodeYaml broke - a converter bug, not an unsupported input.
			Result.Unsupported(
				listOf(
					"skipped: document assembly: internal error (${error.javaClass.simpleName}): " +
						(error.message ?: "no message")
				)
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
		// Refused before parsing: Android's parser recurses per nesting level with no limit, and the
		// StackOverflowError it ends in would take the app down with it.
		if (JsonDepth.exceedsMaxDepth(trimmed)) return null
		if (!isWholeJsonValue(trimmed)) return null

		val value = JSONTokener(trimmed).nextValue().also(XrayKeys::canonicalize)

		val items: List<JSONObject> = when (value) {
			is JSONArray -> (0 until value.length()).mapNotNull { value.opt(it) as? JSONObject }
			is JSONObject -> listOf(value)
			else -> return null
		}
		if (items.isEmpty()) return null

		val configs = ArrayList<JSONObject>(items.size)
		var anyXray = false
		for (item in items) {
			val cfg = normalizeConfig(item) ?: continue
			if (cfg.xObjList("outbounds").any { it.xHas("protocol") }) anyXray = true
			configs.add(cfg)
		}
		if (!anyXray) return null
		return configs
	}

	// Accepts either a full configuration or a single outbound, returning a configuration whose
	// "outbounds" array is always present.
	private fun normalizeConfig(item: JSONObject): JSONObject? {
		// Some tools emit a single outbound at the top level instead of a list.
		val cfg = xrayWithOutbounds(item)
		if (cfg.xArr("outbounds") != null) return cfg
		if (item.xHas("protocol")) {
			val cfg = JSONObject()
			cfg.put("outbounds", JSONArray().put(item))
			return cfg
		}
		return null
	}
}

// A note of the conversion and where it came from - an outbound, a routing or DNS block; fatal when
// the outbound it names was left out.
internal class MihomoDiagnostic(val source: String, val message: String, val fatal: Boolean) {
	fun render(): String =
		(if (fatal) "skipped: " else "") + (if (source.isEmpty()) message else "$source: $message")
}

// A proxy group emitted ahead of the generated ones - how an Xray balancer is represented: its
// nodes become members, and only the group is selectable.
internal class MihomoGroup(
	val name: String,
	val type: String,
	val members: List<String>,
	// The load-balance strategy, for that group type alone.
	val strategy: String = "",
	val note: String = ""
)

// Raised when an outbound has no mihomo equivalent, so the node is dropped.
internal class MihomoUnsupported(message: String) : Exception(message)

// Carries the state shared by one conversion run.
internal class MihomoConversion {
	// The proxy and the Xray tag it dials through, resolved to a proxy name once every proxy of
	// the configuration is named.
	private val chainsToResolve = mutableListOf<Triple<YamlMap, String, String>>()
	val proxies = ArrayList<YamlMap>()
	val groups = ArrayList<MihomoGroup>()
	val routingRules = ArrayList<String>()
	var dnsBlock: YamlMap? = null
		private set
	var hostsBlock: YamlMap? = null
		private set
	var snifferBlock: YamlMap? = null
		private set

	// The CAs servers are verified against: mihomo reads them for the whole document, never per proxy.
	val trustedCertificates = LinkedHashSet<String>()

	private var routingSourceReported = false

	// Said once per pair of configurations that disagree about the same traffic.
	private val conflictsReported = mutableSetOf<String>()
	val diagnostics = ArrayList<MihomoDiagnostic>()
	var converted = 0
		private set
	var skipped = 0
		private set

	// Proxy names claimed by a balancer, offered through its group instead.
	private val balanced = HashSet<String>()

	// Pre-loaded with the generated group names and mihomo's built-ins: it shares one namespace
	// and rejects the whole config on a collision.
	private val names = UniqueNames(listOf(MIHOMO_SELECT_GROUP, MIHOMO_AUTO_GROUP,
		// mihomo resolves these itself; a proxy with one of these names would shadow the
		// built-in target inside every group.
		"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"))

	// Where the conversion is - an outbound, a routing or DNS block - for the notes it writes.
	private var src: String = ""
	// How many configurations the response holds: "config[N]" names one only among several.
	private var configCount = 1

	private fun place(configIndex: Int, path: String = ""): String =
		listOfNotNull("config[$configIndex]".takeIf { configCount > 1 }, path.ifEmpty { null })
			.joinToString(".")

	fun warn(message: String) {
		diagnostics.add(MihomoDiagnostic(src, message, fatal = false))
	}

	fun skip(message: String) {
		diagnostics.add(MihomoDiagnostic(src, message, fatal = true))
		skipped++
	}

	// Takes the routing and DNS of one configuration, once.
	private fun captureRoutingAndDns(
		cfg: JSONObject,
		configIndex: Int,
		tagNames: Map<String, List<String>>,
		freedoms: Map<String, JSONObject>
	) {
		// Mihomo doesn't sniff unless told to either - the first configuration whose inbound
		// asks decides, as with the DNS block below.
		if (snifferBlock == null) {
			src = place(configIndex, "inbounds")
			snifferBlock = MihomoRouting.sniffer(cfg) { message -> warn(message) }
		}

		// Blocks no client-side document holds - named rather than passed over, since a person
		// reading the answer can't see what was in the file it came from.
		src = place(configIndex)
		if (cfg.xHas("transport")) {
			warn(
				"the global transport block was removed from Xray, which refuses a configuration " +
					"carrying it, so nothing here was taken from it"
			)
		}
		if (cfg.xHas("reverse")) {
			warn(
				"reverse builds a tunnel back through this client, which mihomo has no form for, " +
					"so the reverse block was dropped"
			)
		}
		if (cfg.xHas("policy")) {
			warn(
				"policy sets Xray's own timeouts and buffers per user level, which mihomo decides " +
					"for itself, so the policy block was dropped"
			)
		}

		val routing = cfg.xObj("routing")
		val dns = cfg.xObj("dns")
		if (routing == null && dns == null) return

		val auxTargets = HashMap<String, String>()
		for (outbound in cfg.xObjList("outbounds")) {
			val tag = outbound.xStr("tag")
			if (tag.isEmpty()) continue
			when (outbound.xrayProtocol()) {
				// A freedom dialing through a node sends through it whatever goes to it; one whose chain ends
				// in nothing or a circle never connects, and a rule to it goes as a rule to such a node does.
				"freedom" -> {
					val end = chainThroughFreedoms(tag, tagNames, freedoms).second
					val node = end?.let { tagNames[it]?.firstOrNull() }
					when {
						node != null -> auxTargets[tag] = node
						end != null && end in freedoms -> auxTargets[tag] = "DIRECT"
					}
				}
				"blackhole" -> auxTargets[tag] = "REJECT"
			}
		}

		// Every configuration's rules, in order - a rule already in the list decides the same
		// traffic the same way, and the first is the one a core reads, so it isn't repeated.
		if (routing != null) {
			src = place(configIndex, "routing")
			val converted = MihomoRouting.rules(
				routing, { tag -> targetForTag(tag, tagNames, auxTargets) }
			) { warn(it) }
			for (rule in converted) {
				val earlier = routingRules.firstOrNull { conditionOfRule(it) == conditionOfRule(rule) }
				if (earlier == null) {
					routingRules.add(rule)
				} else if (earlier != rule && conflictsReported.add(conditionOfRule(rule))) {
					val first = targetOfRule(earlier)
					val other = targetOfRule(rule)
					warn(
						"two configurations route the same traffic to different places " +
							"(\"$first\" and \"$other\"); the first one decides and the other " +
							"was dropped"
					)
				}
			}
		}

		// One set of resolvers rather than a list to append to - the first configuration that
		// carries one decides, and the rest are said to have been left out.
		if (dns != null) {
			if (dnsBlock == null) {
				src = place(configIndex, "dns")
				dnsBlock = MihomoRouting.dns(cfg) { message -> warn(message) }
				hostsBlock = MihomoRouting.hosts(cfg) { message -> warn(message) }
			} else if (!routingSourceReported) {
				routingSourceReported = true
				src = place(configIndex, "dns")
				warn(
					"the DNS block was taken from the first configuration that carried one; " +
						"the ones after it were dropped"
				)
			}
		}
	}

	// A name can't hold a comma (sanitizeName sees to that, since a rule line is comma-separated),
	// so the target is what follows the last one, beside any trailing modifier.
	private fun conditionOfRule(rule: String): String =
		rule.removeSuffix(",no-resolve").substringBeforeLast(',')

	private fun targetOfRule(rule: String): String =
		rule.removeSuffix(",no-resolve").substringAfterLast(',')

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
		configCount = configs.size
		for ((configIndex, cfg) in configs.withIndex()) {
			val label = configLabel(cfg)
			val balancers = configBalancers(cfg)
			val outbounds = cfg.xObjList("outbounds")
			// A configuration label names a node unambiguously only when the file holds a single
			// proxy outbound - the usual shape of a generated per-node config.
			val proxyOutbounds = proxyOutboundCount(cfg.optJSONArray("outbounds"))

			// Each outbound's tag mapped to the proxies it produced, for the balancers below.
			val tagNames = LinkedHashMap<String, MutableList<String>>()

			for ((outboundIndex, outbound) in outbounds.withIndex()) {
				val proto = outbound.xrayProtocol()
				if (isNonProxyProtocol(proto)) {
					if (proto == "dns") dnsOutboundSettingsNote(outbound)?.let {
						src = place(configIndex, "outbounds[$outboundIndex] (dns)")
						warn(it)
					}
					continue
				}
				val protocolName = if (proto.isEmpty()) "no protocol" else proto
				src = place(configIndex, "outbounds[$outboundIndex] ($protocolName)")

				val preferred = labelledName(label, outbound.xStr("tag"),
					proxyOutbounds == 1 && balancers.isEmpty())
				ignoredServerListNote(outbound)?.let { warn(it) }
				val made = try {
					convertOutbound(xrayAsRead(outbound), proto, preferred)
				} catch (unsupported: MihomoUnsupported) {
					skip(unsupported.message ?: "the outbound could not be converted")
					continue
				} catch (error: Exception) {
					skip("internal error (${error.javaClass.simpleName}): ${error.message ?: "no message"}")
					continue
				}
				for (proxy in made) {
					proxies.add(proxy)
					converted++
					val tag = outbound.xStr("tag")
					if (tag.isNotEmpty()) {
						(proxy.get("name") as? String)?.let {
							tagNames.getOrPut(tag) { ArrayList() }.add(it)
						}
					}
				}
			}

			val freedoms = outbounds.filter { it.xrayProtocol() == "freedom" }.associateBy { it.xStr("tag") }
			resolveChains(proxies, tagNames, freedoms)
			balanced.addAll(buildBalancers(cfg, configIndex, tagNames))
			// Every configuration's rules join the list; the DNS block comes from the first that carries one.
			captureRoutingAndDns(cfg, configIndex, tagNames, freedoms)
		}

		// An "everything else through me" rule is true of one configuration alone, but false of a
		// document holding several - kept, it would pin every connection to one configuration's
		// servers. The closing MATCH into the selector decides instead.
		if (configs.size > 1 && routingRules.any { it.startsWith("MATCH,") }) {
			routingRules.removeAll { it.startsWith("MATCH,") }
			src = "routing"
			warn(
				"a configuration's rule for everything else was dropped, so that the group you " +
					"pick decides where that traffic goes rather than one configuration deciding " +
					"for all of them"
			)
		}

		// Dropped nodes are reported before degraded ones.
		val fatalFirst = diagnostics.filter { it.fatal } + diagnostics.filter { !it.fatal }
		diagnostics.clear()
		diagnostics.addAll(fatalFirst)
	}

	// Every proxy name, in output order.
	fun names(): List<String> = proxies.mapNotNull { it.get("name") as? String }

	// The entries to offer the user: one name per balancer group, plus every proxy no balancer claimed.
	fun selectable(): List<String> {
		val inner = HashSet<String>()
		for (group in groups) inner.addAll(group.members)
		val out = ArrayList<String>(groups.size + proxies.size)
		// A group that only exists to be wrapped by another one is not offered.
		for (group in groups) if (group.name !in inner) out.add(group.name)
		for (name in names()) if (name !in balanced) out.add(name)
		return out
	}

	private fun convertOutbound(outbound: JSONObject, proto: String, preferred: String): List<YamlMap> {
		// A stream in a block sing-box writes is no stream to judge, and the node no node to read.
		singBoxBlockOf(outbound)?.let { throw MihomoUnsupported(it) }
		// Then what Xray itself refuses, ahead of the rest, as in the other passes: the security layer
		// before the server, the credential and what the protocol asks of them.
		securityRefusal(outbound.xObj("streamSettings"))?.let { throw MihomoUnsupported(it) }
		chainConflictNote(outbound)?.let { warn(it) }
		finalmaskRefusal(outbound)?.let { throw MihomoUnsupported(it) }
		transportRefusal(outbound)?.let { throw MihomoUnsupported(it) }
		xrayOwnTransportOf(outbound)?.let { throw MihomoUnsupported(xrayOwnTransportRefusal(it)) }
		return when (proto) {
			"vless" -> convertVless(outbound, preferred)
			"vmess" -> convertVmess(outbound, preferred)
			"trojan" -> convertTrojan(outbound, preferred)
			"shadowsocks", "ss" -> convertShadowsocks(outbound, preferred)
			"socks", "socks5" -> convertSocks(outbound, preferred)
			"http", "https" -> convertHttp(outbound, preferred)
			"wireguard" -> convertWireGuard(outbound, preferred)
			"hysteria2", "hy2" -> convertHysteria2(outbound, preferred)
			"hysteria", "hy" -> convertHysteria(outbound, preferred)
			"tuic" -> convertTuic(outbound, preferred)
			"vlite" -> throw MihomoUnsupported("the VLITE protocol has no mihomo equivalent")
			"mtproto" -> throw MihomoUnsupported("the MTProto protocol has no mihomo equivalent")
			"masque" -> throw MihomoUnsupported(MASQUE_OUTBOUND_REFUSAL)
			else -> throw MihomoUnsupported("unsupported protocol \"$proto\"")
		}
	}

	// Builds a unique proxy name, preferring the configuration label, then the outbound tag, and
	// falling back to protocol/host/port.
	fun name(preferred: String, tag: String, proto: String, host: String, port: Int): String {
		var candidate = preferred.trim()
		if (candidate.isEmpty()) candidate = meaningfulTag(tag)
		if (candidate.isEmpty()) candidate = addressName(proto, host, port)
		return names.take(sanitizeName(candidate))
	}

	// Builds the common head of a proxy entry.
	fun base(name: String, type: String, server: String, port: Int): YamlMap {
		val addr = server.trim()
		// Named by the Xray protocol, as the other passes name it.
		val proto = when (type) { "ss" -> "shadowsocks"; "socks5" -> "socks"; else -> type }
		if (!LinkParams.usableHost(addr) || port !in 1..65535) {
			throw MihomoUnsupported(unusableServerRefusal(proto, addr, port))
		}
		val proxy = YamlMap()
		proxy.set("name", name)
		proxy.set("type", type)
		proxy.set("server", stripBrackets(addr))
		proxy.set("port", port)
		return proxy
	}

	// Sets "udp: true" when the options ask for it.
	fun udpFlag(proxy: YamlMap) {
		proxy.set("udp", true)
	}

	// sockopt options mihomo has no per-proxy field for. The sing-box converter reports the same
	// set, so one configuration reads the same whichever mode produced it.
	private val SOCKOPT_WITHOUT_MIHOMO_EQUIVALENT = listOf(
		"tcpNoDelay", "tcpUserTimeout", "tcpWindowClamp", "tcpMaxSeg",
		"V6Only", "penetrate", "addressPortStrategy", "happyEyeballs"
	)

	// Maps Xray's sockopt onto mihomo's per-proxy dialer options.
	fun applyDialer(proxy: YamlMap, outbound: JSONObject) {
		// mihomo binds by interface for the whole client, so a node pinned to one local
		// address here would silently use another.
		if (outbound.xBindsLocalAddress()) {
			warn("sendThrough is set per outbound, which mihomo has no place for, and was dropped")
		}
		finalmaskFeatures(outbound).forEach {
			warn("$it is Xray's own and has no mihomo equivalent, so it was dropped")
		}
		if (outbound.xStr("targetStrategy").isNotEmpty()) {
			warn(
				"targetStrategy picks the address family this outbound dials with, which mihomo " +
					"decides for the whole client, so it was dropped"
			)
		}
		if (outbound.xObj("streamSettings").xHas("downloadSettings")) warn(MISPLACED_DOWNLOAD_SETTINGS)
		if (outbound.xObj("streamSettings").xHas("dialerProxy")) warn(MISPLACED_DIALER_PROXY)
		olderConfigLeniencies(outbound).forEach { warn(it) }
		val sockopt = outbound.xObj("streamSettings").xObj("sockopt")
		if (sockopt != null) {
			proxy.setBoolTrue("tfo", sockopt.xBool("tcpFastOpen"))
			proxy.setBoolTrue("mptcp", sockopt.xBool("tcpMptcp"))
			proxy.setString("interface-name", sockopt.xStr("interface"))
			proxy.setInt("routing-mark", sockopt.xInt("mark"))

			when (sockopt.xStr("domainStrategy").lowercase()) {
				"useip4", "useipv4", "forceip4", "forceipv4" -> proxy.set("ip-version", "ipv4")
				"useip6", "useipv6", "forceip6", "forceipv6" -> proxy.set("ip-version", "ipv6")
				"useipv4v6", "forceipv4v6" -> proxy.set("ip-version", "ipv4-prefer")
				"useipv6v4", "forceipv6v4" -> proxy.set("ip-version", "ipv6-prefer")
			}
			val tproxy = sockopt.xStr("tproxy")
			if (tproxy.isNotEmpty() && tproxy != "off") {
				warn("sockopt.tproxy is an inbound-side option and was dropped")
			}
			if (sockopt.xAsksForKeepAlive()) {
				warn(
					"sockopt.tcpKeepAliveIdle / tcpKeepAliveInterval have no mihomo " +
						"equivalent and were dropped"
				)
			}
			if (sockopt.xStr("tcpcongestion").isNotEmpty()) {
				warn("sockopt.tcpcongestion has no mihomo equivalent and was dropped")
			}
			// The rest of sockopt has no per-proxy home in mihomo; each field is named one by
			// one, as the sing-box side does, so both modes answer the same config the same way.
			for (field in SOCKOPT_WITHOUT_MIHOMO_EQUIVALENT) {
				if (isTruthy(sockopt.opt(field))) warn(
					"sockopt.$field has no mihomo equivalent and was dropped")
			}
			if (isTruthy(sockopt.opt("customSockopt"))) {
				warn("sockopt.customSockopt sets raw socket options, which mihomo cannot express")
			}
		}

		// The chain as Xray reads it, kept for resolveChains: a tag's name is known once all are named.
		val chained = xrayChainTag(outbound)
		if (chained.isNotEmpty()) chainsToResolve.add(Triple(proxy, chained, src))
	}

	// Each chain as the name its target proxy got - the first, for several - past every freedom dialing
	// through another; at a freedom dialing straight out it ends with no dialer-proxy. A node whose target
	// left no proxy, was left out or goes round in a circle goes too: mihomo refuses such a file.
	fun resolveChains(
		proxies: MutableList<YamlMap>,
		tagNames: Map<String, MutableList<String>>,
		freedoms: Map<String, JSONObject>
	) {
		val chains = ArrayList<Triple<YamlMap, String, String>>()
		val circled = ArrayList<Triple<YamlMap, String, String>>()
		for ((proxy, chainTag, from) in chainsToResolve) {
			val (passed, end) = chainThroughFreedoms(chainTag, tagNames, freedoms)
			if (end == null) {
				circled.add(Triple(proxy, chainTag, from))
				continue
			}
			val straight = freedoms[end] != null
			if (!straight) chains.add(Triple(proxy, end, from))
			if (!straight && tagNames[end].isNullOrEmpty()) continue
			src = from
			for (tag in passed) {
				val settings = freedoms.getValue(tag).xObj("settings")
				val lost = listOfNotNull(
					"fragment".takeIf { settings.xHas(it) }, "noises".takeIf { settings.xHas(it) },
					"redirect".takeIf { settings.xStr(it).isNotEmpty() }
				)
				if (lost.isEmpty()) continue
				val onward = if (straight) "straight out as Xray does" else "which dials through \"$end\""
				warn("dials through freedom \"$tag\", $onward, but without its " +
					"${lost.joinToString(" and ")}, which mihomo has no option for")
			}
		}
		chainsToResolve.clear()
		val written = tagNames.filterValues { it.isNotEmpty() }.keys
		fun leaveOut(chain: Triple<YamlMap, String, String>, why: String) {
			val (proxy, targetTag, from) = chain
			src = from
			skip("dials through \"$targetTag\", which $why")
			proxies.removeAll { it === proxy }
			// Counted as converted when it was made; from here it counts as skipped.
			converted--
			val name = proxy.get("name") as? String
			for (names in tagNames.values) names.remove(name)
		}
		for (chain in circled) leaveOut(chain, "goes round in a circle of freedom outbounds")
		while (true) {
			val live = chains.filter { (proxy) -> proxies.any { it === proxy } }
			val fallen = live.filter { (_, targetTag) -> tagNames[targetTag].isNullOrEmpty() }
			for (chain in fallen) {
				val why = if (chain.second in written) "was left out itself" else "produced no proxy here"
				leaveOut(chain, why)
			}
			if (fallen.isNotEmpty()) continue
			val next = live.mapNotNull { (proxy, targetTag) ->
				(proxy.get("name") as? String)?.let { it to tagNames.getValue(targetTag).first() }
			}.toMap()
			val circling = live.filter { (proxy) -> leadsBack(proxy.get("name") as? String, next) }
			if (circling.isEmpty()) break
			for (chain in circling) leaveOut(chain, "leads back to it in a circle")
		}
		for ((proxy, targetTag, from) in chains) {
			if (proxies.none { it === proxy }) continue
			val targets = tagNames.getValue(targetTag)
			src = from
			proxy.set("dialer-proxy", targets.first())
			if (targets.size > 1) {
				warn("dials through \"$targetTag\", which became ${targets.size} proxies; the first, " +
					"\"${targets.first()}\", was used")
			}
		}
	}

	// The freedom outbounds a chain from this tag passes and the tag it ends at - a node, a freedom that
	// dials straight out, or a tag that produced nothing - with no end where the freedoms go in a circle.
	private fun chainThroughFreedoms(
		tag: String, tagNames: Map<String, List<String>>, freedoms: Map<String, JSONObject>
	): Pair<List<String>, String?> {
		val passed = ArrayList<String>()
		var at = tag
		while (tagNames[at].isNullOrEmpty()) {
			val freedom = freedoms[at] ?: break
			if (at in passed) return passed to null
			passed.add(at)
			at = xrayChainTag(freedom).takeIf { it.isNotEmpty() } ?: break
		}
		return passed to at
	}

	// Whether following dialer-proxies from this name comes back to it.
	private fun leadsBack(start: String?, next: Map<String, String>): Boolean {
		val seen = HashSet<String>()
		var current = next[start ?: return false] ?: return false
		while (true) {
			if (current == start) return true
			if (!seen.add(current)) return false
			current = next[current] ?: return false
		}
	}

	// Maps Xray's mux settings: mihomo doesn't implement mux.cool, but its XUDP fields still
	// describe how UDP is packed.
	fun applyMux(proxy: YamlMap, outbound: JSONObject, proto: String) {
		val mux = outbound.xObj("mux") ?: return
		if (!mux.xBool("enabled")) return
		when (proto) {
			"vless", "vmess" -> {
				if (mux.xInt("xudpConcurrency") != 0) proxy.set("packet-encoding", "xudp")
				warn(
					"mux.cool is enabled but mihomo does not implement it; only the XUDP packet " +
						"encoding was carried over"
				)
			}
			else -> warn("mux.cool is enabled but mihomo does not implement it; it was dropped")
		}
	}

	// Turns one configuration's balancers into proxy groups.
	private fun buildBalancers(
		cfg: JSONObject,
		configIndex: Int,
		tagNames: Map<String, List<String>>
	): Set<String> {
		val balancers = configBalancers(cfg)
		if (balancers.isEmpty()) return emptySet()

		val claimed = HashSet<String>()
		val label = configLabel(cfg)
		val routing = cfg.xObj("routing")
		val rules = routing.xObjList("rules")
		val hasRules = rules.isNotEmpty()
		// A balancer is routed to only by a rule whose balancerTag takes effect - one that names an
		// outbound as well is read as pointing at the outbound.
		val routed = rules.filter { it.xStr("outboundTag").isEmpty() }
			.map { it.xStr("balancerTag") }.filter { it.isNotEmpty() }.toSet()

		for ((balancerIndex, balancer) in balancers.withIndex()) {
			val tag = balancer.xStr("tag")
			src = place(configIndex, "routing.balancers[$balancerIndex] ($tag)")

			val members = balancerMembers(balancer, tagNames)
			if (members.isEmpty()) {
				warn("the balancer selected no node that could be converted; it was dropped")
				continue
			}

			val groupName = balancerGroupName(balancer, label, balancers.size)
			val (groupType, strategy) = balancerGroup(balancer)
			groups.add(
				MihomoGroup(
					name = groupName,
					type = groupType,
					members = members,
					strategy = strategy,
					note = "Xray balancer \"$tag\", strategy ${strategyDisplay(balancer)}"
				)
			)

			// A balancer no rule routes to is inert in Xray, but still becomes a group here since
			// the nodes have to go somewhere - saying so explains a group the panel never uses.
			if (hasRules && tag !in routed) {
				warn("no routing rule uses the balancer; its nodes were grouped anyway")
			}

			claimed.addAll(members)
			applyFallbackTag(balancer, tagNames, claimed)
		}
		return claimed
	}

	// The mihomo group a balancer becomes: roundRobin maps to load-balance's round-robin, and so
	// does random - Xray's default - with the reason said, mihomo having no random pick. leastPing
	// is what url-test measures; the rest fall back to url-test with the reason.
	private fun balancerGroup(balancer: JSONObject): Pair<String, String> {
		val named = balancer.xObj("strategy").xStr("type")
		return when (named.lowercase()) {
			"roundrobin" -> "load-balance" to "round-robin"
			"", "random" -> {
				val chosen = if (named.isEmpty()) {
					"names no strategy, so it ran Xray's default, random"
				} else {
					"uses the $named strategy"
				}
				warn(
					"the balancer $chosen, which picks a node at random for each connection; mihomo " +
						"has no random pick, so its load-balance group takes the nodes in turn"
				)
				"load-balance" to "round-robin"
			}
			else -> {
				balancerStrategyNote(balancer, "mihomo", "url-test")?.let { warn("the balancer $it") }
				"url-test" to ""
			}
		}
	}

	// Resolves the proxy names a balancer covers.
	private fun balancerMembers(balancer: JSONObject, tagNames: Map<String, List<String>>): List<String> {
		val selectors = balancer.xStrList("selector")
		// Xray sorts the selected tags, so the member order is reproducible.
		val tags = tagNames.keys
			.filter { tag -> selectors.any { tag.startsWith(it) } }
			.sorted()
		return tags.flatMap { tagNames[it].orEmpty() }
	}

	// Wraps the balancer group in a fallback group when the balancer names a spare outbound.
	private fun applyFallbackTag(
		balancer: JSONObject,
		tagNames: Map<String, List<String>>,
		claimed: MutableSet<String>
	) {
		val fallbackTag = balancer.xStr("fallbackTag")
		if (fallbackTag.isEmpty()) return
		val spares = tagNames[fallbackTag].orEmpty()
		if (spares.isEmpty()) {
			warn("fallbackTag \"$fallbackTag\" does not name a converted outbound; it was dropped")
			return
		}

		val inner = groups.removeAt(groups.size - 1)
		val outerName = inner.name
		// The two groups need distinct names; the outer one keeps the plain
		// name because that is what the user selects.
		val innerName = names.take("$outerName pool")
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
	private fun balancerGroupName(balancer: JSONObject, label: String, balancerCount: Int): String {
		val tag = balancer.xStr("tag")
		var candidate = when {
			label.isEmpty() -> tag
			// Several balancers share one label, so the tag tells them apart
			// while the label still leads the name.
			balancerCount > 1 -> "$label ($tag)"
			else -> label
		}
		return names.take(sanitizeName(candidate))
	}

}

// The strategy as the configuration spelled it, for messages a person reads.
private fun strategyDisplay(balancer: JSONObject): String {
	val strategy = balancer.xObj("strategy").xStr("type")
	return strategy.ifEmpty { "random" }
}

// The configuration's load balancers, skipping the ones Xray itself refuses.
internal fun configBalancers(cfg: JSONObject): List<JSONObject> =
	cfg.xObj("routing").xObjList("balancers")
		.filter { it.xStr("tag").isNotEmpty() && it.xStrList("selector").isNotEmpty() }

// Strips characters that break mihomo's proxy references or make a name unusable in a group.
internal fun sanitizeName(raw: String): String {
	var name = raw.trim()
	// Control characters and line breaks cannot appear in a name.
	name = name.filter { it.code >= 0x20 && it.code != 0x7f }.trim()
	// A comma would be read as a rule line's own separator - "US, LA" would become a rule
	// pointing at a proxy called "US", and mihomo refuses the whole configuration.
	if (name.contains(',')) {
		name = name.replace(',', ' ').replace(Regex(" {2,}"), " ").trim()
	}
	// A rule modifier closes the line rather than naming a proxy - "no-resolve" would read as
	// a rule with no target, the same reason as the comma.
	if (name.lowercase() in setOf("no-resolve", "src")) name = "$name node"
	if (name.isEmpty()) return "proxy"
	val maxNameLen = 120
	if (name.length > maxNameLen) {
		var end = maxNameLen
		// Do not split a surrogate pair, which would leave invalid text.
		if (Character.isHighSurrogate(name[end - 1])) end--
		name = name.substring(0, end).trim()
		if (name.isEmpty()) return "proxy"
	}
	return name
}

// Reads an outbound's settings object, which every protocol needs.
internal fun outboundSettings(outbound: JSONObject): JSONObject =
	outbound.xObj("settings") ?: throw MihomoUnsupported(
		unusableServerRefusal(outbound.xrayProtocol(), "", 0)
	)
