package com.happwner.convert

// Names of the two groups this builder always generates. The converter reserves them, since mihomo
// shares one namespace for proxies and groups and rejects the whole config on a collision.
internal const val MIHOMO_SELECT_GROUP = "PROXY"
internal const val MIHOMO_AUTO_GROUP = "AUTO"

// The health check the url-test groups run: the probe the source named, or mihomo's usual one.
internal data class MihomoHealthCheck(
	val url: String = "https://www.gstatic.com/generate_204",
	// Seconds between checks.
	val interval: Int = 300
)

// The address blocks routed directly, so that local services keep working without depending on
// downloaded GeoIP data.
private val PRIVATE_RANGES = listOf(
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"::1/128",
	"fc00::/7",
	"fe80::/10"
)

// Assembles the mihomo (Clash Meta) configuration document around the converted proxies. names are
// the entries offered for selection - a balancer's group name stands in for the nodes it covers.
internal fun buildMihomoDocument(
	proxies: List<YamlMap>,
	groups: List<MihomoGroup>,
	names: List<String>,
	healthCheck: MihomoHealthCheck,
	// routing.rules from the source, when it had any.
	convertedRules: List<String>,
	// The source's DNS block and hosts, when it had them.
	convertedDns: YamlMap?,
	convertedHosts: YamlMap?,
	// The sniffer the source's inbounds asked for, when any did.
	convertedSniffer: YamlMap?,
	// The CAs servers are verified against, which mihomo reads for the whole document only.
	trustedCertificates: Collection<String> = emptyList()
): YamlMap {
	val doc = YamlMap()

	doc.set("mixed-port", 7890)
	doc.set("allow-lan", false)
	doc.set("mode", "rule")
	doc.set("log-level", "info")
	doc.set("ipv6", true)
	doc.set("external-controller", "127.0.0.1:9090")
	// The source's own DNS when it stated one; the default is only a
	// stand-in for a configuration that said nothing about it.
	doc.set("dns", convertedDns ?: buildMihomoDns())
	convertedHosts?.let { doc.set("hosts", it) }
	convertedSniffer?.let { doc.set("sniffer", it) }

	if (trustedCertificates.isNotEmpty()) {
		doc.set("tls", YamlMap().set("custom-certifactes", YamlSeq().apply { addAll(trustedCertificates) }))
	}
	doc.set("proxies", YamlSeq(proxies))

	doc.set("proxy-groups", buildMihomoGroups(groups, names, healthCheck))
	// The source's own rules, closed by MATCH where none of them matches everything; the private-address
	// rules only for a source with none: ahead of its block rule they would make it a direct connection
	// for local-resolving names.
	doc.set("rules", if (convertedRules.isEmpty()) buildMihomoRules()
					 else mergeMihomoRules(convertedRules))
	return doc
}

private fun buildMihomoDns(): YamlMap {
	val dns = YamlMap()
	dns.set("enable", true)
	dns.set("ipv6", true)
	dns.set("enhanced-mode", "fake-ip")
	dns.set("fake-ip-range", "198.18.0.1/16")
	dns.set(
		"nameserver",
		YamlFlowSeq(listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"))
	)
	return dns
}

// Turns a balancer group into its YAML mapping.
private fun renderMihomoGroup(group: MihomoGroup, healthCheck: MihomoHealthCheck): YamlMap {
	val rendered = YamlMap()
	rendered.set("name", group.name)
	rendered.set("type", group.type)

	when (group.type) {
		"url-test", "fallback", "load-balance" -> {
			rendered.set("url", healthCheck.url)
			rendered.set("interval", healthCheck.interval)
		}
	}
	if (group.type == "url-test") rendered.set("tolerance", 50)
	if (group.strategy.isNotEmpty()) rendered.set("strategy", group.strategy)

	rendered.set("proxies", YamlSeq(group.members))
	return rendered
}

private fun buildMihomoGroups(
	groups: List<MihomoGroup>,
	names: List<String>,
	healthCheck: MihomoHealthCheck
): YamlSeq {
	val selectName = MIHOMO_SELECT_GROUP
	val autoName = MIHOMO_AUTO_GROUP

	val selectMembers = YamlSeq()
	selectMembers.add(autoName)
	selectMembers.addAll(names)
	selectMembers.add("DIRECT")

	val selector = YamlMap()
	selector.set("name", selectName)
	selector.set("type", "select")
	selector.set("proxies", selectMembers)

	val auto = YamlMap()
	auto.set("name", autoName)
	auto.set("type", "url-test")
	auto.set("url", healthCheck.url)
	auto.set("interval", healthCheck.interval)
	auto.set("tolerance", 50)
	auto.set("proxies", YamlSeq(names))

	// The balancer groups come first: they are what the two generated groups
	// select between, and mihomo resolves references in any order.
	val out = YamlSeq()
	for (group in groups) {
		val rendered = renderMihomoGroup(group, healthCheck)
		if (group.note.isNotEmpty()) {
			// Saying where the group came from makes the file readable without
			// the Xray configuration next to it.
			out.add(YamlCommented(group.note, rendered))
		} else {
			out.add(rendered)
		}
	}
	out.add(selector)
	out.add(auto)
	return out
}

// The converted rules, with only the closing MATCH added - unless one of them matches everything
// already. Nothing of ours goes in front: with the private ranges ahead, a block rule would become
// a direct connection for local-resolving names.
private fun mergeMihomoRules(converted: List<String>): YamlSeq {
	val rules = YamlSeq()
	for (rule in converted) rules.add(rule)
	// The same fallback the group itself is built with: a rule pointing at an empty name is a file
	// mihomo refuses.
	if (converted.none { it.startsWith("MATCH,") }) rules.add("MATCH,${MIHOMO_SELECT_GROUP}")
	return rules
}

private fun buildMihomoRules(): YamlSeq {
	val selectName = MIHOMO_SELECT_GROUP
	val rules = YamlSeq()
	for (cidr in PRIVATE_RANGES) {
		// no-resolve keeps mihomo from looking up a domain just to match a
		// local address range.
		rules.add("IP-CIDR,$cidr,DIRECT,no-resolve")
	}
	rules.add("MATCH,$selectName")
	return rules
}
