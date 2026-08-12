package com.happwner.convert

// Assembles a complete mihomo (Clash Meta) configuration document around a set of converted
// proxies.

// Names of the two groups this builder always generates. The converter reserves them, since mihomo
// shares one namespace for proxies and groups and rejects the whole config on a collision.
internal const val MIHOMO_SELECT_GROUP = "PROXY"
internal const val MIHOMO_AUTO_GROUP = "AUTO"

// Controls the shape of the generated configuration.
internal data class MihomoDocumentOptions(
    // Emits just the "proxies:" block, which is the proxy-provider format.
    val proxiesOnly: Boolean = false,
    // The local HTTP/SOCKS port.
    val mixedPort: Int = 7890,
    // Opens the local listeners to the network.
    val allowLan: Boolean = false,
    val logLevel: String = "info",
    // The API listen address; empty disables it.
    val externalController: String = "127.0.0.1:9090",
    val selectGroup: String = MIHOMO_SELECT_GROUP,
    val autoGroup: String = MIHOMO_AUTO_GROUP,
    // The health-check URL of the automatic group.
    val testUrl: String = "https://www.gstatic.com/generate_204",
    // The health-check interval in seconds.
    val testInterval: Int = 300
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

// Assembles the configuration document. names are the entries offered for selection - a balancer's
// group name stands in for the nodes it covers.
internal fun buildMihomoDocument(
    proxies: List<YamlMap>,
    groups: List<MihomoGroup>,
    names: List<String>,
    opts: MihomoDocumentOptions,
    // routing.rules from the source, when it had any.
    convertedRules: List<String> = emptyList(),
    // The source's DNS block and hosts, when it had them.
    convertedDns: YamlMap? = null,
    convertedHosts: YamlMap? = null
): YamlMap {
    val doc = YamlMap()

    if (!opts.proxiesOnly) {
        doc.set("mixed-port", opts.mixedPort)
        doc.set("allow-lan", opts.allowLan)
        doc.set("mode", "rule")
        doc.set("log-level", opts.logLevel.ifBlank { "info" })
        doc.set("ipv6", true)
        if (opts.externalController.isNotEmpty()) {
            doc.set("external-controller", opts.externalController)
        }
        // The source's own DNS when it stated one; the default is only a
        // stand-in for a configuration that said nothing about it.
        doc.set("dns", convertedDns ?: buildMihomoDns())
        convertedHosts?.let { doc.set("hosts", it) }
    }

    doc.set("proxies", YamlSeq(proxies))

    if (opts.proxiesOnly) return doc

    doc.set("proxy-groups", buildMihomoGroups(groups, names, opts))
    // The source's own rules, with the private-address rules in front so local traffic still leaves the
    // tunnel alone, and MATCH last so anything the source did not decide still has somewhere to go.
    doc.set("rules", if (convertedRules.isEmpty()) buildMihomoRules(opts)
                     else mergeMihomoRules(convertedRules, opts))
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
private fun renderMihomoGroup(g: MihomoGroup, opts: MihomoDocumentOptions): YamlMap {
    val m = YamlMap()
    m.set("name", g.name)
    m.set("type", g.type)

    when (g.type) {
        "url-test", "fallback", "load-balance" -> {
            m.set("url", opts.testUrl.ifBlank { "https://www.gstatic.com/generate_204" })
            m.set("interval", if (opts.testInterval > 0) opts.testInterval else 300)
        }
    }
    if (g.type == "url-test") m.set("tolerance", 50)
    if (g.type == "load-balance" && g.strategy.isNotEmpty()) m.set("strategy", g.strategy)

    m.set("proxies", YamlSeq(g.members))
    return m
}

private fun buildMihomoGroups(
    groups: List<MihomoGroup>,
    names: List<String>,
    opts: MihomoDocumentOptions
): YamlSeq {
    val selectName = opts.selectGroup.ifBlank { "PROXY" }
    val autoName = opts.autoGroup.ifBlank { "AUTO" }

    if (names.isEmpty()) {
        // A group with no members makes mihomo refuse to start, so fall back to
        // the built-in DIRECT target.
        val sel = YamlMap()
        sel.set("name", selectName)
        sel.set("type", "select")
        sel.set("proxies", YamlFlowSeq(listOf("DIRECT")))
        return YamlSeq(listOf(sel))
    }

    val selectMembers = YamlSeq()
    selectMembers.add(autoName)
    selectMembers.addAll(names)
    selectMembers.add("DIRECT")

    val sel = YamlMap()
    sel.set("name", selectName)
    sel.set("type", "select")
    sel.set("proxies", selectMembers)

    val auto = YamlMap()
    auto.set("name", autoName)
    auto.set("type", "url-test")
    auto.set("url", opts.testUrl.ifBlank { "https://www.gstatic.com/generate_204" })
    auto.set("interval", if (opts.testInterval > 0) opts.testInterval else 300)
    auto.set("tolerance", 50)
    auto.set("proxies", YamlSeq(names))

    // The balancer groups come first: they are what the two generated groups
    // select between, and mihomo resolves references in any order.
    val out = YamlSeq()
    for (g in groups) {
        val rendered = renderMihomoGroup(g, opts)
        if (g.note.isNotEmpty()) {
            // Saying where the group came from makes the file readable without
            // the Xray configuration next to it.
            out.add(YamlCommented(g.note, rendered))
        } else {
            out.add(rendered)
        }
    }
    out.add(sel)
    out.add(auto)
    return out
}

// The converted rules, with only the closing MATCH added. Nothing of ours goes in front: with the
// private ranges ahead, a block rule silently became a direct connection for local-resolving names.
private fun mergeMihomoRules(converted: List<String>, opts: MihomoDocumentOptions): YamlSeq {
    val rules = YamlSeq()
    for (r in converted) rules.add(r)
    rules.add("MATCH,${opts.selectGroup}")
    return rules
}

private fun buildMihomoRules(opts: MihomoDocumentOptions): YamlSeq {
    val selectName = opts.selectGroup.ifBlank { "PROXY" }
    val rules = YamlSeq()
    for (cidr in PRIVATE_RANGES) {
        // no-resolve keeps mihomo from looking up a domain just to match a
        // local address range.
        rules.add("IP-CIDR,$cidr,DIRECT,no-resolve")
    }
    rules.add("MATCH,$selectName")
    return rules
}
