package com.happwner

/**
 * Assembles a complete mihomo (Clash Meta) configuration document around a set
 * of converted proxies.
 */

/** Controls the shape of the generated configuration. */
internal data class MihomoDocumentOptions(
    /** Emits just the "proxies:" block, which is the proxy-provider format. */
    val proxiesOnly: Boolean = false,
    /** The local HTTP/SOCKS port. */
    val mixedPort: Int = 7890,
    /** Opens the local listeners to the network. */
    val allowLan: Boolean = false,
    val logLevel: String = "info",
    /** The API listen address; empty disables it. */
    val externalController: String = "127.0.0.1:9090",
    val selectGroup: String = "PROXY",
    val autoGroup: String = "AUTO",
    /** The health-check URL of the automatic group. */
    val testUrl: String = "https://www.gstatic.com/generate_204",
    /** The health-check interval in seconds. */
    val testInterval: Int = 300
)

/**
 * The address blocks routed directly, so that local services keep working
 * without depending on downloaded GeoIP data.
 */
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

/**
 * Assembles the configuration document.
 *
 * [names] are the entries offered for selection. Where a balancer produced a
 * group, that group's name appears there in place of the nodes it covers, so
 * the individual members stay out of the user-facing lists.
 */
internal fun buildMihomoDocument(
    proxies: List<YamlMap>,
    groups: List<MihomoGroup>,
    names: List<String>,
    opts: MihomoDocumentOptions
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
        doc.set("dns", buildMihomoDns())
    }

    doc.set("proxies", YamlSeq(proxies))

    if (opts.proxiesOnly) return doc

    doc.set("proxy-groups", buildMihomoGroups(groups, names, opts))
    doc.set("rules", buildMihomoRules(opts))
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

/** Turns a balancer group into its YAML mapping. */
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
