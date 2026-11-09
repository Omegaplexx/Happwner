package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// Xray reads its config with Go's encoding/json, which takes a key for a field whatever its case; the
// passes read exact spellings, so an Xray config's keys are brought to them once, as it is parsed.
internal object XrayKeys {
	// Every key a pass reads from an Xray config. XrayKeysTest holds it whole: a key read anywhere in
	// the converters and missing here fails the tests.
	internal val READ: Set<String> = setOf(
		"Host", "accounts", "action", "address", "allowInsecure", "allowedIPs", "alpn",
		"alterId", "alter_id", "attrs", "auth", "authStr", "auth_str", "authenticatedLength",
		"authenticated_length", "authority", "balancerTag", "balancers", "bandwidth", "bbrProfile",
		"brutalDown", "brutalUp", "burstObservatory", "cache_file", "certificate", "certificateFile",
		"certificate_path", "certificate_public_key_sha256", "certificate_sha256", "certificates",
		"cipherSuites", "clientIp", "client_subnet", "congestion", "congestion_control", "curvePreferences",
		"customSockopt", "cwnd", "delay", "delays", "destOverride", "destination",
		"detour", "dialerProxy", "disableCache", "disableFallback", "disableSystemRoot", "dns", "domain",
		"domainStrategy", "domain_resolver", "domains", "domainsExcluded", "down", "downMbps", "down_mbps",
		"downlinkCapacity", "downloadSettings", "download_detour", "earlyDataHeaderName", "ech",
		"echConfigList", "enableSessionResumption", "enabled", "encryption", "endpoint", "endpoints",
		"experimental", "experiments", "extra", "fakedns", "fallbackTag", "final", "finalQuery",
		"finalmask", "fingerprint", "flow", "fragment", "globalPadding", "global_padding", "grpcSettings",
		"gunSettings", "hKeepAlivePeriod", "header", "headers", "health_check_timeout", "heartbeatPeriod",
		"hopInterval", "hop_interval", "hop_interval_max", "host", "hosts", "httpSettings",
		"httpupgradeSettings", "hysteriaSettings", "id", "idle_timeout", "inbound", "inboundTag", "inbounds",
		"initConnectionReceiveWindow", "initStreamReceiveWindow", "initial_windows_size", "insecure",
		"interface", "interval", "ip", "ipPool", "ip_cidr", "ip_is_private", "ipsExcluded", "ipv6",
		"kcpSettings", "keepAlive", "key", "keyFile", "listen", "localIP",
		"localPort", "log", "loglevel", "mark", "masterKeyLog",
		"maxConnectionReceiveWindow", "maxEarlyData", "maxStreamReceiveWindow", "maxVersion",
		"metadataOnly", "method", "minVersion", "mldsa65Verify", "mode", "mtu", "multiMode", "mux", "name",
		"network", "noGRPCHeader", "noSSEHeader", "noises", "obfs", "obfs-password", "obfsPassword",
		"observatory", "outbound", "outboundTag", "outbounds", "packetEncoding", "packets",
		"pass", "password",
		"path", "peers", "permit_without_stream", "pinSHA256", "pingConfig", "pinnedPeerCertSha256",
		"pinnedPeerCertificateChainSha256", "pinnedPeerCertificatePublicKeySha256", "plugin", "pluginOpts",
		"plugin_opts", "policy", "port", "ports", "preSharedKey", "probeInterval", "probeURL", "process",
		"protocol", "proxySettings", "ps", "publicKey", "queryStrategy", "query_type", "quicParams",
		"quicSettings", "rawSettings", "read_idle_timeout", "reality", "realitySettings", "redirect",
		"remark", "remarks", "remoteIPs", "remotePorts", "request", "reserved", "response",
		"reuse-settings", "reverse", "route", "routeOnly",
		"routing", "rule_set", "rules", "salamander", "scMaxBufferedPosts", "secretKey", "security",
		"seed", "selector", "sendThrough", "seqKey", "seqPlacement", "server", "serverName", "serverNames",
		"server_name", "server_port", "server_ports", "servers", "serviceName", "sessionIDKey",
		"sessionIDPlacement", "sessionIDTable", "sessionKey", "sessionPlacement", "settings", "shortId",
		"shortIds", "skip-cert-verify", "skipFallback", "sni", "sniffing", "sockopt", "source", "sourceIP",
		"sourcePort", "spiderX",
		"splithttpSettings", "strategy", "streamSettings", "tag", "targetStrategy", "tcpFastOpen",
		"tcpKeepAliveIdle", "tcpKeepAliveInterval", "tcpMptcp", "tcpSettings", "tcpcongestion", "tls",
		"tlsSettings", "token", "tproxy", "transport", "tti", "type", "udp", "udpHop", "udpIdleTimeout",
		"udpMTU", "udp_relay_mode", "unexpectedIPs", "uot", "up", "upMbps", "up_mbps", "uplinkCapacity",
		"uplinkDataKey", "uplinkDataPlacement", "uplinkHTTPMethod",
		"url", "usage", "useBrowserForwarding",
		"user", "user_agent", "username", "users", "uuid", "value", "verifyPeerCertByName",
		"verifyPeerCertInNames", "version", "vlessRoute", "vnext", "webhook", "websocketSettings",
		"workers", "wsSettings", "xPaddingHeader", "xPaddingKey",
		"xPaddingMethod", "xPaddingObfsMode", "xPaddingPlacement", "xhttpSettings", "xmux", "xtlsSettings",
		"xudpConcurrency"
	)

	// A key read in two spellings, and the one Xray's field goes by: "Host" is read as a header name.
	private val PREFERRED = mapOf("host" to "host")

	private val byFold: Map<String, String> = READ.groupBy { it.lowercase() }
		.mapValues { (fold, spellings) -> PREFERRED[fold] ?: spellings.single() }

	// Objects that are maps rather than fields - header names, host names, attributes, levels - keep
	// their keys as written, as Go does.
	private val MAPS = setOf("headers", "hosts", "attrs", "levels")

	// Renames in place, without recursion, every key that differs from one read only in case; a key
	// already spelled exactly keeps its value.
	internal fun canonicalize(root: Any?) {
		val pending = ArrayDeque<Any?>()
		pending.addLast(root)
		while (pending.isNotEmpty()) {
			when (val node = pending.removeLast()) {
				is JSONObject -> for (key in node.keys().asSequence().toList()) {
					val canon = byFold[key.lowercase()]
					val name = if (canon != null && canon != key && !node.has(canon)) {
						node.put(canon, node.remove(key))
						canon
					} else {
						key
					}
					if (name.lowercase() !in MAPS) pending.addLast(node.opt(name))
				}
				is JSONArray -> for (i in 0 until node.length()) pending.addLast(node.opt(i))
			}
		}
	}
}
