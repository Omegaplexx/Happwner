package com.happwner.convert

import com.happwner.text.stripBrackets
import org.json.JSONArray
import org.json.JSONObject

// How a node is named from the configuration it came in, shared so the three passes cannot name one
// node three ways.

// Outbound tags that describe a role rather than a server, so they make poor proxy names.
private val GENERIC_TAGS = setOf(
	"proxy", "proxies", "out", "outbound", "default",
	"direct", "block", "blocked", "agentout", "main", "node"
)

// The name a node takes from its configuration: the label alone for a single proxy, the label with
// the outbound tag when the file holds several. Shared so the three passes cannot name one node three ways.
internal fun labelledName(label: String, tag: String, singleProxy: Boolean): String = when {
	label.isEmpty() -> ""
	singleProxy || tag.isEmpty() -> label
	else -> "$label #$tag"
}

// The human-readable name of a configuration, if it carries one.
internal fun configLabel(cfg: JSONObject): String =
	cfg.xStrOf("remarks", "remark", "name", "ps", "tag")

// Whether the outbound is a local action rather than a remote server. These become mihomo's
// DIRECT/REJECT targets and never appear in the proxies list.
internal fun isNonProxyProtocol(proto: String): Boolean =
	proto in setOf("freedom", "blackhole", "dns", "loopback", "")

// How many of a configuration's outbounds are servers rather than local actions, counted the one
// way every pass counts them: a node is named by what its file holds, not by what a pass carried.
internal fun proxyOutboundCount(outbounds: JSONArray?): Int = (0 until (outbounds?.length() ?: 0)).count {
	val outbound = outbounds?.optJSONObject(it)
	outbound != null &&
		!isNonProxyProtocol(outbound.optString("protocol", outbound.optString("type")).trim().lowercase())
}

// The name a node takes when the configuration named neither the file nor the node: what the node
// is, all that is left to tell it from the next one. A link with no name reaches the client as an
// unnamed row with the address where a name should be. The three passes say the same thing here.
internal fun addressName(proto: String, host: String, port: Int): String {
	val bare = stripBrackets(host)
	val shown = if (bare.contains(":")) "[$bare]" else bare
	if (shown.isEmpty()) return proto
	return if (port > 0) "$proto-$shown:$port" else "$proto-$shown"
}

internal fun meaningfulTag(tag: String): String {
	val trimmed = tag.trim()
	if (trimmed.isEmpty() || trimmed.lowercase() in GENERIC_TAGS) return ""
	return trimmed
}

// Names handed out so far, so a second node or group of one name is told apart from the first: it
// becomes "name #2", then "#3", as every pass names the second.
internal class UniqueNames(reserved: Collection<String> = emptyList()) {
	private val used = HashMap<String, Int>().apply { for (name in reserved) put(name, 1) }

	fun take(candidate: String): String {
		val taken = used[candidate] ?: run {
			used[candidate] = 1
			return candidate
		}
		var suffix = taken
		while (true) {
			suffix++
			val next = "$candidate #$suffix"
			if (!used.containsKey(next)) {
				used[candidate] = suffix
				used[next] = 1
				return next
			}
		}
	}
}
