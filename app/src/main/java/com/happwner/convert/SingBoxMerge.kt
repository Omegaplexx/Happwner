package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject

// Folds several converted sing-box configs into one runnable config: a selector over a url-test
// group, tags deduplicated, one inbound added.
internal object SingBoxMerge {
	// Merge several sing-box configs into one: rename tags, shared selector/urltest
	internal fun mergeUnified(
		fullConfigs: List<JSONObject>,
		notes: MutableList<String> = mutableListOf()
	): JSONObject? {
		if (fullConfigs.isEmpty()) return null
		if (fullConfigs.size == 1) return jsonCopy(fullConfigs[0])
		return SingBoxMergedDocument(fullConfigs, notes).build()
	}

	// What a rule matches on, without what it does about it.
	private val RULE_ACTION_KEYS = setOf("outbound", "action", "invert", "server", "strategy")

	// A value read out of a rule, as text. JSONObject.opt hands back null for a key the rule does
	// not hold, and a rule compared by its text needs an absent value and an empty one to read the same way.
	private fun valueAsText(rule: JSONObject, key: String): String =
		rule.opt(key)?.toString().orEmpty()

	internal fun conditionOf(rule: JSONObject): Map<String, String> =
		rule.keys().asSequence().filter { it !in RULE_ACTION_KEYS }
			.associateWith { valueAsText(rule, it) }

	internal fun sameCondition(one: JSONObject, other: JSONObject): Boolean =
		conditionOf(one) == conditionOf(other)

	// What a rule does, named the way it is written: an outbound, or an action when it has no
	// outbound to name.
	internal fun decisionOf(rule: JSONObject): String =
		rule.optString("outbound").ifEmpty { rule.optString("action") }

	// A rule that narrows on nothing, or only on being TCP or UDP, reaches every connection there is.
	internal fun reachesEverything(rule: JSONObject): Boolean {
		if (rule.optString("outbound").isEmpty()) return false
		val condition = conditionOf(rule)
		if (condition.isEmpty()) return true
		val networks = rule.optJSONArray("network") ?: return false
		val named = (0 until networks.length()).map { networks.getString(it) }.toSet()
		return condition.keys == setOf("network") && named == setOf("tcp", "udp")
	}

	// Two rules are the same when they say the same thing: JSON key order is not part of that.
	internal fun sameRule(one: JSONObject, other: JSONObject): Boolean {
		val keys = one.keys().asSequence().toSortedSet()
		if (keys != other.keys().asSequence().toSortedSet()) return false
		return keys.all { valueAsText(one, it) == valueAsText(other, it) }
	}

	// Built-in pre-rules (sniff/hijack-dns/resolve): we add our own and skip duplicates
	internal fun isPreRule(rule: JSONObject): Boolean {
		val action = rule.optString("action", "")
		if (action == "sniff" && rule.length() == 1) return true
		if (action == "hijack-dns" && (rule.has("protocol") || rule.has("port"))) return true
		if (action == "resolve" && rule.has("inbound")) return true
		return false
	}

	internal fun renameString(obj: JSONObject, key: String, rename: Map<String, String>) {
		val value = obj.opt(key)
		if (value !is String || value.isEmpty()) return
		val mapped = rename[value] ?: return
		if (mapped != value) obj.put(key, mapped)
	}

	internal fun renameStringArray(obj: JSONObject, key: String, rename: Map<String, String>) {
		val entries = obj.optJSONArray(key) ?: return
		var changed = false
		val newArr = JSONArray()
		for (i in 0 until entries.length()) {
			val item = entries.opt(i)
			if (item is String) {
				val mapped = rename[item]
				if (mapped != null && mapped != item) {
					newArr.put(mapped); changed = true
				} else {
					newArr.put(item)
				}
			} else {
				newArr.put(item)
			}
		}
		if (changed) obj.put(key, newArr)
	}

	internal fun rewriteOutbound(outbound: JSONObject, outRename: Map<String, String>,
		dnsRename: Map<String, String>) {
		renameString(outbound, "tag", outRename)
		renameString(outbound, "detour", outRename)
		renameStringArray(outbound, "outbounds", outRename)
		renameString(outbound, "default", outRename)
		val drRaw = outbound.opt("domain_resolver")
		if (drRaw is String && drRaw.isNotEmpty()) {
			val mapped = dnsRename[drRaw]
			if (mapped != null && mapped != drRaw) outbound.put("domain_resolver", mapped)
		} else if (drRaw is JSONObject) {
			renameString(drRaw, "server", dnsRename)
		}
	}

	internal fun rewriteDnsServer(server: JSONObject, outRename: Map<String, String>,
		dnsRename: Map<String, String>) {
		renameString(server, "tag", dnsRename)
		renameString(server, "detour", outRename)
		val drRaw = server.opt("domain_resolver")
		if (drRaw is String && drRaw.isNotEmpty()) {
			val mapped = dnsRename[drRaw]
			if (mapped != null && mapped != drRaw) server.put("domain_resolver", mapped)
		} else if (drRaw is JSONObject) {
			renameString(drRaw, "server", dnsRename)
		}
	}

	// What a DNS server is, apart from what it is called: key order is not part of it.
	internal fun dnsServerContent(server: JSONObject): String =
		server.keys().asSequence().filter { it != "tag" }.sorted()
			.joinToString("\u0000") { "$it=${server.opt(it)}" }

	internal fun rewriteDnsRule(rule: JSONObject, outRename: Map<String, String>,
		dnsRename: Map<String, String>) {
		renameString(rule, "server", dnsRename)
		renameString(rule, "outbound", outRename)
	}

	internal fun rewriteRouteRule(rule: JSONObject, outRename: Map<String, String>,
		dnsRename: Map<String, String>) {
		renameString(rule, "outbound", outRename)
		renameString(rule, "server", dnsRename)
	}
}
