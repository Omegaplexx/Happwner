package com.happwner.convert

import com.happwner.text.isIpLiteral
import org.json.JSONArray
import org.json.JSONObject

// Small shared helpers for the sing-box converter.
internal object SingBoxUtil {

	// The plain direct outbound a document routes to by its "direct" tag.
	internal fun directOutbound(): JSONObject =
		JSONObject().put("type", "direct").put("tag", "direct")

	// Drops each detour to a direct outbound holding nothing of its own, or to "direct" where the document
	// holds none - a "+local" resolver's, when the freedom tagged so dialed through a node: sing-box starts
	// no resolver and connects no node through either; with no detour each dials straight out, as asked.
	internal fun dropEmptyDirectDetours(config: JSONObject) {
		val outbounds = asList(config.opt("outbounds")).filterIsInstance<JSONObject>()
		val empty = outbounds.filter { it.optString("type") == "direct" && it.length() == 2 }
			.map { it.optString("tag") }.toMutableSet()
		if (outbounds.none { it.optString("tag") == "direct" }) empty.add("direct")
		val resolvers = asList(config.optJSONObject("dns")?.opt("servers")).filterIsInstance<JSONObject>()
		val dialing = outbounds + asList(config.opt("endpoints")).filterIsInstance<JSONObject>() + resolvers
		for (holder in dialing) {
			if (holder.optString("detour") !in empty) continue
			holder.remove("detour")
			// Straight out, a resolver finds a server written by name through the local resolver, as the
			// direct outbound found it.
			val named = holder.has("server") && !isIpLiteral(holder.optString("server"))
			if (named && resolvers.any { it === holder } && !holder.has("domain_resolver")) {
				holder.put("domain_resolver", SingBoxConverter.LOCAL_DNS_TAG)
			}
		}
	}

	internal fun asList(value: Any?): List<Any?> {
		if (value == null || value === JSONObject.NULL) return emptyList()
		if (value is JSONArray) {
			val out = ArrayList<Any?>(value.length())
			for (i in 0 until value.length()) out.add(value.opt(i))
			return out
		}
		return listOf(value)
	}

	internal fun asStringList(value: Any?): List<String> {
		return asList(value).mapNotNull {
			when (it) {
				null, JSONObject.NULL -> null
				is String -> it
				else -> it.toString()
			}
		}
	}

	// A duration as sing-box reads one, "Ns", from a number of seconds or a text with a unit; null
	// when the value is not a duration at all.
	internal fun toDuration(value: Any?): String? {
		if (value == null || value === JSONObject.NULL || value is Boolean) return null
		val seconds = when (value) {
			is Number -> value.toInt().takeIf { it > 0 }
			is String -> durationInSeconds(value)
			else -> null
		} ?: return null
		return "${seconds}s"
	}

	// Make the tag unique: base, "base (2)", "base (3)", and so on
	internal fun makeUniqueTag(base: String, used: MutableSet<String>): String {
		if (base !in used) return base
		var position = 2
		while ("$base ($position)" in used) position++
		return "$base ($position)"
	}
}
