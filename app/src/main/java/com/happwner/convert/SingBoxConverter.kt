package com.happwner.convert

import com.happwner.text.JsonDepth
import org.json.JSONArray
import org.json.JSONObject

// Converts an Xray config into a sing-box one.
object SingBoxConverter {

	internal val LOG_LEVEL_MAP = mapOf(
		"debug" to "debug",
		"info" to "info",
		"warning" to "warn",
		"warn" to "warn",
		"error" to "error",
		"none" to "fatal"
	)

	private val SINGBOX_OUTBOUND_TYPES = setOf(
		"vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2",
		"tuic", "wireguard", "anytls", "ssh", "naive", "shadowtls",
		"selector", "urltest", "direct", "block", "dns", "socks", "http"
	)

	// Pull rule-sets (.srs) from SagerNet repositories
	internal const val GEOSITE_URL_TEMPLATE =
		"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/{name}.srs"
	internal const val GEOIP_URL_TEMPLATE =
		"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/{name}.srs"

	sealed class Result {
		// notes: what was left out and why, one line each - such as "skipped: outbounds[2] (vless):
		// transport "xhttp" has no sing-box equivalent".
		data class Ok(val config: JSONObject, val notes: List<String>) : Result()
		object NotXray : Result()
		// Carries notes too: when every outbound in a config is unsupported the config is dropped
		// whole, and a total failure has to explain itself the way partial ones do.
		data class Unsupported(val notes: List<String> = emptyList()) : Result()
		// A lone node written the way sing-box writes it that did not convert: it goes back as it came,
		// as a line that is no Xray does, and the reasons say why.
		data class AsWritten(val notes: List<String>) : Result()
	}

	sealed class OutboundsResult {
		// See Result.Ok.notes above.
		data class Ok(val outbounds: List<JSONObject>, val notes: List<String>) : OutboundsResult()
		object NotXray : OutboundsResult()
		data class Unsupported(val notes: List<String> = emptyList()) : OutboundsResult()
	}

	// The tag of the DNS server buildDns always emits; see applySockopt.
	internal const val LOCAL_DNS_TAG = "local"

	// A full Xray config to a full sing-box config.
	fun convert(input: String, nameFallback: String = ""): Result {
		val trimmed = input.trim()
		if (trimmed.isEmpty()) return Result.NotXray
		if (!trimmed.startsWith("{")) return Result.NotXray
		// Android's parser recurses per nesting level with no depth limit of its
		// own, so this has to be refused before parsing rather than caught after.
		if (JsonDepth.exceedsMaxDepth(trimmed)) return Result.NotXray

		// JSONObject throwing here just means the text isn't valid JSON - the normal way to learn that.
		val xray = try {
			xrayWithOutbounds(JSONObject(trimmed).also(XrayKeys::canonicalize))
		} catch (_: Exception) {
			return Result.NotXray
		}

		if (looksLikeSingBox(xray)) return Result.NotXray
		val config = asXrayConfig(xray) ?: return Result.NotXray
		// A lone node written the way sing-box writes it that does not convert goes back as it came, as a
		// line that is no Xray does: nothing of it is lost.
		val lone = config !== xray && !xray.has("settings")

		return try {
			val built = SingBoxConversion(config, nameFallback).run()
			// "Nothing convertible" comes back as an empty config object, carrying the per-outbound
			// reasons for the log.
			if (built.config.length() == 0) {
				return if (lone) Result.AsWritten(built.notes) else Result.Unsupported(built.notes)
			}
			Result.Ok(built.config, built.notes)
		} catch (_: Exception) {
			// A bug in the conversion for this input rather than an unsupported profile; no
			// per-outbound reasons exist in that case.
			if (lone) Result.AsWritten(emptyList()) else Result.Unsupported()
		}
	}

	// Xray to just the list of sing-box outbounds (no wrapper)
	fun convertToOutbounds(input: String, nameFallback: String = ""): OutboundsResult {
		val trimmed = input.trim()
		if (trimmed.isEmpty()) return OutboundsResult.NotXray
		if (!trimmed.startsWith("{")) return OutboundsResult.NotXray
		// See convert() above.
		if (JsonDepth.exceedsMaxDepth(trimmed)) return OutboundsResult.NotXray

		val xray = try {
			xrayWithOutbounds(JSONObject(trimmed).also(XrayKeys::canonicalize))
		} catch (_: Exception) {
			return OutboundsResult.NotXray
		}

		if (looksLikeSingBox(xray)) return OutboundsResult.NotXray
		val config = asXrayConfig(xray) ?: return OutboundsResult.NotXray

		return try {
			val extracted = extractProxyOutbounds(config,
				nameFallback) ?: return OutboundsResult.Unsupported()
			if (extracted.outbounds.isEmpty()) OutboundsResult.Unsupported(extracted.notes)
			else OutboundsResult.Ok(extracted.outbounds, extracted.notes)
		} catch (_: Exception) {
			OutboundsResult.Unsupported()
		}
	}

	// Extract only supported proxy outbounds; take names from remarks
	private data class ProxyExtraction(val outbounds: List<JSONObject>, val notes: List<String>)

	private fun extractProxyOutbounds(xray: JSONObject, nameFallback: String): ProxyExtraction? {
		// Every spelling a generator writes a name in, read the same way the other two passes read
		// it, so a configuration named under any of them is named here too.
		val remarks = configLabel(xray).ifEmpty { nameFallback.trim() }

		val outsRaw = xray.optJSONArray("outbounds") ?: return null

		val supportedProxies = mutableListOf<IndexedValue<JSONObject>>()
		val notes = mutableListOf<String>()
		for (i in 0 until outsRaw.length()) {
			val outbound = outsRaw.optJSONObject(i) ?: continue
			val proto = outbound.xrayProtocol()
			// Aux outbounds are not proxies and there is nothing to report about them.
			if (proto in SingBoxProtocols.XRAY_PROTOCOLS_AUX) {
				// Nothing to convert, but one detail of blackhole does get lost: it can answer with
				// a canned HTTP reply, where sing-box only closes the connection.
				if (proto == "blackhole") {
					SingBoxProtocols.blackholeResponseNote(outbound, i)?.let { notes.add(it) }
				}
				continue
			}
			// Judged per server, as the document judges it: a flaw in one neither takes down the rest
			// nor slips through behind a sound first one.
			val reasons = expandOutboundEndpoints(outbound).map { SingBoxProtocols.unsupportedReason(it) }
			if (reasons.all { it != null }) {
				val label = proto.ifEmpty { "no protocol" }
				notes.add("skipped: outbounds[$i] ($label): ${reasons.first()}")
				continue
			}
			supportedProxies.add(IndexedValue(i, outbound))
		}

		// Every proxy in the config was rejected. Still return the reasons - the caller turns this
		// into Unsupported, and without carrying them the drop would be invisible in the log.
		if (supportedProxies.isEmpty()) {
			// A configuration of nothing but freedom/blackhole/dns has no proxy to convert.
			if (notes.isEmpty()) {
				notes.add("no proxy outbound in this configuration; there was nothing to convert")
			}
			return ProxyExtraction(emptyList(), notes)
		}

		val results = mutableListOf<JSONObject>()
		// Named by what the file holds, as the other passes name it, not by what this pass carried.
		val singleProxy = proxyOutboundCount(outsRaw) == 1

		// Convert each, naming from remarks (#tag suffix when there are several). An outbound naming
		// several servers is split one per server first, as the other passes split it; with no document
		// to hold a group, the members stand alone, told apart by their server.
		for ((i, outbound) in supportedProxies) {
			val expanded = expandOutboundEndpoints(outbound)
			val place = "outbounds[$i] (${outbound.xrayProtocol().ifEmpty { "no protocol" }})"
			ignoredServerListNote(outbound)?.let { notes.add("$place: $it") }
			for (one in expanded) {
				val proto = outbound.xrayProtocol().ifEmpty { "no protocol" }
				val refusal = SingBoxProtocols.unsupportedReason(one)
				if (refusal != null) {
					notes.add("skipped: outbounds[$i] ($proto): $refusal")
					continue
				}
				val result = SingBoxProtocols.buildOutbound(one)
				// Reported whether or not the outbound survived: a node dropped
				// with nothing said about it is the failure these notes exist for.
				for ((k, note) in result.notes.withIndex()) {
					val skip = result.outbound == null && k == result.notes.lastIndex
					notes.add("${if (skip) "skipped: " else ""}outbounds[$i] ($proto): $note")
				}
				val singBoxOutbound = result.outbound ?: continue

				singBoxOutbound.remove("detour")

				val originalTag = outbound.optString("tag", "").trim()
				// A sing-box outbound must have a tag, so a node with neither a label nor one of its
				// own still gets something to be referred to by.
				val baseTag = labelledName(remarks, originalTag, singleProxy)
					.ifEmpty { originalTag.ifEmpty { "proxy" } }
				val server = singBoxOutbound.optString("server", "")
				val newTag = if (expanded.size == 1) baseTag
				else "$baseTag $server:${singBoxOutbound.optInt("server_port")}"
				singBoxOutbound.put("tag", newTag)
				results.add(singBoxOutbound)
			}
		}

		return ProxyExtraction(results, notes)
	}

	// The configuration to read, whichever shape arrived. A lone outbound is a configuration of one,
	// as the URI and mihomo passes read it - only a proxy (a lone freedom line is not a server), written
	// the way Xray writes one or with its server beside the protocol, the way sing-box writes it.
	private fun asXrayConfig(node: JSONObject): JSONObject? {
		if (looksLikeXray(node)) return node
		if (node.has("outbounds") || !node.has("settings") && !node.has("server")) return null
		if (node.xrayProtocol() !in SingBoxProtocols.XRAY_PROTOCOLS_PROXY) return null
		return JSONObject().put("outbounds", JSONArray().put(node))
	}

	private fun looksLikeXray(document: JSONObject): Boolean {
		val outs = document.optJSONArray("outbounds") ?: return false
		if (outs.length() == 0) return false
		for (i in 0 until outs.length()) {
			val outbound = outs.optJSONObject(i) ?: continue
			if (outbound.has("protocol")) return true
		}
		return false
	}

	// Whether this is already a sing-box document rather than an Xray one: a route block is
	// present and the first outbound's type is a sing-box one.
	internal fun looksLikeSingBox(document: JSONObject): Boolean {
		if (!document.has("route") || !document.has("outbounds")) return false
		val outs = document.optJSONArray("outbounds") ?: return false
		if (outs.length() == 0) return false
		val first = outs.optJSONObject(0) ?: return false
		return first.optString("type", "") in SINGBOX_OUTBOUND_TYPES
	}

	internal fun dedupeByTag(items: List<JSONObject>, used: MutableSet<String>): List<JSONObject> {
		val out = mutableListOf<JSONObject>()
		for (item in items) {
			val tag = item.optString("tag", "")
			if (tag.isEmpty() || tag in used) continue
			used.add(tag)
			out.add(item)
		}
		return out
	}

	// One configuration converted: its document and the notes, as Result.Ok carries them.
	internal data class ConvertedDocument(val config: JSONObject, val notes: List<String>)
}
