package com.happwner.convert

import android.util.Base64
import com.happwner.text.base64Flag
import com.happwner.text.decodeStrictUtf8
import com.happwner.text.hasBinaryControls
import com.happwner.text.isWholeJsonValue
import com.happwner.text.jsonProblem
import com.happwner.text.withoutComments
import org.json.JSONArray
import org.json.JSONObject

// What a conversion is asked to do: which passes run and how the answer is wrapped.
data class ConversionFlags(
	val jsonToUri: Boolean,
	val xrayToSingBox: Boolean,
	val xrayToMihomo: Boolean,
	// Whether the answer is re-encoded to Base64. The person's choice; input is decoded either way.
	val base64Result: Boolean,
	// The URI mode's two "drop what this core could not carry" boxes: sing-box's is xrayToSingBox
	// itself, but mihomo needs its own since xrayToMihomo already means "produce a document".
	val dropIncompatibleMihomo: Boolean = false
)

object SubscriptionConverter {
	data class ConversionResult(
		val text: String,
		val xraySkipped: Int,
		// True when the skipped count is mihomo's, so the caller words the label for it.
		val mihomo: Boolean = false,
		// True when the count is the link pass's alone - nodes no client can use - with no core
		// judging, so the label names the URI conversion rather than a core.
		val uri: Boolean = false,
		// What was left out and why, from whichever pass produced the text.
		val notes: List<String> = emptyList()
	)

	fun convertWithStats(input: String, flags: ConversionFlags): ConversionResult {
		// A byte-order mark stops every pass from recognising the body - removed before anything
		// reads it, and again after base64 decoding.
		val bare = input.removePrefix("\uFEFF")
		val wrapper = tryDecodeBase64WithFlag(bare)
		// Comments, and a comma before a closer, keep a body from reading as JSON only here and not in
		// the mihomo pass, which reads past them; every pass reads it the same way.
		val written = (wrapper?.decoded ?: bare).removePrefix("\uFEFF")
		val body = withoutComments(written)
		val read = convertPlain(body, flags.jsonToUri, flags.xrayToSingBox, flags.xrayToMihomo,
			flags.dropIncompatibleMihomo)
		// A body left as it is goes back as it was written, comments and all.
		val untouched = body !== written && read.text == body.trim()
		val plain = if (untouched) read.copy(text = written.trim()) else read
		// A note names the place it is about, so one said twice - an outbound read once for each of
		// its servers - tells nothing more.
		val converted = plain.copy(notes = plain.notes.distinct())
		if (!flags.base64Result || converted.text.isEmpty()) return converted
		return converted.copy(
			text = if (wrapper != null) encodeBase64Like(converted.text, wrapper)
			else encodeBase64Plain(converted.text)
		)
	}

	// The conversion itself, on text that is already readable.
	private fun convertPlain(
		input: String,
		jsonToUri: Boolean,
		xrayToSingBox: Boolean,
		xrayToMihomo: Boolean,
		dropIncompatibleMihomo: Boolean = false,
		judge: Judge? = null
	): ConversionResult {
		if (xrayToMihomo) convertMihomoFirst(input, jsonToUri, xrayToSingBox)?.let { return it }

		if (!jsonToUri && !xrayToSingBox && !xrayToMihomo) return ConversionResult(input.trim(), 0)

		val trimmed = input.trim()
		val compact = isCompactJson(trimmed)

		// Xray to sing-box only: merge every config into a single one (mergeUnified)
		if (xrayToSingBox && !jsonToUri) {
			val merged = convertXrayToSingBox(input, trimmed, compact)
			if (merged != null) return merged
		}

		if (jsonToUri && (xrayToSingBox || dropIncompatibleMihomo)) {
			return convertLinksFiltered(input, xrayToSingBox, dropIncompatibleMihomo)
		}

		// Handed back unchanged, this would reach the core as the Xray it already was and get
		// refused over a field the person never wrote - said plainly instead.
		if ((xrayToSingBox || xrayToMihomo) && !jsonToUri &&
			(trimmed.startsWith("{") || trimmed.startsWith("[")) && isWholeJsonValue(trimmed)
		) {
			return ConversionResult(
				input.trim(),
				0,
				notes = listOf(
					"this document is JSON but holds no Xray outbound to convert, so it was left as " +
						"it is; a core asked to load it will refuse it"
				)
			)
		}

		// Why the body as a whole couldn't be rendered, kept for the log: the per-line pass
		// below sees only fragments of it, and its complaints would bury the real reason.
		val wholeBodyNotes = mutableListOf<String>()

		// A pretty-printed config spans several lines, so the per-line pass never sees it whole -
		// try the whole body as one value first.
		if (jsonToUri && (trimmed.startsWith("{") || trimmed.startsWith("[")) && isWholeJsonValue(trimmed)) {
			// A body whose every node was refused is answered here too: handed to the per-line pass
			// it would be read a second time and each reason said twice.
			val refused = IntArray(1)
			val links = jsonValueToLinks(trimmed, wholeBodyNotes, refused, judge)
			if (links != null || refused[0] > 0) {
				return ConversionResult(
					links.orEmpty(), refused[0], uri = !xrayToSingBox, notes = wholeBodyNotes
				)
			}
		}

		val lines = convertLines(input, jsonToUri, xrayToSingBox, xrayToMihomo, judge)
		// A whole-body failure explains itself; per-line complaints about its fragments would
		// only hide that.
		if (wholeBodyNotes.isEmpty()) return lines
		val saidWhole = wholeBodyNotes.toHashSet()
		return lines.copy(
			notes = wholeBodyNotes +
				lines.notes.filterNot { it.startsWith(JSON_LINE_NOTE) || it in saidWhole }
		)
	}

	// Mihomo output is a whole YAML document, so it replaces the other passes instead of chaining
	// with them; null when mihomo had nothing to say about the body, which the passes below take.
	private fun convertMihomoFirst(
		input: String, jsonToUri: Boolean, xrayToSingBox: Boolean
	): ConversionResult? {
		val mihomo = convertXrayToMihomo(input)
		mihomo.stats?.let { return it }
		if (mihomo.notes.isEmpty()) return null
		// No document, so the body falls to the passes below - but mihomo's reasons carry onto
		// whatever they return, or a total failure would explain nothing. Its count carries only
		// onto a body handed back as it came: another pass that made the text counts its own.
		val rest = convertPlain(input, jsonToUri, xrayToSingBox, xrayToMihomo = false)
		val asItCame = !jsonToUri && !xrayToSingBox
		// What mihomo said already, the pass after it does not say again.
		val said = mihomo.notes.toHashSet()
		return rest.copy(
			xraySkipped = if (asItCame) mihomo.skipped else rest.xraySkipped,
			mihomo = rest.mihomo || (asItCame && mihomo.skipped > 0),
			notes = mihomo.notes + rest.notes.filterNot { it in said }
		)
	}

	// Xray to URI with a box for sing-box or Mihomo ticked: a whole configuration goes or stays,
	// which is what the setting says and what the filter does.
	private fun convertLinksFiltered(
		input: String, xrayToSingBox: Boolean, dropIncompatibleMihomo: Boolean
	): ConversionResult {
		val filtered = preFilterUnsupported(input, xrayToSingBox, dropIncompatibleMihomo)
		// A node with no link form comes back as its own one-outbound config, judged by the same
		// cores where its place is known - otherwise the box would leave behind what it was
		// ticked to remove, and pressing it twice wouldn't match pressing it once.
		val inner = convertPlain(
			filtered.text, jsonToUri = true, xrayToSingBox = false, xrayToMihomo = false,
			judge = Judge(LinkClients(xrayToSingBox, dropIncompatibleMihomo))
		)
		// The filter and the link pass judge the same nodes: a reason the link pass already gave
		// is not given again, while its own repeats - two configurations alike - all stay.
		val said = inner.notes.toHashSet()
		val judged = filtered.notes.filterNot { it in said }
		return ConversionResult(
			inner.text,
			inner.xraySkipped + filtered.skipped,
			// Which core the count belongs to, so the label names the one that refused; with both
			// boxes ticked a drop can come from either, and the sing-box label speaks for both.
			mihomo = dropIncompatibleMihomo && !xrayToSingBox,
			notes = inner.notes + judged
		)
	}

	// The body a line at a time, for what the whole-body readers left: each line unwrapped,
	// converted or handed back on its own.
	private fun convertLines(
		input: String, jsonToUri: Boolean, xrayToSingBox: Boolean, xrayToMihomo: Boolean, judge: Judge?
	): ConversionResult {
		val output = StringBuilder()
		var skipped = 0
		val notes = mutableListOf<String>()
		input.lines().forEach { line ->
			val trimmedLine = line.trim()
			if (trimmedLine.isEmpty()) return@forEach

			// Unwrap, convert, then wrap the answer once at the end. Can't recurse forever - base64
			// never begins with "{", "[" or a scheme, so a second layer is refused.
			val lineWrapper = tryDecodeBase64WithFlag(trimmedLine)
			if (lineWrapper != null) {
				val inner =
					convertPlain(lineWrapper.decoded, jsonToUri, xrayToSingBox, xrayToMihomo, judge = judge)
				output.append(inner.text).append("\n")
				skipped += inner.xraySkipped
				notes.addAll(inner.notes)
				return@forEach
			}

			// A JSON outbound (or array of them) on this line -> proxy link(s)
			if (jsonToUri && (trimmedLine.startsWith("{") || trimmedLine.startsWith("[")) &&
				isWholeJsonValue(trimmedLine)) {
				val refused = IntArray(1)
				val converted = jsonValueToLinks(trimmedLine, notes, refused, judge)
				skipped += refused[0]
				if (converted != null) output.append(converted).append("\n")
				// A single object that rendered to nothing stays as it was, unless it was refused;
				// an array that did is dropped.
				else if (trimmedLine.startsWith("{") && refused[0] == 0) {
					output.append(trimmedLine).append("\n")
				}
				return@forEach
			}

			// A line that looks like a configuration and did not read as one is passed through, and
			// the reason is said: silence here looks like a node that was never there.
			if (trimmedLine.startsWith("{") || trimmedLine.startsWith("[")) {
				jsonProblem(trimmedLine)?.let { notes.add(JSON_LINE_NOTE + it) }
			}
			// A line nothing above claimed. Whitespace around a link carries nothing and a list
			// reads better without it, so a link is tidied.
			val isLink = PROXY_SCHEMES.any { trimmedLine.startsWith(it, ignoreCase = true) }
			output.append(if (isLink) trimmedLine else line).append("\n")
		}
		return ConversionResult(
			output.toString().trim(), skipped, uri = jsonToUri && !xrayToSingBox, notes = notes
		)
	}

	// A note of one configuration among several, told apart the way every pass tells them:
	// "skipped: config[1].outbounds[0] ...", "config[1].routing.rules[2] ...", "config[1]: ...".
	internal fun ofConfig(note: String, index: Int): String {
		val skipped = note.startsWith("skipped: ")
		val body = note.removePrefix("skipped: ")
		val placed = if (PLACE.containsMatchIn(body)) "config[$index].$body" else "config[$index]: $body"
		return if (skipped) "skipped: $placed" else placed
	}

	// A note that opens with where it comes from: "outbounds[0] ...", "routing.rules ...".
	private val PLACE = Regex("^[A-Za-z]+[\\[.]")

	// A whole JSON value - an outbound object or an array of them - rendered to newline-joined
	// links, or null when it produced none.
	private fun jsonValueToLinks(
		body: String, notes: MutableList<String>, refused: IntArray, judge: Judge?
	): String? {
		return try {
			if (body.startsWith("[")) {
				val configs = JSONArray(body).also(XrayKeys::canonicalize)
				val out = StringBuilder()
				for (i in 0 until configs.length()) {
					val config = configs.optJSONObject(i)
					val piece: String? = if (config != null) {
						val place = if (configs.length() > 1) "config[$i]." else ""
						val before = refused[0]
						// What could not be rendered goes back as it was written, not as it was read.
						processJson(xrayWithOutbounds(config), notes, refused, place, judge)
							?: jsonText(config).takeIf { refused[0] == before }
					} else {
						entryAsWritten(configs.opt(i))
					}
					if (piece != null) {
						if (out.isNotEmpty()) out.append("\n")
						out.append(piece)
					}
				}
				out.toString().takeIf { it.isNotEmpty() }
			} else {
				val config = xrayWithOutbounds(JSONObject(body).also(XrayKeys::canonicalize))
				processJson(config, notes, refused, judge = judge)
			}
		} catch (_: Exception) {
			null
		}
	}

	// A list entry that is no configuration, as it came - a link, a number, a list - and nothing for a null.
	private fun entryAsWritten(raw: Any?): String? = when {
		raw == null || raw === JSONObject.NULL -> null
		raw is JSONArray -> jsonText(raw)
		else -> raw.toString().trim().takeIf { it.isNotEmpty() }
	}

	// Single-line JSON? (no newline within the first 1KB)
	private fun isCompactJson(text: String): Boolean {
		val limit = minOf(text.length, 1024)
		for (i in 0 until limit) {
			val char = text[i]
			if (char == '\n' || char == '\r') return false
		}
		return true
	}

	private fun formatJson(obj: JSONObject, compact: Boolean): String =
		if (compact) jsonText(obj) else jsonText(obj, 2)

	private fun formatJsonArray(arr: JSONArray, compact: Boolean): String =
		if (compact) jsonText(arr) else jsonText(arr, 2)

	private data class FilterResult(val text: String, val skipped: Int, val notes: List<String> = emptyList())

	// Each VLESS flow in the form sing-box takes: xtls-rprx-vision-udp443 becomes xtls-rprx-vision.
	private fun normalizeConfigFlowsInPlace(cfg: JSONObject): Boolean {
		val outs = cfg.optJSONArray("outbounds")
		val outbounds =
			if (outs != null) (0 until outs.length()).mapNotNull { outs.optJSONObject(it) }
			else listOf(cfg)
		var changed = false
		for (outbound in outbounds) {
			if (outbound.xrayProtocol() != "vless") continue
			for (endpoint in xrayEndpoints(outbound.optJSONObject("settings"))) {
				val flow = endpoint.user.xStr("flow")
				if (flow.isEmpty()) continue
				val norm = normalizeFlow(flow)
				if (norm != flow) { endpoint.user.put("flow", norm); changed = true }
			}
		}
		return changed
	}

	private fun isConfiguration(text: String): Boolean =
		xrayWithOutbounds(JSONObject(text).also(XrayKeys::canonicalize)).xArr("outbounds") != null

	// What the chosen cores make of one configuration.
	private enum class Carriage { OK, UNSUPPORTED, NOT_XRAY }

	private class CarriageCheck(val verdict: Carriage, val notes: List<String>)

	// Asks each chosen core whether it could carry this configuration; refused by either is
	// refused. A reader that doesn't recognise the shape says "not Xray", so an unreadable node
	// is kept rather than thrown away on a guess.
	private fun carriage(cfg: String, singBox: Boolean, mihomo: Boolean): CarriageCheck {
		// Only a whole configuration is judged - the two readers disagree on which lone-outbound
		// shapes they parse at all, so a node one couldn't read isn't one the person asked to drop.
		if (!isConfiguration(cfg)) return CarriageCheck(Carriage.NOT_XRAY, emptyList())
		// Only the core that refuses the configuration speaks: what a core would leave out of one
		// it carries is not what the links leave out, since every node with a link form stays.
		var isXray = false
		if (singBox) {
			when (val result = SingBoxConverter.convertToOutbounds(cfg, "")) {
				is SingBoxConverter.OutboundsResult.Ok -> isXray = true
				is SingBoxConverter.OutboundsResult.Unsupported ->
					// A configuration the ticked box drops says why even with nothing to name:
					// a silent log with an empty answer reads as a lost subscription.
					return CarriageCheck(Carriage.UNSUPPORTED, result.notes.ifEmpty {
						listOf("nothing in this configuration is a node sing-box carries, so the " +
							"configuration was dropped")
					})
				SingBoxConverter.OutboundsResult.NotXray -> {}
			}
		}
		if (mihomo) {
			val result = MihomoConverter.check(cfg)
			when (result.verdict) {
				MihomoConverter.Verdict.CARRIED -> isXray = true
				MihomoConverter.Verdict.UNSUPPORTED ->
					return CarriageCheck(Carriage.UNSUPPORTED, result.notes.ifEmpty {
						listOf("nothing in this configuration is a node mihomo carries, so the " +
							"configuration was dropped")
					})
				MihomoConverter.Verdict.NOT_XRAY -> {}
			}
		}
		return CarriageCheck(if (isXray) Carriage.OK else Carriage.NOT_XRAY, emptyList())
	}

	// Keep one Xray config or array, dropping unsupported outbounds
	private fun preFilterUnsupportedOne(text: String, singBox: Boolean, mihomo: Boolean): FilterResult? {
		if (text.isEmpty()) return null
		if (!isWholeJsonValue(text)) return null
		if (text.startsWith("{")) {
			val check = carriage(text, singBox, mihomo)
			return when (check.verdict) {
				Carriage.OK -> {
					val cfg = JSONObject(text).also(XrayKeys::canonicalize)
					val normalized = if (normalizeConfigFlowsInPlace(cfg)) jsonTextOrNull(cfg) else null
					FilterResult(normalized ?: text, 0, check.notes)
				}
				Carriage.UNSUPPORTED -> FilterResult("", 1, check.notes)
				Carriage.NOT_XRAY -> null
			}
		}
		if (text.startsWith("[")) {
			val configs = JSONArray(text)
			val out = JSONArray()
			var anyXray = false
			var skipped = 0
			val notes = mutableListOf<String>()
			for (i in 0 until configs.length()) {
				val config = configs.optJSONObject(i)
				if (config == null) {
					val raw = configs.opt(i)
					if (raw != null && raw !== JSONObject.NULL) {
						if (jsonTextOrNull(JSONArray().put(raw)) != null) {
							out.put(raw)
						} else {
							notes.add(UNWRITABLE_NOTE)
						}
					}
					continue
				}
				val written = jsonTextOrNull(config)
				if (written == null) {
					notes.add(UNWRITABLE_NOTE)
					skipped++
					anyXray = true
					continue
				}
				val check = carriage(written, singBox, mihomo)
				notes.addAll(check.notes)
				when (check.verdict) {
					Carriage.OK -> {
						XrayKeys.canonicalize(config)
						normalizeConfigFlowsInPlace(config)
						out.put(config)
						anyXray = true
					}
					Carriage.UNSUPPORTED -> {
						skipped++
						anyXray = true
					}
					Carriage.NOT_XRAY -> out.put(config)
				}
			}
			if (!anyXray) return null
			return FilterResult(formatJsonArray(out, isCompactJson(text)), skipped, notes)
		}
		return null
	}

	// Drop unsupported Xray configs and outbounds and count the skipped ones
	private fun preFilterUnsupported(input: String, singBox: Boolean, mihomo: Boolean): FilterResult {
		val trimmed = input.trim()
		if ((trimmed.startsWith("{") || trimmed.startsWith("[")) && isWholeJsonValue(trimmed)) {
			val single = preFilterUnsupportedOne(trimmed, singBox, mihomo)
			if (single != null) return single
		}
		val output = StringBuilder()
		var totalSkipped = 0
		var anyFiltered = false
		val totalNotes = mutableListOf<String>()
		for (line in input.lines()) {
			val trimmedLine = line.trim()
			if (trimmedLine.isEmpty()) continue
			val one = preFilterUnsupportedOne(trimmedLine, singBox, mihomo)
			if (one != null) {
				anyFiltered = true
				if (one.text.isNotEmpty()) output.append(one.text).append("\n")
				totalSkipped += one.skipped
				totalNotes.addAll(one.notes)
			} else {
				output.append(trimmedLine).append("\n")
			}
		}
		if (!anyFiltered) return FilterResult(input, 0)
		return FilterResult(output.toString().trimEnd('\n'), totalSkipped, totalNotes)
	}

	// The outcome of the mihomo pass: a document when one was produced, and the per-outbound
	// reasons either way ("no document" is not "nothing to report").
	private data class MihomoPass(val stats: ConversionResult?, val notes: List<String>, val skipped: Int = 0)

	private val MIHOMO_PASS_NONE = MihomoPass(null, emptyList())

	// Convert every Xray config in the body into one mihomo YAML document. A null document means
	// the body holds no Xray config, so the caller can fall back to the other conversion passes.
	private fun convertXrayToMihomo(input: String): MihomoPass {
		var body = input.trim().removePrefix("\uFEFF")
		if (body.isEmpty()) return MIHOMO_PASS_NONE
		if (!body.startsWith("{") && !body.startsWith("[")) {
			// Panels commonly base64-wrap the body. YAML is always emitted plain (what a mihomo
			// client reads); a body that isn't base64 either is read line by line below.
			tryDecodeBase64WithFlag(body)?.decoded?.trim()?.removePrefix("\uFEFF")?.let { body = it }
		}

		val whole = runMihomo(body)
		if (whole.stats != null || whole.notes.isNotEmpty()) return whole

		// Some panels put one config per line instead of an array, sometimes beside links. A link
		// has no place in a YAML document, so it's counted and reported instead of carried along.
		val configs = JSONArray()
		var linesWithoutAPlace = 0
		for (line in body.lines()) {
			val trimmedLine = line.trim()
			if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) continue
			if (!trimmedLine.startsWith("{") || !isWholeJsonValue(trimmedLine)) {
				linesWithoutAPlace++
				continue
			}
			val config = JSONObject(trimmedLine)
			// A line org.json cannot write back has no place in the document either.
			if (jsonTextOrNull(config) == null) {
				linesWithoutAPlace++
				continue
			}
			configs.put(config)
		}
		if (configs.length() == 0) return MIHOMO_PASS_NONE
		val pass = runMihomo(configs.toString())
		if (linesWithoutAPlace == 0 || pass.stats == null) return pass
		return pass.copy(
			stats = pass.stats.copy(
				notes = pass.stats.notes + (
					"$linesWithoutAPlace line(s) that are not Xray configurations - links, or text " +
						"- have no place in a mihomo document and were dropped"
				)
			)
		)
	}

	private fun runMihomo(text: String): MihomoPass =
		when (val result = MihomoConverter.convert(text)) {
			is MihomoConverter.Result.Ok ->
				MihomoPass(
					ConversionResult(result.yaml.trimEnd('\n'), result.skipped, mihomo = true,
						notes = result.notes),
					result.notes
				)
			// Xray, but nothing in it could be converted: leave the body to the other passes rather
			// than handing back an empty configuration.
			is MihomoConverter.Result.Unsupported -> MihomoPass(null, result.notes, result.skipped)
			MihomoConverter.Result.NotXray -> MIHOMO_PASS_NONE
		}

	// Merge Xray configs into one sing-box document; pass any other lines through unchanged
	private fun convertXrayToSingBox(input: String, trimmed: String, compact: Boolean): ConversionResult? {
		val configs = mutableListOf<JSONObject>()
		var skipped = 0
		var hadXray = false
		val passthroughLines = mutableListOf<String>()
		val notes = mutableListOf<String>()
		val notesByConfig = mutableListOf<List<String>>()
		// Why a lone node went back as it came, kept rather than skipped; a set, since a body not taken
		// whole is read again line by line.
		val asWritten = LinkedHashSet<String>()

		// A converted configuration org.json cannot write back can be neither merged nor handed out.
		fun add(result: SingBoxConverter.Result.Ok) {
			if (jsonTextOrNull(result.config) == null) {
				skipped++; notesByConfig.add(listOf(UNWRITABLE_NOTE))
			} else {
				configs.add(result.config); notesByConfig.add(result.notes)
			}
		}

		fun ingestObject(text: String): Boolean {
			return when (val result = SingBoxConverter.convert(text, "")) {
				is SingBoxConverter.Result.Ok -> {
					add(result); hadXray = true; true
				}
				is SingBoxConverter.Result.Unsupported -> {
					skipped++; hadXray = true; notesByConfig.add(result.notes); true
				}
				is SingBoxConverter.Result.AsWritten -> {
					result.notes.mapTo(asWritten) { it.removePrefix("skipped: ") }; false
				}
				SingBoxConverter.Result.NotXray -> false
			}
		}

		fun ingestArray(text: String): Boolean {
			val entries = JSONArray(text)
			var any = false
			// What did not read as Xray goes back as it came, beside the document, as an unread line does.
			val unread = mutableListOf<String>()
			for (i in 0 until entries.length()) {
				val entry = entries.optJSONObject(i)
				if (entry == null) {
					entryAsWritten(entries.opt(i))?.let { unread.add(it) }
					continue
				}
				val written = jsonTextOrNull(entry)
				if (written == null) {
					skipped++; any = true; notesByConfig.add(listOf(UNWRITABLE_NOTE))
					continue
				}
				when (val result = SingBoxConverter.convert(written, "")) {
					is SingBoxConverter.Result.Ok -> {
						add(result); any = true
					}
					is SingBoxConverter.Result.Unsupported -> {
						skipped++; any = true; notesByConfig.add(result.notes)
					}
					is SingBoxConverter.Result.AsWritten -> {
						result.notes.mapTo(asWritten) { it.removePrefix("skipped: ") }
						unread.add(written)
					}
					SingBoxConverter.Result.NotXray -> unread.add(written)
				}
			}
			if (any) {
				hadXray = true
				passthroughLines.addAll(unread)
			}
			return any
		}

		val consumedWhole = when {
			trimmed.startsWith("{") && isWholeJsonValue(trimmed) -> ingestObject(trimmed)
			trimmed.startsWith("[") && isWholeJsonValue(trimmed) -> ingestArray(trimmed)
			else -> false
		}

		if (!consumedWhole) {
			for (line in input.lines()) {
				val trimmedLine = line.trim()
				if (trimmedLine.isEmpty()) continue
				val consumed = when {
					trimmedLine.startsWith("{") && isWholeJsonValue(trimmedLine) -> ingestObject(trimmedLine)
					trimmedLine.startsWith("[") && isWholeJsonValue(trimmedLine) -> ingestArray(trimmedLine)
					else -> false
				}
				if (!consumed) passthroughLines.add(trimmedLine)
			}
		}

		if (!hadXray && asWritten.isEmpty()) return null
		// No Xray at all but lone nodes that went back as they came: the body as it came, and why.
		if (!hadXray) return ConversionResult(input.trim(), 0, notes = asWritten.toList())
		for ((index, configNotes) in notesByConfig.withIndex()) {
			for (note in configNotes) notes.add(if (notesByConfig.size > 1) ofConfig(note, index) else note)
		}
		notes.addAll(asWritten)

		val builder = StringBuilder()
		if (configs.isNotEmpty()) {
			// The merge has things to say when several configurations disagree with each other.
			val merged = SingBoxMerge.mergeUnified(configs, notes)
			if (merged != null) builder.append(formatJson(merged, compact))
		}
		for (line in passthroughLines) {
			if (builder.isNotEmpty()) builder.append("\n")
			builder.append(line)
		}

		return ConversionResult(builder.toString(), skipped, notes = notes)
	}

	private val PROXY_SCHEMES = arrayOf(
		"vless://", "vmess://", "trojan://", "ss://", "ssr://",
		"hysteria://", "hysteria2://", "hy2://", "tuic://", "socks://",
		"http://", "https://", "happ://"
	)

	private data class Base64Result(
		val decoded: String,
		val flag: Int,
		val hadNewlines: Boolean,
		val hadCrlf: Boolean,
		val hadPadding: Boolean,
		val hadTrailingNewline: Boolean,
		val hadTrailingCrlf: Boolean
	)

	// Try to decode as Base64 (remember flag/newlines/padding so we can re-encode the same way)
	private fun tryDecodeBase64WithFlag(input: String): Base64Result? {
		if (input.length < 10) return null
		val cleaned = input.trim()
		val flag = base64Flag(cleaned) ?: return null
		val hadNewlines = cleaned.any { it == '\r' || it == '\n' }
		val hadPadding = cleaned.contains('=')
		val rstripped = input.trimEnd(' ', '\t')
		val hadTrailingCrlf = rstripped.endsWith("\r\n")
		val hadTrailingNewline = hadTrailingCrlf || rstripped.endsWith("\n") || rstripped.endsWith("\r")
		val hadCrlf = (hadNewlines && cleaned.contains("\r\n")) || hadTrailingCrlf

		// Decode, then accept only if it's real text that looks like configs/links
		return try {
			val decodedRaw = decodeStrictUtf8(Base64.decode(cleaned, flag)) ?: return null
			if (hasBinaryControls(decodedRaw)) return null
			// Same as a BOM in front of the body - meaningless, and left in place it would keep
			// this from being recognised at all.
			val decoded = decodedRaw.removePrefix("\uFEFF").trimStart()
			// Happ's parameter lines (#profile-title, #change-user-agent) can sit above the links,
			// so the line that says what this body is need not be the first one.
			val firstLine = decoded.lineSequence()
				.map { it.trimStart() }
				.firstOrNull { it.isNotBlank() && !it.startsWith("#") } ?: return null
			val looksLikeJson = firstLine.startsWith("{") || firstLine.startsWith("[")
			val looksLikeProxyList = PROXY_SCHEMES.any { firstLine.startsWith(it, ignoreCase = true) }
			if (looksLikeJson || looksLikeProxyList) {
				Base64Result(decoded, flag, hadNewlines, hadCrlf, hadPadding, hadTrailingNewline,
					hadTrailingCrlf)
			} else null
		} catch (_: IllegalArgumentException) {
			null
		}
	}

	// The wrapping for an answer whose input had none to copy: the standard alphabet, padded, on
	// one line - the shape every client decodes.
	private fun encodeBase64Plain(text: String): String =
		Base64.encodeToString(
			text.toByteArray(Charsets.UTF_8),
			Base64.NO_WRAP
		)

	// Re-packs into base64 in the same shape as the input: alphabet, padding and line breaks.
	private fun encodeBase64Like(text: String, b64: Base64Result): String {
		var flags = b64.flag
		if (!b64.hadNewlines) {
			flags = flags or Base64.NO_WRAP
		} else if (b64.hadCrlf) {
			flags = flags or Base64.CRLF
		}
		if (!b64.hadPadding) {
			flags = flags or Base64.NO_PADDING
		}
		val raw = Base64.encodeToString(text.toByteArray(Charsets.UTF_8), flags)
		val body = raw.trimEnd('\n', '\r')
		return when {
			b64.hadTrailingCrlf -> "$body\r\n"
			b64.hadTrailingNewline -> "$body\n"
			else -> body
		}
	}

	// Tells "this outbound is not a server" apart from "this one would not render". Both leave no
	// link; only the second is worth reporting.
	private const val AUX_OUTBOUND = "\u0000aux"

	// What a line that looked like a configuration and did not read as one is reported with.
	private const val JSON_LINE_NOTE = "a line that starts like JSON was left as it is: "
	private const val UNWRITABLE_NOTE = "an entry holds a number out of range, so it was dropped"

	// One outbound, written back as a compact config of its own (the result is read a line at a time).
	private fun originalOutbound(root: JSONObject, outbound: JSONObject): String {
		val one = JSONObject()
		val remarks = labelOf(root, withTag = true)
		if (remarks.isNotEmpty()) one.put("remarks", remarks)
		one.put("outbounds", JSONArray().put(outbound))
		return jsonText(one)
	}

	// Every spelling a generator writes the display name in, exactly as written - a name padded
	// for sort order was padded on purpose. A tag only counts at configuration level (naming the
	// file); on an outbound it names a role, weighed separately by nameFallback.
	internal fun labelOf(node: JSONObject, withTag: Boolean): String {
		val label = node.xStrRawOf("remarks", "remark", "name", "ps")
		return if (withTag) label.ifEmpty { node.xStrRaw("tag") } else label
	}

	// Fallback name for an outbound with none of its own: the configuration's label, with the tag
	// added when it holds several nodes. A bare tag comes last: it names a role, and "proxy-de-1"
	// would replace the "Germany" somebody chose to display.
	private fun nameFallback(outbound: JSONObject, label: String, singleProxy: Boolean): String =
		labelledName(label, outbound.xStr("tag"), singleProxy).ifEmpty { meaningfulTag(outbound.xStr("tag")) }

	// One outbound to its link, as its clients take it. AUX_OUTBOUND marks the ones that aren't servers,
	// LinkBuilders.REFUSED a node no client can use, its reason noted; null means a node that works
	// but has no link form - a vmess node under REALITY, say - not a failed conversion.
	private fun linkForOutbound(
		outbound: JSONObject, rem: String, notes: MutableList<String>, clients: LinkClients
	): String? =
		try {
			// A stream in a block sing-box writes is no stream to judge: the node stays a configuration.
			singBoxBlockOf(outbound)?.let {
				notes.add(it)
				return null
			}
			securityRefusal(outbound.optJSONObject("streamSettings"))?.let {
				notes.add(it)
				return LinkBuilders.REFUSED
			}
			transportRefusal(outbound)?.let {
				notes.add(it)
				return LinkBuilders.REFUSED
			}
			// A node over a transport of Xray's own has no link form; it stays a configuration.
			xrayOwnTransportOf(outbound)?.let {
				notes.add(xrayOwnTransportRefusal(it))
				return null
			}
			chainConflictNote(outbound)?.let { notes.add(it) }
			// Said once for every protocol: what no link form holds, whichever builder answers below.
			LinkBuilders.reportOutboundExtrasNotCarried(outbound, notes)
			when (outbound.xrayProtocol().ifEmpty { outbound.optString("type").lowercase() }) {
				"vless" -> LinkBuilders.buildVless(outbound, rem, notes, clients)
				"vmess" -> LinkBuilders.buildVmess(outbound, rem, notes, clients)
				"shadowsocks" -> LinkBuilders.buildShadowsocks(outbound, rem, notes, clients)
				"trojan" -> LinkBuilders.buildTrojan(outbound, rem, notes, clients)
				"hysteria2" -> LinkBuilders.buildHysteria2(outbound, rem, notes, clients)
				// Xray writes a Hysteria node under the "hysteria" name with the version decided by
				// the settings, not the protocol string.
				"hysteria" -> {
					val settings = outbound.optJSONObject("settings") ?: JSONObject()
					if (isHysteria2(settings, outbound.optJSONObject("streamSettings"))) {
						LinkBuilders.buildHysteria2(outbound, rem, notes, clients)
					} else {
						LinkBuilders.buildHysteria(outbound, rem, notes, clients)
					}
				}
				"tuic" -> LinkBuilders.buildTuic(outbound, rem, notes, clients)
				"socks", "socks5" -> LinkBuilders.buildSocks(outbound, rem, notes, clients)
				"http", "https" -> LinkBuilders.buildHttpProxy(outbound, rem, notes, clients)
				// Recognised, with no share link of its own: it comes back as itself rather than
				// being dropped - unless it could never connect, which every pass leaves out.
				"wireguard" -> outbound.xObj("settings").let { settings ->
					wireguardRefusal(settings) ?: settings?.let { wireguardPeerTrouble(it) }
				}?.let {
					notes.add(it)
					LinkBuilders.REFUSED
				}
				// freedom/blackhole/dns/loopback are not proxies and are not
				// servers anybody imports; passing them by loses nothing.
				in SingBoxProtocols.XRAY_PROTOCOLS_AUX -> AUX_OUTBOUND
				else -> if (LinkBuilders.isShadowsocks(outbound)) {
					// No protocol field, but shaped like a shadowsocks server.
					LinkBuilders.buildShadowsocks(outbound, rem, notes, clients)
				} else {
					// Unknown or new: guessing would be worse than saying so.
					null
				}
			}
		} catch (_: Throwable) {
			null
		}

	// The protocol a note's place names, spelled as the other passes spell it: lower case, as Xray
	// reads it, whichever shape the node came in.
	private fun protocolOf(outbound: JSONObject): String =
		outbound.xrayProtocol().ifEmpty { outbound.optString("type").lowercase() }.ifEmpty { "no protocol" }

	// A node's notes under its place; a refused node's reason, its last, reads as the skip it is.
	private fun placeNodeNotes(
		nodeNotes: List<String>, place: String, refused: Boolean, notes: MutableList<String>
	) {
		for ((k, note) in nodeNotes.withIndex()) {
			val skip = refused && k == nodeNotes.lastIndex
			notes.add("${if (skip) "skipped: " else ""}$place: $note")
		}
	}

	// The cores a drop box names, asked about a node with no link form where its place is known - and
	// whose clients its links are then written for.
	private class Judge(val clients: LinkClients) {
		// Why a core refuses the node, judged as the one-outbound configuration it would be kept
		// as, or null when kept. That configuration's place is not the node's, so only the reason
		// stays; the caller puts the node's own place in front.
		fun refusalOf(kept: String): List<String>? {
			val check = carriage(kept, clients.singBox, clients.mihomo)
			if (check.verdict != Carriage.UNSUPPORTED) return null
			return check.notes.map { it.removePrefix("skipped: ").replace(ONE_OUTBOUND_PLACE, "") }
		}
	}

	private val ONE_OUTBOUND_PLACE = Regex("^outbounds\\[0] \\([^)]*\\): ")

	// Reports a node the builders could not render; the caller keeps the outbound as it was
	// written, inside its configuration or on its own.
	private fun noteNoLinkForm(outbound: JSONObject, notes: MutableList<String>) {
		val protocol = outbound.optString("protocol", outbound.optString("type"))
		val what = if (protocol.isEmpty()) "an outbound with no protocol" else "a $protocol outbound"
		notes.add("$what has no link form and was kept as it was written")
	}

	// Every outbound of a config, rendered as far as it can be - what has a share link becomes one,
	// what doesn't comes back as a one-line config of its own in its original position, and a
	// refused node is left out and counted in refused.
	private fun processJson(
		root: JSONObject,
		notes: MutableList<String>,
		refused: IntArray,
		config: String = "",
		judge: Judge?
	): String? {
		// Already a sing-box document: one configuration, not Xray outbounds to render one by
		// one - taking it apart would hand back a fragment for each.
		if (SingBoxConverter.looksLikeSingBox(root)) return null
		val clients = judge?.clients ?: LinkClients.ANY
		val obs = root.optJSONArray("outbounds")
		if (obs == null) {
			// A lone outbound is the same node as one inside a configuration and shouldn't go
			// quiet just for arriving alone; a non-server stays as-is (nothing to drop it from).
			if (!root.xHas("protocol") && !root.xHas("type") && !LinkBuilders.isShadowsocks(root)) return null
			// Several servers are several nodes alone too: it reads as a configuration of one, which
			// gives each its link; a builder reading the whole outbound would read only the first.
			if (expandOutboundEndpoints(root).size > 1) {
				val single = JSONObject().put("outbounds", JSONArray().put(root))
				return processJson(single, notes, refused, config, judge)
			}
			val nodeNotes = mutableListOf<String>()
			ignoredServerListNote(root)?.let { nodeNotes.add(it) }
			val rootName = nameFallback(root, "", singleProxy = true)
			val made = linkForOutbound(xrayAsRead(root), rootName, nodeNotes, clients)
			keepReasonAlone(made, nodeNotes)
			val link = refuseDeadChain(made, root, listOf(root), nodeNotes)
			when (link) {
				null -> noteNoLinkForm(root, nodeNotes)
				LinkBuilders.REFUSED -> refused[0]++
				AUX_OUTBOUND -> {}
				else -> reportOutboundDrops(root, nodeNotes)
			}
			val protocol = protocolOf(root)
			// A configuration of one, as the cores read a lone outbound, so its place reads alike.
			val place = "${config}outbounds[0] ($protocol)"
			placeNodeNotes(nodeNotes, place, link == LinkBuilders.REFUSED, notes)
			return link?.takeIf { it != AUX_OUTBOUND && it != LinkBuilders.REFUSED }
		}

		val label = labelOf(root, withTag = true)
		// Several servers in one configuration are told apart by their tags; one is just itself.
		val singleProxy = proxyOutboundCount(obs) == 1
		val links = mutableListOf<String>()
		val outboundList = (0 until obs.length()).mapNotNull { obs.optJSONObject(it) }
		for (i in 0 until obs.length()) {
			// A non-outbound entry can't be read, and a half-converted configuration would hand
			// back a subscription missing servers without saying which.
			val whole = obs.optJSONObject(i) ?: run {
				notes.add(
					"${config}outbounds[$i] is not an outbound, so the configuration was left as it is"
				)
				return null
			}
			// An outbound naming several servers becomes several links, each carrying everything
			// the outbound says except which server applies to it.
			val rem = nameFallback(whole, label, singleProxy)
			for (outbound in expandOutboundEndpoints(whole)) {
				val nodeNotes = mutableListOf<String>()
				ignoredServerListNote(whole)?.let { nodeNotes.add(it) }
				val made = linkForOutbound(outbound, rem, nodeNotes, clients)
				keepReasonAlone(made, nodeNotes)
				var link = refuseDeadChain(made, whole, outboundList, nodeNotes)
				if (link == null) {
					// A node copied out of sing-box goes back in its own form, the one its readers know.
					val kept = originalOutbound(root, if (singBoxShaped(whole)) whole else outbound)
					val refusal = judge?.refusalOf(kept)
					if (refusal == null) {
						noteNoLinkForm(outbound, nodeNotes)
						links.add(kept)
					} else {
						// Left out: what the link would have lost does not matter, only why.
						nodeNotes.clear()
						nodeNotes.addAll(refusal)
						link = LinkBuilders.REFUSED
					}
				}
				when (link) {
					AUX_OUTBOUND, null -> {}
					LinkBuilders.REFUSED -> refused[0]++
					else -> {
						reportOutboundDrops(outbound, nodeNotes)
						links.add(link)
					}
				}
				val protocol = protocolOf(outbound)
				val place = "${config}outbounds[$i] ($protocol)"
				placeNodeNotes(nodeNotes, place, link == LinkBuilders.REFUSED, notes)
			}
		}
		return links.joinToString("\n").takeIf { it.isNotEmpty() }
	}

	// A node left out is told by its reason alone, as the other passes tell it: what its link would have
	// lost does not matter once there is no link.
	private fun keepReasonAlone(link: String?, nodeNotes: MutableList<String>) {
		if (link != LinkBuilders.REFUSED || nodeNotes.size < 2) return
		nodeNotes.subList(0, nodeNotes.lastIndex).clear()
	}

	// A link cannot name a chain, but one Xray never connects through takes the node with it.
	private fun refuseDeadChain(
		link: String?, outbound: JSONObject, outbounds: List<JSONObject>, nodeNotes: MutableList<String>
	): String? {
		if (link == null || link == AUX_OUTBOUND || link == LinkBuilders.REFUSED) return link
		val dead = deadChainReason(outbound, outbounds) ?: return link
		nodeNotes.clear()
		nodeNotes.add(dead)
		return LinkBuilders.REFUSED
	}

	// What a share link has no room for, whichever protocol it names. The node still connects
	// without these; the person moving it should know they stayed behind.
	private fun reportOutboundDrops(outbound: JSONObject, notes: MutableList<String>) {
		if (isTruthy(outbound.xObj("mux").xOpt("enabled"))) {
			notes.add(
				"mux is a setting of the client rather than of the server, and no link form " +
					"carries it, so it was dropped"
			)
		}
		if (outbound.xStr("sendThrough").isNotEmpty()) {
			notes.add(
				"sendThrough names a local address to leave from, which no link form carries, " +
					"so it was dropped"
			)
		}
		val chain = xrayChainTag(outbound)
		if (chain.isNotEmpty()) {
			notes.add(
				"this outbound is chained through \"$chain\", which a link cannot name, " +
					"so it will connect directly"
			)
		}
	}
}
