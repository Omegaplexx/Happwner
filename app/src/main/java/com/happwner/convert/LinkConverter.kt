package com.happwner.convert

import java.net.URLEncoder
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

object LinkConverter {
    data class ConversionStats(
        val text: String,
        val xraySkipped: Int,
        // True when the mihomo pass produced the text, so the caller can
        // word the skipped-count label for the right target format.
        val mihomo: Boolean = false,
        // Per-outbound reasons from whichever pass produced the text (why a config was skipped,
        // which option was dropped).
        val notes: List<String> = emptyList()
    )

    fun convert(
        input: String,
        jsonToUri: Boolean = true,
        base64Result: Boolean = false,
        xrayToSb: Boolean = false,
        xrayToMihomo: Boolean = false
    ): String {
        return convertWithStats(input, jsonToUri, base64Result, xrayToSb, xrayToMihomo).text
    }

    // Converts a subscription, and decides only how the answer is wrapped.
    fun convertWithStats(
        input: String,
        jsonToUri: Boolean = true,
        base64Result: Boolean = false,
        xrayToSb: Boolean = false,
        xrayToMihomo: Boolean = false
    ): ConversionStats {
        val wrapper = tryDecodeBase64WithFlag(input)
        val converted = convertPlain(wrapper?.decoded ?: input, jsonToUri, xrayToSb, xrayToMihomo)
        if (!base64Result || converted.text.isEmpty()) return converted
        return converted.copy(
            text = if (wrapper != null) encodeBase64Like(converted.text, wrapper)
            else encodeBase64Plain(converted.text)
        )
    }

    // The conversion itself, on text that is already readable.
    private fun convertPlain(
        input: String,
        jsonToUri: Boolean,
        xrayToSb: Boolean,
        xrayToMihomo: Boolean
    ): ConversionStats {
        // Mihomo output is a whole YAML document, so it replaces the other passes instead of
        // chaining with them.
        if (xrayToMihomo) {
            val mihomo = convertXrayToMihomo(input)
            mihomo.stats?.let { return it }
            // The pass produced no document, so the body belongs to the passes below - but carry
            // mihomo's reasons onto whatever they return, or a total failure ends up explaining
            if (mihomo.notes.isNotEmpty()) {
                val rest = convertPlain(input, jsonToUri, xrayToSb, xrayToMihomo = false)
                return rest.copy(notes = mihomo.notes + rest.notes)
            }
        }

        if (!jsonToUri && !xrayToSb && !xrayToMihomo) return ConversionStats(input.trim(), 0)

        val trimmed = input.trim()
        val compact = isCompactJson(trimmed)

        // xray-to-sing-box only: merge every config into a single one (mergeUnified)
        if (xrayToSb && !jsonToUri) {
            val merged = convertXrayToSingbox(input, trimmed, compact)
            if (merged != null) return merged
        }

        // "Drop profiles incompatible with sing-box", next to Xray to URI: a whole configuration
        // goes or stays, which is what the setting says and what the filter does - a configuration
        if (xrayToSb && jsonToUri) {
            val filtered = preFilterUnsupportedXray(input)
            val inner = convertPlain(filtered.text, jsonToUri = true, xrayToSb = false, xrayToMihomo = false)
            return ConversionStats(inner.text, inner.xraySkipped + filtered.skipped, notes = inner.notes + filtered.notes)
        }

        // Whole body is a single xray config -> sing-box
        if (xrayToSb && trimmed.startsWith("{") && isWholeJsonValue(trimmed)) {
            when (val r = SingBoxConverter.convert(trimmed, "")) {
                is SingBoxConverter.Result.Ok ->
                    return ConversionStats(formatJson(r.config, compact), 0, notes = r.notes)
                // Nothing could be converted.
                is SingBoxConverter.Result.Unsupported ->
                    return ConversionStats("", 1, notes = r.notes)
                SingBoxConverter.Result.NotXray -> {}
            }
        }

        // Whole body is an xray array -> sing-box
        if (xrayToSb && trimmed.startsWith("[") && isWholeJsonValue(trimmed)) {
            val arr = tryConvertXrayArray(trimmed, compact)
            if (arr != null) return ConversionStats(arr.text, arr.skipped, notes = arr.notes)
        }

        // A pretty-printed JSON config spans several lines, so the per-line pass never sees it
        // whole. Try the whole body as one value first.
        if (jsonToUri && (trimmed.startsWith("{") || trimmed.startsWith("[")) && isWholeJsonValue(trimmed)) {
            val wholeNotes = mutableListOf<String>()
            jsonValueToLinks(trimmed, wholeNotes)?.let { return ConversionStats(it, 0, notes = wholeNotes) }
        }

        val res = StringBuilder()
        var skipped = 0
        val notes = mutableListOf<String>()
        // Otherwise walk line by line
        input.lines().forEach { line ->
            val t = line.trim()
            if (t.isEmpty()) return@forEach
            val lineCompact = isCompactJson(t)

            // A single line can be wrapped on its own: unwrap, convert, wrap the whole answer once at the end.
            // Unwrapping can't run away - base64 never begins with "{", "[" or a scheme, so a second layer is refused.
            val lineWrapper = tryDecodeBase64WithFlag(t)
            if (lineWrapper != null) {
                val inner = convertPlain(lineWrapper.decoded, jsonToUri, xrayToSb, xrayToMihomo)
                res.append(inner.text).append("\n")
                skipped += inner.xraySkipped
                notes.addAll(inner.notes)
                return@forEach
            }

            if (xrayToSb && t.startsWith("{") && isWholeJsonValue(t)) {
                when (val r = SingBoxConverter.convert(t, "")) {
                    is SingBoxConverter.Result.Ok -> {
                        res.append(formatJson(r.config, lineCompact)).append("\n")
                        notes.addAll(r.notes)
                        return@forEach
                    }
                    is SingBoxConverter.Result.Unsupported -> {
                        skipped++
                        notes.addAll(r.notes)
                        return@forEach
                    }
                    SingBoxConverter.Result.NotXray -> {}
                }
            }

            if (xrayToSb && t.startsWith("[") && isWholeJsonValue(t)) {
                val arr = tryConvertXrayArray(t, lineCompact)
                if (arr != null) {
                    res.append(arr.text).append("\n")
                    skipped += arr.skipped
                    notes.addAll(arr.notes)
                    return@forEach
                }
            }

            // A JSON outbound (or array of them) on this line -> proxy link(s)
            if (jsonToUri && (t.startsWith("{") || t.startsWith("[")) && isWholeJsonValue(t)) {
                val converted = jsonValueToLinks(t, notes)
                if (converted != null) res.append(converted).append("\n")
                // A single object that rendered to nothing stays as it was; an
                // array that did is dropped, exactly as before.
                else if (t.startsWith("{")) res.append(t).append("\n")
                return@forEach
            }

            // A line nothing above claimed. Whitespace around a link carries nothing and a list
            // reads better without it, so a link is tidied.
            val isLink = PROXY_SCHEMES.any { t.startsWith(it, ignoreCase = true) }
            res.append(if (isLink) t else line).append("\n")
        }
        return ConversionStats(res.toString().trim(), skipped, notes = notes)
    }

    // A whole JSON value - an outbound object or an array of them - rendered to newline-joined
    // links, or null when it produced none.
    private fun jsonValueToLinks(body: String, notes: MutableList<String>): String? {
        return try {
            if (body.startsWith("[")) {
                val arr = JSONArray(body)
                val out = StringBuilder()
                for (i in 0 until arr.length()) {
                    val obj = arr.optJSONObject(i)
                    val piece: String? = if (obj != null) {
                        processJson(obj, notes) ?: obj.toString()
                    } else {
                        val raw = arr.opt(i)
                        if (raw == null || raw === JSONObject.NULL) null
                        else raw.toString().trim().takeIf { it.isNotEmpty() }
                    }
                    if (piece != null) {
                        if (out.isNotEmpty()) out.append("\n")
                        out.append(piece)
                    }
                }
                out.toString().takeIf { it.isNotEmpty() }
            } else {
                processJson(JSONObject(body), notes)
            }
        } catch (_: Exception) {
            null
        }
    }

    // Single-line JSON? (no newline within the first 1KB)
    private fun isCompactJson(s: String): Boolean {
        val limit = minOf(s.length, 1024)
        for (i in 0 until limit) {
            val c = s[i]
            if (c == '\n' || c == '\r') return false
        }
        return true
    }

    // true if the whole string is one valid JSON value (no trailing junk).
    private fun isWholeJsonValue(s: String): Boolean {
        return try {
            if (JsonDepth.exceedsMaxDepth(s)) return false
            val t = JSONTokener(s)
            t.nextValue()
            t.nextClean().code == 0
        } catch (_: Exception) {
            false
        }
    }

    private fun formatJson(obj: JSONObject, compact: Boolean): String =
        if (compact) obj.toString() else obj.toString(2)

    private fun formatJsonArray(arr: JSONArray, compact: Boolean): String =
        if (compact) arr.toString() else arr.toString(2)

    private data class ArrayConvResult(val text: String, val skipped: Int, val notes: List<String> = emptyList())

    private data class FilterResult(val text: String, val skipped: Int, val notes: List<String> = emptyList())

    // Normalize vless flow to its sing-box-valid form (xtls-rprx-vision-udp443 -> xtls-rprx-vision)
    private fun normalizeConfigFlowsInPlace(cfg: JSONObject): Boolean {
        val outs = cfg.optJSONArray("outbounds") ?: return false
        var changed = false
        for (i in 0 until outs.length()) {
            val ob = outs.optJSONObject(i) ?: continue
            if (ob.optString("protocol") != "vless") continue
            val vnext = ob.optJSONObject("settings")?.optJSONArray("vnext") ?: continue
            for (j in 0 until vnext.length()) {
                val users = vnext.optJSONObject(j)?.optJSONArray("users") ?: continue
                for (k in 0 until users.length()) {
                    val u = users.optJSONObject(k) ?: continue
                    val flow = u.optString("flow", "")
                    if (flow.isNotEmpty()) {
                        val norm = SingBoxConverter.normalizeFlow(flow)
                        if (norm != flow) { u.put("flow", norm); changed = true }
                    }
                }
            }
        }
        return changed
    }

    // Keep one xray config/array, dropping unsupported outbounds
    private fun preFilterUnsupportedXrayOne(t: String): FilterResult? {
        if (t.isEmpty()) return null
        if (!isWholeJsonValue(t)) return null
        if (t.startsWith("{")) {
            return when (val r = SingBoxConverter.convertToOutbounds(t, "")) {
                is SingBoxConverter.OutboundsResult.Ok -> {
                    val cfg = try { JSONObject(t) } catch (_: Exception) { null }
                    if (cfg != null && normalizeConfigFlowsInPlace(cfg)) FilterResult(cfg.toString(), 0, r.notes)
                    else FilterResult(t, 0, r.notes)
                }
                is SingBoxConverter.OutboundsResult.Unsupported -> FilterResult("", 1, r.notes)
                SingBoxConverter.OutboundsResult.NotXray -> null
            }
        }
        if (t.startsWith("[")) {
            val arr = try { JSONArray(t) } catch (_: Exception) { return null }
            val out = JSONArray()
            var anyXray = false
            var skipped = 0
            val notes = mutableListOf<String>()
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i)
                if (obj == null) {
                    val raw = arr.opt(i)
                    if (raw != null && raw !== JSONObject.NULL) out.put(raw)
                    continue
                }
                when (val r = SingBoxConverter.convertToOutbounds(obj.toString(), "")) {
                    is SingBoxConverter.OutboundsResult.Ok -> {
                        normalizeConfigFlowsInPlace(obj)
                        out.put(obj)
                        anyXray = true
                        notes.addAll(r.notes)
                    }
                    is SingBoxConverter.OutboundsResult.Unsupported -> {
                        skipped++
                        anyXray = true
                        notes.addAll(r.notes)
                    }
                    SingBoxConverter.OutboundsResult.NotXray -> out.put(obj)
                }
            }
            if (!anyXray) return null
            return FilterResult(formatJsonArray(out, isCompactJson(t)), skipped, notes)
        }
        return null
    }

    // Drop unsupported xray configs/outbounds and count the skipped ones
    private fun preFilterUnsupportedXray(input: String): FilterResult {
        val trimmed = input.trim()
        if ((trimmed.startsWith("{") || trimmed.startsWith("[")) && isWholeJsonValue(trimmed)) {
            val single = preFilterUnsupportedXrayOne(trimmed)
            if (single != null) return single
        }
        val res = StringBuilder()
        var totalSkipped = 0
        var anyFiltered = false
        val totalNotes = mutableListOf<String>()
        for (line in input.lines()) {
            val tt = line.trim()
            if (tt.isEmpty()) continue
            val one = preFilterUnsupportedXrayOne(tt)
            if (one != null) {
                anyFiltered = true
                if (one.text.isNotEmpty()) res.append(one.text).append("\n")
                totalSkipped += one.skipped
                totalNotes.addAll(one.notes)
            } else {
                res.append(tt).append("\n")
            }
        }
        if (!anyFiltered) return FilterResult(input, 0)
        return FilterResult(res.toString().trimEnd('\n'), totalSkipped, totalNotes)
    }

    // Convert each xray config inside an array to sing-box
    private fun tryConvertXrayArray(text: String, compact: Boolean): ArrayConvResult? {
        val arr = try { JSONArray(text) } catch (_: Exception) { return null }
        if (arr.length() == 0) return null

        var anyXray = false
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val outs = obj.optJSONArray("outbounds") ?: continue
            for (j in 0 until outs.length()) {
                val o = outs.optJSONObject(j) ?: continue
                if (o.has("protocol")) { anyXray = true; break }
            }
            if (anyXray) break
        }
        if (!anyXray) return null

        val outArr = JSONArray()
        var skipped = 0
        val notes = mutableListOf<String>()
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i)
            if (obj == null) {
                val raw = arr.opt(i)
                if (raw != null && raw !== JSONObject.NULL) outArr.put(raw)
                continue
            }
            when (val r = SingBoxConverter.convert(obj.toString(), "")) {
                is SingBoxConverter.Result.Ok -> { outArr.put(r.config); notes.addAll(r.notes) }
                is SingBoxConverter.Result.Unsupported -> { skipped++; notes.addAll(r.notes) }
                SingBoxConverter.Result.NotXray -> outArr.put(obj)
            }
        }
        return ArrayConvResult(formatJsonArray(outArr, compact), skipped, notes)
    }

    // The outcome of the mihomo pass: a document when one was produced, and the per-outbound
    // reasons either way ("no document" is not "nothing to report").
    private data class MihomoPass(val stats: ConversionStats?, val notes: List<String>)

    private val MIHOMO_PASS_NONE = MihomoPass(null, emptyList())

    // Convert every xray config in the body into one mihomo YAML document. A null document means
    // the body holds no xray config, so the caller can fall back to the other conversion passes.
    private fun convertXrayToMihomo(input: String): MihomoPass {
        var body = input.trim()
        if (body.isEmpty()) return MIHOMO_PASS_NONE
        if (!body.startsWith("{") && !body.startsWith("[")) {
            // Subscription panels commonly base64-wrap the body. The YAML is
            // always emitted plain, which is what a mihomo client reads.
            body = tryDecodeBase64WithFlag(input)?.decoded?.trim() ?: return MIHOMO_PASS_NONE
        }

        val whole = runMihomo(body)
        if (whole.stats != null || whole.notes.isNotEmpty()) return whole

        // Some panels put one configuration per line instead of in an array.
        val arr = JSONArray()
        for (line in body.lines()) {
            val t = line.trim()
            if (!t.startsWith("{") || !isWholeJsonValue(t)) continue
            val obj = try { JSONObject(t) } catch (_: Exception) { continue }
            arr.put(obj)
        }
        if (arr.length() == 0) return MIHOMO_PASS_NONE
        return runMihomo(arr.toString())
    }

    private fun runMihomo(text: String): MihomoPass =
        when (val r = MihomoConverter.convert(text)) {
            is MihomoConverter.Result.Ok ->
                MihomoPass(
                    ConversionStats(r.yaml.trimEnd('\n'), r.skipped, mihomo = true, notes = r.notes),
                    r.notes
                )
            // Xray, but nothing in it could be converted: leave the body to the other passes rather
            // than handing back an empty configuration.
            is MihomoConverter.Result.Unsupported -> MihomoPass(null, r.notes)
            MihomoConverter.Result.NotXray -> MIHOMO_PASS_NONE
        }

    // Merge xray configs into one sing-box; pass any other lines through unchanged
    private fun convertXrayToSingbox(input: String, trimmed: String, compact: Boolean): ConversionStats? {
        val configs = mutableListOf<JSONObject>()
        var skipped = 0
        var hadXray = false
        val passthroughLines = mutableListOf<String>()
        val notes = mutableListOf<String>()

        fun ingestObject(s: String): Boolean {
            return when (val r = SingBoxConverter.convert(s, "")) {
                is SingBoxConverter.Result.Ok -> {
                    configs.add(r.config); hadXray = true; notes.addAll(r.notes); true
                }
                is SingBoxConverter.Result.Unsupported -> {
                    skipped++; hadXray = true; notes.addAll(r.notes); true
                }
                SingBoxConverter.Result.NotXray -> false
            }
        }

        fun ingestArray(s: String): Boolean {
            val arr = try { JSONArray(s) } catch (_: Exception) { return false }
            var any = false
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                when (val r = SingBoxConverter.convert(obj.toString(), "")) {
                    is SingBoxConverter.Result.Ok -> {
                        configs.add(r.config); any = true; notes.addAll(r.notes)
                    }
                    is SingBoxConverter.Result.Unsupported -> {
                        skipped++; any = true; notes.addAll(r.notes)
                    }
                    SingBoxConverter.Result.NotXray -> {}
                }
            }
            if (any) hadXray = true
            return any
        }

        val consumedWhole = when {
            trimmed.startsWith("{") && isWholeJsonValue(trimmed) -> ingestObject(trimmed)
            trimmed.startsWith("[") && isWholeJsonValue(trimmed) -> ingestArray(trimmed)
            else -> false
        }

        if (!consumedWhole) {
            for (line in input.lines()) {
                val t = line.trim()
                if (t.isEmpty()) continue
                val consumed = when {
                    t.startsWith("{") && isWholeJsonValue(t) -> ingestObject(t)
                    t.startsWith("[") && isWholeJsonValue(t) -> ingestArray(t)
                    else -> false
                }
                if (!consumed) passthroughLines.add(t)
            }
        }

        if (!hadXray) return null
        if (configs.isEmpty() && passthroughLines.isEmpty()) return null

        val builder = StringBuilder()
        if (configs.isNotEmpty()) {
            val merged = SingBoxConverter.mergeUnified(configs)
            if (merged != null) builder.append(formatJson(merged, compact))
        }
        for (l in passthroughLines) {
            if (builder.isNotEmpty()) builder.append("\n")
            builder.append(l)
        }

        return ConversionStats(builder.toString(), skipped, notes = notes)
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
        if (cleaned.isEmpty()) return null

        var hasStd = false
        var hasUrl = false
        var hadNewlines = false
        var hadPadding = false
        // Scan the alphabet: std vs url-safe, padding, newlines; bail on anything non-base64
        for (c in cleaned) {
            when {
                c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == ' ' || c == '\t' -> {}
                c == '=' -> hadPadding = true
                c == '\r' || c == '\n' -> { hadNewlines = true }
                c == '+' || c == '/' -> hasStd = true
                c == '-' || c == '_' -> hasUrl = true
                else -> return null
            }
        }
        if (hasStd && hasUrl) return null
        val rstripped = input.trimEnd(' ', '\t')
        val hadTrailingCrlf = rstripped.endsWith("\r\n")
        val hadTrailingNewline = hadTrailingCrlf || rstripped.endsWith("\n") || rstripped.endsWith("\r")
        val hadCrlf = (hadNewlines && cleaned.contains("\r\n")) || hadTrailingCrlf

        val flag = if (hasUrl) android.util.Base64.URL_SAFE else android.util.Base64.DEFAULT

        // Decode, then accept only if it's real text that looks like configs/links
        return try {
            val data = android.util.Base64.decode(cleaned, flag)
            if (data.isEmpty()) return null
            // Strict UTF-8 decode: binary/garbage is rejected (throws CharacterCodingException), valid text passes
            val decodedRaw = try {
                Charsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(data))
                    .toString()
            } catch (_: java.nio.charset.CharacterCodingException) {
                return null
            }
            // Control characters (except \t \n \r) and DEL indicate binary, so reject them
            for (ch in decodedRaw) {
                val cc = ch.code
                if (cc == 0x7f || (cc < 0x20 && cc != 0x09 && cc != 0x0a && cc != 0x0d)) return null
            }
            val decoded = decodedRaw.trimStart()
            val firstLine = decoded.lineSequence().firstOrNull { it.isNotBlank() }?.trimStart() ?: return null
            val looksLikeJson = firstLine.startsWith("{") || firstLine.startsWith("[")
            val looksLikeProxyList = PROXY_SCHEMES.any { firstLine.startsWith(it, ignoreCase = true) }
            if (looksLikeJson || looksLikeProxyList) {
                Base64Result(decoded, flag, hadNewlines, hadCrlf, hadPadding, hadTrailingNewline, hadTrailingCrlf)
            } else null
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    // Re-pack into base64 in exactly the same shape as the input The wrapping for an answer whose
    // input had none to copy: the standard alphabet, padded, on one line - the shape every
    private fun encodeBase64Plain(text: String): String =
        android.util.Base64.encodeToString(
            text.toByteArray(Charsets.UTF_8),
            android.util.Base64.NO_WRAP
        )

    private fun encodeBase64Like(text: String, b64: Base64Result): String {
        var flags = b64.flag
        if (!b64.hadNewlines) {
            flags = flags or android.util.Base64.NO_WRAP
        } else if (b64.hadCrlf) {
            flags = flags or android.util.Base64.CRLF
        }
        if (!b64.hadPadding) {
            flags = flags or android.util.Base64.NO_PADDING
        }
        val raw = android.util.Base64.encodeToString(text.toByteArray(Charsets.UTF_8), flags)
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

    // One outbound, written back as a compact config of its own (the result is read a line at a
    // time).
    private fun originalOutbound(root: JSONObject, ob: JSONObject): String {
        val one = JSONObject()
        val remarks = root.optString("remarks", "")
        if (remarks.isNotEmpty()) one.put("remarks", remarks)
        one.put("outbounds", JSONArray().put(ob))
        return one.toString()
    }

    // Reports a node the builders could not render and hands back nothing, so the caller keeps the
    // outbound as it was written. The wording matches the loop below.
    private fun keptAsWritten(protocol: String, notes: MutableList<String>): String? {
        notes.add("a $protocol outbound has no link form and was kept as it was written")
        return null
    }

    // Every outbound of a config, each rendered as far as it can be. What has a share link becomes
    // one; what does not comes back as a one-line config of its own, in its original position.
    private fun processJson(root: JSONObject, notes: MutableList<String>): String? {
        if (isShadowsocks(root)) {
            return buildShadowsocks(root, root.optString("remarks", ""))
        }

        val protocol = root.optString("protocol", root.optString("type"))
        when (protocol) {
            // Said here as well as in the loop below: one outbound on its own is the same node as
            // one inside a configuration, and it should not go quiet just because it arrived alone.
            "vmess" -> return buildVmess(root, root.optString("tag", root.optString("remarks", "")))
                ?: keptAsWritten("vmess", notes)
            "tuic" -> return buildTuic(root, root.optString("tag", root.optString("remarks", "")))
                ?: keptAsWritten("tuic", notes)
        }

        val obs = root.optJSONArray("outbounds") ?: return null
        val rem = root.optString("remarks", "")
        val links = mutableListOf<String>()
        for (i in 0 until obs.length()) {
            val ob = obs.optJSONObject(i) ?: return null
            val p = ob.optString("protocol", ob.optString("type"))
            // A builder reads a node written by someone else and can meet a shape it cannot take -
            // an empty server list, a port that is not a number.
            val link: String? = try {
                when (p) {
                "vless" -> buildVless(ob, rem)
                "vmess" -> buildVmess(ob, rem)
                "shadowsocks" -> buildShadowsocks(ob, rem)
                "trojan" -> buildTrojan(ob, rem)
                "hysteria2" -> buildHysteria2(ob, rem)
                // Xray writes a Hysteria node under the "hysteria" name with the version decided by
                // the settings, not the protocol string.
                "hysteria" -> {
                    val settings = ob.optJSONObject("settings") ?: JSONObject()
                    if (isHysteria2(settings, ob.optJSONObject("streamSettings"))) {
                        buildHysteria2(ob, rem)
                    } else {
                        buildHysteria(ob, rem)
                    }
                }
                "tuic" -> buildTuic(ob, rem)
                "socks", "socks5" -> buildSocks(ob, rem)
                "http", "https" -> buildHttpProxy(ob, rem)
                    // Recognised, with no share link of its own: it comes back
                    // as itself rather than being dropped.
                    "wireguard" -> null
                    // freedom/blackhole/dns/loopback are not proxies and are not
                    // servers anybody imports; passing them by loses nothing.
                    in SingBoxProtocols.XRAY_PROTOCOLS_AUX -> AUX_OUTBOUND
                    else -> if (isShadowsocks(ob)) {
                        // No protocol field, but shaped like a shadowsocks server.
                        buildShadowsocks(ob, rem)
                    } else {
                        // Unknown or new: guessing would be worse than saying so.
                        null
                    }
                }
            } catch (_: Throwable) {
                null
            }
            when (link) {
                AUX_OUTBOUND -> {}
                null -> {
                    val what = when {
                        p.isEmpty() -> "an outbound with no protocol"
                        else -> "a $p outbound"
                    }
                    notes.add("$what has no link form and was kept as it was written")
                    links.add(originalOutbound(root, ob))
                }
                else -> links.add(link)
            }
        }
        return links.joinToString("\n").takeIf { it.isNotEmpty() }
    }

    // Hysteria v1 as a link, in the scheme the v1 client documents: credential in `auth`, rates in
    // `upmbps`/`downmbps`, SNI in `peer`, obfuscator `xplus` with its password in `obfsParam`.
    private fun buildHysteria(ob: JSONObject, rem: String): String? {
        return try {
            val settings = ob.optJSONObject("settings") ?: JSONObject()
            val ss = ob.optJSONObject("streamSettings")

            val ep = hysteriaEndpoints(settings).firstOrNull() ?: return null
            val address = ep.address
            var port = ep.port
            if (port == 0) firstPortOfRange(ep.ports)?.let { port = it }
            if (address.isEmpty() || port !in 1..65535) return null

            val up = SingBoxHysteria.mbpsNumber(ep.up) ?: return null
            val down = SingBoxHysteria.mbpsNumber(ep.down) ?: return null

            val tls = hysteriaTls(settings, ss)
            // Read beside the address as well as beside the protocol: both shapes are in use, and
            // a link with no obfuscation in it is one the server will not answer.
            val (obfsMode, obfsPassword) = parsedObfsAnywhere(settings)
            // Version 1's obfuscation secret is a single string, read the way the
            // converters read it. When present the mode is xplus, v1's only one.
            val obfsSecret = firstNonEmpty(obfsPassword, obfsMode)

            val params = linkedMapOf<String, String>()
            params["protocol"] = "udp"
            if (ep.password.isNotEmpty()) params["auth"] = ep.password
            if (tls.sni.isNotEmpty()) params["peer"] = tls.sni
            if (tls.insecure) params["insecure"] = "1"
            params["upmbps"] = up.toString()
            params["downmbps"] = down.toString()
            if (tls.alpn.isNotEmpty()) params["alpn"] = tls.alpn.joinToString(",")
            if (obfsSecret.isNotEmpty()) {
                params["obfs"] = "xplus"
                params["obfsParam"] = obfsSecret
            }

            val host = LinkParams.hostForUri(address)
            "hysteria://$host:$port${LinkParams.queryString(params)}#${LinkParams.enc(rem)}"
        } catch (_: Exception) { null }
    }

    private fun isShadowsocks(obj: JSONObject): Boolean {
        if (obj.has("server") && obj.has("server_port") && obj.has("password") && obj.has("method")) return true
        val settings = obj.optJSONObject("settings")
        if (settings != null) {
            val servers = settings.optJSONArray("servers")
            if (servers != null && servers.length() > 0) {
                val s = servers.getJSONObject(0)
                if (s.has("address") && s.has("port") && s.has("password") && s.has("method")) return true
            }
        }
        return false
    }

    // VLESS: vnext/users plus reality/stream params
    // Renders a VLESS node as a link.
    private fun buildVless(ob: JSONObject, rem: String): String? {
        return try {
            val s = ob.optJSONObject("settings") ?: return null
            val vnext = s.optJSONArray("vnext") ?: return null
            if (vnext.length() == 0) return null
            val vn = vnext.getJSONObject(0)
            val users = vn.optJSONArray("users") ?: return null
            if (users.length() == 0) return null
            val u = users.getJSONObject(0)

            val id = u.optString("id", "")
            val address = vn.optString("address", "")
            val port = vn.optInt("port", 0)
            if (id.isEmpty() || address.isEmpty() || port !in 1..65535) return null

            val params = linkedMapOf<String, String>()
            params["encryption"] = u.optString("encryption", "none").ifEmpty { "none" }
            // Verbatim rather than through the sing-box mapping: a share link is read by Xray-family
            // clients, which take "xtls-rprx-vision-udp443" and act on the -udp443 part.
            val flow = u.optString("flow", "").trim()
            if (flow.isNotEmpty() && flow != "none") params["flow"] = flow

            LinkParams.streamParams(ob.optJSONObject("streamSettings"), params)

            val host = LinkParams.hostForUri(address)
            "vless://${LinkParams.enc(id)}@$host:$port${LinkParams.queryString(params)}#${LinkParams.enc(rem)}"
        } catch (_: Exception) { null }
    }

    // Renders a VMess node as a link: the legacy JSON blob, base64-encoded.
    private fun buildVmess(ob: JSONObject, rem: String): String? {
        return try {
            val settings = ob.optJSONObject("settings")
            val vnext = settings?.optJSONArray("vnext")?.optJSONObject(0)
            val user = vnext?.optJSONArray("users")?.optJSONObject(0)

            val addr = firstNonEmpty(vnext?.optString("address") ?: "", ob.optString("server"))
            // Read once: the field was being asked for twice, and the second
            // ask only existed to satisfy the compiler about the first.
            val port = vnext?.optInt("port")?.takeIf { it > 0 } ?: ob.optInt("server_port", 0)
            val uuid = firstNonEmpty(user?.optString("id") ?: "", ob.optString("uuid"))
            if (addr.isEmpty() || port !in 1..65535 || uuid.isEmpty()) return null

            // The stream parameters first, then translated into the blob's own
            // names; the two vocabularies differ only in spelling.
            val params = linkedMapOf<String, String>()
            LinkParams.streamParams(ob.optJSONObject("streamSettings"), params)

            // The vmess blob has TLS fields and none for REALITY, so a REALITY node would go out as a
            // plain-TLS link: complete-looking and refused. Nothing returned means a working fallback.
            if (params["security"] == "reality") return null

            val linkJson = JSONObject()
            linkJson.put("v", "2")
            linkJson.put("add", addr)
            linkJson.put("port", port.toString())
            linkJson.put("id", uuid)
            // alterId is a number in the blob and every current node is zero.
            linkJson.put("aid", (user?.optInt("alterId", 0) ?: 0).toString())
            linkJson.put("scy", user?.optString("security", "auto")?.ifEmpty { "auto" } ?: "auto")
            linkJson.put("net", params["type"] ?: "tcp")
            // The blob calls the masquerade "type" where the query calls it
            // headerType, and expects "none" rather than an absent field.
            linkJson.put("type", params["headerType"] ?: "none")
            linkJson.put("host", params["host"] ?: "")
            linkJson.put("path", params["path"] ?: params["serviceName"] ?: "")
            linkJson.put("tls", if (params["security"] in setOf("tls", "reality")) "tls" else "")
            linkJson.put("sni", params["sni"] ?: "")
            // Present but empty is not absent here: clients read "alpn" as a comma-separated list,
            // so an empty string offers one empty protocol name and the handshake finds no match.
            params["alpn"]?.takeIf { it.isNotEmpty() }?.let { linkJson.put("alpn", it) }
            linkJson.put("fp", params["fp"] ?: "")
            linkJson.put("ps", rem)

            val base64 = android.util.Base64.encodeToString(
                linkJson.toString().toByteArray(), android.util.Base64.NO_WRAP
            )
            "vmess://$base64"
        } catch (_: Exception) { null }
    }

    // Renders a SOCKS node as a link (there was no builder, so it came out as raw JSON).
    // Credentials go in the userinfo base64-encoded, the form clients read.
    private fun buildSocks(ob: JSONObject, rem: String): String? {
        return try {
            val settings = ob.optJSONObject("settings")
            val server = settings?.optJSONArray("servers")?.optJSONObject(0) ?: return null
            val address = server.optString("address", "")
            val port = server.optInt("port", 0)
            if (address.isEmpty() || port !in 1..65535) return null

            val user = server.optJSONArray("users")?.optJSONObject(0)
            val name = user?.optString("user", "") ?: ""
            val pass = user?.optString("pass", "") ?: ""
            val userInfo = if (name.isEmpty() && pass.isEmpty()) "" else {
                val raw = "$name:$pass"
                android.util.Base64.encodeToString(
                    raw.toByteArray(), android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING
                ) + "@"
            }
            val host = LinkParams.hostForUri(address)
            "socks://$userInfo$host:$port#${LinkParams.enc(rem)}"
        } catch (_: Exception) { null }
    }

    // Renders an HTTP proxy node as a link. The scheme follows the TLS layer - an HTTP proxy over
    // TLS is https://, which is how clients tell the two apart.
    private fun buildHttpProxy(ob: JSONObject, rem: String): String? {
        return try {
            val settings = ob.optJSONObject("settings")
            val server = settings?.optJSONArray("servers")?.optJSONObject(0) ?: return null
            val address = server.optString("address", "")
            val port = server.optInt("port", 0)
            if (address.isEmpty() || port !in 1..65535) return null

            val user = server.optJSONArray("users")?.optJSONObject(0)
            val name = user?.optString("user", "") ?: ""
            val pass = user?.optString("pass", "") ?: ""
            val userInfo = if (name.isEmpty() && pass.isEmpty()) ""
            else "${LinkParams.enc(name)}:${LinkParams.enc(pass)}@"

            val ss = ob.optJSONObject("streamSettings")
            val secure = ss?.optString("security", "")?.lowercase() in setOf("tls", "xtls")
            val params = linkedMapOf<String, String>()
            if (secure) {
                val tls = ss?.optJSONObject("tlsSettings")
                val sni = tls?.optString("serverName", "") ?: ""
                if (sni.isNotEmpty()) params["sni"] = sni
                val alpn = LinkParams.joinList(tls?.opt("alpn"))
                if (alpn.isNotEmpty()) params["alpn"] = alpn
                if (tls?.optBoolean("allowInsecure", false) == true) params["allowInsecure"] = "1"
            }
            val scheme = if (secure) "https" else "http"
            val host = LinkParams.hostForUri(address)
            "$scheme://$userInfo$host:$port${LinkParams.queryString(params)}#${LinkParams.enc(rem)}"
        } catch (_: Exception) { null }
    }

    // Shadowsocks: base64(method:password)@host:port
    private fun buildShadowsocks(ob: JSONObject, rem: String): String? {
        return try {
            val address: String
            val port: Int
            val method: String
            val password: String
            if (ob.has("server")) {
                address = ob.getString("server")
                port = ob.getInt("server_port")
                method = ob.getString("method")
                password = ob.getString("password")
            } else {
                val settings = ob.optJSONObject("settings")
                val s = settings?.optJSONArray("servers")?.getJSONObject(0) ?: return null
                address = s.getString("address")
                port = s.getInt("port")
                method = s.getString("method")
                password = s.getString("password")
            }
            // SIP002 carries the userinfo as web-safe base64 of "method:password".
            val ui = if (method.startsWith("2022-")) {
                "${LinkParams.enc(method)}:${LinkParams.enc(password)}"
            } else {
                android.util.Base64.encodeToString(
                    "$method:$password".toByteArray(),
                    android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING or android.util.Base64.URL_SAFE
                )
            }
            val finalRem = if (ob.has("remarks")) ob.getString("remarks") else rem
            val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")
            // The server expects the obfuscation the plugin performs, so a link without it points at
            // a server that will not answer. SIP002 carries it as one "name;options" value.
            val plugin = ob.optString("plugin", "").trim()
            val query = if (plugin.isEmpty()) "" else {
                val opts = SingBoxProtocols.serializePluginOpts(ob.opt("plugin_opts"))
                val spec = if (opts.isEmpty()) plugin else "$plugin;$opts"
                "/?plugin=" + LinkParams.enc(spec)
            }
            "ss://$ui@${LinkParams.hostForUri(address)}:$port$query#$encRem"
        } catch (_: Exception) { null }
    }

    // Trojan: password@host:port with a tls/ws query
    // Renders a Trojan node as a link.
    private fun buildTrojan(ob: JSONObject, rem: String): String? {
        return try {
            val settings = ob.optJSONObject("settings")
            val server = settings?.optJSONArray("servers")?.optJSONObject(0) ?: return null
            val address = server.optString("address", "")
            val port = server.optInt("port", 0)
            val password = server.optString("password", "")
            if (address.isEmpty() || port !in 1..65535) return null

            val params = linkedMapOf<String, String>()
            LinkParams.streamParams(ob.optJSONObject("streamSettings"), params, mirrorSniToHost = true)

            val finalRem = if (ob.has("remarks")) ob.getString("remarks") else rem
            val host = LinkParams.hostForUri(address)
            "trojan://${LinkParams.enc(password)}@$host:$port" +
                "${LinkParams.queryString(params)}#${LinkParams.enc(finalRem)}"
        } catch (_: Exception) { null }
    }

    // Hysteria2: password@host:port with an obfs/sni query
    // Renders a Hysteria2 node as a link, read through the shared parsers.
    private fun buildHysteria2(ob: JSONObject, rem: String): String? {
        return try {
            val settings = ob.optJSONObject("settings") ?: JSONObject()
            val ss = ob.optJSONObject("streamSettings")

            val ep = hysteriaEndpoints(settings).firstOrNull() ?: return null
            val params = HysteriaParams()
            params.fromStream(ArrayList(), ss)

            val address = ep.address
            var port = ep.port
            if (port == 0) firstPortOfRange(firstNonEmpty(ep.ports, params.ports))?.let { port = it }
            if (address.isEmpty() || port !in 1..65535) return null

            val password = firstNonEmpty(ep.password, params.password)
            // Obfuscation can sit beside the address rather than the protocol; read from both, or
            // the link goes out without it and the server will not answer.
            val (obfsFromSettings, obfsPwFromSettings) = parsedObfsAnywhere(settings)
            val obfsType = firstNonEmpty(obfsFromSettings, params.obfs)
            val obfsPassword = firstNonEmpty(obfsPwFromSettings, params.obfsPassword)
            val tls = hysteriaTls(settings, ss)

            val query = StringBuilder()
            if (obfsType.isNotEmpty()) query.append("&obfs=").append(URLEncoder.encode(obfsType, "UTF-8"))
            if (obfsPassword.isNotEmpty()) query.append("&obfs-password=").append(URLEncoder.encode(obfsPassword, "UTF-8"))
            if (tls.sni.isNotEmpty()) query.append("&sni=").append(URLEncoder.encode(tls.sni, "UTF-8"))
            if (tls.insecure) query.append("&insecure=1")
            if (tls.alpn.isNotEmpty()) query.append("&alpn=").append(URLEncoder.encode(tls.alpn.joinToString(","), "UTF-8"))
            // Port hopping: the primary port stays in the authority so every client connects, and
            // the range travels as mport.
            val hopPorts = firstNonEmpty(ep.ports, params.ports)
            if (hopPorts.any { it == ',' || it == '-' || it == ':' }) {
                query.append("&mport=").append(URLEncoder.encode(hopPorts.replace(':', '-'), "UTF-8"))
                val hopInt = params.hopInterval.ifEmpty { hysteriaHopInterval(settings) }
                if (hopInt.isNotEmpty()) query.append("&mportHopInt=").append(URLEncoder.encode(hopInt, "UTF-8"))
            }

            val queryString = if (query.isNotEmpty()) "?" + query.toString().substring(1) else ""
            val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
            val userInfo = if (password.isEmpty()) "" else URLEncoder.encode(password, "UTF-8") + "@"

            "hysteria2://$userInfo${LinkParams.hostForUri(address)}:$port/$queryString#$encRem"
        } catch (_: Exception) { null }
    }

    // TUIC: uuid:password@host:port with a congestion/tls query
    // Renders a TUIC node as a link, in either shape it arrives in.
    private fun buildTuic(ob: JSONObject, rem: String): String? {
        return try {
            val xraySettings = ob.optJSONObject("settings")
            val xraySrv = xraySettings?.optJSONArray("servers")?.optJSONObject(0) ?: xraySettings

            val address = firstNonEmpty(
                xraySrv?.optString("address") ?: "", xraySrv?.optString("server") ?: "",
                ob.optString("server")
            )
            val port = xraySrv?.optInt("port")?.takeIf { it > 0 } ?: ob.optInt("server_port")
            val uuid = firstNonEmpty(xraySrv?.optString("uuid") ?: "", ob.optString("uuid"))
            val password = firstNonEmpty(xraySrv?.optString("password") ?: "", ob.optString("password"))
            if (address.isEmpty() || port !in 1..65535) return null

            val query = mutableMapOf<String, String>()
            val cc = firstNonEmpty(
                xraySettings?.optString("congestion_control") ?: "",
                xraySettings?.optString("congestionController") ?: "",
                ob.optString("congestion_control")
            )
            if (cc.isNotEmpty()) query["congestion_control"] = cc

            val mode = firstNonEmpty(
                xraySettings?.optString("udp_relay_mode") ?: "",
                xraySettings?.optString("udpRelayMode") ?: "",
                ob.optString("udp_relay_mode")
            )
            if (mode.isNotEmpty()) query["udp_relay_mode"] = mode

            if (xraySettings != null) {
                // Xray shape: the TLS parameters sit in streamSettings, read by
                // the same helper the converters use.
                val t = hysteriaTls(xraySettings, ob.optJSONObject("streamSettings"))
                if (t.sni.isNotEmpty()) query["sni"] = t.sni
                if (t.alpn.isNotEmpty()) query["alpn"] = t.alpn.joinToString(",")
                if (t.insecure) query["allow_insecure"] = "1"
            }
            val tls = ob.optJSONObject("tls")
            if (tls != null && tls.optBoolean("enabled", false)) {
                val sni = tls.optString("server_name")
                if (sni.isNotEmpty() && !query.containsKey("sni")) query["sni"] = sni

                val alpnArr = tls.optJSONArray("alpn")
                if (alpnArr != null && alpnArr.length() > 0 && !query.containsKey("alpn")) {
                    query["alpn"] = LinkParams.joinList(alpnArr)
                }

                if (tls.optBoolean("insecure", false)) {
                    query["allow_insecure"] = "1"
                }
            }

            val queryStr = query.toList().sortedBy { it.first }.joinToString("&") {
                "${it.first}=${URLEncoder.encode(it.second, "UTF-8")}"
            }
            val queryString = if (queryStr.isNotEmpty()) "?$queryStr" else ""

            val finalRem = if (ob.has("tag")) ob.getString("tag") else (if (ob.has("remarks")) ob.getString("remarks") else rem)
            val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")

            "tuic://$uuid:$password@${LinkParams.hostForUri(address)}:$port$queryString#$encRem"
        } catch (e: Exception) { null }
    }
}
