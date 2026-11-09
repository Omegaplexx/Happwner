package com.happwner.convert

import android.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// An mKCP node's masks as each Xray reads them - finalmask wrapped first-outermost up to 26.6.1, last-
// outermost from 26.6.22 - and what mihomo, masking as Xray did before 26.1.31, and a link, naming the
// mask as kcpSettings did, can repeat of them. A node either leaves out is one its server never answers.
class MkcpMaskTest {
	private val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811""""

	private fun outbound(tag: String, stream: String, protocol: String = "vmess"): String {
		val who = if (protocol == "vless") """$user,"encryption":"none"}""" else "$user}"
		return """{"protocol":"$protocol","tag":"$tag","settings":{"vnext":[""" +
			"""{"address":"$tag.example.com","port":443,"users":[$who]}]},"streamSettings":$stream}"""
	}

	private fun node(stream: String, protocol: String = "vmess") =
		"""{"outbounds":[${outbound("k", stream, protocol)}]}"""

	private fun masked(vararg masks: String) =
		"""{"network":"kcp","finalmask":{"udp":[${masks.joinToString(",")}]}}"""

	private fun legacy(settings: String = "") =
		if (settings.isEmpty()) """{"type":"mkcp-legacy"}"""
		else """{"type":"mkcp-legacy","settings":{$settings}}"""

	private fun links(body: String, singBox: Boolean = false, mihomo: Boolean = false) =
		SubscriptionConverter.convertWithStats(body, ConversionFlags(true, singBox, false, false, mihomo))

	private fun blob(link: String) =
		JSONObject(String(Base64.decode(link.removePrefix("vmess://"), Base64.DEFAULT)))

	private fun yaml(body: String): String {
		val result = MihomoConverter.convert(body)
		assertTrue("refused: $result", result is MihomoConverter.Result.Ok)
		return (result as MihomoConverter.Result.Ok).yaml
	}

	private fun mihomoRefusal(body: String): String {
		val result = MihomoConverter.convert(body)
		assertTrue("kept: $result", result is MihomoConverter.Result.Unsupported)
		return (result as MihomoConverter.Result.Unsupported).notes.joinToString("\n")
	}

	private fun singBoxRefusal(body: String): String {
		val result = SingBoxConverter.convert(body, "N")
		assertTrue("kept: $result", result is SingBoxConverter.Result.Unsupported)
		return (result as SingBoxConverter.Result.Unsupported).notes.joinToString("\n")
	}

	private val seeded = """{"type":"mkcp-aes128gcm","settings":{"password":"s3cret"}}"""
	private val wechat = """{"type":"header-wechat"}"""
	private val blank = """{"network":"kcp","kcpSettings":{"seed":""}}"""
	private val seededSettings = """{"network":"kcp","kcpSettings":{"seed":"ks"}}"""

	@Test
	fun `each generation's masks are read in the order its Xray wraps them`() {
		val outside = listOf(
			masked(wechat, seeded), masked(legacy(""""value":"s3cret""""), legacy(""""header":"wechat""""))
		)
		for (stream in outside) {
			val written = yaml(node(stream))
			assertTrue(written, "seed: s3cret" in written && "header: wechat-video" in written)
			val link = blob(links(node(stream)).text)
			assertEquals("s3cret", link.optString("path"))
			assertEquals("wechat-video", link.optString("type"))
		}
		val inside = listOf(
			masked(seeded, wechat), masked(legacy(""""header":"wechat""""), legacy(""""value":"s3cret""""))
		)
		val under = "puts the mKCP header under the seed or original mask"
		for (stream in inside) {
			val why = mihomoRefusal(node(stream))
			assertTrue(why, under in why)
			val kept = links(node(stream))
			assertTrue(kept.text, kept.text.startsWith("{"))
			assertTrue("${kept.notes}", kept.notes.any { under in it && "which no vmess link carries" in it })
			// A vless link carries finalmask whole, its order with it.
			assertTrue(links(node(stream, "vless")).text.startsWith("vless://"))
		}
	}

	@Test
	fun `a mask mihomo cannot repeat leaves the node out of its document and its links`() {
		val emptySeed = "keyed by an empty seed, which mihomo takes for none"
		val reasons = mapOf(
			masked("""{"type":"header-srtp"}""") to "with no seed or original mask under it",
			masked("""{"type":"mkcp-original"}""", """{"type":"mkcp-original"}""") to "more than one",
			"""{"network":"kcp","kcpSettings":{"header":{"type":"dns"}}}""" to "\"dns\" is not one mihomo",
			blank to emptySeed,
			masked("""{"type":"mkcp-aes128gcm"}""") to emptySeed
		)
		for ((stream, reason) in reasons) {
			val why = mihomoRefusal(node(stream))
			assertTrue("$stream: $why", reason in why)
			val dropped = links(node(stream), mihomo = true)
			assertEquals(stream, "", dropped.text)
			assertEquals(stream, 1, dropped.xraySkipped)
		}
	}

	@Test
	fun `a link names the outermost of several headers and seeds`() {
		val srtp = """{"type":"header-srtp"}"""
		val other = """{"type":"mkcp-aes128gcm","settings":{"password":"other"}}"""
		val legacyLayout = masked(
			legacy(""""value":"other""""), legacy(""""value":"s3cret""""),
			legacy(""""header":"wechat""""), legacy(""""header":"srtp"""")
		)
		for (stream in listOf(masked(srtp, wechat, seeded, other), legacyLayout)) {
			val link = links(node(stream, "vless")).text
			assertTrue(link, "headerType=srtp" in link && "seed=s3cret" in link)
		}
	}

	@Test
	fun `a seed keyed empty goes as written where no link names it`() {
		for (protocol in listOf("vmess", "vless")) {
			val kept = links(node(blank, protocol))
			assertTrue(kept.text, kept.text.startsWith("{"))
			val why = "empty seed, which no $protocol link carries"
			assertTrue("${kept.notes}", kept.notes.any { why in it })
		}
		val unkeyed = masked("""{"type":"mkcp-aes128gcm"}""")
		assertTrue(links(node(unkeyed)).text.startsWith("{"))
		assertTrue(links(node(unkeyed, "vless")).text.startsWith("vless://"))
	}

	@Test
	fun `masks Xray refuses the configuration over leave the node out in every mode`() {
		val never = "the node never worked"
		val unknownOld = masked("""{"type":"header-foo"}""", """{"type":"mkcp-original"}""")
		val unknownWritten = """{"network":"kcp","kcpSettings":{"header":{"type":"wechat"}}}"""
		val withHeader = { header: String -> """{"network":"kcp","kcpSettings":{"header":$header}}""" }
		val noObject = "an mKCP header that is no object, which no Xray has"
		val besideOlder = """{"network":"kcp","kcpSettings":{"header":"srtp"},""" +
			""""finalmask":{"udp":[$wechat,$seeded]}}"""
		val refusals = mapOf(
			masked(legacy(), legacy(""""header":"foo"""")) to "the mKCP header \"foo\", which no Xray has",
			unknownOld to "the mKCP header \"foo\", which no Xray has",
			masked(legacy(), """{"type":"header-srtp"}""") to "two Xray generations",
			unknownWritten to "the mKCP header \"wechat\", which no Xray has",
			withHeader("{}") to "an mKCP header of no type, which no Xray has",
			withHeader("""{"type":""}""") to "an mKCP header of no type, which no Xray has",
			withHeader("null") to noObject,
			withHeader("\"srtp\"") to noObject,
			withHeader("[]") to noObject,
			besideOlder to noObject
		)
		for ((stream, reason) in refusals) {
			for (protocol in listOf("vmess", "vless")) {
				val body = node(stream, protocol)
				for (why in listOf(singBoxRefusal(body), mihomoRefusal(body))) {
					assertTrue("$stream $protocol: $why", reason in why && never in why)
				}
				val left = links(body)
				assertEquals("$stream $protocol", "", left.text)
				assertTrue("${left.notes}", left.notes.any { reason in it && never in it })
			}
		}
	}

	@Test
	fun `under a box whose client runs no mKCP its link is left out, the node beside it kept`() {
		val ws = """{"network":"ws","wsSettings":{"path":"/w"}}"""
		val legacySeed = masked(legacy(""""value":"s3cret""""))
		val cases = listOf(
			Triple("vmess", legacySeed, true) to "a sing-box client runs no mKCP",
			Triple("vmess", blank, true) to "a sing-box client runs no mKCP",
			Triple("vless", """{"network":"kcp"}""", false) to "runs mKCP under vmess alone"
		)
		for ((case, reason) in cases) {
			val (protocol, stream, singBox) = case
			val two = """{"outbounds":[${outbound("k", stream, protocol)},${outbound("w", ws)}]}"""
			val boxed = links(two, singBox = singBox, mihomo = !singBox)
			assertEquals(boxed.text, 1, boxed.text.lines().size)
			assertTrue(boxed.text, boxed.text.startsWith("vmess://"))
			assertTrue("${boxed.notes}", boxed.notes.any { it.startsWith("skipped: ") && reason in it })
			// Alone too, and without a box the link is there for the clients of Xray.
			val alone = outbound("k", stream, protocol)
			assertEquals("", links(alone, singBox = singBox, mihomo = !singBox).text)
		}
		assertTrue(links(outbound("k", legacySeed)).text.startsWith("vmess://"))
		assertTrue(links(outbound("k", """{"network":"kcp"}""", "vless")).text.startsWith("vless://"))
	}

	@Test
	fun `a kcpSettings seed beside finalmask is read as the one Xray that loads the node reads it`() {
		val older = """{"network":"kcp","kcpSettings":{"seed":"ks","header":{"type":"srtp"}},""" +
			""""finalmask":{"udp":[$wechat,{"type":"mkcp-aes128gcm","settings":{"password":"fm"}}]}}"""
		val written = yaml(node(older))
		assertTrue(written, "seed: ks" in written && "header: srtp" in written)
		val olderNotes = (MihomoConverter.convert(node(older)) as MihomoConverter.Result.Ok).notes
		assertTrue("$olderNotes", olderNotes.any { "only one before 26.1.13 loads the node" in it })
		val newer = """{"network":"kcp","kcpSettings":{"seed":"ks"},""" +
			""""finalmask":{"udp":[${legacy(""""value":"fm"""")}]}}"""
		assertTrue(yaml(node(newer)), "seed: fm" in yaml(node(newer)))
		val newerNotes = (MihomoConverter.convert(node(newer)) as MihomoConverter.Result.Ok).notes
		assertTrue("$newerNotes", newerNotes.any { "which was read instead" in it })
		assertEquals("fm", blob(links(node(newer)).text).optString("path"))
		// Read past, a header written as no object refuses nothing.
		val pastHeader = newer.replace(""""seed":"ks"""", """"header":null""")
		assertTrue(yaml(node(pastHeader)), "seed: fm" in yaml(node(pastHeader)))
		val pastNotes = (MihomoConverter.convert(node(pastHeader)) as MihomoConverter.Result.Ok).notes
		assertTrue("$pastNotes", pastNotes.any { "which was read instead" in it })
		val alone = (MihomoConverter.convert(node(seededSettings)) as MihomoConverter.Result.Ok).notes
		assertTrue("$alone", alone.any { "they were kept as written" in it })
	}

	@Test
	fun `two mkcp-legacy masks are read as later Xray wraps them, the older order named`() {
		val two = masked(legacy(""""value":"s3cret""""), legacy(""""header":"wechat""""))
		val document = MihomoConverter.convert(node(two)) as MihomoConverter.Result.Ok
		assertTrue(document.yaml, "seed: s3cret" in document.yaml && "header: wechat-video" in document.yaml)
		assertTrue("${document.notes}", document.notes.any { it.endsWith(MIHOMO_KCP_LEGACY_ORDER_NOTE) })
		val one = MihomoConverter.convert(node(masked(legacy(""""value":"s3cret""""))))
		assertFalse("$one", (one as MihomoConverter.Result.Ok).notes.any { "26.6.1" in it })
		// The other order, which mihomo cannot send as the later Xray reads it, says what 26.6.1 made of it.
		val turned = masked(legacy(""""header":"wechat""""), legacy(""""value":"s3cret""""))
		val why = mihomoRefusal(node(turned))
		assertTrue(why, "a 26.6.1 server wraps them the other way" in why)
		// Its masks ride in the vmess link's type and path, so finalmask is not called lost there.
		val link = links(node(two))
		assertFalse("${link.notes}", link.notes.any { "no field for fm" in it })
		// Over another transport the blob carries none of it.
		val salamander = """{"type":"salamander","settings":{"password":"o"}}"""
		val other = links(node("""{"network":"hysteria","finalmask":{"udp":[$salamander]}}"""))
		assertTrue("${other.notes}", other.notes.any { "no field for fm" in it })
	}

	@Test
	fun `a node that names no mask is told which servers answer mihomo`() {
		val told = { notes: List<String> -> notes.any { it.endsWith(MIHOMO_KCP_UNSTATED_NOTE) } }
		val unnamed = node("""{"network":"kcp","kcpSettings":{"mtu":1350}}""")
		val document = MihomoConverter.convert(unnamed) as MihomoConverter.Result.Ok
		assertTrue("${document.notes}", told(document.notes))
		val boxed = links(unnamed, mihomo = true)
		assertTrue(boxed.text, boxed.text.startsWith("vmess://"))
		assertTrue("${boxed.notes}", told(boxed.notes))
		assertFalse("${links(unnamed).notes}", told(links(unnamed).notes))
		val named = listOf(
			"""{"network":"kcp","kcpSettings":{"header":{"type":"none"}}}""",
			masked("""{"type":"mkcp-original"}"""), masked(legacy())
		)
		for (stream in named) {
			val result = MihomoConverter.convert(node(stream)) as MihomoConverter.Result.Ok
			assertFalse("$stream: ${result.notes}", told(result.notes))
			assertFalse(result.yaml, "seed:" in result.yaml || "header:" in result.yaml)
		}
	}

	@Test
	fun `mask names are read in any case, as Xray reads them`() {
		val cases = listOf(
			masked("""{"type":"MKCP-Legacy","settings":{"value":"s3cret"}}""") to "seed: s3cret",
			masked("""{"type":"Header-SRTP"}""", """{"type":"MKCP-Original"}""") to "header: srtp",
			masked(legacy(), legacy(""""header":"SRTP"""")) to "header: srtp"
		)
		for ((stream, written) in cases) {
			val out = yaml(node(stream))
			assertTrue(out, written in out)
		}
	}
}
