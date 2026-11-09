package com.happwner.convert

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// Go's encoding/json takes an Xray config key whatever its case, and so must every pass.
class XrayKeysTest {
	private val readCall = Regex(
		"""\.(?:x(?:Opt|Obj|Arr|Str|StrList|Int|Long|Bool|Has|Headers|Double|Num|Port)\w*|""" +
			"""opt(?:String|JSONObject|JSONArray|Boolean|Int|Long|Double)?|has|isNull|""" +
			"""get(?:String|JSONObject|JSONArray|Int|Boolean|Long)?)\(\s*"([^"${'$'}]+)""""
	)
	private val keyLoop = Regex("""for \(key in listOf\(([^)]*)\)\)""")
	private val multiRead = Regex("""\.x\w*Of\(([^)]*)\)""")
	private val literal = Regex(""""([^"${'$'}]+)"""")
	private val identifier = Regex("[A-Za-z][A-Za-z0-9_-]*")

	@Test
	fun `every key the converters read is one the keys are brought to`() {
		val sources = File("src/main/java/com/happwner/convert").walk().filter { it.extension == "kt" }
		val read = sources.flatMap { file ->
			val text = file.readText()
			val looped = (keyLoop.findAll(text) + multiRead.findAll(text)).flatMap { call ->
				literal.findAll(call.groupValues[1]).map { it.groupValues[1] }
			}
			readCall.findAll(text).map { it.groupValues[1] } + looped
		}.filter { identifier.matches(it) }.toSet()
		assertTrue("no sources found", read.isNotEmpty())
		assertEquals("read but not in XrayKeys.READ", emptySet<String>(), read - XrayKeys.READ)
	}

	private val canonical = """{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[
		{"address":"a.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811",
		"encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"tls",
		"tlsSettings":{"serverName":"sni.example.com"},"wsSettings":{"path":"/p",
		"headers":{"User-Agent":"UA"}}}}],"observatory":{"subjectSelector":["proxy"],
		"probeURL":"https://probe.example.com/"}}"""

	private val anyCase = """{"Outbounds":[{"PROTOCOL":"vless","Tag":"proxy","Settings":{"VNext":[
		{"Address":"a.example.com","Port":443,"Users":[{"ID":"b831381d-6324-4d53-ad4f-8cda48b30811",
		"Encryption":"none"}]}]},"StreamSettings":{"Network":"ws","SECURITY":"tls",
		"TLSSettings":{"serverNAME":"sni.example.com"},"wsSettings":{"PATH":"/p",
		"Headers":{"User-Agent":"UA"}}}}],"Observatory":{"SubjectSelector":["proxy"],
		"probeUrl":"https://probe.example.com/"}}"""

	@Test
	fun `a config read in any case converts as in its own, in every pass`() {
		for ((singBox, uri, mihomo) in listOf(Triple(true, false, false), Triple(false, true, false),
			Triple(false, false, true))) {
			val expected = SubscriptionConverter.convertWithStats(
				canonical, jsonToUri = uri, xrayToSingBox = singBox, xrayToMihomo = mihomo
			).text
			val actual = SubscriptionConverter.convertWithStats(
				anyCase, jsonToUri = uri, xrayToSingBox = singBox, xrayToMihomo = mihomo
			).text
			assertTrue(expected, "sni.example.com" in expected)
			assertEquals(expected, actual)
		}
	}

	@Test
	fun `a map keeps its keys as written`() {
		val text =
			SubscriptionConverter.convertWithStats(anyCase, jsonToUri = false, xrayToSingBox = true).text
		assertTrue(text, "User-Agent" in text)
	}

	// A config kept whole while nodes a core cannot carry are dropped has its VLESS flow brought to the
	// form sing-box takes; that reads the config as the passes do, whatever the case of its keys.
	@Test
	fun `a kept config's flow is brought to form in any case`() {
		val node = """{"address":"a.example.com","port":443,"users":[{
			"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none",
			"flow":"xtls-rprx-vision-udp443"}]}"""
		val stream = """"streamSettings":{"network":"tcp","security":"tls",
			"tlsSettings":{"serverName":"a.example.com"}}"""
		val canonical = """{"outbounds":[{"protocol":"vless","settings":{"vnext":[$node]},$stream}]}"""
		val anyCase = listOf("outbounds", "settings", "users", "flow").fold(canonical) { text, key ->
			text.replace("\"$key\"", "\"${key.replaceFirstChar { it.uppercase() }}\"")
		}
		val expected =
			SubscriptionConverter.convertWithStats(canonical, jsonToUri = true, xrayToSingBox = true).text
		val actual =
			SubscriptionConverter.convertWithStats(anyCase, jsonToUri = true, xrayToSingBox = true).text
		assertTrue(expected, "flow=xtls-rprx-vision" in expected && "udp443" !in expected)
		assertEquals(expected, actual)
	}
}
