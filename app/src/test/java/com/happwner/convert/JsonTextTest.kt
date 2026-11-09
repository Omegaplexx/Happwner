package com.happwner.convert

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

// Android's org.json escapes every slash; the text the converters hand out spells it plainly, and an
// escaped backslash that happens to stand before a slash is left as it was.
class JsonTextTest {
	@Test
	fun `a slash escaped the Android way reads plain`() {
		assertEquals("""{"path":"/ws","alpn":["http/1.1"]}""",
			withPlainSlashes("""{"path":"\/ws","alpn":["http\/1.1"]}"""))
	}

	@Test
	fun `an escaped backslash before a slash keeps both`() {
		// Android writes the two characters \/ as \\\/; plain, that is \\/ - still a backslash, a slash.
		assertEquals("""{"v":"\\/"}""", withPlainSlashes("""{"v":"\\\/"}"""))
		assertEquals("\\/", JSONObject(withPlainSlashes("""{"v":"\\\/"}""")).getString("v"))
		// And the way a desktop JVM writes them is already plain.
		assertEquals("""{"v":"\\/"}""", withPlainSlashes("""{"v":"\\/"}"""))
	}

	@Test
	fun `other escapes pass through untouched`() {
		val text = """{"a":"\"q\"\n\t\u002F\\"}"""
		assertEquals(text, withPlainSlashes(text))
	}
}
