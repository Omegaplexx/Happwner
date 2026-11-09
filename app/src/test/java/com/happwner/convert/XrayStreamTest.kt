package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

// The range reader of XrayStream: what Xray writes as "a-b", "a", or a number.
class XrayStreamTest {

	@Test
	fun `ranges keep negative bounds and reject junk`() {
		assertEquals("114", parseRangeString("114")!!.render())
		assertEquals("114-514", parseRangeString("114-514")!!.render())
		// A leading minus belongs to the first bound, not to the separator.
		assertEquals(-114, parseRangeString("-114-514")!!.from)
		assertEquals(514, parseRangeString("-114-514")!!.to)
		// Reversed bounds are normalised rather than refused.
		assertEquals("114-514", parseRangeString("514-114")!!.render())
		assertNull(parseRangeString("114-514-999"))
		assertNull(parseRangeString("a-b"))
		assertEquals("", XRange.UNSET.render())
		assertEquals("", XRange(0, 0, true).renderNonZero())
	}
}
