package com.happwner.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TapDebounceTest {
	private var clock = 0L
	private val debounce = TapDebounce { clock }

	@Test
	fun `a tap passes once the window has run out, and one inside it is ignored without extending it`() {
		assertTrue("the first tap passes whatever the clock", debounce.accept())
		clock += TapDebounce.WINDOW_MS - 1
		assertFalse(debounce.accept())
		clock += 1
		assertTrue("a tap at the end of the window passes", debounce.accept())
		clock += TapDebounce.WINDOW_MS - 100
		assertFalse(debounce.accept())
		clock += 100
		assertTrue("the ignored tap did not extend the window", debounce.accept())
	}
}
