package com.happwner.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// A captured id comes by broadcast from whichever app sends one and goes on as the x-hwid header,
// so only a short one without control characters is kept.
class CapturedIdTest {

	@Test
	fun `a short id without control characters is kept, beyond ASCII too, and the rest is turned away`() {
		assertTrue(PrefsManager.isPlausibleId("9f2c4e1a7b3d5f60"))
		assertTrue(PrefsManager.isPlausibleId("123e4567-e89b-12d3-a456-426614174000"))
		// Android sends such a header value as UTF-8.
		assertTrue(PrefsManager.isPlausibleId("идентификатор"))
		assertFalse(PrefsManager.isPlausibleId(""))
		assertFalse(PrefsManager.isPlausibleId("a".repeat(257)))
		assertFalse(PrefsManager.isPlausibleId("abc\r\nX-Injected: 1"))
		assertFalse(PrefsManager.isPlausibleId("abc\tdef"))
	}
}
