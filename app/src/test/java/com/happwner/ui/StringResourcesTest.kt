package com.happwner.ui

import android.content.res.Configuration
import com.happwner.R
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

// aapt2 builds a string longer than 32,767 bytes of UTF-8 into the app as "STRING_TOO_LARGE" and
// fails nothing: every string reaches the app whole, in each of its languages.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class StringResourcesTest {
	@Test
	fun `no string comes out as the placeholder aapt2 puts in place of one too long`() {
		val app = RuntimeEnvironment.getApplication()
		val titles = listOf("en", "ru").map { language ->
			val config = Configuration(app.resources.configuration)
			config.setLocale(Locale.forLanguageTag(language))
			val resources = app.createConfigurationContext(config).resources
			val tooLong = R.string::class.java.fields.map { it.getInt(null) }
				.filter { resources.getString(it) == "STRING_TOO_LARGE" }
				.map { resources.getResourceEntryName(it) }
			assertEquals(language, emptyList<String>(), tooLong)
			resources.getString(R.string.setting_process_mode_off)
		}
		assertNotEquals("each language is read from its own strings", titles[0], titles[1])
	}
}
