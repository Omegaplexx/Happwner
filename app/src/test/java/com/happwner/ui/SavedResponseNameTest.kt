package com.happwner.ui

import android.content.Intent
import android.view.View
import androidx.core.content.edit
import com.happwner.R
import com.happwner.data.PrefsManager
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

// The name a response is saved under follows the mode it was converted in, not the setting as it
// stands when the file is saved.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SavedResponseNameTest {

	@Test
	fun `a change of mode after the response does not change its file name`() {
		UiTestSupport.pacedFrames()
		val controller = Robolectric.buildActivity(MainActivity::class.java).setup()
		val activity = controller.get()
		fun set(name: String, value: String) = MainActivity::class.java.getDeclaredField(name)
			.apply { isAccessible = true }.set(activity, value)
		set("lastFetchedDomain", "example")
		set("lastResponseSuffix", activity.getString(R.string.filename_suffix_singbox))
		PrefsManager.getSafePrefs(activity).edit {
			putString(PrefsManager.conversionModeKey(PrefsManager.SCOPE_MANUAL), PrefsManager.MODE_URI)
		}
		activity.findViewById<View>(R.id.btnSaveOutput).performClick()
		val asked = shadowOf(activity).nextStartedActivity
		assertEquals("Happwneresp_example_sb.txt", asked.getStringExtra(Intent.EXTRA_TITLE))
		controller.pause().stop().destroy()
	}

	@Test
	fun `the three tails are _sb, _mhm and _uri`() {
		val app = org.robolectric.RuntimeEnvironment.getApplication()
		assertEquals("_sb", app.getString(R.string.filename_suffix_singbox))
		assertEquals("_mhm", app.getString(R.string.filename_suffix_mihomo))
		assertEquals("_uri", app.getString(R.string.filename_suffix_uri))
	}
}
