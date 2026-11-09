package com.happwner.ui

import android.app.Activity
import android.os.Build
import android.view.KeyEvent
import android.view.View
import android.widget.ImageButton
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import com.google.android.material.checkbox.MaterialCheckBox
import com.happwner.R
import com.happwner.ui.UiTestSupport.decor
import com.happwner.ui.UiTestSupport.dims
import com.happwner.ui.UiTestSupport.field
import com.happwner.ui.UiTestSupport.idle
import com.happwner.ui.UiTestSupport.key
import com.happwner.ui.UiTestSupport.rotate
import com.happwner.ui.UiTestSupport.setAnimMode
import com.happwner.ui.UiTestSupport.settle
import com.happwner.ui.UiTestSupport.topBackCallback
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config

// The dialogs' way through a rotation, Back and their pages on each Android the code has a branch
// for: 6.0 the oldest, 11 (the window's insets), 13 (the Back dispatcher), 16 and 17 (Back through
// it) - in the software and the system mode.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [23, 30, 33, 36, 37])
class SdkMatrixTest {
	@Before
	fun setUp() {
		UiTestSupport.pacedFrames()
		RuntimeEnvironment.setQualifiers("port")
	}

	private fun current(host: Any): AlertDialog? = field(host, "currentDialog")

	// The dialog put back for the new screen, once it is in and the old one gone.
	private fun settledSwap(host: Any, old: AlertDialog): AlertDialog {
		assertTrue(settle { current(host) !== old && current(host) != null })
		val next = current(host)!!
		assertTrue(settle { !next.isInTransit() && decor(next).alpha == 1f && dims(next) })
		assertTrue(settle { !old.isShowing })
		assertEquals(2, next.context.resources.configuration.orientation)
		assertNotSame(old, next)
		return next
	}

	private fun close(host: Any, dialog: AlertDialog) {
		key(dialog, KeyEvent.KEYCODE_BACK)
		assertTrue("Back closes it", settle { !dialog.isShowing })
		assertNull(current(host))
	}

	private fun <A : Activity> ActivityController<A>.finish() {
		pause().stop().destroy()
		idle(100)
	}

	private fun mainScreen(mode: Int) {
		val controller = Robolectric.buildActivity(MainActivity::class.java).setup()
		val activity = controller.get()
		setAnimMode(activity, mode)
		idle(100)
		activity.findViewById<ImageButton>(R.id.infoUrl).performClick()
		val info = current(activity)!!
		idle(400)
		rotate(controller, landscape = true)
		close(activity, settledSwap(activity, info))
		// The agent dialog's note page: opened, Back takes it down and leaves the dialog.
		activity.findViewById<ImageButton>(R.id.btnEditUaManual).performClick()
		val agent = current(activity)!!
		idle(400)
		decor(agent).findViewById<View>(R.id.btnPreferSubscriptionUaInfo).performClick()
		idle(600)
		assertEquals("ua_note", field(activity, "uaPage"))
		key(agent, KeyEvent.KEYCODE_BACK)
		assertTrue(settle { field<String?>(activity, "uaPage") == null })
		assertTrue(agent.isShowing)
		idle(600)
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
			assertNotNull("Back reaches the dialog through the dispatcher", topBackCallback(agent.window!!))
		}
		close(activity, agent)
		controller.finish()
	}

	private fun settingsScreen(mode: Int) {
		val controller = Robolectric.buildActivity(SettingsActivity::class.java).setup()
		val activity = controller.get()
		setAnimMode(activity, mode)
		idle(100)
		val settings: Fragment =
			activity.supportFragmentManager.findFragmentByTag("settings_fragment_activity")!!
		settings.requireView().findViewById<View>(R.id.itemProcessManualScope).performClick()
		val dialog = current(settings)!!
		idle(400)
		decor(dialog).findViewById<View>(R.id.btnModeUriSettings).performClick()
		idle(600)
		assertEquals("process_uri_options", field(settings, "scopePage"))
		rotate(controller, landscape = true)
		val put = settledSwap(settings, dialog)
		assertEquals("put back on its page", "process_uri_options", field(settings, "scopePage"))
		assertTrue(decor(put).findViewById<MaterialCheckBox>(R.id.checkDropIncompatible).isShown)
		put.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
		assertTrue(settle { field<String?>(settings, "scopePage") == null })
		idle(600)
		put.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
		assertTrue(settle { !put.isShowing })
		assertNull(current(settings))
		controller.finish()
	}

	@Test
	fun `the main screen's dialogs in the software mode`() = mainScreen(ANIM_MODE_SOFTWARE)

	@Test
	fun `the main screen's dialogs in the system mode`() = mainScreen(ANIM_MODE_SYSTEM)

	@Test
	fun `the settings' dialog with pages in the software mode`() = settingsScreen(ANIM_MODE_SOFTWARE)

	@Test
	fun `the settings' dialog with pages in the system mode`() = settingsScreen(ANIM_MODE_SYSTEM)

	@Test
	fun `the settings open inside the main screen, where the main screen keeps them`() {
		val controller = Robolectric.buildActivity(MainActivity::class.java).setup()
		val activity = controller.get()
		setAnimMode(activity, ANIM_MODE_SOFTWARE)
		idle(100)
		activity.openSettings()
		idle(600)
		val settings = activity.supportFragmentManager.findFragmentByTag("settings_fragment")!!
		assertTrue(settings.isVisible)
		rotate(controller, landscape = true)
		idle(600)
		assertTrue(settings.isVisible)
		assertNull("under the settings the main screen keeps no dialog", current(activity))
		activity.closeSettings()
		assertTrue(settle { settings.isHidden })
		controller.finish()
	}
}
