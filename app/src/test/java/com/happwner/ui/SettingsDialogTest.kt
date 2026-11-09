package com.happwner.ui

import android.text.Spanned
import android.text.style.URLSpan
import android.view.KeyEvent
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import com.google.android.material.checkbox.MaterialCheckBox
import com.happwner.R
import com.happwner.data.ModuleIds
import com.happwner.data.PrefsManager
import com.happwner.ui.UiTestSupport.decor
import com.happwner.ui.UiTestSupport.dims
import com.happwner.ui.UiTestSupport.field
import com.happwner.ui.UiTestSupport.idle
import com.happwner.ui.UiTestSupport.key
import com.happwner.ui.UiTestSupport.rotate
import com.happwner.ui.UiTestSupport.setAnimMode
import com.happwner.ui.UiTestSupport.settle
import com.happwner.ui.UiTestSupport.topBackCallback
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config

// The settings' dialog with pages - the conversion mode, its URI options and the notes over them -
// through Back, the Android 16 dispatcher and a rotation, and what its OK sends out.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SettingsDialogTest {
	private lateinit var controller: ActivityController<MainActivity>
	private val activity: MainActivity get() = controller.get()
	private val settings: Fragment
		get() = activity.supportFragmentManager.findFragmentByTag("settings_fragment")!!
	private val scope = PrefsManager.SCOPE_MANUAL

	@Before
	fun setUp() {
		UiTestSupport.pacedFrames()
		RuntimeEnvironment.setQualifiers("port")
		controller = Robolectric.buildActivity(MainActivity::class.java).setup()
		setAnimMode(activity, ANIM_MODE_SOFTWARE)
		idle(100)
		activity.openSettings()
		idle(600)
		assertTrue(settings.isVisible)
	}

	@After
	fun tearDown() {
		current()?.dismiss()
		controller.pause().stop().destroy()
		idle(100)
	}

	private fun current(): AlertDialog? = field(settings, "currentDialog")

	private fun currentTag(): String? = field(settings, "currentDialogTag")

	private fun page(): String? = field(settings, "scopePage")

	private fun sent() = shadowOf(RuntimeEnvironment.getApplication()).broadcastIntents

	private fun settingsSent(from: Int) =
		sent().drop(from).count { it.action == ModuleIds.ACTION_SETTINGS_UPDATE }

	// A page turn takes its time, and taps and Back wait for it: the tests do too.
	private fun turned() = idle(600)

	private fun openModeDialog(): AlertDialog {
		settings.requireView().findViewById<View>(R.id.itemProcessManualScope).performClick()
		val dialog = current()
		assertNotNull(dialog)
		assertEquals("process_scope_manual", currentTag())
		idle(400)
		return dialog!!
	}

	private fun shownBox(dialog: AlertDialog, id: Int): MaterialCheckBox? =
		decor(dialog).findViewById<MaterialCheckBox>(id)?.takeIf { it.isShown }

	private fun openUriOptions(dialog: AlertDialog): MaterialCheckBox {
		decor(dialog).findViewById<View>(R.id.btnModeUriSettings).performClick()
		assertEquals("process_uri_options", page())
		assertTrue(settle { shownBox(dialog, R.id.checkDropIncompatible) != null })
		turned()
		return shownBox(dialog, R.id.checkDropIncompatible)!!
	}

	@Test
	fun `the uri options open over the mode page, and Back peels them off`() {
		val dialog = openModeDialog()
		val box = openUriOptions(dialog)
		assertFalse(box.isChecked)
		box.performClick()
		assertTrue(box.isChecked)
		key(dialog, KeyEvent.KEYCODE_BACK)
		assertTrue(settle {
			page() == null && decor(dialog).findViewById<View>(R.id.radioModeUri).isShown
		})
		assertTrue(dialog.isShowing)
		turned()
		// Nothing was saved: the boxes are written when OK takes the page.
		val prefs = PrefsManager.getSafePrefs(activity)
		assertFalse(prefs.getBoolean(PrefsManager.uriDropIncompatibleKey(scope), false))
		key(dialog, KeyEvent.KEYCODE_BACK)
		assertTrue(settle { !dialog.isShowing })
		assertNull(current())
	}

	@Test
	fun `the mode dialog says not every profile converts and links to the limitations file`() {
		val dialog = openModeDialog()
		val text = decor(dialog).findViewById<TextView>(R.id.textProcessLimits).text as Spanned
		val links = text.getSpans(0, text.length, URLSpan::class.java)
		assertEquals(1, links.size)
		assertTrue(links[0].url.endsWith("/conversion_limitations.md"))
	}

	@Test
	fun `on Android 16 Back reaches the dialog through its window's dispatcher and turns a page back`() {
		val dialog = openModeDialog()
		openUriOptions(dialog)
		val callback = topBackCallback(dialog.window!!)
		assertNotNull("the dialog's own callback stands first", callback)
		callback!!.onBackInvoked()
		assertTrue(settle { page() == null })
		assertTrue("a page back, not the dialog closed", dialog.isShowing)
		turned()
		callback.onBackInvoked()
		assertTrue(dialog.dialogState.dismissing)
		assertTrue("the way out the key takes, with its animation", settle { !dialog.isShowing })
		assertNull(current())
	}

	@Test
	fun `a rotation puts the dialog back on the page it was on`() {
		val old = openModeDialog()
		openUriOptions(old)
		rotate(controller, landscape = true)
		assertTrue(settle { current() !== old && current() != null })
		val next = current()!!
		assertNotSame(old, next)
		assertEquals("process_scope_manual", currentTag())
		assertEquals("process_uri_options", page())
		assertTrue(settle { !next.isInTransit() && decor(next).alpha == 1f && dims(next) })
		assertNotNull("the same page, laid out anew", shownBox(next, R.id.checkDropIncompatible))
		assertTrue(settle { !old.isShowing })
		assertEquals(2, next.context.resources.configuration.orientation)
		assertFalse(old.dialogState.box != null)
		assertTrue("the new one draws its own frame", next.dialogState.box != null)
	}

	@Test
	fun `OK on the uri options writes the boxes and sends the settings out, OK on the mode page the mode`() {
		val dialog = openModeDialog()
		val box = openUriOptions(dialog)
		box.performClick()
		val before = sent().size
		dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
		assertTrue(settle { page() == null })
		turned()
		val prefs = PrefsManager.getSafePrefs(activity)
		assertTrue(prefs.getBoolean(PrefsManager.uriDropIncompatibleKey(scope), false))
		assertEquals(1, settingsSent(before))
		assertTrue("the page's OK keeps the dialog", dialog.isShowing)
		decor(dialog).findViewById<View>(R.id.radioModeUri).performClick()
		decor(dialog).findViewById<MaterialCheckBox>(R.id.checkDecodeBase64).performClick()
		val beforeMode = sent().size
		dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
		assertTrue(settle { !dialog.isShowing })
		assertEquals(PrefsManager.MODE_URI, prefs.getString(PrefsManager.conversionModeKey(scope), null))
		assertTrue(prefs.getBoolean(PrefsManager.base64ChoiceKey(scope), false))
		assertEquals(1, settingsSent(beforeMode))
	}

	@Test
	fun `the Xposed dialog offers the patcher whether or not Xposed is active`() {
		for (active in listOf(false, true)) {
			PrefsManager.getSafePrefs(activity).edit().putBoolean(PrefsManager.PREF_LSPATCH_MODE, active).commit()
			settings.requireView().findViewById<View>(R.id.itemXposed).performClick()
			val dialog = current()!!
			assertEquals("xposed", currentTag())
			idle(400)
			val patcher = dialog.getButton(AlertDialog.BUTTON_NEGATIVE)
			assertEquals(activity.getString(R.string.btn_patcher), patcher.text.toString())
			assertTrue(patcher.isShown)
			patcher.performClick()
			idle(600)
			assertEquals("patcher", currentTag())
			current()!!.dismissAnimated()
			idle(600)
		}
	}

	@Test
	fun `the Xposed dialog's switches send the settings out, the link switch being on by default`() {
		// The switches show only where the module is live: a patched app counts as that.
		PrefsManager.getSafePrefs(activity).edit().putBoolean(PrefsManager.PREF_LSPATCH_MODE, true).commit()
		settings.requireView().findViewById<View>(R.id.itemXposed).performClick()
		val dialog = current()!!
		assertEquals("xposed", currentTag())
		idle(400)
		val before = sent().size
		decor(dialog).findViewById<View>(R.id.itemShowDuplicates).performClick()
		assertTrue(PrefsManager.getSafePrefs(activity).getBoolean(PrefsManager.PREF_SHOW_DUPLICATES, false))
		assertEquals(1, settingsSent(before))
		decor(dialog).findViewById<View>(R.id.itemInterceptLinks).performClick()
		assertFalse(PrefsManager.isInterceptEnabled(activity))
		assertEquals(2, settingsSent(before))
		assertEquals(false, sent().last().getBooleanExtra(PrefsManager.PREF_INTERCEPT_ENABLED, true))

		val switch = decor(dialog).findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switchRedirect)
		assertTrue(switch.isChecked)
		decor(dialog).findViewById<View>(R.id.itemRedirect).performClick()
		assertFalse(switch.isChecked)
		assertFalse(PrefsManager.isRedirectIntentsEnabled(activity))
		assertEquals(3, settingsSent(before))
		assertEquals(false, sent().last().getBooleanExtra(PrefsManager.PREF_REDIRECT_INTENTS, true))
		decor(dialog).findViewById<View>(R.id.itemRedirect).performClick()
		assertTrue(PrefsManager.isRedirectIntentsEnabled(activity))
	}

	private fun hooksDialogCard(): View {
		PrefsManager.getSafePrefs(activity).edit().putBoolean(PrefsManager.PREF_LSPATCH_MODE, true).commit()
		settings.requireView().findViewById<View>(R.id.itemXposed).performClick()
		val dialog = current()!!
		idle(600)
		return decor(dialog).findViewById<android.view.ViewGroup>(android.R.id.content).getChildAt(0)
	}

	@Test
	fun `a list of hooks that does not fit the screen makes the dialog four fifths of it`() {
		val card = hooksDialogCard()
		val screen = activity.resources.displayMetrics.heightPixels
		assertTrue("${card.height} of $screen", card.height in (screen * 0.79f).toInt()..(screen * 0.8f).toInt() + 1)
	}

	@Test
	fun `a list of hooks that fits the screen makes the dialog only as tall as the list`() {
		controller.pause().stop().destroy()
		RuntimeEnvironment.setQualifiers("w393dp-h851dp-port-xxhdpi")
		controller = Robolectric.buildActivity(MainActivity::class.java).setup()
		setAnimMode(activity, ANIM_MODE_SOFTWARE)
		idle(100)
		activity.openSettings()
		idle(600)
		val card = hooksDialogCard()
		val screen = activity.resources.displayMetrics.heightPixels
		assertTrue("${card.height} of $screen", card.height < screen * 0.79f)
	}
}
