package com.happwner.ui

import android.content.ClipboardManager
import android.content.Context
import android.view.KeyEvent
import android.view.View
import android.widget.ImageButton
import androidx.appcompat.app.AlertDialog
import com.happwner.R
import com.happwner.ui.UiTestSupport.decor
import com.happwner.ui.UiTestSupport.dimAmount
import com.happwner.ui.UiTestSupport.dims
import com.happwner.ui.UiTestSupport.field
import com.happwner.ui.UiTestSupport.frames
import com.happwner.ui.UiTestSupport.idle
import com.happwner.ui.UiTestSupport.key
import com.happwner.ui.UiTestSupport.rotate
import com.happwner.ui.UiTestSupport.setAnimMode
import com.happwner.ui.UiTestSupport.settle
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
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config

// A dialog open on the main screen through a rotation: put back for the new screen in every
// animation mode, with the one laid out for the old screen gone once the new one is in.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class MainDialogRotationTest {
	private lateinit var controller: ActivityController<MainActivity>
	private val activity: MainActivity get() = controller.get()

	@Before
	fun setUp() {
		UiTestSupport.pacedFrames()
		RuntimeEnvironment.setQualifiers("port")
	}

	@After
	fun tearDown() {
		if (::controller.isInitialized) {
			current()?.dismiss()
			controller.pause().stop().destroy()
			idle(100)
		}
	}

	private fun launch(mode: Int) {
		controller = Robolectric.buildActivity(MainActivity::class.java).setup()
		setAnimMode(activity, mode)
		idle(100)
	}

	private fun current(): AlertDialog? = field(activity, "currentDialog")

	private fun currentTag(): String? = field(activity, "currentDialogTag")

	private fun openInfo(): AlertDialog {
		activity.findViewById<ImageButton>(R.id.infoUrl).performClick()
		val dialog = current()
		assertNotNull("the info dialog opens", dialog)
		assertEquals("info", currentTag())
		return dialog!!
	}

	// The import dialog a link from another app brings up, which has no button of its own to open it.
	private fun openImportConfirm(link: String): AlertDialog {
		val show = MainActivity::class.java.getDeclaredMethod("showImportConfirmDialog", String::class.java)
		show.isAccessible = true
		show.invoke(activity, link)
		assertEquals("import_confirm", currentTag())
		return current()!!
	}

	// Copy is left of No, puts the link on the clipboard, says so for a moment and leaves the dialog open.
	private fun assertCopies(dialog: AlertDialog, link: String) {
		val copy = dialog.getButton(AlertDialog.BUTTON_NEUTRAL)
		assertEquals(activity.getString(R.string.btn_copy), copy.text.toString())
		val at = IntArray(2)
		copy.getLocationInWindow(at)
		val copyLeft = at[0]
		dialog.getButton(AlertDialog.BUTTON_NEGATIVE).getLocationInWindow(at)
		assertTrue("$copyLeft < ${at[0]}", copyLeft < at[0])
		val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
		clipboard.clearPrimaryClip()
		copy.performClick()
		idle(100)
		assertEquals(link, clipboard.primaryClip?.getItemAt(0)?.text?.toString())
		assertTrue(dialog.isShowing)
		assertEquals(activity.getString(R.string.btn_copied), copy.text.toString())
		idle(1100)
		assertEquals(activity.getString(R.string.btn_copy), copy.text.toString())
	}

	// Showing, in no swap, seen and dimming: a dialog at rest.
	private fun settled(): Boolean {
		val dialog = current() ?: return false
		return dialog.isShowing && !dialog.isInTransit() && decor(dialog).alpha == 1f &&
			dims(dialog) && dimAmount(dialog) > 0f
	}

	private fun assertPutBack(old: AlertDialog, tag: String) {
		assertTrue("the swap settles", settle { settled() && current() !== old })
		val next = current()!!
		assertNotSame(old, next)
		assertEquals(tag, currentTag())
		assertTrue("the old one goes once the new one is in", settle { !old.isShowing })
		assertEquals("as any fresh dialog stands with accessibility",
			View.IMPORTANT_FOR_ACCESSIBILITY_YES, decor(next).importantForAccessibility)
		assertFalse(next.dialogState.waiting != null)
		assertFalse(next.dialogState.puttingBack)
		assertFalse(old.dialogState.waiting != null)
		assertEquals("laid out for the new screen", 2, next.context.resources.configuration.orientation)
	}

	@Test
	fun `software mode puts the dialog back hidden until its way in has ended`() {
		launch(ANIM_MODE_SOFTWARE)
		val old = openInfo()
		idle(600)
		assertTrue(settled())
		rotate(controller, landscape = true)
		assertTrue("the old one goes from sight", old.dialogState.puttingBack)
		assertEquals(0f, decor(old).alpha)
		assertEquals(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS,
			decor(old).importantForAccessibility)
		// The new one comes unseen, without dim, and waits for its way in.
		assertTrue(settle { current() !== old })
		val next = current()!!
		assertTrue(next.dialogState.waiting != null)
		assertEquals(0f, decor(next).alpha)
		assertFalse(dims(next))
		assertTrue("no key reaches it while the swap runs", key(next, KeyEvent.KEYCODE_BACK).first)
		assertTrue(next.isShowing)
		assertPutBack(old, "info")
	}

	@Test
	fun `system mode puts the dialog back seen from its first frame, the system's way in alone`() {
		launch(ANIM_MODE_SYSTEM)
		val old = openInfo()
		idle(600)
		rotate(controller, landscape = true)
		assertEquals(0f, decor(old).alpha)
		assertTrue(settle { current() !== old })
		val next = current()!!
		// Never hidden: what the window animation of its theme shows is the dialog itself.
		assertEquals(1f, decor(next).alpha)
		assertEquals(View.IMPORTANT_FOR_ACCESSIBILITY_YES, decor(next).importantForAccessibility)
		assertTrue("it still waits for the dim", next.dialogState.waiting != null)
		assertFalse(dims(next))
		var touched = false
		assertTrue(settle {
			touched = touched || decor(next).alpha < 1f || decor(next).scaleX < 1f
			settled() && current() === next
		})
		assertFalse("no animation of the app's own touched it", touched)
		assertPutBack(old, "info")
	}

	@Test
	fun `off mode swaps at once`() {
		launch(ANIM_MODE_OFF)
		val old = openInfo()
		idle(100)
		rotate(controller, landscape = true)
		val next = current()!!
		assertNotSame(old, next)
		assertEquals(1f, decor(next).alpha)
		assertTrue(dims(next))
		assertFalse(next.dialogState.waiting != null)
		assertPutBack(old, "info")
	}

	@Test
	fun `a rotation while the dialog is still coming in stops it there and puts it back`() {
		launch(ANIM_MODE_SOFTWARE)
		val old = openInfo()
		frames(2)
		assertTrue("caught on its way in", decor(old).alpha < 1f)
		rotate(controller, landscape = true)
		assertEquals("stopped at full size", 1f, decor(old).scaleX)
		// Its way in is cancelled: it stays out of sight while it is being replaced.
		var seen = false
		assertTrue(settle { seen = seen || decor(old).alpha > 0f; !old.isShowing })
		assertFalse("the one being replaced stayed out of sight", seen)
		assertPutBack(old, "info")
	}

	@Test
	fun `the import dialog's Copy copies the link and keeps the dialog open, before and after a rotation`() {
		launch(ANIM_MODE_SOFTWARE)
		val link = "https://example.com/sub?token=abc"
		val old = openImportConfirm(link)
		idle(600)
		assertCopies(old, link)
		rotate(controller, landscape = true)
		assertTrue(settle { settled() && current() !== old })
		assertEquals("import_confirm", currentTag())
		assertCopies(current()!!, link)
	}

	@Test
	fun `a rotation while the dialog is closing does not bring it back`() {
		launch(ANIM_MODE_SOFTWARE)
		val dialog = openInfo()
		idle(600)
		key(dialog, KeyEvent.KEYCODE_BACK)
		assertTrue("closing", dialog.dialogState.dismissing)
		assertNull("forgotten as its way out begins", current())
		rotate(controller, landscape = true)
		assertFalse("not taken for a swap", dialog.dialogState.puttingBack)
		assertTrue(settle { !dialog.isShowing })
		idle(500)
		assertNull("nothing was put back", current())
		assertNull(currentTag())
	}

	@Test
	fun `a second rotation in the middle of a swap ends with one dialog, put back for the last screen`() {
		launch(ANIM_MODE_SOFTWARE)
		val old = openInfo()
		idle(600)
		rotate(controller, landscape = true)
		assertTrue(settle { current() !== old })
		val middle = current()!!
		assertTrue("caught halfway through being put back", middle.dialogState.waiting != null)
		rotate(controller, landscape = false)
		assertFalse("shown at once, to be the one replaced now", middle.dialogState.waiting != null)
		assertTrue(middle.dialogState.puttingBack)
		assertTrue(settle { settled() && current() !== middle })
		val last = current()!!
		assertFalse(old.isShowing)
		assertTrue("the middle one goes once the last is in", settle { !middle.isShowing })
		assertTrue(last.isShowing)
		assertEquals("info", currentTag())
		assertEquals(1, last.context.resources.configuration.orientation)
		assertFalse(middle.dialogState.waiting != null)
		assertFalse(last.dialogState.puttingBack)
	}
}
