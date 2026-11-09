package com.happwner.ui

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.os.Bundle
import android.os.SystemClock
import android.provider.Settings
import android.text.Spanned
import android.text.method.LinkMovementMethod
import android.text.style.URLSpan
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.widget.AutoCompleteTextView
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.view.allViews
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.RecyclerView
import com.happwner.R
import com.happwner.patcher.InstalledApp
import com.happwner.patcher.PatchSession
import com.happwner.patcher.PatchSource
import com.happwner.ui.UiTestSupport.decor
import com.happwner.ui.UiTestSupport.field
import com.happwner.ui.UiTestSupport.focusWindow
import com.happwner.ui.UiTestSupport.idle
import com.happwner.ui.UiTestSupport.key
import com.happwner.ui.UiTestSupport.settle
import java.io.File
import java.nio.file.Files
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
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

// The patcher's dialog and the page of installed apps that opens inside it: choosing "Installed",
// picking an app, and Back, which closes the page and not the dialog; then the dialog that offers to
// launch the app once it is installed.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class PatcherDialogTest {
	private lateinit var controller: ActivityController<MainActivity>
	private lateinit var folder: File
	private val activity: MainActivity get() = controller.get()
	private val settings: Fragment
		get() = activity.supportFragmentManager.findFragmentByTag("settings_fragment")!!

	@Before
	fun setUp() {
		UiTestSupport.pacedFrames()
		PatchSession.reset()
		folder = Files.createTempDirectory("apps").toFile()
		val base = File(folder, "base.apk").apply { writeText("apk") }
		val info = PackageInfo().apply {
			packageName = "com.example.alpha"
			versionName = "7.2"
			applicationInfo = ApplicationInfo().apply {
				packageName = "com.example.alpha"
				nonLocalizedLabel = "Alpha"
				sourceDir = base.path
			}
		}
		shadowOf(RuntimeEnvironment.getApplication().packageManager).installPackage(info)
		RuntimeEnvironment.setQualifiers("w393dp-h851dp-port-xxhdpi")
		controller = Robolectric.buildActivity(MainActivity::class.java).setup()
		UiTestSupport.setAnimMode(activity, ANIM_MODE_SOFTWARE)
		idle(100)
		activity.openSettings()
		idle(600)
	}

	@After
	fun tearDown() {
		PatchSession.reset()
		current()?.dismiss()
		controller.pause().stop().destroy()
		idle(100)
		folder.deleteRecursively()
	}

	private fun current(): AlertDialog? = field(settings, "currentDialog")

	private fun patcherPage(): String? = field(settings, "patcherPage")

	private fun openPatcher(): AlertDialog {
		val show = settings.javaClass.getDeclaredMethod("showPatcherDialog", String::class.java)
		show.isAccessible = true
		show.invoke(settings, null as String?)
		idle(400)
		return current()!!
	}

	// The third entry of the target list is the installed apps: after the releases.
	private fun chooseInstalled(dialog: AlertDialog) {
		val target = decor(dialog).findViewById<AutoCompleteTextView>(R.id.inputPatcherTarget)
		target.onItemClickListener.onItemClick(null, null, target.adapter.count - 1, 0)
		assertEquals("patcher_installed_apps", patcherPage())
		idle(600)
	}

	private fun appList(dialog: AlertDialog) =
		decor(dialog).findViewById<RecyclerView>(R.id.listInstalledApps)?.takeIf { it.isShown }

	private fun listFilled(dialog: AlertDialog) = settle(8000) {
		Thread.sleep(5)
		appList(dialog)?.adapter?.itemCount == 1
	}

	@Test
	fun `choosing Installed opens the list inside the dialog, Back closes it and keeps the dialog and the earlier choice, and a tap on an app fills the fields`() {
		val dialog = openPatcher()
		chooseInstalled(dialog)
		assertTrue(listFilled(dialog))
		key(dialog, KeyEvent.KEYCODE_BACK)
		assertTrue(settle { appList(dialog) == null })
		idle(600)
		assertTrue(dialog.isShowing)
		assertNull(patcherPage())
		val target = decor(dialog).findViewById<AutoCompleteTextView>(R.id.inputPatcherTarget)
		assertEquals("Happ (GitHub)", target.text.toString())
		assertTrue(decor(dialog).findViewById<View>(R.id.inputSigBypass).isShown)

		chooseInstalled(dialog)
		assertTrue(listFilled(dialog))
		idle(100)
		appList(dialog)!!.findViewHolderForAdapterPosition(0)!!.itemView.performClick()
		assertTrue(settle { appList(dialog) == null })
		idle(600)
		assertTrue(dialog.isShowing)
		assertNull(patcherPage())
		assertEquals("Alpha", target.text.toString())
		val details = decor(dialog).findViewById<TextView>(R.id.textPatcherPackageName).text.toString()
		assertTrue(details, details.contains("com.example.alpha"))
		val version = decor(dialog).findViewById<TextView>(R.id.textPatcherVersionName).text.toString()
		assertTrue(version, version.contains("7.2"))
	}

	private fun fields(dialog: AlertDialog) = listOf(R.id.inputPatcherTarget, R.id.inputSigBypass)
		.map { decor(dialog).findViewById<DropdownField>(it) }

	// A run's end is held by the session until it has been seen; the screen follows it from there.
	private fun patched(source: PatchSource): AlertDialog? {
		PatchSession.simulate(null, PatchSession.Result.Installed(source))
		idle(400)
		return current()
	}

	private fun installed(packageName: String) = PatchSource.Installed(
		InstalledApp(packageName, "Alpha", "7.2", listOf(File(folder, "base.apk")), 0L)
	)

	@Test
	fun `a launchable app gets a dialog with Details, OK and Launch left to right, and Launch opens it`() {
		val dialog = patched(installed(activity.packageName))!!
		assertEquals("patched", field<String?>(settings, "currentDialogTag"))
		val title = dialog.findViewById<TextView>(androidx.appcompat.R.id.alertTitle)!!.text.toString()
		assertEquals(activity.getString(R.string.dialog_title_patch_installed), title)
		val version = activity.packageManager.getPackageInfo(activity.packageName, 0).versionName ?: "?"
		assertEquals(
			"Alpha $version\n${activity.packageName}",
			dialog.findViewById<TextView>(android.R.id.message)!!.text.toString()
		)
		val details = dialog.getButton(AlertDialog.BUTTON_NEUTRAL)
		val ok = dialog.getButton(AlertDialog.BUTTON_NEGATIVE)
		val launch = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
		assertEquals(activity.getString(R.string.btn_details), details.text.toString())
		assertEquals(activity.getString(R.string.btn_ok), ok.text.toString())
		assertEquals(activity.getString(R.string.btn_launch), launch.text.toString())
		val at = IntArray(2)
		details.getLocationInWindow(at)
		val detailsLeft = at[0]
		ok.getLocationInWindow(at)
		val okLeft = at[0]
		launch.getLocationInWindow(at)
		assertTrue("$detailsLeft < $okLeft", detailsLeft < okLeft)
		assertTrue("$okLeft < ${at[0]}", okLeft < at[0])
		launch.performClick()
		idle(600)
		assertEquals(MainActivity::class.java.name, shadowOf(activity).nextStartedActivity.component?.className)
		assertFalse(dialog.isShowing)
	}

	@Test
	fun `an app with no screen gets Details and OK and no Launch, Details opens its system screen, and OK ends the dialog`() {
		val dialog = patched(installed("com.example.alpha"))!!
		assertEquals("patched", field<String?>(settings, "currentDialogTag"))
		assertTrue(dialog.getButton(AlertDialog.BUTTON_NEUTRAL).isShown)
		assertTrue(dialog.getButton(AlertDialog.BUTTON_NEGATIVE).isShown)
		assertFalse(dialog.getButton(AlertDialog.BUTTON_POSITIVE).isShown)
		dialog.getButton(AlertDialog.BUTTON_NEUTRAL).performClick()
		idle(300)
		val opened = shadowOf(activity).nextStartedActivity
		assertEquals(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, opened.action)
		assertEquals("package:com.example.alpha", opened.dataString)
		assertTrue(dialog.isShowing)
		assertNotNull("not seen yet, so still to be shown", PatchSession.result.value)
		dialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
		assertTrue(settle { current() == null })
		assertNull(PatchSession.result.value)
	}

	private fun ended(result: PatchSession.Result): AlertDialog {
		PatchSession.simulate(null, result)
		idle(400)
		return current()!!
	}

	private fun assertErrorDialog(dialog: AlertDialog, text: String) {
		assertEquals("patch_error", field<String?>(settings, "currentDialogTag"))
		assertEquals(
			activity.getString(R.string.dialog_title_error),
			dialog.findViewById<TextView>(androidx.appcompat.R.id.alertTitle)!!.text.toString()
		)
		val message = dialog.findViewById<TextView>(android.R.id.message)!!
		assertEquals(text, message.text.toString())
		// Nothing to press but OK: the text is there to be selected and copied by hand.
		assertTrue(message.isTextSelectable)
		assertFalse(dialog.getButton(AlertDialog.BUTTON_NEGATIVE).isShown)
		assertFalse(dialog.getButton(AlertDialog.BUTTON_NEUTRAL).isShown)
		val ok = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
		assertEquals(activity.getString(R.string.btn_ok), ok.text.toString())
		ok.performClick()
		assertTrue(settle { !dialog.isShowing })
		assertNull("seen, so not shown again", PatchSession.result.value)
	}

	@Test
	fun `a finger on the field or on its arrow opens a plain list that stands still, a bare click does not`() {
		val dialog = openPatcher()
		focusWindow(decor(dialog))
		fields(dialog).forEach { dropdown ->
			dropdown.performClick()
			dropdown.showDropDown()
			idle(400)
			assertFalse("no finger, no list", dropdown.isPopupShowing)
			val arrow = (dropdown.parent.parent as DropdownLayout).findViewById<View>(com.google.android.material.R.id.text_input_end_icon)
			listOf(dropdown, arrow).forEach { target ->
				tap(dialog, target)
				assertTrue(target.javaClass.simpleName, dropdown.isPopupShowing)
				val list = openList(dropdown)
				assertEquals(dropdown.adapter.count, list.adapter.count)
				// The platform list of a field like this one is set to stretch, even when all of it shows.
				assertEquals(View.OVER_SCROLL_IF_CONTENT_SCROLLS, list.overScrollMode)
				assertFalse(list.canScrollVertically(1) || list.canScrollVertically(-1))
				dropdown.dismissDropDown()
				idle(400)
				assertFalse(dropdown.isPopupShowing)
			}
		}
	}

	@Test
	fun `choosing in a list sets the field, tells its owner and closes the list`() {
		val dialog = openPatcher()
		focusWindow(decor(dialog))
		val dropdown = fields(dialog)[1]
		var picked = -1
		dropdown.setOnItemClickListener { _, _, position, _ -> picked = position }
		tap(dialog, dropdown)
		val list = openList(dropdown)
		list.performItemClick(list.getChildAt(2), 2, list.adapter.getItemId(2))
		idle(300)
		assertEquals(2, picked)
		assertEquals(dropdown.adapter.getItem(2).toString(), dropdown.text.toString())
		assertFalse(dropdown.isPopupShowing)
	}

	private fun tap(dialog: AlertDialog, target: View) {
		val at = IntArray(2)
		target.getLocationInWindow(at)
		val x = at[0] + target.width / 2f
		val y = at[1] + target.height / 2f
		val down = SystemClock.uptimeMillis()
		decor(dialog).dispatchTouchEvent(MotionEvent.obtain(down, down, MotionEvent.ACTION_DOWN, x, y, 0))
		decor(dialog).dispatchTouchEvent(MotionEvent.obtain(down, down + 50, MotionEvent.ACTION_UP, x, y, 0))
		idle(300)
	}

	// The list a dropdown has open: the popup draws the dropdown's background around it.
	private fun openList(dropdown: DropdownField) = (dropdown.dropDownBackground.callback as View).allViews
		.filterIsInstance<ListView>().first()

	@Test
	fun `the description of LSPortable links to the project and shows no markup`() {
		val info = decor(openPatcher()).findViewById<TextView>(R.id.textPatcherInfo)
		val text = info.text as Spanned
		assertFalse(text.contains("<a"))
		val link = text.getSpans(0, text.length, URLSpan::class.java).single()
		assertEquals("https://github.com/Omegaplexx/LSPortable", link.url)
		assertEquals("LSPortable", text.substring(text.getSpanStart(link), text.getSpanEnd(link)))
		assertTrue(info.movementMethod is LinkMovementMethod)
	}

	@Test
	fun `a failed patch, download or install is shown as an error dialog with only OK`() {
		assertErrorDialog(ended(PatchSession.Result.PatchFailed("LSPatch said no")), "LSPatch said no")
		assertErrorDialog(
			ended(PatchSession.Result.DownloadFailed("Happ")),
			activity.getString(R.string.msg_patch_download_failed, "Happ")
		)
		assertErrorDialog(
			ended(PatchSession.Result.InstallFailed("boom")),
			activity.getString(R.string.msg_patch_install_failed, "boom")
		)
	}

	// What a change of theme does: the activity and its fragments are destroyed and made anew.
	private fun rebuild() {
		val state = Bundle()
		controller.pause().saveInstanceState(state).stop().destroy()
		controller = Robolectric.buildActivity(MainActivity::class.java).setup(state)
	}

	private fun progressDialog(): AlertDialog? = field(settings, "patchProgressDialog")

	private fun progressText() = progressDialog()!!.findViewById<TextView>(android.R.id.message)!!.text.toString()

	@Test
	fun `a run shows its progress, and Back on that dialog cancels it`() {
		PatchSession.simulate(PatchSession.Progress.Downloading("Happ", 5L shl 20, 10L shl 20))
		idle(400)
		assertEquals(activity.getString(R.string.status_patch_downloading_progress, "Happ", "5.0", "10.0", 50), progressText())
		PatchSession.simulate(PatchSession.Progress.Patching)
		idle(100)
		assertEquals(activity.getString(R.string.status_patch_patching), progressText())
		val dialog = progressDialog()!!
		key(dialog, KeyEvent.KEYCODE_BACK)
		idle(600)
		assertFalse(PatchSession.running)
		assertNull(PatchSession.progress.value)
		assertNull(progressDialog())
		assertFalse(dialog.isShowing)
	}

	@Test
	fun `a screen rebuilt in the middle of a run neither stops it nor loses its dialogs`() {
		PatchSession.simulate(PatchSession.Progress.Downloading("Happ", 1L shl 20, 4L shl 20))
		idle(400)
		rebuild()
		idle(1000)
		assertTrue("the run goes on", PatchSession.running)
		assertEquals(activity.getString(R.string.status_patch_downloading_progress, "Happ", "1.0", "4.0", 25), progressText())
		assertTrue(progressDialog()!!.isShowing)
		// It ends while that screen is up, and the end is shown to the person once.
		PatchSession.simulate(null, PatchSession.Result.PatchFailed("late"))
		idle(600)
		assertNull(progressDialog())
		rebuild()
		idle(1000)
		assertErrorDialog(current()!!, "late")
		rebuild()
		idle(1000)
		assertNull(current())
	}
}
