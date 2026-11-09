package com.happwner.ui

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.graphics.Color
import android.view.View
import android.view.ViewGroup
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.inputmethod.EditorInfo
import android.widget.FrameLayout
import android.widget.TextView
import androidx.core.view.isVisible
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.happwner.R
import com.happwner.patcher.InstalledApp
import com.happwner.patcher.InstalledApps
import com.happwner.ui.UiTestSupport.idle
import java.io.File
import java.nio.file.Files
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
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

// The page of installed apps: which apps it lists, in what order, how the search narrows them and
// what a tap hands back.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class InstalledAppsPickerTest {
	private lateinit var controller: ActivityController<MainActivity>
	private lateinit var folder: File
	private var picked: InstalledApp? = null
	private lateinit var page: View

	private val list get() = page.findViewById<RecyclerView>(R.id.listInstalledApps)
	private val status get() = page.findViewById<TextView>(R.id.textInstalledStatus)
	private val search get() = page.findViewById<TextInputEditText>(R.id.inputInstalledSearch)

	@Before
	fun setUp() {
		UiTestSupport.pacedFrames()
		folder = Files.createTempDirectory("apps").toFile()
		install("com.example.beta", "Beta", system = false, splits = listOf("split_config.en.apk"))
		install("com.example.alpha", "Alpha", system = false)
		install("com.example.clock", "Clock", system = true)
		controller = Robolectric.buildActivity(MainActivity::class.java).setup()
		val context = controller.get()
		InstalledApps.refresh(context)
		page = InstalledAppsPicker { picked = it }.create(FrameLayout(context))
		context.addContentView(page, ViewGroup.LayoutParams(MATCH_PARENT, MATCH_PARENT))
		idle(100)
	}

	@After
	fun tearDown() {
		controller.pause().stop().destroy()
		folder.deleteRecursively()
	}

	private fun install(name: String, label: String, system: Boolean, splits: List<String> = emptyList()) {
		val base = File(folder, "$name.apk").apply { writeText("apk") }
		val info = PackageInfo().apply {
			packageName = name
			versionName = "1.0"
			applicationInfo = ApplicationInfo().apply {
				packageName = name
				nonLocalizedLabel = label
				sourceDir = base.path
				splitSourceDirs = splits.map { File(folder, it).apply { writeText("apk") }.path }.toTypedArray()
				if (system) flags = flags or ApplicationInfo.FLAG_SYSTEM
			}
		}
		shadowOf(RuntimeEnvironment.getApplication().packageManager).installPackage(info)
	}

	// The list is read and diffed off the main thread, so the clock alone does not bring it in.
	private fun waitFor(condition: () -> Boolean): Boolean {
		repeat(500) {
			if (condition()) return true
			idle(16)
			Thread.sleep(5)
		}
		return condition()
	}

	private fun labels(): List<String> = (0 until list.adapter!!.itemCount).map { position ->
		list.findViewHolderForAdapterPosition(position)!!.itemView
			.findViewById<TextView>(R.id.textAppLabel).text.toString()
	}

	private fun type(query: String) = search.setText(query)

	@Test
	fun `only the user's apps are listed, in the order of their names`() {
		assertTrue(waitFor { list.adapter!!.itemCount == 2 })
		idle(100)
		assertEquals(listOf("Alpha", "Beta"), labels())
		assertFalse(status.isVisible)
	}

	@Test
	fun `the search narrows by name or by package and says so when nothing is left`() {
		assertTrue(waitFor { list.adapter!!.itemCount == 2 })
		type("BET")
		assertTrue(waitFor { list.adapter!!.itemCount == 1 })
		type("example.alp")
		assertTrue(waitFor { list.adapter!!.itemCount == 1 })
		idle(100)
		assertEquals(listOf("Alpha"), labels())
		type("zzz")
		assertTrue(waitFor { list.adapter!!.itemCount == 0 })
		assertTrue(status.isVisible)
		type("")
		assertTrue(waitFor { list.adapter!!.itemCount == 2 })
		assertFalse(status.isVisible)
	}

	@Test
	fun `a tap hands back the app with its base apk first and its splits after`() {
		assertTrue(waitFor { list.adapter!!.itemCount == 2 })
		idle(100)
		list.findViewHolderForAdapterPosition(1)!!.itemView.performClick()
		val app = picked
		assertNotNull(app)
		assertEquals("com.example.beta", app!!.packageName)
		assertEquals(listOf("com.example.beta.apk", "split_config.en.apk"), app.apks.map { it.name })
	}

	@Test
	fun `the search field takes the cursor and the selection colour from the accent`() {
		val accent = MaterialColors.getColor(search, R.attr.happAccent, 0)
		val layout = page.findViewById<TextInputLayout>(R.id.layoutInstalledSearch)
		assertEquals(accent, layout.cursorColor!!.defaultColor)
		assertEquals(Color.argb(115, Color.red(accent), Color.green(accent), Color.blue(accent)), search.highlightColor)
	}

	@Test
	fun `the search action takes the focus off the field`() {
		search.requestFocus()
		assertTrue(search.hasFocus())
		search.onEditorAction(EditorInfo.IME_ACTION_SEARCH)
		assertFalse(search.hasFocus())
	}
}
