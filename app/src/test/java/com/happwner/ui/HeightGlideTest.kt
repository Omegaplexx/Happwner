package com.happwner.ui

import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import com.happwner.R
import com.happwner.data.PrefsManager
import com.happwner.ui.UiTestSupport.decor
import com.happwner.ui.UiTestSupport.field
import com.happwner.ui.UiTestSupport.frames
import com.happwner.ui.UiTestSupport.idle
import com.happwner.ui.UiTestSupport.setAnimMode
import kotlin.math.abs
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config

// What changes height glides, whatever changes it: a dialog's frame and rows go to the new size in steps,
// and so do the rows of the screen.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HeightGlideTest {
	private lateinit var controller: ActivityController<MainActivity>
	private val activity: MainActivity get() = controller.get()
	private val settings: Fragment
		get() = activity.supportFragmentManager.findFragmentByTag("settings_fragment")!!

	@Before
	fun setUp() {
		UiTestSupport.pacedFrames()
		// A screen the hooks fit in, so that what the status line takes is what the dialog gives.
		RuntimeEnvironment.setQualifiers("w393dp-h851dp-port-xxhdpi")
		controller = Robolectric.buildActivity(MainActivity::class.java).setup()
		setAnimMode(activity, ANIM_MODE_SOFTWARE)
		idle(100)
		activity.openSettings()
		idle(600)
	}

	@After
	fun tearDown() {
		(field<AlertDialog?>(settings, "currentDialog"))?.dismiss()
		controller.pause().stop().destroy()
		idle(100)
	}

	private fun openXposedDialog(): AlertDialog {
		PrefsManager.getSafePrefs(activity).edit().putBoolean(PrefsManager.PREF_LSPATCH_MODE, true).commit()
		settings.requireView().findViewById<View>(R.id.itemXposed).performClick()
		val dialog = field<AlertDialog?>(settings, "currentDialog")!!
		idle(600)
		return dialog
	}

	private fun card(dialog: AlertDialog) =
		decor(dialog).findViewById<ViewGroup>(android.R.id.content).getChildAt(0)

	private fun status(dialog: AlertDialog) = decor(dialog).findViewById<TextView>(R.id.textHwidSpoofStatus)

	private fun lines(count: Int) = (1..count).joinToString("\n") { "line $it" }

	// The card's heights frame by frame, with the frame drawn around it.
	private class Seen(val cards: List<Int>, val boxes: List<Int>, val centres: List<Int>)

	private fun watch(dialog: AlertDialog, count: Int = 40): Seen {
		val card = card(dialog)
		val box = dialog.box()!!
		val cards = mutableListOf<Int>()
		val drawn = mutableListOf<Int>()
		val centres = mutableListOf<Int>()
		repeat(count) {
			frames(1)
			cards += card.height
			drawn += box.height
			centres += card.top + card.height / 2
		}
		return Seen(cards, drawn, centres)
	}

	@Test
	fun `a status line taking more lines grows the dialog in steps, its frame with it`() {
		val dialog = openXposedDialog()
		val before = card(dialog).height
		status(dialog).crossfadeText(lines(6))
		assertEquals("nothing jumps before the first frame", before, card(dialog).height)

		val seen = watch(dialog)
		val end = card(dialog).height
		assertTrue("the dialog grew: $before to $end", end > before)
		assertEquals("it never goes back on the way", seen.cards.sorted(), seen.cards)
		assertTrue("with a step between the two sizes: ${seen.cards}", seen.cards.any { it in (before + 1) until end })
		assertTrue("the frame is the card's size every frame", seen.cards.indices.all {
			abs(seen.cards[it] - seen.boxes[it]) <= 1
		})
		assertTrue("the card stays about the window's middle: ${seen.centres}",
			seen.centres.max() - seen.centres.min() <= 2)
		assertFalse("the frame is the card's own again once it is there", (dialog.box()!!).driven)
	}

	@Test
	fun `the line the pencil asks for changes through the dialog's glide`() {
		val dialog = openXposedDialog()
		// Text here has no width to wrap at, so what the line does to the height is seen above; this
		// is that the toggle's own change goes the same way.
		val host = decor(dialog).getTag(R.id.tag_height_glide) as HeightGlide
		var glides = 0
		decor(dialog).setTag(R.id.tag_height_glide, HeightGlide { duration, change ->
			glides++
			host.run(duration, change)
		})
		val toggle = decor(dialog).findViewById<View>(R.id.rowHwidSpoofToggle)
		val line = status(dialog)
		val first = line.text.toString()
		toggle.performClick()
		assertEquals(1, glides)
		assertTrue("the line took another text", line.text.toString() != first)
		idle(600)
		toggle.performClick()
		assertEquals(2, glides)
		idle(600)
		assertEquals(first, line.text.toString())
	}

	@Test
	fun `with animations off the dialog takes its size at once`() {
		val dialog = openXposedDialog()
		val before = card(dialog).height
		setAnimMode(activity, ANIM_MODE_OFF)
		status(dialog).crossfadeText(lines(6))
		frames(1)
		val seen = watch(dialog, count = 5)
		assertTrue("grown: $before to ${seen.cards.first()}", seen.cards.first() > before)
		assertEquals("and never in steps: ${seen.cards}", 1, seen.cards.toSet().size)
	}

	@Test
	fun `two changes in a frame are one glide`() {
		val dialog = openXposedDialog()
		val before = card(dialog).height
		status(dialog).crossfadeText(lines(3))
		status(dialog).crossfadeText(lines(6))
		val seen = watch(dialog)
		val end = card(dialog).height
		assertTrue("grown: $before to $end", end > before)
		assertEquals("in one run to the later size", seen.cards.sorted(), seen.cards)
		assertTrue("with steps: ${seen.cards}", seen.cards.any { it in (before + 1) until end })
	}

	@Test
	fun `a view with no host above it just changes`() {
		val view = TextView(activity)
		var ran = 0
		view.glideHeights { ran++ }
		assertEquals(1, ran)
	}

	@Test
	fun `the nearest host above a view glides it`() {
		val outer = FrameLayout(activity)
		val inner = FrameLayout(activity)
		val leaf = TextView(activity)
		outer.addView(inner)
		inner.addView(leaf)
		val glided = mutableListOf<String>()
		outer.setTag(R.id.tag_height_glide, HeightGlide { _, change -> glided += "outer"; change() })
		inner.setTag(R.id.tag_height_glide, HeightGlide { _, change -> glided += "inner"; change() })
		leaf.glideHeights { }
		assertEquals(listOf("inner"), glided)
	}

	@Test
	fun `what a settings row's height moves glides on the screen`() {
		val root = settings.requireView() as ViewGroup
		val scroll = root.findViewById<ViewGroup>(R.id.settingsScrollView)
		val content = scroll.getChildAt(0) as LinearLayout
		val block = View(activity)
		content.addView(block, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 400))
		idle(100)
		val before = content.height
		block.glideHeights { block.visibility = View.GONE }
		assertEquals("nothing jumps before the first frame", before, content.height)
		val seen = mutableListOf<Int>()
		repeat(40) {
			frames(1)
			seen += content.height
		}
		assertTrue("the content got shorter: $before to ${seen.last()}", seen.last() < before)
		assertEquals("never going back up", seen.sortedDescending(), seen)
		assertTrue("with a step between: $seen", seen.any { it in (seen.last() + 1) until before })
	}
}
