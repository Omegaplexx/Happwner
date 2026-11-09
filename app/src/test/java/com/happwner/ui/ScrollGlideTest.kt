package com.happwner.ui

import android.transition.ChangeBounds
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.happwner.R
import com.happwner.ui.UiTestSupport.frames
import com.happwner.ui.UiTestSupport.idle
import com.happwner.ui.UiTestSupport.setAnimMode
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config

// A change that leaves a scroll view past its new end moves the scroll in steps, not at once: on
// either screen, and whatever makes the change, so long as it is animated.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ScrollGlideTest {
	private lateinit var controller: ActivityController<MainActivity>
	private val activity: MainActivity get() = controller.get()

	@Before
	fun setUp() {
		UiTestSupport.pacedFrames()
		controller = Robolectric.buildActivity(MainActivity::class.java).setup()
		setAnimMode(activity, ANIM_MODE_SOFTWARE)
		idle(100)
	}

	@After
	fun tearDown() {
		controller.pause().stop().destroy()
		idle(100)
	}

	private fun scrollEnd(scroll: ScrollView) = scroll.getChildAt(0).height -
		(scroll.height - scroll.paddingTop - scroll.paddingBottom)

	// A tall block at the end of the content, for a change to take away.
	private fun addBlock(scroll: ScrollView): View {
		val block = View(activity)
		(scroll.getChildAt(0) as LinearLayout).addView(block, LinearLayout.LayoutParams(
			ViewGroup.LayoutParams.MATCH_PARENT, 3000))
		idle(100)
		return block
	}

	// Scrolled to the end, makes the change and follows the scroll to its new end.
	private fun assertGlides(scroll: ScrollView, change: () -> Unit) {
		val bottom = scrollEnd(scroll)
		assertTrue("a page that scrolls: $bottom", bottom > 0)
		scroll.scrollTo(0, bottom)
		change()
		assertEquals("nothing jumps before the first frame", bottom, scroll.scrollY)
		val seen = mutableListOf<Int>()
		repeat(60) {
			frames(1)
			seen += scroll.scrollY
		}
		val end = scrollEnd(scroll)
		assertTrue("the page got shorter and was let go of its held height: $end < $bottom", end < bottom)
		assertEquals("it ends at the new end", end, scroll.scrollY)
		assertEquals("and never goes back down on the way", seen.sortedDescending(), seen)
		assertTrue("with a step between the two ends: $seen", seen.any { it in (end + 1) until bottom })
	}

	@Test
	fun `collapsing the result glides the main screen`() {
		val scroll = activity.findViewById<ScrollView>(R.id.mainScrollView)
		val output = activity.findViewById<TextView>(R.id.output)
		output.text = (1..300).joinToString("\n") { "line $it" }
		output.visibility = View.VISIBLE
		idle(100)
		assertGlides(scroll) { activity.findViewById<View>(R.id.outputHeader).performClick() }
		assertEquals(View.GONE, output.visibility)
	}

	@Test
	fun `any animated change on the main screen glides, not only a button's`() {
		val scroll = activity.findViewById<ScrollView>(R.id.mainScrollView)
		val block = addBlock(scroll)
		assertGlides(scroll) {
			(scroll.getChildAt(0) as ViewGroup).beginDelayedTransitionIfEnabled(
				ChangeBounds().apply { duration = 300 })
			block.visibility = View.GONE
		}
	}

	@Test
	fun `a change on the settings screen glides`() {
		activity.openSettings()
		idle(600)
		val scroll = activity.findViewById<ScrollView>(R.id.settingsScrollView)
		val block = addBlock(scroll)
		assertGlides(scroll) {
			(scroll.parent as ViewGroup).beginChangeBounds(300)
			block.visibility = View.GONE
		}
	}
}
