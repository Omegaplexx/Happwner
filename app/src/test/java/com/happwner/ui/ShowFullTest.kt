package com.happwner.ui

import android.graphics.Color
import android.text.PrecomputedText
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.view.View
import android.widget.TextView
import com.happwner.R
import com.happwner.ui.UiTestSupport.field
import com.happwner.ui.UiTestSupport.idle
import com.happwner.ui.UiTestSupport.setAnimMode
import com.happwner.ui.UiTestSupport.settle
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
import org.robolectric.annotation.GraphicsMode

// "Show full" on a long result: the text comes to the screen as the one measured off the UI thread.
// Native graphics: the default ones cannot tell two equal paints apart, so would refuse any such text.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class ShowFullTest {
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

	@Test
	fun `the full text is set as the precomputed one, selectable and with the labels above it kept`() {
		val output = activity.findViewById<TextView>(R.id.output)
		val labels = activity.findViewById<TextView>(R.id.outputLabels)
		activity.findViewById<View>(R.id.outputBox).visibility = View.VISIBLE
		output.text = "head"
		output.setTextIsSelectable(true)
		labels.text = SpannableStringBuilder("prefix").apply {
			setSpan(ForegroundColorSpan(Color.RED), 0, 6, 0)
		}
		labels.visibility = View.VISIBLE
		val body = (1..2000).joinToString("\n") { "vless://id-$it@host:443?type=tcp#node$it" }
		val expand = MainActivity::class.java.getDeclaredMethod(
			"expandOutputToFull", String::class.java, Int::class.javaPrimitiveType)
		expand.isAccessible = true
		expand.invoke(activity, body, field<Int>(activity, "fetchGeneration"))

		assertTrue(settle(8000) { Thread.sleep(5); output.text.length > 10 })
		assertTrue("measured off the UI thread: ${output.text.javaClass}", output.text is PrecomputedText)
		assertEquals(body, output.text.toString())
		assertTrue(output.isTextSelectable)
		assertEquals("prefix", labels.text.toString())
		assertEquals(1, (labels.text as Spanned).getSpans(0, 6, ForegroundColorSpan::class.java).size)
	}
}
