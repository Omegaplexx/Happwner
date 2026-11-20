package com.happwner.ui

import android.content.res.Configuration
import android.widget.EditText
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsAnimationCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import com.google.android.material.textfield.TextInputLayout
import com.happwner.R
import kotlin.math.abs

// Keeps the field being typed in above the keyboard: makes room at the page's foot and glides to the field.
// Insets are ignored while the keyboard slides (read at its start and end); the area must not clip to its padding.
internal class KeyboardRoom(private val area: GlideScrollView) {
	private var resting = 0
	private var keyboard = 0
	private var known = 0 // the keyboard's last height, used to make room before it starts
	private var expected = false
	private var sliding = false
	private val gap = area.resources.getDimensionPixelSize(R.dimen.spacing_small)

	init {
		area.viewTreeObserver.addOnGlobalFocusChangeListener { _, focused ->
			if (focused != null) area.post(::revealFocused)
			// The focus has gone where no keyboard comes: the room made for it is given back.
			if (expected && !(focused is EditText && focused.onCheckIsTextEditor())) {
				expected = false
				read()
			}
		}
		// The keyboard a window had meanwhile is read again once the focus is back.
		area.viewTreeObserver.addOnWindowFocusChangeListener { focused ->
			if (focused) read()
		}
	}

	fun onInsets(insets: WindowInsetsCompat) {
		resting = insets.getInsets(WindowInsetsCompat.Type.systemBars()).bottom
		if (!sliding && !expected && area.hasWindowFocus()) hear(keyboardOf(insets))
		follow()
	}

	fun onPrepare(animation: WindowInsetsAnimationCompat) {
		if (animation.isKeyboard()) sliding = true
	}

	// The layout of the slide's end is done by now.
	fun onStart(animation: WindowInsetsAnimationCompat) {
		if (animation.isKeyboard()) read()
	}

	fun onEnd(animation: WindowInsetsAnimationCompat) {
		if (!animation.isKeyboard()) return
		sliding = false
		read()
	}

	private fun WindowInsetsAnimationCompat.isKeyboard() = typeMask and WindowInsetsCompat.Type.ime() != 0

	private fun keyboardOf(insets: WindowInsetsCompat) = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom

	private fun read() {
		val insets = ViewCompat.getRootWindowInsets(area) ?: return
		if (area.hasWindowFocus()) hear(keyboardOf(insets))
		follow()
	}

	private fun hear(height: Int) {
		keyboard = height
		expected = false
		if (height > 0) known = height
	}

	// The room the keyboard needs, made at once; the page glides to its new end, or up to the field under the keyboard.
	private fun follow() {
		val content = area.getChildAt(0) ?: return
		val room = maxOf(resting, keyboard - below())
		val change = room - area.paddingBottom
		if (change == 0) return
		area.glideBeside(abs(change))
		val hidden = hiddenBelow()
		area.updatePadding(bottom = room)
		val to = minOf(area.scrollY + hidden, rangeOf(content.height, room))
		// Back toward a smaller end is set here too: the glide's own measure may come before the room shrinks.
		if ((hidden > 0 && to > area.scrollY) || to < area.scrollY) area.glideTo(to)
	}

	private fun revealFocused() {
		val content = area.getChildAt(0) ?: return
		if (!area.hasWindowFocus()) return
		if (keyboard == 0 && known > 0 && keyboardComes()) {
			expected = true
			keyboard = known
			return follow()
		}
		val to = minOf(area.scrollY + hiddenBelow(), rangeOf(content.height, area.paddingBottom))
		if (to > area.scrollY) area.glideTo(to)
	}

	private fun keyboardComes() = (area.findFocus() as? EditText)?.onCheckIsTextEditor() == true &&
		area.resources.configuration.keyboard == Configuration.KEYBOARD_NOKEYS

	private fun rangeOf(contentHeight: Int, room: Int) =
		maxOf(0, contentHeight - (area.height - area.paddingTop - room))

	// How far the area's foot stands above the window's.
	private fun below(): Int {
		val at = IntArray(2)
		area.getLocationInWindow(at)
		return area.rootView.height - (at[1] + area.height)
	}

	// How far the field that has the focus lies under the keyboard's edge, with a gap kept above it.
	private fun hiddenBelow(): Int {
		if (keyboard == 0) return 0
		val field = area.findFocus() as? EditText ?: return 0
		val box = generateSequence(field.parent) { it.parent }.filterIsInstance<TextInputLayout>().firstOrNull() ?: field
		val at = IntArray(2)
		box.getLocationInWindow(at)
		val top = area.rootView.height - keyboard
		return maxOf(0, at[1] + box.height - (top - gap))
	}
}
