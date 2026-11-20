package com.happwner.ui

import android.R as AndroidR
import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ValueAnimator
import android.view.ViewGroup
import android.view.WindowManager
import androidx.appcompat.app.AlertDialog
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import com.happwner.R

// Lifts a dialog above the keyboard (shortens it if too tall), on the project's clock instead of the system's
// instant window fitting. The window keeps the screen's height.
internal class DialogKeyboard(private val dialog: AlertDialog) {
	private val content: ViewGroup? = dialog.window?.decorView?.findViewById(AndroidR.id.content)
	private var keyboardTop: Int? = null
	// The room the keyboard takes at the foot of the window's content.
	private var padding = 0
	private var glide: ValueAnimator? = null
	private var goal: Int? = null
	// The card's height with nothing lifted, as far as it was seen.
	private var natural = 0
	private var waiting: (() -> Unit)? = null
	private val gap = dialog.context.resources.getDimensionPixelSize(R.dimen.spacing_small)

	fun attach() {
		val content = content ?: return
		ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
			val ime = WindowInsetsCompat.Type.ime()
			keyboardTop = if (insets.isVisible(ime)) view.rootView.height - insets.getInsets(ime).bottom else null
			settle()
			insets
		}
	}

	// Runs once the dialog is back down, as the keyboard leaves; at once if it is. A keyboard that never leaves
	// holds nothing back for long.
	fun afterDown(action: () -> Unit) {
		if (padding == 0 && glide == null) return action()
		waiting = action
		content?.postDelayed(::runWaiting, WAIT_MS)
	}

	private fun runWaiting() {
		val action = waiting ?: return
		waiting = null
		action()
	}

	private fun takesKeyboard(): Boolean {
		val flags = dialog.window?.attributes?.flags ?: return false
		return flags and WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM == 0
	}

	private fun settle() {
		val content = content ?: return
		val card = dialog.card() ?: return
		if (padding == 0 && glide == null && card.height > 0) natural = card.height
		val top = keyboardTop
		val want = if (top != null && takesKeyboard()) wanted(content, top) else 0
		val running = goal
		if (running != null) {
			if (running == want) return
		} else if (want == padding) {
			return
		}
		glide?.cancel()
		val context = dialog.context
		val mode = context.animMode()
		if (mode == ANIM_MODE_OFF || context.isLowRam() || !content.isLaidOut) return place(want)
		val from = padding
		goal = want
		glide = ValueAnimator.ofInt(from, want).apply {
			duration = context.stateChangeDuration(R.integer.duration_standard_transition)
			interpolator = curveFor(mode, materialStandard)
			addUpdateListener { move(it.animatedValue as Int) }
			addListener(object : AnimatorListenerAdapter() {
				override fun onAnimationEnd(animation: Animator) {
					if (glide !== animation) return
					glide = null
					goal = null
					if (padding == 0) runWaiting()
				}
			})
			start()
		}
	}

	// What the content gives up at its foot so that the card, centred in the rest, ends a gap above the keyboard.
	private fun wanted(content: ViewGroup, top: Int): Int {
		val at = IntArray(2)
		content.getLocationInWindow(at)
		val contentTop = at[1] + content.paddingTop
		val contentBottom = at[1] + content.height
		val limit = top - gap
		val toFill = maxOf(0, contentBottom - limit)
		val toCentre = 2 * maxOf(0, (contentTop + contentBottom) / 2 + natural / 2 - limit)
		return minOf(toCentre, toFill)
	}

	private fun place(want: Int) {
		glide?.cancel()
		move(want)
		if (padding == 0) runWaiting()
	}

	private fun move(value: Int) {
		padding = value
		content?.updatePadding(bottom = value)
	}

	private companion object {
		const val WAIT_MS = 600L
	}
}
