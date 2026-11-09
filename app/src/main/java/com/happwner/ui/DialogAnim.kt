package com.happwner.ui

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ValueAnimator
import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.AutoCompleteTextView
import androidx.appcompat.app.AlertDialog

// Dialog timings, and the size it grows from.
private const val DIALOG_ENTER_MS = 165L
private const val DIALOG_EXIT_MS = 140L
private const val LOWRAM_DIALOG_MS = 120L
private const val DIALOG_SCALE_FROM = 0.94f

// Material 3's scrim opacity (m3_comp_scrim_container_opacity).
internal const val DIALOG_DIM_TARGET = 0.32f
// Not 0f: a zero dimAmount drops FLAG_DIM_BEHIND, leaving the fade nothing to animate from.
internal const val DIALOG_DIM_NONE = 0.001f

// False if the window refused: it may be gone already.
internal fun Window.setDim(amount: Float): Boolean = runCatching { setDimAmount(amount) }.isSuccess

private fun Window.currentDim(): Float =
	runCatching { attributes?.dimAmount }.getOrNull() ?: DIALOG_DIM_TARGET

// Dim animated on the dialog's own curve, so dim and window move at one rate.
// Registered so a later call can cancel it; forgotten when it ends.
private fun AlertDialog.dimAnimator(window: Window, from: Float, to: Float, duration: Long): ValueAnimator {
	val state = dialogState
	state.dim?.cancel()
	val anim = ValueAnimator.ofFloat(from, to).apply {
		this.duration = duration
		interpolator = materialSmooth
		addUpdateListener { window.setDim(it.animatedValue as Float) }
		addListener(object : AnimatorListenerAdapter() {
			override fun onAnimationEnd(animation: Animator) {
				if (state.dim === animation) state.dim = null
			}
		})
	}
	state.dim = anim
	return anim
}

internal fun AlertDialog.animateDimIn(duration: Long, low: Boolean) {
	val window = window ?: return
	runCatching { window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND) }
	if (low) {
		window.setDim(DIALOG_DIM_TARGET)
		return
	}
	if (!window.setDim(DIALOG_DIM_NONE)) return
	dimAnimator(window, 0f, DIALOG_DIM_TARGET, duration).start()
}

private fun AlertDialog.animateDimOut(duration: Long, low: Boolean) {
	val window = window ?: return
	if (low) {
		window.setDim(0f)
		return
	}
	dimAnimator(window, window.currentDim(), 0f, duration).start()
}

// How long a dialog takes to come in and to go: shorter on a low-RAM device.
internal fun dialogEnterMs(low: Boolean): Long = if (low) LOWRAM_DIALOG_MS else DIALOG_ENTER_MS
private fun dialogExitMs(low: Boolean): Long = if (low) LOWRAM_DIALOG_MS else DIALOG_EXIT_MS

// Fade plus a slight scale-up; no scale on a low-RAM device.
internal fun View.animateDialogIn(low: Boolean, onEnd: () -> Unit = {}) {
	alpha = 0f
	if (!low) {
		scaleX = DIALOG_SCALE_FROM
		scaleY = DIALOG_SCALE_FROM
	}
	val anim = animate()
		.alpha(1f)
		.setDuration(dialogEnterMs(low))
		.setInterpolator(materialSmooth)
		.withLayer()
		.withEndAction { onEnd() }
	if (!low) anim.scaleX(1f).scaleY(1f)
	anim.start()
}

private fun View.animateDialogOut(low: Boolean, onEnd: () -> Unit) {
	val anim = animate()
		.alpha(0f)
		.setDuration(dialogExitMs(low))
		// Same even curve as the entry: accelerate is fastest on the last frame and makes closing snap.
		.setInterpolator(materialSmooth)
		.withLayer()
		.withEndAction { onEnd() }
	if (!low) anim.scaleX(DIALOG_SCALE_FROM).scaleY(DIALOG_SCALE_FROM)
	anim.start()
}

// Idempotent: runs once.
fun AlertDialog.dismissAnimated(after: (() -> Unit)? = null) {
	val state = dialogState
	// Closes at once: no window to animate, or animations off or left to the system.
	val dismissNow: () -> Unit = {
		// The follow-up's failure stays its own.
		runCatching { after?.invoke() }
		runCatching { dismiss() }
		state.dismissing = false
	}
	if (state.dismissing) return
	state.dismissing = true

	state.dismissListeners.forEach { runCatching { it.onDismiss(this) } }
	state.dismissListeners.clear()

	val dialogWindow = window
	val dialogDecor = dialogWindow?.decorView
	if (dialogWindow == null || dialogDecor == null || !isShowing) {
		dismissNow()
		return
	}
	// A list is a window of its own and does not fade with the dialog, so it goes first.
	dialogDecor.closeDropdowns()
	val low = context.isLowRam()
	val mode = shownAnimMode()
	val duration = dialogExitMs(low)

	if (mode == ANIM_MODE_OFF) {
		dialogWindow.setDim(0f)
		dismissNow()
		return
	}

	if (mode == ANIM_MODE_SYSTEM) {
		dismissNow()
		return
	}

	// The dim lasts as long as the dialog: dismiss() fires when this animation ends, so a longer dim would be cut off.
	animateDimOut(duration, low)

	// The window swallows touches until dismiss() fires: stop taking input now,
	// or the screen behind is dead for the whole exit.
	runCatching {
		dialogWindow.addFlags(
			WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE or
				WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
		)
	}

	dialogDecor.animateDialogOut(low, dismissNow)
}

internal fun View.closeDropdowns() {
	if (this is AutoCompleteTextView) dismissDropDown()
	if (this is ViewGroup) for (i in 0 until childCount) getChildAt(i).closeDropdowns()
}

// Dialogs here have no text field, and a window that hides the keyboard for itself is not reliable.
internal fun Context.hideKeyboard() {
	val activity = generateSequence(this) { (it as? ContextWrapper)?.baseContext }
		.filterIsInstance<Activity>().firstOrNull() ?: return
	(activity.currentFocus ?: activity.window.decorView).hideKeyboard()
}

internal fun View.hideKeyboard() {
	(context.getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager)
		?.hideSoftInputFromWindow(windowToken, 0)
}
