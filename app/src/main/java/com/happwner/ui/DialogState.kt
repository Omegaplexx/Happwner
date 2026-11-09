package com.happwner.ui

import android.animation.ValueAnimator
import android.content.DialogInterface
import android.view.View
import android.view.WindowManager
import androidx.appcompat.app.AlertDialog
import com.happwner.R

// Per-dialog state; lives on the window's decor view and is cleared on dismiss.
internal class DialogState {
	var animMode: Int? = null
	var dismissing = false
	var puttingBack = false
	var waiting: Waiting? = null
	var box: CardBox? = null
	var dim: ValueAnimator? = null
	var blockOutsideTap = false
	// Sees a button index, or Back/outside (null), before closing; true keeps the dialog open.
	var stayOpenHook: ((Int?) -> Boolean)? = null
	val dismissListeners = mutableListOf<DialogInterface.OnDismissListener>()
}

internal val AlertDialog.dialogState: DialogState
	get() {
		val decor = window?.decorView ?: return DialogState()
		return decor.getTag(R.id.tag_dialog_state) as? DialogState
			?: DialogState().also { decor.setTag(R.id.tag_dialog_state, it) }
	}

internal fun AlertDialog.isLeaving(): Boolean =
	!isShowing || dialogState.dismissing || dialogState.puttingBack

// While above zero, shown dialogs wait hidden to replace one being put back (rotation).
internal var putBackShows = 0

fun showInPlace(block: () -> Unit) {
	putBackShows++
	try {
		block()
	} finally {
		putBackShows--
	}
}

// The dim a put-back dialog takes once shown, what waits on that, and its accessibility mode.
internal class Waiting(val dim: Float, val accessibility: Int) {
	val after = mutableListOf<() -> Unit>()
}

// Keeps input out until shown, then takes the dim.
internal fun AlertDialog.takeDimOnceShown(dim: Float) {
	val decor = window?.decorView
	dialogState.waiting =
		Waiting(dim, decor?.importantForAccessibility ?: View.IMPORTANT_FOR_ACCESSIBILITY_AUTO)
}

// Waits hidden, from accessibility too, until put back.
internal fun AlertDialog.holdHidden(dim: Float) {
	takeDimOnceShown(dim)
	window?.decorView?.let { decor ->
		decor.alpha = 0f
		decor.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
	}
}

// Ends the wait: shows the dialog and applies its dim.
private fun AlertDialog.reveal() {
	val state = dialogState
	val pending = state.waiting ?: return
	state.waiting = null
	window?.let {
		it.decorView.alpha = 1f
		it.decorView.importantForAccessibility = pending.accessibility
		runCatching {
			it.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
			it.setDimAmount(pending.dim)
		}
	}
	pending.after.forEach { it() }
}

// Closes without the exit animation: the dialog is already hidden.
private fun AlertDialog.dismissInstantly() {
	runCatching { dismiss() }
}

// Input is blocked while a dialog is being swapped.
internal fun AlertDialog.isInTransit() = dialogState.puttingBack || dialogState.waiting != null

// After a rotation, swaps in a fresh dialog so it gets the new screen's size.
fun AlertDialog.putBackForNewScreen(reopen: () -> AlertDialog?) {
	if (isLeaving()) return
	val decor = window?.decorView ?: return
	// Caught mid-entry: stops at full size and shows at once.
	decor.animate().cancel()
	decor.scaleX = 1f
	decor.scaleY = 1f
	reveal()
	if (shownAnimMode() == ANIM_MODE_OFF) putBackAtOnce(reopen) else putBackAfterGlide(decor, reopen)
}

// Animations off: the new dialog replaces this one in the same frame.
private fun AlertDialog.putBackAtOnce(reopen: () -> AlertDialog?) {
	val next = reopen() ?: return
	dialogState.puttingBack = true
	// Shown at once, even if it would wait.
	next.reveal()
	dismissInstantlyUnder(next)
}

// Animations on: this one is hidden, and the new one appears once the screen has settled.
private fun AlertDialog.putBackAfterGlide(decor: View, reopen: () -> AlertDialog?) {
	dialogState.puttingBack = true
	// Left alone to lay out for the new screen: resizing the window afterwards makes the system slide it.
	decor.alpha = 0f
	val accessibility = decor.importantForAccessibility
	decor.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
	// A frame after the glide ends, so building it does not land on a glide frame.
	decor.afterScreenGlide {
		val next = reopen()
		if (next != null) {
			appearAs(next)
		} else {
			// Nothing to reopen: comes back as laid out, box at card size.
			decor.alpha = 1f
			decor.importantForAccessibility = accessibility
			dialogState.puttingBack = false
			dialogState.box?.rest()
		}
	}
}

// Shows the new dialog as a dialog opens, then drops this one under it.
// System mode leaves the entry to the theme's window animation.
private fun AlertDialog.appearAs(next: AlertDialog) {
	dismissInstantlyUnder(next)
	val nextDecor = next.window?.decorView ?: return next.reveal()
	nextDecor.onNextPreDraw {
		// A frame after its first draw: that frame is long and would eat the animation's start.
		nextDecor.postOnAnimation {
			// Already shown (second rotation).
			if (next.dialogState.waiting == null) return@postOnAnimation
			if (next.shownAnimMode() == ANIM_MODE_SYSTEM) {
				next.reveal()
				return@postOnAnimation
			}
			nextDecor.animateDialogIn(next.context.isLowRam()) { next.reveal() }
		}
	}
}

// Drops this dialog two frames after the new one takes the dim, or after its first draw.
private fun AlertDialog.dismissInstantlyUnder(next: AlertDialog?) {
	val nextDecor = next?.window?.decorView
	if (nextDecor == null || !next.isShowing) {
		dismissInstantly()
		return
	}
	val go = { nextDecor.postOnAnimation { nextDecor.postOnAnimation { dismissInstantly() } } }
	val pending = next.dialogState.waiting
	if (pending != null) {
		pending.after += go
	} else {
		nextDecor.onNextPreDraw(go)
	}
	// If the new one closes first, this one goes with it.
	next.setOnExternalDismissListener { dismissInstantly() }
}

fun AlertDialog.setOnExternalDismissListener(listener: DialogInterface.OnDismissListener) {
	dialogState.dismissListeners.add(listener)
}

// Back still closes. The system's canceledOnTouchOutside is ignored: dismissal goes through AnimatedDismissCallback.
fun AlertDialog.blockOutsideTapDismiss() {
	dialogState.blockOutsideTap = true
}

// Lets a dialog with pages handle a button (index) or Back/outside (null) itself; true keeps it open.
internal fun AlertDialog.setStayOpenHook(hook: (button: Int?) -> Boolean) {
	dialogState.stayOpenHook = hook
}

// Dismiss listener: cancels the dim animation, clears the state, then calls the registered listeners.
internal fun AlertDialog.setOnDismissListenerDispatch() {
	setOnDismissListener { dialog ->
		val state = dialogState
		state.dim?.cancel()
		window?.decorView?.setTag(R.id.tag_dialog_state, null)
		state.dismissListeners.forEach { runCatching { it.onDismiss(dialog) } }
	}
}

// The mode the dialog was shown in; it leaves the same way.
internal fun AlertDialog.shownAnimMode(): Int = dialogState.animMode ?: context.animMode()
