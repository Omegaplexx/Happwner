package com.happwner.ui

import android.R as AndroidR
import android.graphics.Outline
import android.graphics.Rect
import android.graphics.drawable.Drawable
import android.transition.ChangeBounds
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.ViewTreeObserver
import android.widget.FrameLayout
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.graphics.drawable.DrawableWrapperCompat
import com.happwner.R

// Where the card lies as laid out, before any animation: bars may pad the window unevenly.
private fun layoutOffset(card: View, decor: View, into: IntArray) {
	var left = card.left
	var top = card.top
	var parent = card.parent as? View
	while (parent != null && parent !== decor) {
		left += parent.left
		top += parent.top
		parent = parent.parent as? View
	}
	into[0] = left
	into[1] = top
}

// The dialog's background, drawn about the card's centre at any size; its outline keeps the shadow.
internal class CardBox(private val decor: View, private val card: View, private val shape: Drawable) {
	private val padding = Rect().also { shape.getPadding(it) }
	private val at = IntArray(2)
	private val inner = Rect()
	var width = card.width
	var height = card.height
	// While an animation sets the box's size, the card's own layout only places it.
	var driven = false

	// The window gives the frame the whole screen; place() sets the band the shape draws in, the shape owns the outline.
	val frame: Drawable = object : DrawableWrapperCompat(shape) {
		override fun onBoundsChange(bounds: Rect) = Unit

		override fun getOutline(outline: Outline) = shape.getOutline(outline)
	}

	fun band(): Rect {
		layoutOffset(card, decor, at)
		val left = at[0] + card.width / 2 - width / 2
		val top = at[1] + card.height / 2 - height / 2
		inner.set(left, top, left + width, top + height)
		return inner
	}

	// Called when the size or the card's place changes, never from drawing: a drawable that moved itself
	// as it drew would make the view rebuild its outline endlessly.
	fun place() {
		val band = band()
		shape.setBounds(
			band.left - padding.left, band.top - padding.top,
			band.right + padding.right, band.bottom + padding.bottom
		)
		frame.invalidateSelf()
	}

	// Takes the card's current size, whatever animates it.
	fun track() {
		width = card.width
		height = card.height
		place()
	}

	fun rest() {
		driven = false
		track()
	}
}

// What the window shows inside the frame its background draws.
internal fun AlertDialog.card(): View? =
	window?.decorView?.findViewById<ViewGroup>(AndroidR.id.content)?.getChildAt(0)

// Made on first need; from then on the window draws the dialog's background around the card through it.
internal fun AlertDialog.box(): CardBox? {
	dialogState.box?.let { return it }
	val window = window ?: return null
	val decor = window.decorView
	val background = decor.background ?: return null
	val card = card() ?: return null
	val box = CardBox(decor, card, background)
	dialogState.box = box
	window.setBackgroundDrawable(box.frame)
	box.place()
	card.addOnLayoutChangeListener { changed, _, _, _, _, _, _, _, _ ->
		if (!box.driven) {
			box.width = changed.width
			box.height = changed.height
		}
		box.place()
	}
	return box
}

// The window keeps the screen's height and the frame is drawn around the centred card:
// resizing the window per change costs frames at both ends.
internal fun AlertDialog.holdTall(): CardBox? {
	val window = window ?: return null
	(card()?.layoutParams as? FrameLayout.LayoutParams)?.gravity = Gravity.CENTER_VERTICAL
	val box = box() ?: return null
	window.setLayout(window.attributes.width, ViewGroup.LayoutParams.MATCH_PARENT)
	return box
}

// Hosts height glides (see glideHeights): the card goes to its new size, the frame with it.
fun AlertDialog.hostHeightGlides() {
	val decor = window?.decorView ?: return
	holdTall() ?: return
	decor.setTag(R.id.tag_height_glide, DialogHeightGlide(this))
}

private class DialogHeightGlide(private val dialog: AlertDialog) : HeightGlide {
	private var running = 0
	// From a glide's start to the next draw, further changes belong to it.
	private var pending = false
	private val follower = ViewTreeObserver.OnPreDrawListener {
		dialog.box()?.track()
		true
	}

	override fun run(duration: Long, change: () -> Unit) {
		val decor = dialog.window?.decorView
		val content = decor?.findViewById<ViewGroup>(AndroidR.id.content)
		val box = dialog.box()
		if (decor == null || content == null || box == null || !decor.isLaidOut || pending ||
			dialog.isLeaving() || dialog.isInTransit()
		) {
			return change()
		}
		val transition = ChangeBounds().apply {
			this.duration = duration
			interpolator = materialStandard
		}
		if (!content.beginThen(transition) { settle(decor, box) }) return change()
		running++
		pending = true
		box.driven = true
		// After the transition's own listener, so the card is where this frame draws it.
		decor.viewTreeObserver.removeOnPreDrawListener(follower)
		decor.viewTreeObserver.addOnPreDrawListener(follower)
		decor.onNextPreDraw { pending = false }
		change()
	}

	private fun settle(decor: View, box: CardBox) {
		if (--running > 0) return
		decor.viewTreeObserver.removeOnPreDrawListener(follower)
		if (!dialog.isLeaving()) box.rest()
	}
}

// Dialogs being put back: a second rotation before the new one is made doesn't put one back twice,
// and none of them takes input meanwhile.
