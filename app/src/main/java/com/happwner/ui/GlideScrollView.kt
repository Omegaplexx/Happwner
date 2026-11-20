package com.happwner.ui

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.TimeInterpolator
import android.animation.ValueAnimator
import android.content.Context
import android.util.AttributeSet
import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import kotlin.math.max

// A ScrollView that glides back, not jumps, when a change leaves it past the new end (an area above collapses
// with the view at the bottom). Runs on the clock and curve of the transition that shows the change.
open class GlideScrollView @JvmOverloads constructor(
	context: Context,
	attrs: AttributeSet? = null,
	defStyleAttr: Int = android.R.attr.scrollViewStyle
) : ScrollView(context, attrs, defStyleAttr) {

	// The scroll's new end once the change is measured (null: it stays), and the height the content keeps meanwhile.
	private class Glide(val duration: Long, val interpolator: TimeInterpolator?) {
		var to: Int? = null
		var held = 0
	}

	// Begun, change not yet measured; and measured past the end, content holding its height.
	private var waiting: Glide? = null
	private var holding: Glide? = null
	private var running: ValueAnimator? = null

	// Called as a transition begins over this view's content; the change is made after it, laid out before its first frame.
	internal fun glideWith(duration: Long, interpolator: TimeInterpolator?) {
		if (waiting != null || !isLaidOut || getChildAt(0) == null) return
		val glide = Glide(duration, interpolator)
		waiting = glide
		// The transition begins on the next draw, before this runs.
		onNextPreDraw {
			if (waiting === glide) waiting = null
			if (glide.to != null) start(glide)
		}
	}

	override fun onMeasure(widthSpec: Int, heightSpec: Int) {
		super.onMeasure(widthSpec, heightSpec)
		val content = getChildAt(0) ?: return
		waiting?.takeIf { it.to == null }?.let { hold(it, content) }
		val held = holding?.held ?: return
		if (content.measuredHeight < held) {
			content.measure(
				View.MeasureSpec.makeMeasureSpec(content.measuredWidth, View.MeasureSpec.EXACTLY),
				View.MeasureSpec.makeMeasureSpec(held, View.MeasureSpec.EXACTLY)
			)
		}
	}

	// The content keeps the height the scroll stands on: its own, or what a viewport that grew leaves it past.
	private fun hold(glide: Glide, content: View) {
		val margins = (content.layoutParams as? ViewGroup.MarginLayoutParams)
			?.let { it.topMargin + it.bottomMargin } ?: 0
		val viewport = measuredHeight - paddingTop - paddingBottom
		val end = max(0, content.measuredHeight + margins - viewport)
		if (scrollY <= end) return
		glide.to = end
		glide.held = max(content.height, scrollY + viewport)
		holding = glide
	}

	// A change made at once (the keyboard's room) glides beside it, on the clock and curve of an area's toggle of this size.
	internal fun glideBeside(deltaPx: Int) {
		val mode = context.animMode()
		if (mode != ANIM_MODE_OFF) glideWith(pace(mode, deltaPx), curveFor(mode, materialStandard))
	}

	// Scrolls to y as a change that asks for it would: on the glide begun beside it, or else on one of its own.
	internal fun glideTo(y: Int) {
		waiting?.let {
			it.to = y
			return
		}
		val mode = context.animMode()
		if (mode == ANIM_MODE_OFF || !isLaidOut) return scrollTo(scrollX, y)
		start(Glide(pace(mode, y - scrollY), curveFor(mode, materialStandard)).also { it.to = y })
	}

	private fun pace(mode: Int, deltaPx: Int) =
		context.durationFor(mode, adaptiveAnimDuration(deltaPx, resources.displayMetrics.density))

	// A glide goes back toward the end the content will have, which may not be laid out yet (a transition keeps the
	// layout back). Meanwhile neither the glide nor a layout may cut the scroll to the content's height as it stands.
	override fun scrollTo(x: Int, y: Int) {
		if (y > scrollY || (waiting == null && holding == null && running == null)) return super.scrollTo(x, y)
		onOverScrolled(x, max(0, y), false, false)
	}

	// Scrolled by anything else on the way (a person), the scroll is theirs and the glide lets go.
	private fun start(glide: Glide) {
		val to = glide.to ?: return
		running?.cancel()
		var placed = scrollY
		// Set before it starts: its first step is already a scroll that must not be cut.
		val animator = ValueAnimator.ofInt(placed, to).also { running = it }
		animator.apply {
			duration = glide.duration
			glide.interpolator?.let { interpolator = it }
			addUpdateListener {
				if (scrollY != placed) return@addUpdateListener
				placed = it.animatedValue as Int
				scrollTo(scrollX, placed)
			}
			addListener(object : AnimatorListenerAdapter() {
				override fun onAnimationEnd(animation: Animator) {
					if (running === animation) running = null
					if (holding === glide) {
						holding = null
						requestLayout()
					}
				}
			})
			start()
		}
	}

	override fun onDetachedFromWindow() {
		running?.cancel()
		waiting = null
		holding = null
		super.onDetachedFromWindow()
	}
}
