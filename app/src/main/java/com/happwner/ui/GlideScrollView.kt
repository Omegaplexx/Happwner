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

	private fun hold(glide: Glide, content: View) {
		val margins = (content.layoutParams as? ViewGroup.MarginLayoutParams)
			?.let { it.topMargin + it.bottomMargin } ?: 0
		val viewport = measuredHeight - paddingTop - paddingBottom
		val end = max(0, content.measuredHeight + margins - viewport)
		if (scrollY <= end) return
		glide.to = end
		glide.held = content.height
		holding = glide
	}

	// Scrolled by anything else on the way (a person), the scroll is theirs and the glide lets go.
	private fun start(glide: Glide) {
		val to = glide.to ?: return
		running?.cancel()
		var placed = scrollY
		running = ValueAnimator.ofInt(placed, to).apply {
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
