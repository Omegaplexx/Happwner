package com.happwner.ui

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ValueAnimator
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.view.View
import android.view.ViewGroup
import android.view.ViewPropertyAnimator
import android.widget.TextView
import androidx.core.graphics.createBitmap
import androidx.core.graphics.drawable.toDrawable
import androidx.core.view.isGone
import com.happwner.R

// Runs onChange once, a frame after the window takes a new width (turn, resize), not inside that layout pass.
// A window not laid out yet keeps its first width. Returns the call that stops the watch.
private fun View.onWindowWidthChange(
	wanted: () -> Boolean = { true },
	onChange: () -> Unit
): () -> Unit {
	val root = rootView
	var width = root.width
	lateinit var stop: () -> Unit
	val listener = View.OnLayoutChangeListener { _, left, _, right, _, _, _, _, _ ->
		val newWidth = right - left
		when {
			!wanted() -> stop()
			width == 0 -> width = newWidth
			newWidth != 0 && newWidth != width -> {
				stop()
				post { onChange() }
			}
		}
	}
	stop = { root.removeOnLayoutChangeListener(listener) }
	root.addOnLayoutChangeListener(listener)
	return stop
}

// A hardware layer speeds up a fade of a view up to a screen tall; a taller one costs more to build than it saves.
internal fun ViewPropertyAnimator.withLayerIfFits(view: View, height: Int = view.height): ViewPropertyAnimator =
	if (height <= view.resources.displayMetrics.heightPixels) withLayer() else this

fun View.crossfadeContent(onEnd: (() -> Unit)? = null, action: () -> Unit) {
	val mode = context.animMode()
	if (mode == ANIM_MODE_OFF || context.isLowRam()) {
		action()
		alpha = 1f
		onEnd?.invoke()
		return
	}
	val params = layoutParams

	val preHeight = if (isGone) 0 else height

	animate().cancel()
	(getTag(R.id.tag_crossfade_height_anim) as? ValueAnimator)?.let {
		it.removeAllListeners()
		it.cancel()
	}
	setTag(R.id.tag_crossfade_height_anim, null)

	if (params != null && preHeight > 0) {
		params.height = preHeight
		layoutParams = params
	}

	runCatching { action() }

	val targetHeight = if (params != null) {
		val parentForMeasure = parent as? ViewGroup
		if (parentForMeasure != null) {
			try {
				val widthSpec = View.MeasureSpec.makeMeasureSpec(parentForMeasure.width,
					View.MeasureSpec.AT_MOST)
				val heightSpec = View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
				params.height = ViewGroup.LayoutParams.WRAP_CONTENT
				measure(widthSpec, heightSpec)
				val measured = measuredHeight
				params.height = if (preHeight > 0) preHeight else measured
				layoutParams = params
				measured
			} catch (_: Throwable) {
				preHeight
			}
		} else preHeight
	} else preHeight

	val duration = context.durationFor(
		mode, adaptiveAnimDuration(targetHeight - preHeight, resources.displayMetrics.density)
	)
	val curve = curveFor(mode, materialStandard)

	alpha = 0f

	if (params != null && targetHeight != preHeight) {
		params.height = preHeight
		layoutParams = params
		lateinit var stopWatching: () -> Unit
		val anim = ValueAnimator.ofInt(preHeight, targetHeight).apply {
			this.duration = duration
			interpolator = curve
			addUpdateListener {
				params.height = it.animatedValue as Int
				layoutParams = params
			}
			addListener(object : AnimatorListenerAdapter() {
				override fun onAnimationEnd(animation: Animator) {
					params.height = ViewGroup.LayoutParams.WRAP_CONTENT
					layoutParams = params
					setTag(R.id.tag_crossfade_height_anim, null)
					stopWatching()
				}
			})
		}
		setTag(R.id.tag_crossfade_height_anim, anim)
		// Turned mid-way, the target height was measured for the old window, so it settles at once.
		// One a later crossfade replaced is left alone.
		val current = { getTag(R.id.tag_crossfade_height_anim) === anim }
		stopWatching = onWindowWidthChange(current) { if (current()) anim.end() }
		anim.start()
	} else if (params != null) {
		params.height = ViewGroup.LayoutParams.WRAP_CONTENT
		layoutParams = params
	}

	animate()
		.alpha(1f)
		.setDuration(duration)
		.setInterpolator(curve)
		.withLayerIfFits(this, maxOf(preHeight, targetHeight))
		.withEndAction {
			onEnd?.invoke()
		}
		.start()
}

// The snapshot sits in the parent's overlay, so layout is untouched and rapid calls just collapse.
fun View.crossfadeSnapshot(apply: () -> Unit) {
	val view = this

	// So a burst of taps lands on the latest state.
	(view.getTag(R.id.tag_ua_crossfade) as? ValueAnimator)?.cancel()
	val host = view.parent as? ViewGroup
	(view.getTag(R.id.tag_ua_overlay) as? Drawable)?.let { old ->
		host?.overlay?.remove(old)
		view.overlay.remove(old)
	}
	view.setTag(R.id.tag_ua_overlay, null)
	view.alpha = 1f

	if (view.context.skipProgrammaticAnimations() || view.context.isLowRam() || host == null ||
		view.width == 0 || view.height == 0
	) {
		apply()
		return
	}

	val snapshot = try {
		val bmp = createBitmap(view.width, view.height)
		view.draw(Canvas(bmp))
		bmp.toDrawable(view.resources).apply {
			// Parent coordinates: the overlay belongs to the parent now.
			setBounds(view.left, view.top, view.left + view.width, view.top + view.height)
		}
	} catch (_: Throwable) {
		null
	}

	apply()

	if (snapshot == null) return
	host.overlay.add(snapshot)
	view.setTag(R.id.tag_ua_overlay, snapshot)

	view.alpha = 0f

	lateinit var stopWatching: () -> Unit
	val cleanup = {
		view.alpha = 1f
		host.overlay.remove(snapshot)
		view.setTag(R.id.tag_ua_overlay, null)
		view.setTag(R.id.tag_ua_crossfade, null)
		stopWatching()
	}
	val animator = ValueAnimator.ofFloat(0f, 1f).apply {
		duration = view.context.stateChangeDuration(R.integer.duration_standard_transition)
		addUpdateListener {
			val fraction = it.animatedFraction
			snapshot.alpha = ((1f - fraction) * 255f).toInt()
			// 1 - (1-p)^2: rises fast, so the new state carries the frame while the old one leaves.
			view.alpha = 1f - (1f - fraction) * (1f - fraction)
		}
		addListener(object : AnimatorListenerAdapter() {
			override fun onAnimationEnd(animation: Animator) = cleanup()
			override fun onAnimationCancel(animation: Animator) = cleanup()
		})
	}
	view.setTag(R.id.tag_ua_crossfade, animator)
	// A turned or resized window moves the view out from under its snapshot: the fade ends. Only
	// the window's width tells, as the view's own height may change with what it shows.
	stopWatching = view.onWindowWidthChange { animator.cancel() }
	animator.start()
}

// No-op on identical text: some labels refresh twice, and the second call would restart the fade.
// afterApply runs once the new text is in place, not when the fade ends.
fun TextView.crossfadeText(newText: CharSequence, afterApply: (() -> Unit)? = null) {
	if (text?.toString() != newText.toString()) glideHeights { crossfadeSnapshot { text = newText } }
	afterApply?.invoke()
}
