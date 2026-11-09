package com.happwner.ui

import android.transition.ChangeBounds
import android.transition.Fade
import android.transition.Transition
import android.transition.TransitionManager
import android.transition.TransitionSet
import android.view.View
import android.view.ViewGroup
import android.view.ViewTreeObserver
import android.view.animation.Interpolator
import androidx.core.view.allViews
import androidx.core.view.isVisible
import kotlin.math.abs

private const val RESIZE_MS = 160L

// Skipped when animations are off; in system mode runs at the system's pace and curve. Returns the one begun.
fun ViewGroup.beginDelayedTransitionIfEnabled(transition: Transition): Transition? {
	val mode = context.animMode()
	if (mode == ANIM_MODE_OFF) return null
	// Paced on a copy: the caller may keep its transition, and the next mode must find it as built.
	val paced = if (mode != ANIM_MODE_SYSTEM) transition else transition.clone().apply {
		duration = context.durationFor(mode, duration)
		interpolator = platformCurve
	}
	TransitionManager.beginDelayedTransition(this, paced)
	// A scroll view this root holds, or is held by, glides beside it where the change would jump it.
	if (isLaidOut) {
		val duration = paced.duration.takeIf { it >= 0 } ?: GLIDE_DEFAULT_MS
		glideScrolls().forEach { it.glideWith(duration, paced.interpolator) }
	}
	return paced
}

private const val GLIDE_DEFAULT_MS = 300L

// The scroll view this view is in, or else the ones it holds.
private fun View.glideScrolls(): List<GlideScrollView> =
	generateSequence(this) { it.parent as? View }.filterIsInstance<GlideScrollView>().take(1).toList()
		.ifEmpty { allViews.filterIsInstance<GlideScrollView>().toList() }

fun buildBoundsFadeTransition(
	durationMs: Long,
	smooth: Boolean = false,
	excludeFadeTargetId: Int = View.NO_ID
): Transition {
	return TransitionSet().apply {
		addTransition(ChangeBounds())
		addTransition(Fade().apply {
			if (excludeFadeTargetId != View.NO_ID) excludeTarget(excludeFadeTargetId, true)
		})
		ordering = TransitionSet.ORDERING_TOGETHER
		duration = durationMs
		if (smooth) interpolator = materialStandard
	}
}

fun adaptiveAnimDuration(deltaPx: Int, density: Float): Long {
	val deltaDp = abs(deltaPx) / density
	return when {
		deltaDp <= 50f -> 180L
		deltaDp <= 150f -> 220L
		deltaDp <= 400f -> 270L
		deltaDp <= 800f -> 320L
		else -> 360L
	}
}

private fun View.estimateExpandedHeight(): Int {
	if (isVisible) return height
	val parentGroup = parent as? ViewGroup ?: return height
	val params = layoutParams ?: return height
	return try {
		val widthSpec = View.MeasureSpec.makeMeasureSpec(parentGroup.width, View.MeasureSpec.AT_MOST)
		val heightSpec = View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
		val saved = params.height
		params.height = ViewGroup.LayoutParams.WRAP_CONTENT
		measure(widthSpec, heightSpec)
		val measured = measuredHeight
		params.height = saved
		layoutParams = params
		measured
	} catch (_: Throwable) { height }
}

fun ViewGroup.beginChangeBounds(duration: Long, interpolator: Interpolator = materialStandard) {
	beginDelayedTransitionIfEnabled(ChangeBounds().apply {
		this.duration = duration
		this.interpolator = interpolator
	})
}

// Runs block once on the next draw. The listener comes off the observer it went on: a detached view hands out another,
// and the window's would keep calling it, holding this view, for good.
internal fun View.onNextPreDraw(block: () -> Unit) {
	val observer = viewTreeObserver
	observer.addOnPreDrawListener(object : ViewTreeObserver.OnPreDrawListener {
		override fun onPreDraw(): Boolean {
			(if (observer.isAlive) observer else viewTreeObserver).removeOnPreDrawListener(this)
			block()
			return true
		}
	})
}

// Listens for a transition's end and removes itself; also tells whether it ever began,
// as the manager begins none on a root with one pending.
private class OnTransitionEnd(private val then: () -> Unit) : Transition.TransitionListener {
	var begun = false

	override fun onTransitionStart(transition: Transition) {
		begun = true
	}

	override fun onTransitionEnd(transition: Transition) {
		transition.removeListener(this)
		then()
	}

	override fun onTransitionCancel(transition: Transition) = Unit

	override fun onTransitionPause(transition: Transition) = Unit

	override fun onTransitionResume(transition: Transition) = Unit
}

// Runs onEnd when the transition ends, or after the next draw if the manager never began it
// (one is pending on the root). False where animations are off.
internal fun ViewGroup.beginThen(transition: Transition, onEnd: () -> Unit): Boolean {
	// The listener goes on before beginning: what is begun is a copy that shares only the listeners present by then.
	val ended = OnTransitionEnd(onEnd)
	transition.addListener(ended)
	if (beginDelayedTransitionIfEnabled(transition) == null) return false
	onNextPreDraw { if (!ended.begun) ended.onTransitionEnd(transition) }
	return true
}

// The screen's glide under way and what waits for it: a dialog put back is made anew only then.
// It ends once, by its transition or by its root going first.
private class ScreenGlide {
	val then = mutableListOf<() -> Unit>()

	fun end() {
		if (screenGlide === this) screenGlide = null
		val waited = then.toList()
		then.clear()
		waited.forEach { it() }
	}
}

private var screenGlide: ScreenGlide? = null

// Rotation or resize: the content glides into the new bounds, on the main screen as in settings.
// A root not laid out yet gets no glide.
fun ViewGroup.beginResizeTransition(configure: ChangeBounds.() -> Unit = {}) {
	if (context.skipProgrammaticAnimations() || !isLaidOut) return
	resetAnimatorScale(context)
	val glide = ScreenGlide()
	val rootGone = object : View.OnAttachStateChangeListener {
		override fun onViewAttachedToWindow(v: View) = Unit

		override fun onViewDetachedFromWindow(v: View) {
			removeOnAttachStateChangeListener(this)
			glide.end()
		}
	}
	val transition = ChangeBounds().apply {
		duration = RESIZE_MS
		interpolator = materialDecelerate
		configure()
	}
	val begun = beginThen(transition) {
		removeOnAttachStateChangeListener(rootGone)
		glide.end()
	}
	if (!begun) return
	screenGlide = glide
	addOnAttachStateChangeListener(rootGone)
}

// Runs block a frame after the screen's glide ends, so the ending frame is drawn first; with none, on the next frame.
internal fun View.afterScreenGlide(block: () -> Unit) {
	val glide = screenGlide
	if (glide == null) {
		postOnAnimation { block() }
		return
	}
	// Ended under a second glide - a second rotation - it waits for that one instead.
	glide.then += { afterScreenGlide(block) }
}

fun ViewGroup.beginAdaptiveToggleTransition(toggledView: View, excludeFadeTargetId: Int) {
	val duration = adaptiveAnimDuration(toggledView.estimateExpandedHeight(),
		resources.displayMetrics.density)
	beginDelayedTransitionIfEnabled(buildBoundsFadeTransition(duration, smooth = true,
		excludeFadeTargetId = excludeFadeTargetId))
}
