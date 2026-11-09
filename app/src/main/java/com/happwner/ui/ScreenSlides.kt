package com.happwner.ui

import android.R as AndroidR
import android.app.Activity
import android.os.Build
import android.view.View
import androidx.annotation.RequiresApi

private const val ACTIVITY_ENTER_MS = 260L
private const val SETTINGS_OPEN_MS = 180L
private const val SETTINGS_CLOSE_MS = 160L
private const val LOWRAM_ACTIVITY_MS = 100L
private const val LOWRAM_SETTINGS_MS = 140L

// Share of its width each screen slides. The strip the main one vacates on the right is covered by the
// backdrop in activity_main.xml, which repeats the status bar and toolbar colours behind the sliding view.
private const val MAIN_SLIDE_FRACTION = 0.10f
private const val SETTINGS_SLIDE_FRACTION = 0.33f
private const val SETTINGS_FADE_START = 0.0f

// Skipped in off/system modes.
fun Activity.animateEntry() {
	val content = findViewById<View>(AndroidR.id.content) ?: return
	val mode = animMode()
	if (mode == ANIM_MODE_OFF) {
		runCatching { disableActivityTransition() }
		content.alpha = 1f
		return
	}
	if (mode == ANIM_MODE_SYSTEM) {
		content.alpha = 1f
		return
	}
	val low = isLowRam()
	content.alpha = 0f
	content.post {
		val anim = content.animate()
			.alpha(1f)
			.setDuration(if (low) LOWRAM_ACTIVITY_MS else ACTIVITY_ENTER_MS)
			.setInterpolator(materialDecelerate)
		if (!low) anim.withLayer()
		anim.start()
	}
}

// Silences the system's own transition.
@Suppress("DEPRECATION")
fun Activity.disableActivityTransition() {
	if (Build.VERSION.SDK_INT >= 34) {
		runCatching { Api34Transition.disable(this) }
	} else {
		runCatching { overridePendingTransition(0, 0) }
	}
}

// API 34 replaced overridePendingTransition.
private object Api34Transition {
	@RequiresApi(34)
	fun disable(activity: Activity) {
		activity.overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
		activity.overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
	}

	@RequiresApi(34)
	fun close(activity: Activity, muted: Boolean) {
		if (muted) activity.overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
		else activity.clearOverrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE)
	}
}

// Closes with the animation mode as it is now, not as at opening: muted with animations off
// (said right after finishing on older Android), else the system's.
@Suppress("DEPRECATION")
fun Activity.finishForMode(superFinish: () -> Unit) {
	val off = animMode() == ANIM_MODE_OFF
	if (Build.VERSION.SDK_INT >= 34) {
		runCatching { Api34Transition.close(this, muted = off) }
	}
	superFinish()
	if (off && Build.VERSION.SDK_INT < 34) {
		runCatching { overridePendingTransition(0, 0) }
	}
}

fun slideSettingsIn(host: View, container: View) {
	val ctx = host.context
	val low = ctx.isLowRam()
	val mode = ctx.animMode()
	val width = host.resources.displayMetrics.widthPixels
	val duration = if (low) LOWRAM_SETTINGS_MS else SETTINGS_OPEN_MS

	host.animate().cancel()
	container.animate().cancel()

	if (mode == ANIM_MODE_OFF || low) {
		showSettingsAt(host, container, -width.toFloat() * MAIN_SLIDE_FRACTION)
		return
	}

	val mainTarget = -width.toFloat() * MAIN_SLIDE_FRACTION
	container.translationX = width.toFloat() * SETTINGS_SLIDE_FRACTION
	container.alpha = SETTINGS_FADE_START
	container.visibility = View.VISIBLE
	container.bringToFront()

	val mainAnim = host.animate()
		.translationX(mainTarget)
		.setDuration(duration)
		.setInterpolator(materialSmooth)
		.withLayer()
	mainAnim.start()

	val containerAnim = container.animate()
		.translationX(0f)
		.alpha(1f)
		.setDuration(duration)
		.setInterpolator(materialSmooth)
		.withLayer()
	containerAnim.start()
}

fun slideSettingsOut(host: View, container: View, onEnd: () -> Unit) {
	val ctx = host.context
	val low = ctx.isLowRam()
	val mode = ctx.animMode()
	val width = host.resources.displayMetrics.widthPixels
	val duration = if (low) LOWRAM_SETTINGS_MS else SETTINGS_CLOSE_MS

	host.animate().cancel()
	container.animate().cancel()

	if (mode == ANIM_MODE_OFF || low) {
		host.translationX = 0f
		container.translationX = width.toFloat() * SETTINGS_SLIDE_FRACTION
		container.alpha = SETTINGS_FADE_START
		container.visibility = View.GONE
		runCatching { onEnd() }
		return
	}

	val mainAnim = host.animate()
		.translationX(0f)
		.setDuration(duration)
		.setInterpolator(materialSmooth)
		.withLayer()
	mainAnim.start()

	var ended = false
	val finish: () -> Unit = {
		if (!ended) {
			ended = true
			container.visibility = View.GONE
			container.translationX = width.toFloat() * SETTINGS_SLIDE_FRACTION
			container.alpha = SETTINGS_FADE_START
			host.translationX = 0f
			runCatching { onEnd() }
		}
	}

	val containerAnim = container.animate()
		.translationX(width.toFloat() * SETTINGS_SLIDE_FRACTION)
		.alpha(0f)
		.setDuration(duration)
		.setInterpolator(materialSmooth)
		.withLayer()
		.withEndAction(finish)
	containerAnim.start()
}

fun applySettingsOpenStateInstantly(host: View, container: View) {
	val width = host.resources.displayMetrics.widthPixels
	val hostX =
		if (host.context.animMode() == ANIM_MODE_SYSTEM) 0f else -width.toFloat() * MAIN_SLIDE_FRACTION
	showSettingsAt(host, container, hostX)
}

// The settings pane shown at once over the main screen, which sits at hostX.
private fun showSettingsAt(host: View, container: View, hostX: Float) {
	host.translationX = hostX
	container.translationX = 0f
	container.alpha = 1f
	container.visibility = View.VISIBLE
	container.bringToFront()
}
