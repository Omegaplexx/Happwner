package com.happwner.ui

import android.R as AndroidR
import android.animation.ValueAnimator
import android.app.ActivityManager
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.view.View
import android.view.ViewParent
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.Interpolator
import android.view.animation.PathInterpolator
import android.widget.ScrollView
import com.happwner.data.PrefsManager

// The Material curves every animation in the app runs on.
internal val materialDecelerate: Interpolator = PathInterpolator(0.0f, 0.0f, 0.2f, 1.0f)
val materialStandard: Interpolator = PathInterpolator(0.4f, 0.0f, 0.2f, 1.0f)
// Symmetric ease-in-out for dialogs and settings. Peaks at 1.7x average speed mid-way, where materialStandard
// peaks at 2.7x a third in and reads as a lurch.
internal val materialSmooth: Interpolator = PathInterpolator(0.4f, 0.0f, 0.6f, 1.0f)

// The curve the platform gives an animation that names none: the system mode's own.
internal val platformCurve: Interpolator = AccelerateDecelerateInterpolator()

const val ANIM_MODE_OFF = 0
const val ANIM_MODE_SYSTEM = 1
const val ANIM_MODE_SOFTWARE = 2

@Volatile private var weakDeviceCached: Boolean? = null

fun Context.isNightMode(): Boolean = resources.configuration.isNightMode()

fun Configuration.isNightMode(): Boolean =
	(uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES

fun Context.animMode(): Int {
	val prefs = PrefsManager.getSafePrefs(this)
	return if (prefs.contains(PrefsManager.PREF_ANIM_MODE)) {
		prefs.getInt(PrefsManager.PREF_ANIM_MODE, ANIM_MODE_SOFTWARE)
	} else {
		computeDefaultAnimMode(this)
	}
}

fun Context.skipProgrammaticAnimations(): Boolean = animMode() == ANIM_MODE_OFF

// System mode: the platform's short time; otherwise the app's own.
fun Context.stateChangeDuration(ownDurationRes: Int): Long =
	durationFor(animMode(), resources.getInteger(ownDurationRes).toLong())

// The same rule for an animation shown in a given mode.
fun Context.durationFor(mode: Int, ownMs: Long): Long {
	if (mode != ANIM_MODE_SYSTEM) return ownMs
	return resources.getInteger(AndroidR.integer.config_shortAnimTime).toLong()
}

// System mode: the platform's default curve; otherwise the app's own.
fun curveFor(mode: Int, own: Interpolator): Interpolator =
	if (mode == ANIM_MODE_SYSTEM) platformCurve else own

// At once with animations off: a scroller's glide ignores the animator scale that mutes the rest.
fun ScrollView.smoothScrollToIfEnabled(y: Int) {
	if (context.skipProgrammaticAnimations()) scrollTo(0, y) else smoothScrollTo(0, y)
}

// Off on a low-RAM device, the system's own on a weak one, otherwise the app's.
private fun computeDefaultAnimMode(context: Context): Int = when {
	context.isLowRam() -> ANIM_MODE_OFF
	context.isWeakDevice() -> ANIM_MODE_SYSTEM
	else -> ANIM_MODE_SOFTWARE
}

fun View.fadeIn(duration: Long) {
	alpha = 0f
	visibility = View.VISIBLE
	animate().alpha(1f).setDuration(duration).withLayer().start()
}

fun View.isDescendantOfView(ancestor: View): Boolean {
	var viewParent: ViewParent? = this.parent
	while (viewParent != null) {
		if (viewParent === ancestor) return true
		viewParent = viewParent.parent
	}
	return false
}

internal fun Context.isLowRam(): Boolean =
	(getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager)?.isLowRamDevice == true

// Four cores or fewer with 3 GB or less, or older than Android 7. Worked out once.
private fun Context.isWeakDevice(): Boolean = weakDeviceCached ?: run {
	val memoryInfo = ActivityManager.MemoryInfo()
	runCatching {
		(getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager)?.getMemoryInfo(memoryInfo)
	}
	val totalMemGb = memoryInfo.totalMem.toDouble() / (1024.0 * 1024.0 * 1024.0)
	val weakSoc = Runtime.getRuntime().availableProcessors() <= 4 && totalMemGb > 0.0 && totalMemGb <= 3.0
	weakSoc || Build.VERSION.SDK_INT < Build.VERSION_CODES.N
}.also { weakDeviceCached = it }

// Mutes or restores the global animator duration scale via reflection.
fun resetAnimatorScale(context: Context) {
	val mode = context.animMode()
	val scale = if (mode == ANIM_MODE_OFF) 0.0f else 1.0f
	runCatching {
		val method = ValueAnimator::class.java
			.getDeclaredMethod("setDurationScale", Float::class.javaPrimitiveType)
		method.isAccessible = true
		method.invoke(null, scale)
	}
}
