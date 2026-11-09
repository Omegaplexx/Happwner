package com.happwner.ui

import android.view.View
import android.view.ViewGroup
import com.happwner.R

// Begins the glide, then lets the change be made; two requests in one frame make one glide.
internal fun interface HeightGlide {
	fun run(duration: Long, change: () -> Unit)
}

// The one way to change what is on screen in height: the change is made at once and the nearest host above
// glides what it moves into place. With no host above, it just happens.
fun View.glideHeights(
	duration: Long = context.stateChangeDuration(R.integer.duration_standard_transition),
	change: () -> Unit
) {
	val host = generateSequence(this) { it.parent as? View }
		.firstNotNullOfOrNull { it.getTag(R.id.tag_height_glide) as? HeightGlide }
	if (host == null) change() else host.run(duration, change)
}

// Makes this view the host: its content glides to the bounds a change gives it.
fun ViewGroup.hostHeightGlides() {
	setTag(R.id.tag_height_glide, HeightGlide { duration, change ->
		beginChangeBounds(duration)
		change()
	})
}
