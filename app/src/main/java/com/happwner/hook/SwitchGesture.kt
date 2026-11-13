package com.happwner.hook

import android.view.MotionEvent

// The gesture that swaps between Happwner and the hooked app: a third finger touching down.
object SwitchGesture {
	fun isTriggered(event: MotionEvent): Boolean =
		event.pointerCount == 3 && event.actionMasked == MotionEvent.ACTION_POINTER_DOWN
}
