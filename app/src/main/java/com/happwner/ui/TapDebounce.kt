package com.happwner.ui

import android.os.SystemClock

// Lets a tap through and ignores the rest within the window after it, so a double tap does the
// work once. The clock is a parameter only so the tests can drive it.
class TapDebounce(private val now: () -> Long = SystemClock::elapsedRealtime) {
	private var lastAcceptedMs: Long? = null

	fun accept(): Boolean {
		val nowMs = now()
		val last = lastAcceptedMs
		if (last != null && nowMs - last < WINDOW_MS) return false
		lastAcceptedMs = nowMs
		return true
	}

	companion object {
		// Ignore a second tap within this window, or the work gets queued twice.
		const val WINDOW_MS = 500L
	}
}
