package com.happwner.ui

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.app.Activity
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.os.Handler
import android.os.Looper
import android.view.ViewGroup
import android.view.animation.LinearInterpolator
import android.widget.FrameLayout
import android.widget.ImageView
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.graphics.createBitmap
import androidx.core.graphics.drawable.toDrawable
import java.util.concurrent.atomic.AtomicLong

// How long the old screen fades off the new one after a theme (or Monet) change and after a
// language change: the whole screen cross-fades, so these run longer than a dialog's fades.
const val THEME_CHANGE_MS = 440L
const val LANGUAGE_CHANGE_MS = 360L

object ThemeTransition {
	private const val CLEANUP_TIMEOUT_MS = 10_000L

	// Sets the night mode the stored theme setting asks for: 1 is light, 2 and 3 (AMOLED) are
	// dark, anything else follows the system.
	fun applyNightMode(themeMode: Int) {
		AppCompatDelegate.setDefaultNightMode(when (themeMode) {
			1 -> AppCompatDelegate.MODE_NIGHT_NO
			2, 3 -> AppCompatDelegate.MODE_NIGHT_YES
			else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
		})
	}

	@Volatile var pendingOverlay: Bitmap? = null
		private set
	@Volatile private var pendingDuration = 0L
	@Volatile private var savedOriginalBackground: Drawable? = null

	private val stateLock = Any()
	private val cleanupHandler by lazy { Handler(Looper.getMainLooper()) }
	// Generation counter: cancels stale pending snapshot cleanups
	private val cleanupGeneration = AtomicLong(0)

	// Snapshot the current screen, then recreate(); the snapshot survives the recreate
	fun captureAndRecreate(activity: Activity, durationMs: Long) {
		var newBitmap: Bitmap? = null
		val decor = activity.window?.decorView
		if (decor != null && decor.width > 0 && decor.height > 0) {
			try {
				val bitmap = createBitmap(decor.width, decor.height)
				val canvas = Canvas(bitmap)
				decor.draw(canvas)
				newBitmap = bitmap
			} catch (_: Throwable) {
				newBitmap?.recycle()
				newBitmap = null
			}
		}

		// Swap in the new snapshot and recycle the previous one
		val previous: Bitmap?
		val scheduledGen: Long
		synchronized(stateLock) {
			previous = pendingOverlay
			pendingOverlay = newBitmap
			pendingDuration = durationMs
			scheduledGen = cleanupGeneration.incrementAndGet()
		}

		if (previous != null && previous !== newBitmap) {
			previous.recycle()
		}

		if (newBitmap != null) {
			// Safety net: clear the snapshot if consumeOverlay was never called
			cleanupHandler.postDelayed({
				if (cleanupGeneration.get() != scheduledGen) return@postDelayed
				var orphan: Bitmap? = null
				synchronized(stateLock) {
					if (cleanupGeneration.get() == scheduledGen) {
						orphan = pendingOverlay
						pendingOverlay = null
						savedOriginalBackground = null
					}
				}
				val toRecycle = orphan
				if (toRecycle != null) {
					toRecycle.recycle()
				}
			}, CLEANUP_TIMEOUT_MS)
		}

		try { activity.recreate() } catch (_: Throwable) {}
	}

	// Set the snapshot as the window background before setContentView, to avoid a flash
	fun preApplyBackground(activity: Activity) {
		val bitmap = pendingOverlay ?: return
		val window = activity.window ?: return
		val decor = window.decorView ?: return
		try {
			savedOriginalBackground = decor.background
			val bgDrawable = bitmap.toDrawable(activity.resources)
			bgDrawable.alpha = 255
			window.setBackgroundDrawable(bgDrawable)
		} catch (_: Throwable) {}
	}

	// Overlay the snapshot on top of the new content and fade it out
	fun consumeOverlay(activity: Activity) {
		val bitmap: Bitmap?
		val duration: Long
		val originalBackground: Drawable?
		synchronized(stateLock) {
			cleanupGeneration.incrementAndGet()
			bitmap = pendingOverlay
			pendingOverlay = null
			duration = pendingDuration
			originalBackground = savedOriginalBackground
			savedOriginalBackground = null
		}

		if (bitmap == null) return

		val window = activity.window
		val decor = window?.decorView as? ViewGroup
		if (window == null || decor == null) {
			bitmap.recycle()
			return
		}

		try {
			// Full-screen snapshot laid over the fresh content
			val overlay = ImageView(activity).apply {
				setImageBitmap(bitmap)
				scaleType = ImageView.ScaleType.FIT_XY
				layoutParams = FrameLayout.LayoutParams(
					ViewGroup.LayoutParams.MATCH_PARENT,
					ViewGroup.LayoutParams.MATCH_PARENT
				)
				// Above everything the fresh screen puts up, so the old frame is what is seen
				// until it fades.
				elevation = 100000f
				isClickable = true
				isFocusable = false
				alpha = 1f
			}
			decor.addView(overlay)
			overlay.bringToFront()
			// Turned or resized mid-fade, the old frame no longer fits the window: it goes at once
			// rather than stretched - after the layout pass that found it, not inside it. An empty
			// layout, before it is measured, is not a size to compare with.
			var laidOut: Pair<Int, Int>? = null
			overlay.addOnLayoutChangeListener { view, _, _, _, _, _, _, _, _ ->
				if (view.width == 0 || view.height == 0) return@addOnLayoutChangeListener
				val size = view.width to view.height
				if (laidOut != null && size != laidOut) view.post { view.animate().cancel() }
				laidOut = size
			}

			// Fade it out, then remove the overlay and restore the original background. With
			// animations off it only covers the recreate, gone the next frame.
			val mode = activity.animMode()
			overlay.animate()
				.alpha(0f)
				.setDuration(if (mode == ANIM_MODE_OFF) 0L else activity.durationFor(mode, duration))
				.setStartDelay(16L)
				.setInterpolator(curveFor(mode, LinearInterpolator()))
				.setListener(object : AnimatorListenerAdapter() {
					private var done = false
					private fun cleanup() {
						if (done) return
						done = true
						try { decor.removeView(overlay) } catch (_: Throwable) {}
						try { window.setBackgroundDrawable(originalBackground) } catch (_: Throwable) {}
						bitmap.recycle()
					}
					override fun onAnimationEnd(animation: Animator) { cleanup() }
					override fun onAnimationCancel(animation: Animator) { cleanup() }
				})
				.start()
		} catch (_: Throwable) {
			try { window.setBackgroundDrawable(originalBackground) } catch (_: Throwable) {}
			bitmap.recycle()
		}
	}
}
