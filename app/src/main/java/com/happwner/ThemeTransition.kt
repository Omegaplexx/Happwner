package com.happwner

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.app.Activity
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import java.util.concurrent.atomic.AtomicLong

object ThemeTransition {
    private const val CLEANUP_TIMEOUT_MS = 10_000L

    @Volatile var pendingOverlay: Bitmap? = null
        private set
    @Volatile var pendingDuration: Long = 220L
        private set
    @Volatile private var savedOriginalBackground: Drawable? = null

    private val stateLock = Any()
    private val cleanupHandler by lazy { Handler(Looper.getMainLooper()) }
    // Generation counter: cancels stale pending snapshot cleanups
    private val cleanupGeneration = AtomicLong(0)

    // Snapshot the current screen, then recreate(); the snapshot survives the recreate
    fun captureAndRecreate(activity: Activity, durationMs: Long = 220L) {
        var newBitmap: Bitmap? = null
        val decor = activity.window?.decorView
        if (decor != null && decor.width > 0 && decor.height > 0) {
            try {
                val b = Bitmap.createBitmap(decor.width, decor.height, Bitmap.Config.ARGB_8888)
                val canvas = Canvas(b)
                decor.draw(canvas)
                newBitmap = b
            } catch (_: Throwable) {
                try { newBitmap?.recycle() } catch (_: Throwable) {}
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
            try { previous.recycle() } catch (_: Throwable) {}
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
                    try { toRecycle.recycle() } catch (_: Throwable) {}
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
            val bgDrawable = BitmapDrawable(activity.resources, bitmap)
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
            try { bitmap.recycle() } catch (_: Throwable) {}
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
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    elevation = 100000f
                }
                isClickable = true
                isFocusable = false
                alpha = 1f
            }
            decor.addView(overlay)
            overlay.bringToFront()

            // Fade it out, then remove the overlay and restore the original background
            overlay.animate()
                .alpha(0f)
                .setDuration(duration)
                .setStartDelay(16L)
                .setInterpolator(android.view.animation.LinearInterpolator())
                .setListener(object : AnimatorListenerAdapter() {
                    private var done = false
                    private fun cleanup() {
                        if (done) return
                        done = true
                        try { decor.removeView(overlay) } catch (_: Throwable) {}
                        try { window.setBackgroundDrawable(originalBackground) } catch (_: Throwable) {}
                        try { bitmap.recycle() } catch (_: Throwable) {}
                    }
                    override fun onAnimationEnd(animation: Animator) { cleanup() }
                    override fun onAnimationCancel(animation: Animator) { cleanup() }
                })
                .start()
        } catch (_: Throwable) {
            try { window.setBackgroundDrawable(originalBackground) } catch (_: Throwable) {}
            try { bitmap.recycle() } catch (_: Throwable) {}
        }
    }
}
