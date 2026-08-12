package com.happwner.ui

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.view.View
import android.view.animation.DecelerateInterpolator
import androidx.core.content.ContextCompat
import com.google.android.material.color.MaterialColors
import com.happwner.R

private const val THUMB_FADE_IN_MS = 160L
private const val THUMB_FADE_OUT_MS = 220L
private const val THUMB_ALPHA_IDLE = 128      // ~50% opacity at rest
private const val THUMB_ALPHA_DRAGGING = 191  // ~75% opacity while dragging
private const val SLIDE_EPS = 1f

// Overlay sibling that paints the fast-scroll pill where NoAutoScrollView tells it to (shared bounds -> 1:1 coords).
// The fade runs through the paint alpha, leaving the view's own alpha at 1 so scroll redraws stay reliable.
class FastScrollThumb @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val rect = RectF()        // currently drawn pill
    private val targetRect = RectF()  // where the pill is heading (used while sliding)
    private var hasThumb = false
    private var dragging = false
    private var activeTarget = false
    private var fadeFraction = 0f
    private var fadeAnimator: ValueAnimator? = null
    private var slideAnimator: ValueAnimator? = null

    // Slide tempo matches the result's expand cross-fade so the two move together
    private val slideDurationMs = resources.getInteger(R.integer.duration_standard_transition).toLong()

    // Safe default until the first activation re-reads the themed accent
    private var accentColor = ContextCompat.getColor(context, R.color.brand_purple_secondary)

    private fun resolveAccent() {
        accentColor = MaterialColors.getColor(
            this, R.attr.happAccent,
            ContextCompat.getColor(context, R.color.brand_purple_secondary)
        )
    }

    // Fade the pill in/out via paint alpha; re-reads the accent on show so it tracks theme changes
    fun setActive(active: Boolean) {
        if (active == activeTarget) return
        activeTarget = active
        if (active) resolveAccent()
        slideAnimator?.cancel()
        fadeAnimator?.cancel()
        val target = if (active) 1f else 0f
        if (context.skipProgrammaticAnimations()) {
            fadeFraction = target
            invalidate()
            return
        }
        fadeAnimator = ValueAnimator.ofFloat(fadeFraction, target).apply {
            duration = if (active) THUMB_FADE_IN_MS else THUMB_FADE_OUT_MS
            interpolator = DecelerateInterpolator()
            addUpdateListener {
                fadeFraction = it.animatedValue as Float
                invalidate()
            }
            start()
        }
    }

    // New pill rectangle (shared viewport coords). Scroll updates snap instantly; a length change
    // (only happens on a content-size change like "show full") glides to the new spot instead of jumping.
    fun setThumbRect(left: Float, top: Float, right: Float, bottom: Float) {
        val sliding = slideAnimator?.isRunning == true
        val sameTarget = hasThumb &&
            Math.abs(left - targetRect.left) < SLIDE_EPS && Math.abs(top - targetRect.top) < SLIDE_EPS &&
            Math.abs(right - targetRect.right) < SLIDE_EPS && Math.abs(bottom - targetRect.bottom) < SLIDE_EPS
        if (sliding && sameTarget) return  // destination re-confirmed mid-slide; let it finish
        val lengthJump = hasThumb && Math.abs((bottom - top) - targetRect.height()) > SLIDE_EPS
        targetRect.set(left, top, right, bottom)
        hasThumb = true
        if (lengthJump && fadeFraction >= 0.999f && !context.skipProgrammaticAnimations()) {
            startSlide()
        } else {
            slideAnimator?.cancel()
            rect.set(targetRect)
            invalidate()
        }
    }

    private fun startSlide() {
        slideAnimator?.cancel()
        val fromL = rect.left
        val fromT = rect.top
        val fromR = rect.right
        val fromB = rect.bottom
        slideAnimator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = slideDurationMs
            interpolator = DecelerateInterpolator()
            addUpdateListener {
                val f = it.animatedValue as Float
                rect.set(
                    fromL + (targetRect.left - fromL) * f,
                    fromT + (targetRect.top - fromT) * f,
                    fromR + (targetRect.right - fromR) * f,
                    fromB + (targetRect.bottom - fromB) * f
                )
                invalidate()
            }
            start()
        }
    }

    fun setDragging(value: Boolean) {
        if (value == dragging) return
        dragging = value
        invalidate()
    }

    override fun onDetachedFromWindow() {
        fadeAnimator?.cancel()
        fadeAnimator = null
        slideAnimator?.cancel()
        slideAnimator = null
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        if (fadeFraction <= 0f || !hasThumb) return
        val base = if (dragging) THUMB_ALPHA_DRAGGING else THUMB_ALPHA_IDLE
        paint.color = accentColor
        paint.alpha = (base * fadeFraction).toInt().coerceIn(0, 255)
        val r = rect.width() / 2f
        canvas.drawRoundRect(rect, r, r, paint)
    }
}
