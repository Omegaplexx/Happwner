package com.happwner.ui

import android.content.Context
import android.graphics.RectF
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.ViewTreeObserver
import android.widget.TextView
import com.happwner.R

private const val THUMB_IDLE_TIMEOUT_MS = 1000L

// ScrollView that suppresses auto-scroll-to-result on focus-tap, and drives the FastScrollThumb overlay
class NoAutoScrollView @JvmOverloads constructor(
	context: Context,
	attrs: AttributeSet? = null,
	defStyleAttr: Int = 0
) : GlideScrollView(context, attrs, defStyleAttr) {

	// The selectable result view whose focus-driven scroll is suppressed.
	var selectionView: TextView? = null

	override fun requestChildFocus(child: View?, focused: View?) {
		val target = selectionView
		// If the result view is gaining focus without a real selection, register focus but don't scroll to it
		if (target != null && focused === target && !target.hasSelection()) {
			super.requestChildFocus(child, null)
			return
		}
		super.requestChildFocus(child, focused)
	}

	// The fast-scroll thumb: geometry and drag live here, the pixels are painted by the overlay sibling.
	private val thumbWidthPx = resources.getDimension(R.dimen.fastscroll_thumb_width)
	private val thumbMinLenPx = resources.getDimension(R.dimen.fastscroll_thumb_min_length)
	private val thumbMarginEndPx = resources.getDimension(R.dimen.fastscroll_thumb_margin_end)
	private val thumbMarginVertPx = resources.getDimension(R.dimen.fastscroll_thumb_margin_vertical)
	private val touchTargetWidthPx = resources.getDimension(R.dimen.fastscroll_touch_target_width)
	private val touchSlopVertPx = resources.getDimension(R.dimen.fastscroll_touch_slop_vertical)

	private val thumbRect = RectF()

	// Scroll/track metrics filled by computeMetrics() and consumed right after (single-threaded UI)
	private var scrollMax = 0
	private var trackTopPx = 0f
	private var scrollableTrackPx = 0f
	private var thumbLenPx = 0f

	// fastScrollActive = a large result is on screen (master gate); thumbShown = currently faded in
	private var fastScrollActive = false
	private var thumbShown = false
	private var dragging = false
	private var dragGrabOffset = 0f

	private var listenersAttached = false
	private var thumbView: FastScrollThumb? = null

	// Fades the thumb out after a spell of no scrolling; never fires mid-drag
	private val hideThumbRunnable = Runnable {
		if (dragging) return@Runnable
		if (thumbShown) {
			thumbShown = false
			thumb()?.setActive(false)
		}
	}

	// The overlay lives as a sibling in the same parent; resolve it lazily and cache
	private fun thumb(): FastScrollThumb? {
		thumbView?.let { return it }
		thumbView = (parent as? ViewGroup)?.findViewById(R.id.fastScrollThumb)
		return thumbView
	}

	// Push the current pill geometry to the overlay; false when there's nothing to scroll
	private fun pushGeometry(): Boolean {
		if (!fastScrollActive) return false
		val overlay = thumb() ?: return false
		if (!computeThumbRect()) return false
		overlay.setThumbRect(thumbRect.left, thumbRect.top, thumbRect.right, thumbRect.bottom)
		return true
	}

	// Activity (scroll, drag, new result): reposition, make visible, and re-arm the idle fade-out timer
	private fun pokeThumb() {
		if (!pushGeometry()) {
			hideThumb()
			return
		}
		if (!thumbShown) {
			thumbShown = true
			thumb()?.setActive(true)
		}
		removeCallbacks(hideThumbRunnable)
		// While dragging we keep the thumb pinned; the countdown resumes on release (endDragInternal)
		if (!dragging) postDelayed(hideThumbRunnable, THUMB_IDLE_TIMEOUT_MS)
	}

	private fun hideThumb() {
		removeCallbacks(hideThumbRunnable)
		if (thumbShown) {
			thumbShown = false
			thumb()?.setActive(false)
		}
	}

	// Catches content-height changes (expand, collapse, height animations); reposition, or hide
	// when nothing scrolls
	private val layoutListener = ViewTreeObserver.OnGlobalLayoutListener {
		if (fastScrollActive && !pushGeometry()) hideThumb()
	}

	// Activity calls this whenever the displayed result changes
	fun setFastScrollActive(active: Boolean) {
		fastScrollActive = active
		// Two modes: stock system scrollbar below the threshold, our custom thumb above it
		isVerticalScrollBarEnabled = !active
		if (active) {
			pokeThumb()
		} else {
			if (dragging) endDragInternal()
			hideThumb()
		}
	}

	override fun onAttachedToWindow() {
		super.onAttachedToWindow()
		if (!listenersAttached) {
			viewTreeObserver.addOnGlobalLayoutListener(layoutListener)
			listenersAttached = true
		}
	}

	override fun onDetachedFromWindow() {
		if (listenersAttached) {
			val vto = viewTreeObserver
			if (vto.isAlive) {
				try {
					vto.removeOnGlobalLayoutListener(layoutListener)
				} catch (_: Throwable) {}
			}
			listenersAttached = false
		}
		removeCallbacks(hideThumbRunnable)
		dragging = false
		thumbShown = false
		thumbView = null
		super.onDetachedFromWindow()
	}

	// Called as the scroll nears the bottom, to page in more history. Set by the
	// activity; kept as a plain callback so this view has no dependency on it.
	var onNearBottom: (() -> Unit)? = null

	// Framework scroll callback (touch scroll, fling, and our drag's scrollTo); keeps the thumb
	// glued to the real position
	override fun onScrollChanged(left: Int, top: Int, oldl: Int, oldt: Int) {
		super.onScrollChanged(left, top, oldl, oldt)
		if (fastScrollActive) pokeThumb()
		maybeSignalNearBottom()
	}

	// Fire onNearBottom once we're within a viewport of the end.
	private fun maybeSignalNearBottom() {
		val callback = onNearBottom ?: return
		val child = getChildAt(0) ?: return
		val viewport = height - paddingTop - paddingBottom
		val distanceToEnd = child.height - (scrollY + viewport)
		if (distanceToEnd <= viewport) callback()
	}

	// Mirror ScrollView's own scroll model (child height vs the padded viewport) so the thumb's
	// travel matches what a finger can reach; false when there's nothing to scroll
	private fun computeMetrics(): Boolean {
		val child = getChildAt(0) ?: return false
		val contentHeight = child.height
		val viewport = height - paddingTop - paddingBottom
		scrollMax = (contentHeight - viewport).coerceAtLeast(0)
		if (contentHeight <= 0 || viewport <= 0 || scrollMax <= 0) return false

		trackTopPx = paddingTop + thumbMarginVertPx
		val trackBottom = height - paddingBottom - thumbMarginVertPx
		val trackHeight = trackBottom - trackTopPx
		if (trackHeight <= thumbMinLenPx) return false

		thumbLenPx = (trackHeight * viewport.toFloat() / contentHeight.toFloat())
			.coerceIn(thumbMinLenPx, trackHeight)
		scrollableTrackPx = trackHeight - thumbLenPx
		return true
	}

	// Fill thumbRect (viewport coords) for the current scroll position; false if there's no thumb to show
	private fun computeThumbRect(): Boolean {
		if (!computeMetrics()) return false
		val offset = scrollY.coerceIn(0, scrollMax)
		val top = trackTopPx +
			if (scrollableTrackPx <= 0f) 0f else scrollableTrackPx * (offset.toFloat() / scrollMax.toFloat())
		val right = width - paddingRight - thumbMarginEndPx
		val left = right - thumbWidthPx
		thumbRect.set(left, top, right, top + thumbLenPx)
		return true
	}

	// True when (x,y) lands on the thumb's grab strip (a little wider/taller than the visual thumb)
	private fun isOnThumb(touchX: Float, touchY: Float): Boolean {
		if (!computeThumbRect()) return false
		val hitLeft = (width - paddingRight - touchTargetWidthPx).coerceAtMost(thumbRect.left)
		return touchX >= hitLeft && touchX <= width.toFloat() &&
			   touchY >= thumbRect.top - touchSlopVertPx &&
			   touchY <= thumbRect.bottom + touchSlopVertPx
	}

	private fun beginDrag(touchY: Float) {
		dragging = true                      // set first so pokeThumb keeps the thumb pinned (no idle timer)
		dragGrabOffset = touchY - thumbRect.top   // thumbRect was just filled by isOnThumb()
		thumb()?.setDragging(true)
		// Stop any in-flight fling so it can't fight the drag, then take over the gesture
		smoothScrollBy(0, 0)
		parent?.requestDisallowInterceptTouchEvent(true)
		pokeThumb()
	}

	private fun dragTo(touchY: Float) {
		if (!computeMetrics() || scrollableTrackPx <= 0f) return
		val desiredTop = (touchY - dragGrabOffset).coerceIn(trackTopPx, trackTopPx + scrollableTrackPx)
		val fraction = (desiredTop - trackTopPx) / scrollableTrackPx
		val targetY = Math.round(fraction * scrollMax)
		// scrollTo triggers onScrollChanged -> pokeThumb; if already clamped, poke directly
		if (targetY != scrollY) scrollTo(0, targetY) else pokeThumb()
	}

	private fun endDragInternal() {
		dragging = false
		thumb()?.setDragging(false)
		parent?.requestDisallowInterceptTouchEvent(false)
		// Drag is over: resume the idle countdown from now
		removeCallbacks(hideThumbRunnable)
		postDelayed(hideThumbRunnable, THUMB_IDLE_TIMEOUT_MS)
	}

	override fun onInterceptTouchEvent(event: MotionEvent): Boolean {
		if (fastScrollActive && thumbShown &&
			event.actionMasked == MotionEvent.ACTION_DOWN && isOnThumb(event.x, event.y)) {
			beginDrag(event.y)
			return true
		}
		return super.onInterceptTouchEvent(event)
	}

	// Takes the thumb drag, which is no click; every other touch stays the ScrollView's own.
	override fun onTouchEvent(event: MotionEvent): Boolean {
		when (event.actionMasked) {
			MotionEvent.ACTION_DOWN -> {
				if (!dragging && fastScrollActive && thumbShown && isOnThumb(event.x, event.y)) {
					beginDrag(event.y)
					return true
				}
			}
			MotionEvent.ACTION_MOVE -> if (dragging) {
				dragTo(event.y)
				return true
			}
			MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> if (dragging) {
				endDragInternal()
				return true
			}
		}
		return super.onTouchEvent(event)
	}
}
