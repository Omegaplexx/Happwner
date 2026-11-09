package com.happwner.ui

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ValueAnimator
import android.content.Context
import android.content.res.Configuration
import android.graphics.Canvas
import android.graphics.Rect
import android.view.View
import android.view.ViewGroup
import android.view.ViewTreeObserver
import android.view.WindowManager
import android.widget.FrameLayout
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.graphics.drawable.DrawableWrapperCompat
import androidx.core.graphics.createBitmap
import androidx.core.graphics.drawable.toDrawable
import androidx.core.graphics.withClip
import com.happwner.R

// Pages shown inside the dialog's own window, replacing its page; the frame glides to the new height.
// OK, Back and a tap outside return to the page beneath instead of closing.
class DialogPages(
	context: Context,
	private val homeTitle: CharSequence,
	private val homeButtons: Boolean = true,
	private val onPage: (String?) -> Unit = {},
	createHome: (ViewGroup) -> View
) {
	// Built on every open. The key lets a host reopen it after a recreate; a tall page gets most of the screen.
	class Page(
		val title: CharSequence,
		val key: String? = null,
		val onOk: (View) -> Unit = {},
		val buttons: Boolean = true,
		val textInput: Boolean = false,
		val tall: Boolean = false,
		val create: (ViewGroup) -> View
	)

	// The dialog's view: its own page plus the open ones; re-lays out on a new configuration.
	val view: FrameLayout = object : FrameLayout(context) {
		override fun onConfigurationChanged(newConfig: Configuration) {
			super.onConfigurationChanged(newConfig)
			release()
		}
	}

	val home: View = createHome(view).also { view.addView(it) }

	private var dialog: AlertDialog? = null
	// The last one shows; the ones beneath keep their views.
	private val shownPages = ArrayDeque<Pair<Page, View>>()
	// While a turn runs, taps and Back wait, so a second OK cannot confirm two pages.
	private var turning = false
	// Stopped if the dialog closes mid-turn.
	private var glide: ValueAnimator? = null
	// The window's margins as shown, and the focus rule a turn replaces.
	private var restPadding: Rect? = null
	private var restFocus: Int? = null

	fun attach(dialog: AlertDialog) {
		this.dialog = dialog
		buttonBar()?.visibility = if (homeButtons) View.VISIBLE else View.GONE
		dialog.holdTall()
		dialog.window?.decorView?.let {
			restPadding = Rect(it.paddingLeft, it.paddingTop, it.paddingRight, it.paddingBottom)
		}
		dialog.setOnExternalDismissListener { glide?.cancel() }
		dialog.setStayOpenHook { button ->
			if (shownPages.isEmpty()) return@setStayOpenHook turning
			if (!turning) closeTop(confirmed = button == AlertDialog.BUTTON_POSITIVE)
			true
		}
	}

	// Leaves the page showing for the one beneath, as Back does.
	fun close() {
		if (!turning && shownPages.isNotEmpty()) closeTop(confirmed = false)
	}

	private fun closeTop(confirmed: Boolean) {
		val (page, pageView) = shownPages.removeLast()
		if (confirmed) page.onOk(pageView)
		if (page.textInput) pageView.hideKeyboard()
		val beneath = shownPages.lastOrNull()
		onPage(beneath?.first?.key)
		// No page types any more: the window stops taking the keyboard.
		if (page.textInput && shownPages.none { it.first.textInput }) {
			dialog?.window?.addFlags(WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM)
		}
		turn {
			view.removeView(pageView)
			fitWindowMargins(shownPages.any { it.first.tall })
			if (beneath == null) {
				home.visibility = View.VISIBLE
				show(homeTitle, homeButtons)
			} else {
				beneath.second.visibility = View.VISIBLE
				show(beneath.first.title, beneath.first.buttons)
			}
		}
	}

	// A tall page cannot afford the window's wide margin above and below the card.
	private fun fitWindowMargins(tall: Boolean) {
		val decor = dialog?.window?.decorView ?: return
		val rest = restPadding ?: return
		val margin = view.resources.getDimensionPixelSize(R.dimen.dialog_tall_margin)
		decor.setPadding(
			rest.left,
			if (tall) minOf(rest.top, margin) else rest.top,
			rest.right,
			if (tall) minOf(rest.bottom, margin) else rest.bottom
		)
	}

	fun open(page: Page, animated: Boolean = true) {
		if (turning) return
		val beneath = shownPages.lastOrNull()?.second ?: home
		val pageView = page.create(view)
		pageView.visibility = View.GONE
		(pageView as? TallPageLayout)?.dialogFloor = card()?.height ?: 0
		view.addView(pageView)
		shownPages.addLast(page to pageView)
		if (page.textInput) {
			dialog?.window?.clearFlags(WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM)
		}
		// The host hears of the page as its turn starts, so a recreate mid-turn reopens it.
		onPage(page.key)
		turn(animated) {
			beneath.visibility = View.GONE
			pageView.visibility = View.VISIBLE
			fitWindowMargins(page.tall)
			show(page.title, page.buttons)
		}
	}

	private fun show(title: CharSequence, buttons: Boolean) {
		dialog?.setTitle(title)
		buttonBar()?.visibility = if (buttons) View.VISIBLE else View.GONE
	}

	// One page turn: the frame glides to the new height as the old page, kept as a picture, dissolves
	// into the new one. Off, or with little memory, it just swaps.
	private fun turn(animated: Boolean = true, flip: () -> Unit) {
		val dialog = dialog ?: return flip()
		val card = card()
		val mode = dialog.shownAnimMode()
		// No focus while pages change hands, so a field of the new page is not woken by it.
		restFocus = view.descendantFocusability
		view.descendantFocusability = ViewGroup.FOCUS_BLOCK_DESCENDANTS
		view.findFocus()?.clearFocus()
		view.closeDropdowns()
		if (!animated || card == null || mode == ANIM_MODE_OFF || card.context.isLowRam()) {
			flip()
			return endTurn()
		}
		turning = true
		glideTo(dialog, card, mode, flip)
	}

	private fun endTurn() {
		turning = false
		view.closeDropdowns()
		restFocus?.let { view.descendantFocusability = it }
		restFocus = null
	}

	// The old page is kept as a picture; without memory for it, the new page fades in alone.
	private fun glideTo(dialog: AlertDialog, card: View, mode: Int, flip: () -> Unit) {
		val decor = dialog.window?.decorView
		val drawn = dialog.box()
		if (decor == null || drawn == null || decor.height == 0) {
			flip()
			return endTurn()
		}
		val went = try {
			val bitmap = createBitmap(card.width, card.height)
			card.draw(Canvas(bitmap))
			bitmap.toDrawable(card.resources)
		} catch (_: Throwable) {
			null
		}
		val from = drawn.height
		drawn.driven = true
		val visible = Rect().also { decor.getWindowVisibleDisplayFrame(it) }
		flip()
		card.alpha = 0f
		val room = decor.height - decor.paddingTop - decor.paddingBottom
		card.measure(
			View.MeasureSpec.makeMeasureSpec(card.width, View.MeasureSpec.EXACTLY),
			View.MeasureSpec.makeMeasureSpec(room, View.MeasureSpec.AT_MOST)
		)
		val to = card.measuredHeight
		val clip = Rect()
		val visibleNow = Rect()
		val clipToFrame = ViewTreeObserver.OnPreDrawListener {
			decor.getWindowVisibleDisplayFrame(visibleNow)
			if (visibleNow != visible) {
				release()
				return@OnPreDrawListener true
			}
			val top = card.height / 2 - drawn.height / 2
			clip.set(0, top, card.width, top + drawn.height)
			card.clipBounds = clip
			true
		}
		decor.viewTreeObserver.addOnPreDrawListener(clipToFrame)
		// The picture lies where the old page lay, over the card, and shows only inside the frame.
		val dissolving = went?.let { picture ->
			object : DrawableWrapperCompat(picture) {
				override fun draw(canvas: Canvas) = canvas.withClip(drawn.band()) { picture.draw(this) }
			}.also {
				it.bounds = Rect(drawn.band())
				decor.overlay.add(it)
			}
		}
		val layerBefore = card.layerType
		card.setLayerType(View.LAYER_TYPE_HARDWARE, null)
		val density = card.resources.displayMetrics.density
		val own = maxOf(
			adaptiveAnimDuration(to - from, density),
			card.resources.getInteger(R.integer.duration_standard_transition).toLong()
		)
		glide = ValueAnimator.ofInt(from, to).apply {
			duration = card.context.durationFor(mode, own)
			interpolator = curveFor(mode, materialStandard)
			addUpdateListener {
				val fraction = it.animatedFraction
				drawn.height = it.animatedValue as Int
				drawn.place()
				// The new page is well in by half-way, so the two never read as one washed-out page.
				card.alpha = 1f - (1f - fraction) * (1f - fraction)
				dissolving?.let { picture ->
					picture.alpha = ((1f - fraction) * 255f).toInt()
					picture.invalidateSelf()
				}
			}
			addListener(object : AnimatorListenerAdapter() {
				override fun onAnimationEnd(animation: Animator) {
					glide = null
					endTurn()
					decor.viewTreeObserver.removeOnPreDrawListener(clipToFrame)
					card.clipBounds = null
					card.alpha = 1f
					card.setLayerType(layerBefore, null)
					dissolving?.let { decor.overlay.remove(it) }
					// A leaving dialog keeps its frame: resizing it now would show as a jump.
					if (dialog.isLeaving()) return
					drawn.rest()
				}
			})
			start()
		}
	}

	// Ends a turn at once for a window that must lay out anew (rotation, keyboard, resize).
	private fun release() {
		glide?.end()
	}

	private fun card(): View? = dialog?.card()

	private fun buttonBar(): View? {
		val card = card() ?: return null
		var view: View = dialog?.getButton(AlertDialog.BUTTON_POSITIVE) ?: return null
		while (view.parent !== card) view = view.parent as? View ?: return null
		return view
	}
}
