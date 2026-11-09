package com.happwner.ui

import android.content.Context
import android.graphics.Rect
import android.graphics.drawable.Drawable
import android.graphics.drawable.LayerDrawable
import android.os.Bundle
import android.os.SystemClock
import android.util.AttributeSet
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityManager
import androidx.appcompat.content.res.AppCompatResources
import androidx.appcompat.widget.ListPopupWindow
import com.google.android.material.textfield.MaterialAutoCompleteTextView
import com.happwner.R

// A dropdown that opens, and takes the focus, for its owner's own touch or key and for nothing else:
// a click that no finger made would flip the arrow and ring the field with no list to show.
class DropdownField @JvmOverloads constructor(
	context: Context,
	attrs: AttributeSet? = null
) : MaterialAutoCompleteTextView(context, attrs) {

	private var touchedAt = NEVER
	private var askedAt = NEVER
	private var dismissListener: OnDismissListener? = null

	// The list a Spinner opens, without the platform list's grow animation and stretch under a finger. Made on first use:
	// the platform asks whether it is open while the field is built.
	private var popup: ListPopupWindow? = null

	private fun menu() = popup ?: ListPopupWindow(context).apply {
		anchorView = this@DropdownField
		isModal = true
		inputMethodMode = ListPopupWindow.INPUT_METHOD_NOT_NEEDED
		setOnItemClickListener { _, row, position, id -> pick(row, position, id) }
		setOnDismissListener { dismissListener?.onDismiss() }
	}.also { popup = it }

	// Material's own touch handling opens the list for a finger, and hears the click that follows a key.
	// The arrow does not take a touch of its own, so a finger on it comes through here too.
	override fun dispatchTouchEvent(event: MotionEvent): Boolean {
		touchedAt = SystemClock.uptimeMillis()
		return super.dispatchTouchEvent(event)
	}

	override fun dispatchKeyEvent(event: KeyEvent): Boolean {
		askedAt = SystemClock.uptimeMillis()
		return super.dispatchKeyEvent(event)
	}

	// Called when the list closes, or does not open, to put Material's arrow back.
	override fun setOnDismissListener(listener: OnDismissListener?) {
		dismissListener = listener
	}

	// Material rings a closed dropdown in a ripple that fills the whole box with its own color, so the wave
	// under the finger cannot be told from the box. The outline stays, over the project's ripple.
	override fun setBackground(background: Drawable?) {
		super.setBackground(
			if (background is LayerDrawable) {
				val outline = background.getDrawable(background.numberOfLayers - 1)
				LayerDrawable(arrayOf(AppCompatResources.getDrawable(context, R.drawable.bg_row_ripple), outline))
			} else {
				background
			}
		)
		unfocusRipple()
	}

	override fun drawableStateChanged() {
		super.drawableStateChanged()
		unfocusRipple()
	}

	// A ripple keeps a tint while its view has the focus, which would leave the box tinted after a
	// choice. This one answers a finger only.
	private fun unfocusRipple() {
		(background as? LayerDrawable)?.getDrawable(0)?.state =
			drawableState.filter { it != android.R.attr.state_focused }.toIntArray()
	}

	override fun showDropDown() {
		if (isPopupShowing) return
		if (hasWindowFocus() && isShown && wanted()) {
			menu().apply {
				setAdapter(adapter)
				setBackgroundDrawable(dropDownBackground)
				show()
			}
		} else {
			dismissListener?.onDismiss()
		}
	}

	override fun dismissDropDown() {
		popup?.dismiss()
	}

	override fun isPopupShowing() = popup?.isShowing == true

	// The open list takes the window's focus, which the field would take as a reason to close it.
	override fun onWindowFocusChanged(hasWindowFocus: Boolean) {
		if (!isPopupShowing) super.onWindowFocusChanged(hasWindowFocus)
	}

	override fun onDetachedFromWindow() {
		popup?.dismiss()
		super.onDetachedFromWindow()
	}

	private fun pick(row: View?, position: Int, id: Long) {
		val item = adapter.getItem(position)
		val list = popup?.listView
		dismissDropDown()
		setText(convertSelectionToString(item), false)
		onItemClickListener?.onItemClick(list, row, position, id)
	}

	override fun requestFocus(direction: Int, previouslyFocusedRect: Rect?): Boolean =
		(!isInTouchMode || wanted()) && super.requestFocus(direction, previouslyFocusedRect)

	override fun performAccessibilityAction(action: Int, arguments: Bundle?): Boolean {
		askedAt = SystemClock.uptimeMillis()
		return super.performAccessibilityAction(action, arguments)
	}

	// Material takes these as a click on the field and toggles the list. After a touch it has already
	// done so, and would close what the touch opened.
	override fun onPopulateAccessibilityEvent(event: AccessibilityEvent) {
		if (event.eventType in TOGGLING_EVENTS && !(recent(askedAt) || touchExploring())) return
		super.onPopulateAccessibilityEvent(event)
	}

	private fun wanted() = recent(touchedAt) || recent(askedAt) || touchExploring()

	// The click a touch makes is posted a moment after its release.
	private fun recent(at: Long) = at != NEVER && SystemClock.uptimeMillis() - at <= INVITATION_MS

	// Material opens the list for a screen reader its own way, which is not ours to refuse.
	private fun touchExploring() =
		(context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager)
			?.isTouchExplorationEnabled == true

	private companion object {
		const val NEVER = -1L
		const val INVITATION_MS = 1000L
		val TOGGLING_EVENTS = intArrayOf(
			AccessibilityEvent.TYPE_VIEW_CLICKED,
			AccessibilityEvent.TYPE_VIEW_FOCUSED,
			AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUSED
		)
	}
}
