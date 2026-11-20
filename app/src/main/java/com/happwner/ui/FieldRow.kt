package com.happwner.ui

import android.content.Context
import android.graphics.Rect
import android.util.AttributeSet
import android.widget.EditText
import android.widget.LinearLayout
import androidx.core.view.allViews

// A field with buttons beside it, centred on the field's box rather than its frame (label above, message below).
class FieldRow @JvmOverloads constructor(
	context: Context,
	attrs: AttributeSet? = null
) : LinearLayout(context, attrs) {

	private val box = Rect()

	override fun onLayout(changed: Boolean, l: Int, t: Int, r: Int, b: Int) {
		super.onLayout(changed, l, t, r, b)
		val field = getChildAt(0) ?: return
		var top = Int.MAX_VALUE
		var bottom = Int.MIN_VALUE
		field.allViews.filterIsInstance<EditText>().filter { it.isShown }.forEach { edit ->
			box.set(0, 0, edit.width, edit.height)
			offsetDescendantRectToMyCoords(edit, box)
			top = minOf(top, box.top)
			bottom = maxOf(bottom, box.bottom)
		}
		if (top > bottom) return
		val middle = (top + bottom) / 2
		for (i in 1 until childCount) {
			val button = getChildAt(i)
			if (button.visibility != GONE) button.offsetTopAndBottom(middle - (button.top + button.bottom) / 2)
		}
	}
}
