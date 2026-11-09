package com.happwner.ui

import android.content.Context
import android.util.AttributeSet
import android.view.View
import com.google.android.material.textfield.TextInputLayout

// The layout around a DropdownField. Its arrow is part of the field, not a button of its own, so the
// whole box answers a touch and ripples under it.
class DropdownLayout @JvmOverloads constructor(
	context: Context,
	attrs: AttributeSet? = null,
	defStyleAttr: Int = com.google.android.material.R.attr.textInputStyle
) : TextInputLayout(context, attrs, defStyleAttr) {

	override fun onAttachedToWindow() {
		super.onAttachedToWindow()
		findViewById<View>(com.google.android.material.R.id.text_input_end_icon)?.apply {
			// Clearing the listener makes the arrow clickable again, so it comes first.
			setOnClickListener(null)
			isClickable = false
			isFocusable = false
			background = null
		}
	}
}
