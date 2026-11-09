package com.happwner.ui

import android.content.res.ColorStateList
import android.graphics.Color
import android.os.Build
import android.widget.EditText
import android.widget.TextView

// Tint the text-selection handles and highlight
internal fun updateTextViewHandlesColor(view: TextView, color: Int) {
	if (color == 0) return

	val alpha = 115 // ~45% opacity
	val highlightColor = Color.argb(
		alpha,
		Color.red(color),
		Color.green(color),
		Color.blue(color)
	)

	view.highlightColor = highlightColor

	if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
		val colorStateList = ColorStateList.valueOf(color)
		try {
			if (view is EditText) {
				view.textCursorDrawable?.mutate()?.setTintList(colorStateList)
			}
			view.textSelectHandle?.mutate()?.setTintList(colorStateList)
			view.textSelectHandleLeft?.mutate()?.setTintList(colorStateList)
			view.textSelectHandleRight?.mutate()?.setTintList(colorStateList)
		} catch (_: Exception) {}
	}
}
