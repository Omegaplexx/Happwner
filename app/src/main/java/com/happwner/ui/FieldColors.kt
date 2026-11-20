package com.happwner.ui

import android.content.res.ColorStateList
import android.graphics.Color
import android.os.Build
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.core.content.ContextCompat
import com.google.android.material.color.MaterialColors
import com.google.android.material.textfield.TextInputLayout
import com.happwner.R

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

private fun accentOf(view: View): Int = MaterialColors.getColor(
	view, R.attr.happAccent,
	ContextCompat.getColor(view.context, R.color.brand_purple_secondary)
)

// Tints the cursor, selection handles and highlight with the accent, as in the main fields.
internal fun tintAccent(layout: TextInputLayout, field: EditText) {
	val accent = accentOf(field)
	if (Build.VERSION.SDK_INT >= 29) layout.setCursorColor(ColorStateList.valueOf(accent))
	updateTextViewHandlesColor(field, accent)
}

// The same for a field with no layout around it.
internal fun tintAccent(field: EditText) = updateTextViewHandlesColor(field, accentOf(field))
