package com.happwner.ui

import android.content.Context
import android.util.AttributeSet
import android.view.View
import android.widget.LinearLayout
import androidx.appcompat.R as AppCompatR
import androidx.core.content.res.use
import androidx.core.view.isVisible
import com.happwner.R

// A page that makes the dialog a set share of the screen's height, whatever the page holds: its size
// never follows its content, so a list filling in or being filtered cannot move the frame or the rows.
// With fitContent that share is only a ceiling, and a page that holds less is as tall as it holds.
class TallPageLayout @JvmOverloads constructor(
	context: Context,
	attrs: AttributeSet? = null
) : LinearLayout(context, attrs) {

	private val fitContent = context.obtainStyledAttributes(attrs, R.styleable.TallPageLayout).use {
		it.getBoolean(R.styleable.TallPageLayout_fitContent, false)
	}

	// The height of the dialog this page replaces, which the new dialog is never smaller than.
	var dialogFloor = 0

	override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
		if (MeasureSpec.getMode(heightMeasureSpec) == MeasureSpec.UNSPECIFIED) {
			return super.onMeasure(widthMeasureSpec, heightMeasureSpec)
		}
		val dialog = maxOf((resources.displayMetrics.heightPixels * TALL_SHARE).toInt(), dialogFloor)
		val height = (dialog - titleAndButtons()).coerceIn(0, MeasureSpec.getSize(heightMeasureSpec))
		// As wide as the page it replaces, which also fills what the dialog can give.
		val width = if (MeasureSpec.getMode(widthMeasureSpec) == MeasureSpec.AT_MOST) {
			MeasureSpec.makeMeasureSpec(MeasureSpec.getSize(widthMeasureSpec), MeasureSpec.EXACTLY)
		} else {
			widthMeasureSpec
		}
		val mode = if (fitContent) MeasureSpec.AT_MOST else MeasureSpec.EXACTLY
		super.onMeasure(width, MeasureSpec.makeMeasureSpec(height, mode))
	}

	// What the dialog spends around the page; the dialog measures both before it measures the page.
	private fun titleAndButtons(): Int =
		listOf(AppCompatR.id.topPanel, AppCompatR.id.buttonPanel).sumOf { id ->
			rootView.findViewById<View>(id)?.takeIf { it.isVisible }?.measuredHeight ?: 0
		}

	private companion object {
		const val TALL_SHARE = 0.8f
	}
}
