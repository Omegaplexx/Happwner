package com.happwner.ui

import android.text.Spannable
import android.text.method.ArrowKeyMovementMethod
import android.text.style.ClickableSpan
import android.view.MotionEvent
import android.widget.TextView
import java.lang.ref.WeakReference

// MovementMethod that keeps text selection working while still firing ClickableSpan taps
class OutputLinkMovementMethod private constructor() : ArrowKeyMovementMethod() {

    // Held weakly: this is a process-wide singleton, and the span on the truncated-output link
    // closes over the activity and the full converted body.
    private var pressed: WeakReference<ClickableSpan>? = null

    override fun onTouchEvent(widget: TextView, buffer: Spannable, event: MotionEvent): Boolean {
        when (event.action) {
            MotionEvent.ACTION_DOWN -> pressed = spanUnder(widget, buffer, event)?.let { WeakReference(it) }
            MotionEvent.ACTION_UP -> {
                val up = spanUnder(widget, buffer, event)
                val down = pressed?.get()
                pressed = null
                // Only treat it as a tap when down and up land on the same span
                if (down != null && down === up) {
                    down.onClick(widget)
                    return true
                }
            }
            MotionEvent.ACTION_CANCEL -> pressed = null
        }
        return super.onTouchEvent(widget, buffer, event)
    }

    // The ClickableSpan under the touch point, or null
    private fun spanUnder(widget: TextView, buffer: Spannable, event: MotionEvent): ClickableSpan? {
        val layout = widget.layout ?: return null
        val x = event.x.toInt() - widget.totalPaddingLeft + widget.scrollX
        val y = event.y.toInt() - widget.totalPaddingTop + widget.scrollY
        val line = layout.getLineForVertical(y)
        if (x < layout.getLineLeft(line) || x > layout.getLineRight(line)) return null
        val offset = layout.getOffsetForHorizontal(line, x.toFloat())
        return buffer.getSpans(offset, offset, ClickableSpan::class.java).firstOrNull()
    }

    companion object {
        private val shared = OutputLinkMovementMethod()
        fun getInstance(): OutputLinkMovementMethod = shared
    }
}
