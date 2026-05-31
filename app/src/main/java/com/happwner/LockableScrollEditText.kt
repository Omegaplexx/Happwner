package com.happwner

import android.content.Context
import android.util.AttributeSet
import com.google.android.material.textfield.TextInputEditText

class LockableScrollEditText @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = com.google.android.material.R.attr.editTextStyle
) : TextInputEditText(context, attrs, defStyleAttr) {

    // Auto-scroll lock counter (supports nested lock/unlock)
    private var scrollLockCount = 0

    val isScrollLocked: Boolean
        get() = scrollLockCount > 0

    // Lock and snap to the top
    fun acquireScrollLock() {
        scrollLockCount++
        scrollTo(0, 0)
    }

    // Unlock; snap to top once the last lock is released
    fun releaseScrollLock() {
        if (scrollLockCount > 0) scrollLockCount--
        if (scrollLockCount == 0) scrollTo(0, 0)
    }

    // While scroll is locked, pin to (0,0) and stop the system scrolling to the cursor
    override fun bringPointIntoView(offset: Int): Boolean {
        if (isScrollLocked) {
            scrollTo(0, 0)
            return false
        }
        return super.bringPointIntoView(offset)
    }
}
