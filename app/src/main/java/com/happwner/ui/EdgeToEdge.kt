package com.happwner.ui

import android.app.Activity
import android.graphics.Color
import android.os.Build
import android.view.WindowManager
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsControllerCompat

// Edge-to-edge: transparent system bars, content behind them. Android 10+ paints a translucent scrim behind a
// transparent navigation bar unless that is switched off - the pale band behind the navigation buttons.
internal fun Activity.drawEdgeToEdge() {
	WindowCompat.setDecorFitsSystemWindows(window, false)
	window.apply {
		addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS)
		@Suppress("DEPRECATION")
		statusBarColor = Color.TRANSPARENT
		@Suppress("DEPRECATION")
		navigationBarColor = Color.TRANSPARENT
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
			isNavigationBarContrastEnforced = false
		}
	}
}

// Status bar icons stay light over the app's dark header in either theme; the navigation bar
// follows the theme.
internal fun Activity.applySystemBarAppearance(isNightMode: Boolean) {
	WindowInsetsControllerCompat(window, window.decorView).apply {
		isAppearanceLightStatusBars = false
		isAppearanceLightNavigationBars = !isNightMode
	}
}
