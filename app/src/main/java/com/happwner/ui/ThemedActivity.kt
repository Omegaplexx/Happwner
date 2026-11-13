package com.happwner.ui

import android.R as AndroidR
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.os.Bundle
import android.view.MotionEvent
import androidx.appcompat.app.AppCompatActivity
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import com.happwner.R
import com.happwner.data.AppLocale
import com.happwner.data.PrefsManager

// The app's screens: the chosen language, theme mode and Monet accent, drawn edge to edge under
// system bars that follow the theme.
abstract class ThemedActivity : AppCompatActivity() {

	// Whether a cold start shows the splash screen - set where the manifest gives the splash theme.
	protected open val showsSplash = false

	override fun attachBaseContext(newBase: Context) {
		super.attachBaseContext(AppLocale.wrap(newBase, setProcessDefault = true))
	}

	override fun onCreate(savedInstanceState: Bundle?) {
		val prefs = PrefsManager.getSafePrefs(this)
		val themeMode = prefs.getInt(PrefsManager.PREF_THEME_MODE, 0)
		ThemeTransition.applyNightMode(themeMode)
		if (showsSplash && savedInstanceState == null && ThemeTransition.pendingOverlay == null) {
			try { installSplashScreen() } catch (_: Throwable) {}
		}
		setTheme(R.style.Theme_Happwner)
		if (themeMode == 3) setTheme(R.style.Theme_Happwner_Amoled)
		super.onCreate(savedInstanceState)
		resetAnimatorScale(this)
		// Monet accent (Android 12+), where the system palette can be read
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
			prefs.getBoolean(PrefsManager.PREF_MONET_ACCENT, false)) {
			try {
				resources.getColor(AndroidR.color.system_accent1_500, theme)
				theme.applyStyle(R.style.ThemeOverlay_Happwner_Monet, true)
			} catch (_: Throwable) {}
		}
		drawEdgeToEdge()
		applySystemBarAppearance(isNightMode())
	}

	override fun finish() = finishForMode { super.finish() }

	override fun onStart() {
		super.onStart()
		SwitchBack.screenStarted()
	}

	override fun onStop() {
		SwitchBack.screenStopped(isChangingConfigurations)
		super.onStop()
	}

	override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
		SwitchBack.onTouch(this, ev)
		return super.dispatchTouchEvent(ev)
	}

	override fun onConfigurationChanged(newConfig: Configuration) {
		super.onConfigurationChanged(newConfig)
		applySystemBarAppearance(newConfig.isNightMode())
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
			window.isNavigationBarContrastEnforced = false
		}
	}
}
