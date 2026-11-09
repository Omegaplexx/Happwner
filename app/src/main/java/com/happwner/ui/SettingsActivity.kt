package com.happwner.ui

import android.os.Bundle
import com.happwner.R

// Settings as a standalone activity, a fallback for system-animation mode
class SettingsActivity : ThemedActivity() {

	override fun onCreate(savedInstanceState: Bundle?) {
		super.onCreate(savedInstanceState)
		// Crossfade on a theme/language change
		ThemeTransition.preApplyBackground(this)
		setContentView(R.layout.activity_settings)
		ThemeTransition.consumeOverlay(this)

		// First launch: attach the settings fragment
		if (savedInstanceState == null) {
			try {
				val fragment = SettingsFragment()
				supportFragmentManager.beginTransaction()
					.add(R.id.settingsActivityRoot, fragment, "settings_fragment_activity")
					.commitNow()
			} catch (_: Throwable) {}
		}
	}
}
