package com.happwner.ui

import android.content.Context
import android.content.Intent
import android.view.MotionEvent
import com.happwner.data.ModuleIds
import com.happwner.data.SettingsProvider
import com.happwner.hook.SwitchGesture

// The way back for the three-finger swap: only a visit that began with the hook's gesture can be
// ended with it, and any other way out of Happwner (Home, Recents) forgets the app.
object SwitchBack {
	private var sourceApp: String? = null
	private var startedScreens = 0

	// The intent the hook's gesture opens Happwner with.
	fun remember(intent: Intent?) {
		if (intent?.action != ModuleIds.ACTION_SWITCH_FROM_APP) return
		val source = SettingsProvider.readUntrustedExtras { intent.getStringExtra(SettingsProvider.EXTRA_PACKAGE) }
		if (!source.isNullOrEmpty() && source != ModuleIds.PACKAGE) sourceApp = source
	}

	fun screenStarted() {
		startedScreens++
	}

	// A recreate (theme, language) stops and restarts the screen, which is not leaving.
	fun screenStopped(changingConfigurations: Boolean) {
		startedScreens--
		if (startedScreens == 0 && !changingConfigurations) sourceApp = null
	}

	// Called for every touch on a screen or dialog of the app.
	fun onTouch(context: Context, event: MotionEvent) {
		if (!SwitchGesture.isTriggered(event)) return
		val source = sourceApp ?: return
		val launch = context.packageManager.getLaunchIntentForPackage(source) ?: return
		sourceApp = null
		context.startActivity(launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
	}
}
