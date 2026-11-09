package com.happwner.hook

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.edit
import com.happwner.data.PrefsManager
import com.happwner.data.SettingsProvider

// Receives the identifier the hooked application was going to use, as the module reports it.
class IdReceiver : BroadcastReceiver() {
	override fun onReceive(context: Context, intent: Intent) {
		val originalId = SettingsProvider.readUntrustedExtras {
			intent.getStringExtra(SettingsProvider.EXTRA_ORIGINAL_ID)
		}
		if (originalId != null && PrefsManager.isPlausibleId(originalId)) {
			val prefs = PrefsManager.getSafePrefs(context)
			prefs.edit { putString(PrefsManager.PREF_CAPTURED_ID, originalId) }
			PrefsManager.broadcastSettings(context)
		}
	}
}
