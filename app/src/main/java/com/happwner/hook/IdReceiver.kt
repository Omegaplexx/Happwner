package com.happwner.hook

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.happwner.data.PrefsManager
import com.happwner.data.SettingsProvider

class IdReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val originalId = intent.getStringExtra(SettingsProvider.EXTRA_ORIGINAL_ID)
        if (originalId != null) {
            val prefs = PrefsManager.getSafePrefs(context)
            prefs.edit().putString(PrefsManager.PREF_CAPTURED_ID, originalId).apply()
            PrefsManager.broadcastSettings(context)
        }
    }
}
