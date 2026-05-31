package com.happwner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class IdReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val originalId = intent.getStringExtra("original_id")
        if (originalId != null) {
            val prefs = PrefsManager.getSafePrefs(context)
            prefs.edit().putString("captured_id", originalId).apply()
            PrefsManager.broadcastSettings(context)
        }
    }
}
