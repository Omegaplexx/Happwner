package com.happwner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class SettingsRequestReceiver : BroadcastReceiver() {

    // On a SETTINGS_REQUEST, reply with the current settings
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == "${context.packageName}.SETTINGS_REQUEST") {
            val requester = intent.getStringExtra("requester") ?: "unknown"
            Log.d("Happwner:IPC", "Received PULL request from $requester, sending response...")

            // Immediately send the current settings back in reply
            PrefsManager.broadcastSettings(context)
        }
    }
}
