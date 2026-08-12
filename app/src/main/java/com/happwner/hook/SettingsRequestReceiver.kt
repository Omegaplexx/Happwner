package com.happwner.hook

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.happwner.data.ModuleIds
import com.happwner.data.PrefsManager

class SettingsRequestReceiver : BroadcastReceiver() {

    // On a SETTINGS_REQUEST, reply with the current settings
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ModuleIds.ACTION_SETTINGS_REQUEST) {
            val requester = intent.getStringExtra("requester") ?: "unknown"
            Log.d("Happwner:IPC", "Received PULL request from $requester, sending response...")

            // Immediately send the current settings back in reply
            PrefsManager.broadcastSettings(context)
        }
    }
}
