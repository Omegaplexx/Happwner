package com.happwner.hook

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.happwner.data.ModuleIds
import com.happwner.data.PrefsManager
import com.happwner.data.SettingsProvider

class SettingsRequestReceiver : BroadcastReceiver() {

	companion object {
		private const val TAG = "Happwner:IPC"
	}

	// On a SETTINGS_REQUEST, reply with the current settings
	override fun onReceive(context: Context, intent: Intent) {
		if (intent.action == ModuleIds.ACTION_SETTINGS_REQUEST) {
			val requester = SettingsProvider.readUntrustedExtras {
				intent.getStringExtra("requester")
			} ?: "unknown"
			Log.d(TAG, "Received PULL request from $requester, sending response...")

			// Immediately send the current settings back in reply
			PrefsManager.broadcastSettings(context)
		}
	}
}
