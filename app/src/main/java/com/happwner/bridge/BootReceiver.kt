package com.happwner.bridge

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.happwner.data.PrefsManager

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            val prefs = PrefsManager.getSafePrefs(context)
            val bridgeEnabled = prefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)

            if (bridgeEnabled) {
                val workRequest = OneTimeWorkRequestBuilder<BootWorker>().build()
                WorkManager.getInstance(context).enqueue(workRequest)
            }
        }
    }
}
