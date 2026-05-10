package com.happwner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            val prefs = PrefsManager.getSafePrefs(context)
            val bridgeEnabled = prefs.getBoolean("bridge_enabled", false)

            if (bridgeEnabled) {
                val workRequest = OneTimeWorkRequestBuilder<BootWorker>().build()
                WorkManager.getInstance(context).enqueue(workRequest)
            }
        }
    }
}
