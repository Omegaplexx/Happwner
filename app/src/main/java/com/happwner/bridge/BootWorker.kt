package com.happwner.bridge

import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.work.Worker
import androidx.work.WorkerParameters

class BootWorker(val context: Context, workerParams: WorkerParameters) : Worker(context, workerParams) {

    override fun doWork(): Result {
        val serviceIntent = Intent(context, SubscriptionService::class.java)
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
            Result.success()
        } catch (e: Throwable) {
            // Starting a foreground service from the background is refused since Android 12, and the reboot
            // exemption may have lapsed by the time WorkManager runs. failure, not retry: recovery is the watchdog's.
            Log.e("Happwner:Boot", "Could not start the bridge after boot (${e.javaClass.simpleName}): ${e.message}")
            Result.failure()
        }
    }
}
