package com.happwner.bridge

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.util.Log
import com.happwner.data.ModuleIds
import com.happwner.data.PrefsManager

// The two alarms that bring the bridge back: a recovery check after a boot or an update, and the
// watchdog's own tick while that option is on.
class WatchdogReceiver : BroadcastReceiver() {
	override fun onReceive(context: Context, intent: Intent) {
		if (intent.action == ModuleIds.ACTION_BRIDGE_RECOVERY) {
			BridgeRecovery.check(context, intent.getIntExtra(BridgeRecovery.EXTRA_ATTEMPT, 0))
			return
		}

		val prefs = PrefsManager.getSafePrefs(context)
		val bridgeEnabled = prefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)
		val watchdogEnabled = prefs.getBoolean(PrefsManager.PREF_BRIDGE_WATCHDOG, false)

		if (!bridgeEnabled || !watchdogEnabled) return

		Log.d(TAG, "Watchdog tick received")
		BridgeController.startService(context)
		scheduleNextWatchdog(context)
	}

	companion object {
		private const val TAG = "Happwner:Watchdog"

		// Re-arm the watchdog alarm (exact when permitted, otherwise best-effort)
		fun scheduleNextWatchdog(context: Context) {
			val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
			val intent = Intent(context, WatchdogReceiver::class.java)
			val flags = BridgeController.PENDING_INTENT_FLAGS

			val pendingIntent = PendingIntent.getBroadcast(context, 1001, intent, flags)

			// Ten seconds on the clock that setting the phone's time cannot move: an alarm on the
			// wall clock set back an hour would wait out the hour first. As the recovery checks do.
			val clock = AlarmManager.ELAPSED_REALTIME_WAKEUP
			val triggerAt = SystemClock.elapsedRealtime() + 10000

			try {
				if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
					if (alarmManager.canScheduleExactAlarms()) {
						alarmManager.setExactAndAllowWhileIdle(clock, triggerAt, pendingIntent)
					} else {
						alarmManager.setAndAllowWhileIdle(clock, triggerAt, pendingIntent)
					}
				} else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
					alarmManager.setExactAndAllowWhileIdle(clock, triggerAt, pendingIntent)
				} else {
					alarmManager.setExact(clock, triggerAt, pendingIntent)
				}
			} catch (error: Exception) {
				Log.e(TAG, "Failed to schedule alarm: ${error.message}")

				// Fallback: inexact alarm
				alarmManager.set(clock, triggerAt, pendingIntent)
			}
		}
	}
}
