package com.happwner.bridge

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.util.Log
import com.happwner.R
import com.happwner.data.AppLocale
import com.happwner.data.ModuleIds

// Brings the bridge back after a boot or an update: one start inside the window the broadcast
// opens, then checks on exact alarms, which open a window of their own. Without leave for exact
// alarms there is no window to retry in, so the chain is not started at all.
internal object BridgeRecovery {

	private const val TAG = "Happwner:Bridge"
	private const val REQUEST_CODE = 1002
	const val EXTRA_ATTEMPT = "attempt"

	// Seconds from one check to the next: the first catches a start that was refused or dropped,
	// the later ones a port another app was still holding.
	private val CHECK_DELAYS_S = longArrayOf(5, 20, 60, 180, 600)

	fun begin(context: Context, reason: String) {
		Log.i(TAG, "Bringing the bridge back after $reason")
		tryStart(context.applicationContext, attempt = 0)
	}

	// A check from the alarm. The chain ends here of itself: nothing more is scheduled once the
	// bridge answers or the person has switched it off.
	fun check(context: Context, attempt: Int) {
		val app = context.applicationContext
		if (!BridgeController.isEnabled(app)) return
		if (BridgeController.isUp(app)) {
			Log.i(TAG, "Bridge is back (check $attempt)")
			return
		}
		Log.i(TAG, "Bridge still down, or its notification is missing, at check $attempt")
		tryStart(app, attempt)
	}

	// A refusal is told only once nothing more is coming: until then a check may still mend it,
	// and a message about a bridge that comes back on its own only misleads.
	private fun tryStart(app: Context, attempt: Int) {
		val started = BridgeController.startService(app)
		if (!schedule(app, attempt + 1) && !started) {
			BridgeController.tell(app,
				AppLocale.wrap(app).getString(R.string.bridge_recovery_refused))
		}
	}

	// True when a check is now pending.
	private fun schedule(app: Context, attempt: Int): Boolean {
		if (attempt > CHECK_DELAYS_S.size) {
			Log.w(TAG, "Giving up after ${CHECK_DELAYS_S.size} checks")
			return false
		}
		val alarms = app.getSystemService(Context.ALARM_SERVICE) as AlarmManager
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && !alarms.canScheduleExactAlarms()) {
			Log.w(TAG, "No leave for exact alarms, so no checks from the background")
			return false
		}
		val at = SystemClock.elapsedRealtime() + CHECK_DELAYS_S[attempt - 1] * 1000
		val pending = operation(app, attempt)
		return try {
			// While idle as well, or a check waits for a maintenance window with the phone asleep.
			// Below M there is neither the call nor the Doze that would need it.
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
				alarms.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pending)
			} else {
				alarms.setExact(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pending)
			}
			true
		} catch (error: Throwable) {
			// Leave for exact alarms can be withdrawn between the question and the call.
			Log.w(TAG, "Could not schedule check $attempt: $error")
			false
		}
	}

	// One request code, so a new chain replaces whatever check was pending.
	private fun operation(app: Context, attempt: Int): PendingIntent {
		val intent = Intent(app, WatchdogReceiver::class.java)
			.setAction(ModuleIds.ACTION_BRIDGE_RECOVERY)
			.putExtra(EXTRA_ATTEMPT, attempt)
		val flags = BridgeController.PENDING_INTENT_FLAGS
		return PendingIntent.getBroadcast(app, REQUEST_CODE, intent, flags)
	}
}
