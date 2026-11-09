package com.happwner.patcher

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// Installs an app that is one apk or a base with splits, as a single PackageInstaller session.
object ApkInstaller {

	enum class Outcome { INSTALLED, CANCELLED, FAILED }

	private const val ACTION = "com.happwner.PATCH_INSTALL_RESULT"

	// The system asks the person to confirm, so the result comes later: confirm is given the
	// screen to show, and onDone hears the end. Throws if the session cannot be made or written.
	suspend fun install(
		context: Context,
		apks: List<File>,
		confirm: (Intent) -> Unit,
		onDone: (Outcome, message: String?) -> Unit
	) {
		val app = context.applicationContext
		val installer = app.packageManager.packageInstaller
		val sessionId = installer.createSession(
			PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
		)
		val action = "$ACTION.$sessionId"
		val receiver = object : BroadcastReceiver() {
			override fun onReceive(context: Context, intent: Intent) {
				val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
				val outcome = when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -1)) {
					PackageInstaller.STATUS_PENDING_USER_ACTION -> {
						IntentCompat.getParcelableExtra(intent, Intent.EXTRA_INTENT, Intent::class.java)
							?.let(confirm)
						return
					}
					PackageInstaller.STATUS_SUCCESS -> Outcome.INSTALLED
					PackageInstaller.STATUS_FAILURE_ABORTED -> Outcome.CANCELLED
					else -> Outcome.FAILED
				}
				app.unregisterReceiver(this)
				onDone(outcome, message)
			}
		}
		ContextCompat.registerReceiver(
			app, receiver, IntentFilter(action), ContextCompat.RECEIVER_NOT_EXPORTED
		)
		try {
			withContext(Dispatchers.IO) { writeApks(installer, sessionId, apks) }
			// The installer adds its status to this intent, so it has to be mutable.
			val flags = PendingIntent.FLAG_UPDATE_CURRENT or
				(if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
			val result = PendingIntent.getBroadcast(
				app, sessionId, Intent(action).setPackage(app.packageName), flags
			)
			installer.openSession(sessionId).use { it.commit(result.intentSender) }
		} catch (e: Throwable) {
			app.unregisterReceiver(receiver)
			runCatching { installer.abandonSession(sessionId) }
			throw e
		}
	}

	private fun writeApks(installer: PackageInstaller, sessionId: Int, apks: List<File>) {
		installer.openSession(sessionId).use { session ->
			for (apk in apks) {
				apk.inputStream().use { input ->
					session.openWrite(apk.name, 0, apk.length()).use { out ->
						input.copyTo(out)
						session.fsync(out)
					}
				}
			}
		}
	}
}
