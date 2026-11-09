package com.happwner.bridge

import android.Manifest
import android.app.ForegroundServiceStartNotAllowedException
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ShortcutInfo
import android.content.pm.ShortcutManager
import android.graphics.drawable.Icon
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.service.quicksettings.TileService
import android.util.Log
import android.widget.Toast
import androidx.activity.result.ActivityResultCaller
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.withResumed
import com.happwner.R
import com.happwner.data.AppLocale
import com.happwner.data.ModuleIds
import com.happwner.data.PrefsManager
import kotlinx.coroutines.launch

object BridgeController {

	private const val TAG = "Happwner:Bridge"
	const val SHORTCUT_ID_TOGGLE = "bridge_toggle"

	// Immutable wherever the flag exists, so no one else fills in a bridge PendingIntent;
	// updated in place, so a new one carries the current extras.
	internal val PENDING_INTENT_FLAGS = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
		PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
	} else {
		PendingIntent.FLAG_UPDATE_CURRENT
	}

	fun isEnabled(context: Context): Boolean =
		PrefsManager.getSafePrefs(context).getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)

	// LAN mode as it takes effect: switched on, with nothing standing in its way.
	fun isLanModeOn(context: Context): Boolean =
		PrefsManager.getSafePrefs(context).getBoolean(PrefsManager.PREF_BRIDGE_LAN_MODE, false) &&
			lanModePermissionNeeded(context) == null

	// What LAN mode has yet to ask for, or null: where the system closes the local network to an app,
	// it stays closed until the person lets it in.
	fun lanModePermissionNeeded(context: Context): String? =
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.CINNAMON_BUN &&
			ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_LOCAL_NETWORK) !=
				PackageManager.PERMISSION_GRANTED
		) {
			Manifest.permission.ACCESS_LOCAL_NETWORK
		} else {
			null
		}

	// Whether the bridge is answering right now - the service's own word, not the preference.
	fun isServing(): Boolean = SubscriptionService.isServing

	// On as the switch, the tile and the shortcut show it: the preference, and a service serving -
	// a preference can outlive a start that was refused.
	fun isOn(context: Context): Boolean = isEnabled(context) && isServing()

	// Serving, with its notification up unless the person or their settings took it down.
	fun isUp(context: Context): Boolean =
		isServing() && !SubscriptionService.notificationDropped(context.applicationContext)

	// Asks the system to start the service. False when refused (no exemption for a background start
	// on Android 12+) or dropped silently, which is what "Restricted" battery use does.
	fun startService(
		context: Context,
		tellPerson: Boolean = false,
		action: String? = null
	): Boolean {
		val app = context.applicationContext
		val intent = Intent(app, SubscriptionService::class.java)
			.setAction(action)
			.putExtra(SubscriptionService.EXTRA_TELL_PERSON, tellPerson)
		var refusal: Throwable? = null
		try {
			val started = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
				app.startForegroundService(intent)
			} else {
				app.startService(intent)
			}
			if (started != null) return true
		} catch (error: Throwable) {
			refusal = error
		}
		Log.w(TAG, "Bridge did not start: ${refusal ?: "the system dropped the request"}")
		if (tellPerson) tell(app, refusalMessage(app, refusal))
		return false
	}

	// What the person can do about a refusal; a start dropped without a word is a background
	// restriction too. The technical name is kept only when the cause has no known remedy.
	private fun refusalMessage(app: Context, refusal: Throwable?): String = when {
		refusal == null || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
			refusal is ForegroundServiceStartNotAllowedException) ->
			AppLocale.wrap(app).getString(R.string.bridge_start_refused_background)
		refusal is SecurityException -> AppLocale.wrap(app).getString(
			R.string.bridge_start_refused_permission)
		else -> AppLocale.wrap(app).getString(R.string.bridge_start_refused_other,
			refusal.javaClass.simpleName.removeSuffix("Exception"))
	}

	fun tell(context: Context, message: String) {
		val app = context.applicationContext
		Handler(Looper.getMainLooper()).post {
			try { Toast.makeText(app, message, Toast.LENGTH_LONG).show() } catch (_: Throwable) {}
		}
	}

	// Turns the preference on and starts the service, turning it back off if the start is refused.
	// The tile asks without telling - a refusal there falls back to an activity that tells itself.
	fun enable(context: Context, tellPerson: Boolean = true): Boolean {
		val app = context.applicationContext
		val prefs = PrefsManager.getSafePrefs(app)
		prefs.edit { putBoolean(PrefsManager.PREF_BRIDGE_ENABLED, true) }
		val started = startService(app, tellPerson)
		if (!started) prefs.edit { putBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false) }
		notifyChanged(app)
		return started
	}

	// Starts the service where the preference says on but it is not up - after an update or a kill.
	// Every bridge surface calls this first. True if up or just asked to start.
	fun ensureServing(context: Context, tellPerson: Boolean = true): Boolean {
		val app = context.applicationContext
		if (!isEnabled(app)) return false
		if (isUp(app)) {
			// Leave to reach the local network, given in the system settings meanwhile, doesn't move a
			// bound socket.
			if (SubscriptionService.servesLan != isLanModeOn(app)) rebind(app, tellPerson)
			return true
		}
		// Not up can mean serving with the notification dropped: starting a running service reposts
		// its notification and keeps its accept loop.
		return startService(app, tellPerson)
	}

	// A bound socket can't be given a new address - the service closes and reopens it instead.
	fun rebind(context: Context, tellPerson: Boolean = true) {
		val app = context.applicationContext
		if (!isEnabled(app)) return
		startService(app, tellPerson, action = SubscriptionService.ACTION_REBIND)
	}

	// Not stopService(): landing while a start still waits for startForeground() gets the app
	// killed. A plain start is safe here since every caller is a visible screen, the tile, or
	// the service itself.
	fun disable(context: Context) {
		val app = context.applicationContext
		PrefsManager.getSafePrefs(app).edit { putBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false) }
		if (SubscriptionService.isAlive) {
			app.startService(Intent(app, SubscriptionService::class.java))
		}
		notifyChanged(app)
	}

	fun notifyChanged(context: Context) {
		val app = context.applicationContext
		try {
			app.sendBroadcast(Intent(ModuleIds.ACTION_REFRESH_UI).setPackage(app.packageName))
		} catch (_: Throwable) {
		}
		refreshSurfaces(app)
	}

	fun refreshSurfaces(context: Context) {
		val app = context.applicationContext
		refreshTile(app)
		refreshShortcut(app)
	}

	// Nudge the system to re-poll the QS tile (it re-reads state on listening)
	fun refreshTile(context: Context) {
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return
		try {
			TileService.requestListeningState(
				context.applicationContext,
				ComponentName(context.applicationContext, BridgeTileService::class.java)
			)
		} catch (_: Throwable) {
		}
	}

	fun refreshShortcut(context: Context) {
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N_MR1) return
		val app = context.applicationContext
		val manager = app.getSystemService(ShortcutManager::class.java) ?: return
		val enabled = isOn(app)
		val local = AppLocale.wrap(app)
		val label = local.getString(R.string.tile_bridge_label)
		val intent = Intent(app, BridgeToggleActivity::class.java).apply {
			action = ModuleIds.ACTION_TOGGLE_BRIDGE
			addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
		}
		val shortcut = ShortcutInfo.Builder(app, SHORTCUT_ID_TOGGLE)
			.setShortLabel(label)
			.setLongLabel(label)
			.setIcon(
				Icon.createWithResource(
					app,
					if (enabled) R.drawable.ic_shortcut_bridge_on else R.drawable.ic_shortcut_bridge_off
				)
			)
			.setIntent(intent)
			.build()
		try {
			manager.setDynamicShortcuts(listOf(shortcut))
		} catch (_: Throwable) {
		}
	}

	// The system's own prompt to stop optimizing this app, or null when there is nothing to ask -
	// before Android 6, or with the exemption already granted.
	private fun batteryExemptionRequest(context: Context): Intent? {
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
		val power = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return null
		if (power.isIgnoringBatteryOptimizations(context.packageName)) return null
		return Intent(
			Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, "package:${context.packageName}".toUri()
		)
	}

	// What turning the bridge on from the app's screens asks for: notifications, then no battery
	// optimization, one after the other whatever the answers. Each is asked at most twice, the
	// second time only after a refusal, so someone who said no is not asked on every start.
	class Permissions<H>(
		private val host: H,
		private val context: () -> Context?,
		private val onFinished: () -> Unit
	) where H : ActivityResultCaller, H : LifecycleOwner {

		// A second tap before the first prompt is up would spend the second ask unseen.
		private var asking = false

		private val notifications = host.registerForActivityResult(
			ActivityResultContracts.RequestPermission()
		) { granted ->
			if (granted) settle(PrefsManager.PREF_BRIDGE_NOTIFICATION_ASKS)
			inFront { askBatteryExemption() }
		}

		private val batteryExemption = host.registerForActivityResult(
			ActivityResultContracts.StartActivityForResult()
		) {
			val ctx = context()
			if (ctx != null && batteryExemptionRequest(ctx) == null) {
				settle(PrefsManager.PREF_BRIDGE_BATTERY_ASKS)
			}
			inFront { finish() }
		}

		// Asks what is left to ask, then runs onFinished - at once when nothing is.
		fun enableBridge() {
			if (asking) return
			asking = true
			inFront { askNotifications() }
		}

		private fun askNotifications() {
			val ctx = context() ?: return finish()
			if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return askBatteryExemption()
			val allowed = ContextCompat.checkSelfPermission(
				ctx, Manifest.permission.POST_NOTIFICATIONS
			) == PackageManager.PERMISSION_GRANTED
			if (allowed || !takeAsk(ctx, PrefsManager.PREF_BRIDGE_NOTIFICATION_ASKS)) {
				return askBatteryExemption()
			}
			try {
				notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
			} catch (_: RuntimeException) {
				// A prompt that cannot open must not keep the bridge off.
				askBatteryExemption()
			}
		}

		private fun askBatteryExemption() {
			val ctx = context() ?: return finish()
			val request = batteryExemptionRequest(ctx)
			if (request == null || !takeAsk(ctx, PrefsManager.PREF_BRIDGE_BATTERY_ASKS)) {
				finish()
				return
			}
			try {
				batteryExemption.launch(request)
			} catch (_: RuntimeException) {
				// No such prompt on this firmware, or none for this app: the bridge goes on anyway.
				finish()
			}
		}

		private fun finish() {
			asking = false
			onFinished()
		}

		// True, with the ask counted, while fewer than two were made.
		private fun takeAsk(ctx: Context, key: String): Boolean {
			val prefs = PrefsManager.getSafePrefs(ctx)
			val asked = prefs.getInt(key, 0)
			if (asked >= MAX_ASKS) return false
			prefs.edit { putInt(key, asked + 1) }
			return true
		}

		// Allowed once means never asked again, even after it is taken back in the system's
		// settings: the second ask is for a refusal alone.
		private fun settle(key: String) {
			val ctx = context() ?: return
			PrefsManager.getSafePrefs(ctx).edit { putInt(key, MAX_ASKS) }
		}

		// A result arrives before its screen is back in front, and a prompt opened then can be
		// dropped - silently, on some firmware - so each next step waits for the screen to resume.
		private fun inFront(step: () -> Unit) {
			host.lifecycleScope.launch { host.withResumed { step() } }
		}

		private companion object {
			const val MAX_ASKS = 2
		}
	}
}
