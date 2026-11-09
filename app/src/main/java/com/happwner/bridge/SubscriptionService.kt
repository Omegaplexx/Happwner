package com.happwner.bridge

import android.app.ForegroundServiceStartNotAllowedException
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.provider.Settings
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.core.net.toUri
import com.happwner.R
import com.happwner.client.HappCrypto
import com.happwner.convert.SubscriptionConverter
import com.happwner.data.AppLocale
import com.happwner.data.PrefsManager
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import java.util.Locale
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class SubscriptionService : Service() {

	private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

	// stopSelf(startId) leaves the service running if a newer start came since - stopping then
	// would cut off that start's startForeground().
	@Volatile
	private var lastStartId = 0

	private val dismissReceiver = object : BroadcastReceiver() {
		override fun onReceive(context: Context, intent: Intent) {
			dismissedByPerson = true
		}
	}

	private val inFlight = Semaphore(MAX_CONCURRENT_REQUESTS)

	// Which accept loop is the current one; see the finally in startServer.
	@Volatile
	private var serverGeneration = 0

	// Written from the main thread (onStartCommand / onDestroy) and read from the accept loop on an
	// IO coroutine, so the write must be visible across threads.
	@Volatile
	private var isRunning = false

	companion object {
		const val BRIDGE_PORT = 8166

		// The truth about the bridge, unlike the preference that says it should be on: a killed process (update,
		// low memory) leaves the preference set and this false.
		@Volatile
		var isServing: Boolean = false
			private set

		// Whether the bound socket takes the local network too, set with it.
		@Volatile
		var servesLan: Boolean = false
			private set

		// Whether a refusal is a person's to hear about; see portInUse.
		const val EXTRA_TELL_PERSON = "tell_person"

		// Close the socket and open it again: the address it binds to is a setting.
		const val ACTION_REBIND = "ACTION_REBIND"

		// Shared by the notification, its channel, and the "Hide" deep-link into the system
		// channel settings, so the three can't drift apart.
		private const val CHANNEL_ID = "bridge_channel"

		// How long the service lets a start settle before it looks for its notification.
		private const val NOTIFICATION_LOOK_MS = 5000L

		private const val ACTION_DISCONNECT = "ACTION_DISCONNECT"
		// Sent by the notification's delete intent when the person swipes it away.
		private const val ACTION_DISMISSED = "com.happwner.bridge.NOTIFICATION_DISMISSED"
		private const val LOG_SERVER = "Happwner:Server"
		private const val LOG_CONVERT = "Happwner:Convert"

		// Longest request line accepted. A real one is a few hundred bytes.
		private const val MAX_REQUEST_LINE = 16 * 1024

		// Same number as the socket timeout below on purpose - otherwise the socket would out-wait
		// this deadline and a silent client would keep its place past it.
		private const val REQUEST_DEADLINE_MS = 10_000L

		// Socket timeout once the request is in hand and the reply is going out.
		private const val RESPONSE_TIMEOUT_MS = 30_000

		// The request (with a read that may run past its own deadline), two fetches at their limits
		// (a request is repeated at most once), and two minutes to convert and write a large reply.
		private const val EXCHANGE_DEADLINE_MS =
			2 * REQUEST_DEADLINE_MS + 2 * SubscriptionFetch.LONGEST_FETCH_MS + 2 * 60_000L

		// How many requests the bridge serves at once.
		private const val MAX_CONCURRENT_REQUESTS = 10

		// The upstream headers a subscription client needs, and nothing else.
		private val FORWARDED_HEADERS = setOf(
			"subscription-userinfo", "content-disposition", "profile-update-interval", "profile-title"
		)

		// Written under synchronized(...) but read without it in the accept loop.
		@Volatile
		private var serverSocket: ServerSocket? = null

		// disable() checks this before sending a stop request, since starting the service only
		// to stop it would flash its notification.
		@Volatile
		var isAlive: Boolean = false
			private set

		// The accept loop running or winding down, of this service or one before it - the next
		// loop waits it out, since a closed socket keeps the port until its accept() returns.
		private var serverJob: Job? = null

		// Set when the person swipes the notification away, cleared when the service is created:
		// nothing puts back what they took down. Written and read on the main thread.
		private var dismissedByPerson = false

		// True when the notification is gone though neither the person nor their settings took it
		// down - after MY_PACKAGE_REPLACED it can drop while the socket stays fine.
		fun notificationDropped(context: Context): Boolean {
			if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
			val manager = context.getSystemService(NotificationManager::class.java) ?: return false
			if (dismissedByPerson || notificationSwitchedOff(context, manager)) return false
			val id = context.resources.getInteger(R.integer.id_fgs_notif)
			return manager.activeNotifications.none { it.id == id }
		}

		// Off for the app as a whole, or just for the bridge's own channel.
		private fun notificationSwitchedOff(context: Context, manager: NotificationManager): Boolean {
			if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) return true
			if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return false
			val channel = manager.getNotificationChannel(CHANNEL_ID) ?: return false
			return channel.importance == NotificationManager.IMPORTANCE_NONE
		}
	}

	override fun attachBaseContext(newBase: Context) {
		super.attachBaseContext(AppLocale.wrap(newBase, setProcessDefault = true))
	}

	override fun onBind(intent: Intent?): IBinder? = null

	override fun onCreate() {
		super.onCreate()
		isAlive = true
		dismissedByPerson = false
		// Not exported: the only sender is this app's own delete intent.
		ContextCompat.registerReceiver(this, dismissReceiver, IntentFilter(ACTION_DISMISSED),
			ContextCompat.RECEIVER_NOT_EXPORTED)
		watchNotification()
	}

	// Listens on loopback, where a client on this phone reaches it, and on every interface only
	// where the settings ask for that.
	override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
		val prefs = PrefsManager.getSafePrefs(this)
		lastStartId = startId

		// Refused the foreground, the service cannot run. The setting stays on, so the next start
		// allowed - app opened, a reboot, the watchdog - brings the bridge back.
		if (!updateNotificationState()) {
			stopSelf(startId)
			return START_NOT_STICKY
		}

		// "Disable" button from the notification
		if (intent?.action == ACTION_DISCONNECT) {
			prefs.edit { putBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false) }
			ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
			stopSelf(startId)
			BridgeController.notifyChanged(this)
			return START_NOT_STICKY
		}

		val bridgeEnabled = prefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)

		if (!bridgeEnabled) {
			ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
			stopSelf(startId)
			return START_NOT_STICKY
		}

		// A bound socket cannot be told a new address, so it is closed and the start below reopens it; stopping the service
		// would not do, as a start arriving while it stops cancels the stop.
		if (intent?.action == ACTION_REBIND) closeServer()

		if (!isRunning) {
			startServer(tellPerson = intent?.getBooleanExtra(EXTRA_TELL_PERSON, false) == true)
		}

		if (prefs.getBoolean(PrefsManager.PREF_BRIDGE_WATCHDOG, false)) {
			WatchdogReceiver.scheduleNextWatchdog(this)
		}

		BridgeController.refreshSurfaces(this)
		return START_STICKY
	}

	// False when Android 12+ refuses - a start the system makes on its own, like a sticky
	// restart, can land in the background.
	private fun updateNotificationState(): Boolean {
		// Here rather than once in onCreate: a start after a change of language renames it too.
		createNotificationChannel()
		val notification = buildNotification()

		val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
			ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
		} else {
			0
		}

		try {
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
				startForeground(resources.getInteger(R.integer.id_fgs_notif), notification, fgsType)
			} else {
				startForeground(resources.getInteger(R.integer.id_fgs_notif), notification)
			}
		} catch (error: IllegalStateException) {
			// That refusal alone is expected; anything else startForeground() throws is a bug.
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
				error is ForegroundServiceStartNotAllowedException
			) {
				Log.w(LOG_SERVER, "Foreground refused: ${error.javaClass.simpleName}")
				return false
			}
			throw error
		}
		return true
	}

	private fun buildNotification(): Notification {
		// Not baseContext: this service's own resources still hold the language it was created in.
		val text = AppLocale.wrap(this)
		val hideIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
			Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS).apply {
				putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
				putExtra(Settings.EXTRA_CHANNEL_ID, CHANNEL_ID)
				addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
			}
		} else {
			Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
				data = "package:$packageName".toUri()
				addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
			}
		}

		val flags = BridgeController.PENDING_INTENT_FLAGS

		// Opens through the launcher intent rather than naming an activity: the interface depends
		// on the bridge, not the other way round.
		val contentIntent: Intent = packageManager.getLaunchIntentForPackage(packageName) ?: Intent()
		contentIntent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
		val contentPendingIntent = PendingIntent.getActivity(this, 0, contentIntent, flags)

		val hidePendingIntent = PendingIntent.getActivity(this, 200, hideIntent, flags)

		val disconnectIntent = Intent(this, SubscriptionService::class.java).apply {
			action = ACTION_DISCONNECT
		}
		val disconnectPendingIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
			PendingIntent.getForegroundService(this, 201, disconnectIntent, flags)
		} else {
			PendingIntent.getService(this, 201, disconnectIntent, flags)
		}

		return NotificationCompat.Builder(this, CHANNEL_ID)
			.setContentTitle(text.getString(R.string.notif_title))
			.setContentText(text.getString(R.string.notif_content))
			.setSmallIcon(R.drawable.ic_dns)
			.setPriority(NotificationCompat.PRIORITY_LOW)
			.setOngoing(true)
			.setOnlyAlertOnce(true)
			.setContentIntent(contentPendingIntent)
			.setDeleteIntent(PendingIntent.getBroadcast(this, 202,
				Intent(ACTION_DISMISSED).setPackage(packageName), flags))
			.addAction(R.drawable.ic_delete, text.getString(R.string.notif_action_hide),
				hidePendingIntent)
			.addAction(R.drawable.ic_settings, text.getString(R.string.notif_action_disconnect),
				disconnectPendingIntent)
			.build()
	}

	// Five seconds in, looks for the notification and, while it has dropped, puts it back and looks
	// again, three times at most.
	private fun watchNotification() {
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
		val manager = getSystemService(NotificationManager::class.java)
		val id = resources.getInteger(R.integer.id_fgs_notif)
		// On the main thread, like onDestroy (which cancels the scope) - so no look runs after it.
		scope.launch(Dispatchers.Main) {
			repeat(3) {
				delay(NOTIFICATION_LOOK_MS)
				if (!isServing || !BridgeController.isEnabled(this@SubscriptionService)) {
					return@launch
				}
				if (!notificationDropped(this@SubscriptionService)) return@launch
				Log.i(LOG_SERVER, "Notification went missing, putting it back")
				manager.notify(id, buildNotification())
			}
		}
	}

	// Wakes the accept loop and lets it end quietly: isRunning is already false, or a rebind has
	// already started the loop that replaces it.
	private fun closeServer() {
		isRunning = false
		synchronized(SubscriptionService::class.java) {
			// Inside the lock a start binds under: no start asked for before this close can bind
			// after it with an address read before the change that caused the close.
			serverGeneration++
			isServing = false
			val socket = serverSocket ?: return
			try {
				socket.close()
				serverSocket = null
				Log.d(LOG_SERVER, "Server socket closed")
			} catch (error: Exception) {
				Log.w(LOG_SERVER, "Closing server socket failed: ${error.message}")
			}
		}
	}

	private fun startServer(tellPerson: Boolean) {
		if (isRunning) return
		isRunning = true
		val generation = ++serverGeneration
		val previous = serverJob
		serverJob = scope.launch {
			// Binding while the last loop still sits in accept() on its closed socket fails as if
			// another app held the port, so let that loop finish first.
			previous?.join()
			try {
				// LAN mode off: loopback alone, only this phone reaches it. On: every interface,
				// so another device can too - and its requests are held back from this phone's own services.
				val lanMode = BridgeController.isLanModeOn(this@SubscriptionService)
				// Null binds every interface. Loopback is the literal address, since
				// getLoopbackAddress() can answer ::1 (Android's does), which 127.0.0.1 never hears.
				val host = if (lanMode) null else InetAddress.getByName(BridgeLink.LOOPBACK)
				synchronized(SubscriptionService::class.java) {
					// A close since this start was asked for moved the generation on - the address
					// read above may already be stale, and this start with it.
					if (generation != serverGeneration) return@launch
					if (serverSocket?.isClosed != false) {
						serverSocket = ServerSocket().apply {
							reuseAddress = true
							bind(InetSocketAddress(host, BRIDGE_PORT))
						}
					}
					isServing = true
					servesLan = lanMode
				}

				val reach = if (lanMode) "every interface" else "loopback"
				Log.d(LOG_SERVER, "Server started on port $BRIDGE_PORT ($reach)")
				BridgeController.refreshSurfaces(applicationContext)
				// Stops a loop a rebind has replaced: the closed socket alone wouldn't do it, since
				// by the time this looks again the field already holds the new one.
				while (isRunning && generation == serverGeneration) {
					val socket = try {
						serverSocket?.accept()
					} catch (error: Exception) {
						// A replaced loop stays quiet: its socket was closed on purpose, and
						// isRunning now belongs to the loop that took its place.
						if (isRunning && generation == serverGeneration) {
							Log.e(LOG_SERVER, "Accept error: ${error.message}")
						}
						null
					} ?: break
					Log.d(LOG_SERVER, "Received request from other app")
					// Loopback, or this phone's own address via an app here using the network
					// link, counts as this phone's own request.
					val fromNetwork = !BridgeLink.cameFromThisPhone(socket.inetAddress)
					handleClient(socket, fromNetwork)
				}
			} catch (error: Exception) {
				// Only the current generation may speak for the bridge - a replaced loop failing
				// on its way out must not report a port in use and take the bridge down with it.
				if (isRunning && generation == serverGeneration) {
					Log.e(LOG_SERVER, "Server error: ${error.message}")
					if (!isServing) portInUse(tellPerson)
				}
			} finally {
				// Same generation check: a rebind may already have the next loop running while
				// this one is still unwinding.
				if (generation == serverGeneration) {
					isRunning = false
					isServing = false
				}
			}
		}
	}

	// The port could not be bound. Where a person asked for the start, the preference follows, so no surface shows
	// "on" over a dead service; where none did, it keeps their choice and the next start tries again.
	private fun portInUse(tellPerson: Boolean) {
		if (!tellPerson) {
			ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
			stopSelf(lastStartId)
			return
		}
		BridgeController.disable(applicationContext)
		BridgeController.tell(
			applicationContext,
			AppLocale.wrap(applicationContext)
				.getString(R.string.bridge_port_in_use, BRIDGE_PORT)
		)
	}

	// readLine() would grow until a newline, so a client that never ends the line would exhaust
	// memory while the per-read timeout never fires. Capped at 16 KB instead.
	private fun readRequestLine(reader: BufferedReader): String? {
		val line = StringBuilder()
		val giveUpAt = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(REQUEST_DEADLINE_MS)
		while (true) {
			if (System.nanoTime() - giveUpAt > 0) return null
			val nextChar = reader.read()
			if (nextChar < 0) return if (line.isEmpty()) null else line.toString()
			if (nextChar == '\n'.code) return line.toString()
			if (nextChar == '\r'.code) continue
			if (line.length >= MAX_REQUEST_LINE) return null
			line.append(nextChar.toChar())
		}
	}

	// Bridge request: pull the subscription, decrypt, convert, then return it
	private fun handleClient(socket: Socket, fromNetwork: Boolean) {
		scope.launch {
			var responded = false
			if (!inFlight.tryAcquire()) {
				// Answered rather than dropped, so the client knows to retry - a closed
				// connection would just look like a broken bridge.
				try { sendError(socket.getOutputStream(), 503,
					"Bridge busy, try again") } catch (_: Throwable) {}
				try { socket.close() } catch (_: Throwable) {}
				return@launch
			}
			// Writes never time out, so a client that stops reading would keep its place
			// indefinitely - past this deadline the socket is closed instead.
			val deadline = scope.launch {
				delay(EXCHANGE_DEADLINE_MS)
				try { socket.close() } catch (_: Throwable) {}
			}
			// Held from when a body grows large until the reply is out; see LargeTurn.
			val turn = SubscriptionFetch.LargeTurn()
			try {
				socket.soTimeout = REQUEST_DEADLINE_MS.toInt()
				val socketInput = socket.getInputStream()
				// Don't let BufferedReader close the socket - the response goes out on it too.
				val nonClosingInput = object : InputStream() {
					override fun read(): Int = socketInput.read()
					override fun read(buffer: ByteArray, off: Int,
						len: Int): Int = socketInput.read(buffer, off, len)
					override fun available(): Int = socketInput.available()
					override fun close() {}
				}
				val output = socket.getOutputStream()

				BufferedReader(InputStreamReader(nonClosingInput, Charsets.UTF_8)).use { reader ->
					val line = readRequestLine(reader) ?: return@use
					socket.soTimeout = RESPONSE_TIMEOUT_MS
					Log.d(LOG_SERVER, "Request line: $line")
					val parts = line.split(" ")
					if (parts.size < 2) return@use

					val path = parts[1]
					val query = if (path.contains("?")) {
						path.substring(path.indexOf("?") + 1)
					} else if (path.startsWith("/url=")) {
						path.substring(1)
					} else {
						""
					}

					if (query.isNotEmpty()) {
						val params = parseParams(query)
						val targetUrl = params["url"]
						val hwid = params["hwid"] ?: ""
						val userAgent = params["ua"] ?: ""

						if (targetUrl != null) {
							// Would leave this request waiting on one it makes to itself, tying up
							// another server slot on every hop. Named in the reply; nothing fetched.
							if (BridgeLink.leadsHere(targetUrl)) {
								Log.w(LOG_SERVER, "Refusing an address that is the Bridge itself")
								responded = true
								sendError(output, 400, "That address is the Bridge itself")
								return@use
							}

							val prefs = PrefsManager.getSafePrefs(this@SubscriptionService)
							val fetched = SubscriptionFetch.fetchHonouringSubUa(targetUrl, hwid,
								userAgent, PrefsManager.preferSubscriptionUa(prefs), fromNetwork,
								turn)
							val response = fetched.resp
							// The client gets the error, not a 200 whose body it would take for a subscription.
							if (response.isError) {
								Log.w(LOG_SERVER, "Subscription fetch failed: status ${response.status}")
								responded = true
								sendError(output, SubscriptionFetch.bridgeStatusFor(response), response.body)
								return@use
							}
							// Derived from process_mode_server, migrated once from the old
							// process_server / process_xray_server / process_mihomo_server flags.
							val flags = PrefsManager.conversionFlagsFor(prefs, PrefsManager.SCOPE_SERVER)

							val decrypted = fetched.decrypted
							if (decrypted is HappCrypto.Result.Failed) {
								showDecryptErrorToast(decrypted.keyName, decrypted.reason)
							}
							val stats = SubscriptionConverter.convertWithStats(
								HappCrypto.plaintextOf(decrypted, response.body), flags
							)
							val finalBody = stats.text

							// The Bridge has no UI to show a skipped-count label in, so logcat is
							// the only place these notes (from any conversion pass) surface.
							if (stats.notes.isNotEmpty()) {
								for (note in stats.notes) Log.d(LOG_CONVERT, note)
							}

							Log.d(LOG_SERVER, "Sending response back. Final length: ${finalBody.length}")

							responded = true
							sendResponse(output, finalBody, response.headers)
						} else {
							responded = true
							sendError(output, 400, "Missing URL")
						}
					} else {
						responded = true
						sendError(output, 404, "Not Found")
					}
				}
			} catch (error: Throwable) {
				// org.json's message can quote the whole input it failed on, so release logs only
				// the error kind; the detail is debug-only.
				Log.e(LOG_SERVER, "Error handling client: ${error.javaClass.simpleName}")
				Log.d(LOG_SERVER, "Error handling client", error)
				// Otherwise the client just reports "Bridge unreachable" instead of the real cause.
				if (!responded) {
					try {
						sendError(socket.getOutputStream(), 500, "Internal error")
					} catch (_: Throwable) {}
				}
			} finally {
				deadline.cancel()
				turn.close()
				inFlight.release()
				try {
					socket.outputStream.flush()
					socket.close()
				} catch (_: Exception) {}
			}
		}
	}

	private fun parseParams(query: String): Map<String, String> {
		val map = mutableMapOf<String, String>()
		val pairs = query.split("&")
		for (pair in pairs) {
			val idx = pair.indexOf("=")
			if (idx != -1) {
				val key = pair.substring(0, idx)
				val value = pair.substring(idx + 1)
				try {
					map[key] = URLDecoder.decode(value, "UTF-8")
				} catch (_: Exception) {
					map[key] = value
				}
			}
		}
		return map
	}

	private fun sendResponse(output: OutputStream, body: String, headers: Map<String, List<String>>) {
		val bodyBytes = body.toByteArray(Charsets.UTF_8)
		val headerSb = StringBuilder()
		headerSb.append("HTTP/1.1 200 OK\r\n")
		headerSb.append("Content-Type: text/plain; charset=utf-8\r\n")
		headerSb.append("Content-Length: ${bodyBytes.size}\r\n")
		headerSb.append("Access-Control-Allow-Origin: *\r\n")
		headerSb.append("Connection: close\r\n")

		for ((key, values) in headers) {
			if (key.lowercase(Locale.US) !in FORWARDED_HEADERS) continue
			val value = values.joinToString(", ")
			// A CR or LF in the provider's own text would end our header line early, letting what
			// follows be read as more headers or a body of its own.
			if (key.any { it.code < 0x20 || it.code == 0x7f } ||
				value.any { it.code < 0x20 || it.code == 0x7f }
			) continue
			headerSb.append("$key: $value\r\n")
		}

		headerSb.append("\r\n")
		output.write(headerSb.toString().toByteArray(Charsets.UTF_8))
		output.write(bodyBytes)
		output.flush()
	}

	private fun sendError(output: OutputStream, code: Int, message: String) {
		val response = "HTTP/1.1 $code Error\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			message
		output.write(response.toByteArray(Charsets.UTF_8))
		output.flush()
	}

	private fun showDecryptErrorToast(keyName: String, reason: String) {
		val appContext = applicationContext
		val text = AppLocale.wrap(appContext).getString(R.string.toast_decrypt_failed, keyName, reason)
		Handler(Looper.getMainLooper()).post {
			try {
				Toast.makeText(appContext, text, Toast.LENGTH_LONG).show()
			} catch (error: Throwable) {
				Log.w(LOG_SERVER, "Toast failed: ${error.message}")
			}
		}
	}

	private fun createNotificationChannel() {
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
			val channel = NotificationChannel(
				CHANNEL_ID,
				AppLocale.wrap(this).getString(R.string.notif_channel_name),
				NotificationManager.IMPORTANCE_LOW
			).apply {
				description = AppLocale.wrap(this@SubscriptionService)
					.getString(R.string.notif_channel_desc)
				setShowBadge(false)
				lockscreenVisibility = Notification.VISIBILITY_PUBLIC
			}
			val manager = getSystemService(NotificationManager::class.java)
			manager?.createNotificationChannel(channel)
		}
	}

	override fun onDestroy() {
		Log.d(LOG_SERVER, "Server stopping...")
		closeServer()
		BridgeController.refreshSurfaces(applicationContext)
		scope.cancel()
		unregisterReceiver(dismissReceiver)
		isAlive = false
		super.onDestroy()
	}
}
