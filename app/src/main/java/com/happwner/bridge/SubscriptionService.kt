package com.happwner.bridge

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.happwner.R
import com.happwner.convert.LinkConverter
import com.happwner.crypto.HappCrypto
import com.happwner.data.AppLocale
import com.happwner.data.PrefsManager
import com.happwner.ui.MainActivity
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.util.*
import kotlinx.coroutines.*

class SubscriptionService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // What bounds a bridge request.

    // Longest request line accepted. A real one is a few hundred bytes.
    private val MAX_REQUEST_LINE = 16 * 1024

    // How long a client may take to send that line, and the socket timeout while it does - the same
    // number on purpose, or the socket would out-wait the deadline and a silent client would keep
    private val REQUEST_DEADLINE_MS = 10_000L

    // Socket timeout once the request is in hand and the reply is going out.
    private val RESPONSE_TIMEOUT_MS = 30_000

    // How many requests the bridge serves at once.
    private val MAX_CONCURRENT_REQUESTS = 10

    private val inFlight = java.util.concurrent.Semaphore(MAX_CONCURRENT_REQUESTS)

    // Largest subscription accepted; any real one is far smaller.
    private val MAX_BODY_BYTES = 32L * 1024 * 1024

    // Longest a single fetch may take in total, however it is paced.
    private val FETCH_BUDGET_MS = 120_000L

    // Written from the main thread (onStartCommand / onDestroy) and read from the accept loop on an
    // IO coroutine, so the write must be visible across threads.
    @Volatile
    private var isRunning = false

    companion object {
        // Written under synchronized(...) but read without it in the accept loop.
        @Volatile
        private var serverSocket: ServerSocket? = null
    }

    // Apply the app language to the service context
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(AppLocale.wrap(newBase, setProcessDefault = true))
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // Create the notification channel up front
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    // Start/stop the local HTTP bridge on 127.0.0.1:8166
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val prefs = PrefsManager.getSafePrefs(this)

        updateNotificationState()

        // "Disable" button from the notification
        if (intent?.action == "ACTION_DISCONNECT") {
            prefs.edit().putBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false).apply()
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
            BridgeController.notifyChanged(this)
            return START_NOT_STICKY
        }

        val bridgeEnabled = prefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)

        // Bridge turned off: tear down the foreground service and stop
        if (!bridgeEnabled) {
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        // Bring the accept loop up if it isn't already running
        if (!isRunning) {
            startServer()
        }

        if (prefs.getBoolean(PrefsManager.PREF_BRIDGE_WATCHDOG, false)) {
            WatchdogReceiver.scheduleNextWatchdog(this)
        }

        BridgeController.refreshSurfaces(this)
        return START_STICKY
    }

    // Persistent foreground-service notification (shown the whole time the service is alive)
    private fun updateNotificationState() {
        val hideIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Intent(android.provider.Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS).apply {
                putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, packageName)
                putExtra(android.provider.Settings.EXTRA_CHANNEL_ID, "bridge_channel")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        } else {
            Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = android.net.Uri.parse("package:$packageName")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        }

        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }

        val contentIntent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val contentPendingIntent = PendingIntent.getActivity(this, 0, contentIntent, flags)

        val hidePendingIntent = PendingIntent.getActivity(this, 200, hideIntent, flags)

        val disconnectIntent = Intent(this, SubscriptionService::class.java).apply {
            action = "ACTION_DISCONNECT"
        }
        val disconnectPendingIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            PendingIntent.getForegroundService(this, 201, disconnectIntent, flags)
        } else {
            PendingIntent.getService(this, 201, disconnectIntent, flags)
        }

        // Build the ongoing notification with Hide / Disconnect actions
        val notification = NotificationCompat.Builder(this, "bridge_channel")
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_content))
            .setSmallIcon(R.drawable.ic_dns)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(contentPendingIntent)
            .addAction(R.drawable.ic_delete, getString(R.string.notif_action_hide), hidePendingIntent)
            .addAction(R.drawable.ic_settings, getString(R.string.notif_action_disconnect), disconnectPendingIntent)
            .build()

        val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(resources.getInteger(R.integer.id_fgs_notif), notification, fgsType)
        } else {
            startForeground(resources.getInteger(R.integer.id_fgs_notif), notification)
        }
    }

    // Open the socket and run the accept loop on an IO coroutine
    private fun startServer() {
        if (isRunning) return
        isRunning = true
        scope.launch {
            try {
                synchronized(SubscriptionService::class.java) {
                    if (serverSocket?.isClosed != false) {
                        serverSocket = ServerSocket().apply {
                            reuseAddress = true
                            bind(InetSocketAddress(8166)) // fixed bridge port
                        }
                    }
                }

                Log.d("Happwner:Server", "Server started on port 8166")
                while (isRunning) {
                    val socket = try {
                        serverSocket?.accept()
                    } catch (e: Exception) {
                        if (isRunning) Log.e("Happwner:Server", "Accept error: ${e.message}")
                        null
                    } ?: break
                    Log.d("Happwner:Server", "Received request from other app")
                    handleClient(socket)
                }
            } catch (e: Exception) {
                if (isRunning) Log.e("Happwner:Server", "Server error: ${e.message}")
            } finally {
                isRunning = false
            }
        }
    }

    // The request line, and no more than one can be: readLine grows until a newline, so a client that
    // never ends the line exhausts memory while the per-read timeout never fires. 16 KB, then dropped.
    private fun readRequestLine(reader: BufferedReader): String? {
        val line = StringBuilder()
        val giveUpAt = System.currentTimeMillis() + REQUEST_DEADLINE_MS
        while (true) {
            if (System.currentTimeMillis() > giveUpAt) return null
            val c = reader.read()
            if (c < 0) return if (line.isEmpty()) null else line.toString()
            if (c == '\n'.code) return line.toString()
            if (c == '\r'.code) continue
            if (line.length >= MAX_REQUEST_LINE) return null
            line.append(c.toChar())
        }
    }

    // Bridge request: pull the subscription, decrypt, convert, then return it
    private fun handleClient(socket: Socket) {
        scope.launch {
            // Declared out here so the catch below can read it.
            var responded = false
            if (!inFlight.tryAcquire()) {
                // Answered rather than dropped: a client that is told to come back knows to, where
                // a closed connection looks like a broken bridge.
                try { sendError(socket.getOutputStream(), 503, "Bridge busy, try again") } catch (_: Throwable) {}
                try { socket.close() } catch (_: Throwable) {}
                return@launch
            }
            try {
                // While the request is read, the socket must not out-wait the deadline below, or a
                // client that connects and says nothing holds its place for the whole socket
                socket.soTimeout = REQUEST_DEADLINE_MS.toInt()
                val socketInput = socket.getInputStream()
                // Don't let BufferedReader close the socket, we write the response to that same socket
                val nonClosingInput = object : InputStream() {
                    override fun read(): Int = socketInput.read()
                    override fun read(b: ByteArray, off: Int, len: Int): Int = socketInput.read(b, off, len)
                    override fun available(): Int = socketInput.available()
                    override fun close() {}
                }
                val output = socket.getOutputStream()

                BufferedReader(InputStreamReader(nonClosingInput, Charsets.UTF_8)).use { reader ->
                    val line = readRequestLine(reader) ?: return@use
                    socket.soTimeout = RESPONSE_TIMEOUT_MS
                    Log.d("Happwner:Server", "Request line: $line")
                    val parts = line.split(" ")
                    if (parts.size < 2) return@use

                    val path = parts[1]
                    // Pull the query string out of the request path
                    val query = if (path.contains("?")) {
                        path.substring(path.indexOf("?") + 1)
                    } else if (path.startsWith("/url=")) {
                        path.substring(1)
                    } else {
                        ""
                    }

                    // Parse url/hwid/ua, fetch, transform, then reply
                    if (query.isNotEmpty()) {
                        val params = parseParams(query)
                        val targetUrl = params["url"]
                        val hwid = params["hwid"] ?: ""
                        val ua = params["ua"] ?: ""

                        if (targetUrl != null) {
                            val response = fetchSubscription(targetUrl, hwid, ua)
                            val prefs = PrefsManager.getSafePrefs(this@SubscriptionService)
                            // Derived from process_mode_server (with a one-time migration from the
                            // old process_server/ process_xray_server/process_mihomo_server flags)
                            val flags = PrefsManager.conversionFlagsFor(prefs, PrefsManager.SCOPE_SERVER)
                            val jsonToUri = flags.jsonToUri
                            val base64Result = flags.base64Result
                            val xrayToSb = flags.xrayToSb
                            val xrayToMihomo = flags.xrayToMihomo

                            // Decrypt if the body is encrypted, then run the link conversion
                            val stats = when (val r = HappCrypto.process(targetUrl, response.body, response.headers)) {
                                is HappCrypto.Result.Success ->
                                    LinkConverter.convertWithStats(r.plaintext, jsonToUri, base64Result, xrayToSb, xrayToMihomo)
                                is HappCrypto.Result.Failed -> {
                                    showDecryptErrorToast(r.keyName, r.reason)
                                    LinkConverter.convertWithStats(r.originalBody, jsonToUri, base64Result, xrayToSb, xrayToMihomo)
                                }
                                HappCrypto.Result.NotEncrypted ->
                                    LinkConverter.convertWithStats(response.body, jsonToUri, base64Result, xrayToSb, xrayToMihomo)
                            }
                            val finalBody = stats.text

                            // The Bridge has no UI to show a skipped-count label in (unlike MainActivity), so logcat is the only
                            // place these reasons surface at all. Both the mihomo and sing-box passes can populate this.
                            if (stats.notes.isNotEmpty()) {
                                for (note in stats.notes) Log.d("Happwner:Convert", note)
                            }

                            Log.d("Happwner:Server", "Sending response back. Final length: ${finalBody.length}")

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
            } catch (e: Throwable) {
                Log.e("Happwner:Server", "Error handling client (${e.javaClass.simpleName}): ${e.message}")
                // Closing without a reply leaves the client reporting "the Bridge is unreachable" rather than "that
                // subscription could not be processed"; a status line says which it was. Only if nothing has gone out.
                if (!responded) {
                    try {
                        sendError(socket.getOutputStream(), 500, "Internal error")
                    } catch (_: Throwable) {}
                }
            } finally {
                inFlight.release()
                try {
                    socket.outputStream.flush()
                    socket.close()
                } catch (e: Exception) {}
            }
        }
    }

    // Parse url-encoded key=value pairs
    private fun parseParams(query: String): Map<String, String> {
        val map = mutableMapOf<String, String>()
        val pairs = query.split("&")
        for (pair in pairs) {
            val idx = pair.indexOf("=")
            if (idx != -1) {
                val key = pair.substring(0, idx)
                val value = pair.substring(idx + 1)
                try {
                    map[key] = java.net.URLDecoder.decode(value, "UTF-8")
                } catch (e: Exception) {
                    map[key] = value
                }
            }
        }
        return map
    }

    data class ProxyResponse(val body: String, val headers: Map<String, List<String>>)

    // The body, bounded by size and by time.
    private fun readBodyCapped(input: InputStream): String {
        val out = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(16 * 1024)
        var total = 0L
        val giveUpAt = System.currentTimeMillis() + FETCH_BUDGET_MS
        input.use {
            while (true) {
                val n = it.read(chunk)
                if (n < 0) break
                total += n
                if (total > MAX_BODY_BYTES) throw java.io.IOException("Response body exceeds size limit")
                if (System.currentTimeMillis() > giveUpAt) {
                    throw java.io.IOException("Subscription took too long to arrive")
                }
                out.write(chunk, 0, n)
            }
        }
        return out.toString("UTF-8")
    }

    // GET the subscription with x-hwid + User-Agent; capture body and headers
    private suspend fun fetchSubscription(url: String, hwid: String, ua: String): ProxyResponse = withContext(Dispatchers.IO) {
        var conn: HttpURLConnection? = null
        try {
            conn = URL(url).openConnection() as HttpURLConnection
            conn.apply {
                requestMethod = "GET"
                setRequestProperty("x-hwid", hwid)
                if (ua.isNotBlank()) setRequestProperty("User-Agent", ua)
                // Reaching the server is one thing; waiting for what it sends is another.
                connectTimeout = 15000
                // Per read, not for the whole download, so a large subscription arriving steadily
                // never trips it.
                readTimeout = 60000
            }

            val headers = conn.headerFields.filterKeys { it != null }
            val body = if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                readBodyCapped(conn.inputStream)
            } else {
                "Error: ${conn.responseCode}"
            }
            ProxyResponse(body, headers)
        } catch (e: Exception) {
            ProxyResponse("Error: ${e.message}", emptyMap())
        } finally {
            conn?.disconnect()
        }
    }

    // The upstream headers a subscription client needs, and nothing else.
    private val FORWARDED_HEADERS = setOf(
        "subscription-userinfo", "content-disposition", "profile-update-interval", "profile-title"
    )

    // Forward only subscription-related headers to the client
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
            // The provider's own text goes into a line of our response, so a CR or LF inside it
            // ends that line and what follows is read as further headers, or as a body of its own -
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

    // Minimal HTTP error response
    private fun sendError(output: OutputStream, code: Int, message: String) {
        val response = "HTTP/1.1 $code Error\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Connection: close\r\n" +
            "\r\n" +
            message
        output.write(response.toByteArray(Charsets.UTF_8))
        output.flush()
    }

    // Toast a decryption failure on the main thread
    private fun showDecryptErrorToast(keyName: String, reason: String) {
        val appContext = applicationContext
        val text = appContext.getString(R.string.toast_decrypt_failed, keyName, reason)
        Handler(Looper.getMainLooper()).post {
            try {
                Toast.makeText(appContext, text, Toast.LENGTH_LONG).show()
            } catch (e: Throwable) {
                Log.w("Happwner:Server", "Toast failed: ${e.message}")
            }
        }
    }

    // Low-importance channel for the persistent bridge notification
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "bridge_channel",
                getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notif_channel_desc)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    // Stop the loop, close the socket, cancel the coroutines
    override fun onDestroy() {
        isRunning = false
        BridgeController.refreshSurfaces(applicationContext)
        Log.d("Happwner:Server", "Server stopping...")
        synchronized(SubscriptionService::class.java) {
            try {
                serverSocket?.close()
                serverSocket = null
                Log.d("Happwner:Server", "Server socket closed")
            } catch (e: Exception) {
                Log.w("Happwner:Server", "Closing server socket failed: ${e.message}")
            }
        }
        scope.cancel()
        super.onDestroy()
    }
}
