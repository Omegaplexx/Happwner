package com.happwner

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
import kotlinx.coroutines.*
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

class SubscriptionService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var isRunning = false

    companion object {
        private var serverSocket: ServerSocket? = null
    }

    // Apply the app language to the service context
    override fun attachBaseContext(newBase: Context) {
        val prefs = PrefsManager.getSafePrefs(newBase)
        val lang = prefs.getString("app_lang", "system") ?: "system"
        val config = newBase.resources.configuration

        val locale = if (lang == "system") {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                android.content.res.Resources.getSystem().configuration.locales.get(0)
            } else {
                @Suppress("DEPRECATION")
                android.content.res.Resources.getSystem().configuration.locale
            }
        } else {
            java.util.Locale.forLanguageTag(lang)
        }

        java.util.Locale.setDefault(locale)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            config.setLocale(locale)
        } else {
            @Suppress("DEPRECATION")
            config.locale = locale
        }
        super.attachBaseContext(newBase.createConfigurationContext(config))
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
            prefs.edit().putBoolean("bridge_enabled", false).apply()
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
            BridgeController.notifyChanged(this)
            return START_NOT_STICKY
        }

        val bridgeEnabled = prefs.getBoolean("bridge_enabled", false)

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

        if (prefs.getBoolean("bridge_watchdog", false)) {
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
                    if (serverSocket == null || serverSocket!!.isClosed) {
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

    // Bridge request: pull the subscription, decrypt, convert, then return it
    private fun handleClient(socket: Socket) {
        scope.launch {
            try {
                socket.soTimeout = 30000 // 30s
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
                    val line = reader.readLine() ?: return@use
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
                            val jsonToUri = prefs.getBoolean("process_server", false)
                            val tryB64 = prefs.getBoolean("process_b64_server", false)
                            val xrayToSb = prefs.getBoolean("process_xray_server", false)

                            // Decrypt if the body is encrypted, then run the link conversion
                            val finalBody = when (val r = HappCrypto.process(targetUrl, response.body, response.headers)) {
                                is HappCrypto.Result.Success ->
                                    LinkConverter.convert(r.plaintext, jsonToUri, tryB64, xrayToSb)
                                is HappCrypto.Result.Failed -> {
                                    showDecryptErrorToast(r.keyName, r.reason)
                                    LinkConverter.convert(r.originalBody, jsonToUri, tryB64, xrayToSb)
                                }
                                HappCrypto.Result.NotEncrypted ->
                                    LinkConverter.convert(response.body, jsonToUri, tryB64, xrayToSb)
                            }

                            Log.d("Happwner:Server", "Sending response back. Final length: ${finalBody.length}")
                            Log.v("Happwner:Server", "Response content: $finalBody")

                            sendResponse(output, finalBody, response.headers)
                        } else {
                            sendError(output, 400, "Missing URL")
                        }
                    } else {
                        sendError(output, 404, "Not Found")
                    }
                }
            } catch (e: Exception) {
                Log.e("Happwner:Server", "Error handling client: ${e.message}")
            } finally {
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

    // Read the body with explicit UTF-8 and a size cap, to guard against OOM on a huge response
    private fun readBodyCapped(input: InputStream): String {
        val maxBytes = 32L * 1024 * 1024 // 32 MB; any real subscription is far smaller
        val out = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(16 * 1024)
        var total = 0L
        input.use {
            while (true) {
                val n = it.read(chunk)
                if (n < 0) break
                total += n
                if (total > maxBytes) throw java.io.IOException("Response body exceeds size limit")
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
                setRequestProperty("User-Agent", ua)
                connectTimeout = 15000 // 15s
                readTimeout = 15000 // 15s
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
            val k = key.lowercase(Locale.US)
            if (k == "subscription-userinfo" || k == "content-disposition" || k == "profile-update-interval" || k == "profile-title") {
                headerSb.append("$key: ${values.joinToString(", ")}\r\n")
            }
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
            } catch (e: Exception) {}
        }
        scope.cancel()
        super.onDestroy()
    }
}
