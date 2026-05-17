package com.happwner

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.HttpURLConnection
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

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val prefs = PrefsManager.getSafePrefs(this)
        
        if (intent?.action == "ACTION_DISCONNECT") {
            prefs.edit().putBoolean("bridge_enabled", false).apply()
            stopSelf()
            return START_NOT_STICKY
        }
        
        val bridgeEnabled = prefs.getBoolean("bridge_enabled", false)

        if (!bridgeEnabled) {
            stopSelf()
            return START_NOT_STICKY
        }

        updateNotificationState()

        if (!isRunning) {
            startServer()
        }

        if (prefs.getBoolean("bridge_watchdog", false)) {
            WatchdogReceiver.scheduleNextWatchdog(this)
        }

        return START_STICKY
    }

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

        // Notification is always shown when the service is active
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(resources.getInteger(R.integer.id_fgs_notif), notification, fgsType)
        } else {
            startForeground(resources.getInteger(R.integer.id_fgs_notif), notification)
        }
    }

    private fun startServer() {
        if (isRunning) return
        isRunning = true
        scope.launch {
            try {
                synchronized(SubscriptionService::class.java) {
                    if (serverSocket == null || serverSocket!!.isClosed) {
                        serverSocket = ServerSocket(8166).apply {
                            reuseAddress = true
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

    private fun handleClient(socket: Socket) {
        scope.launch {
            try {
                socket.soTimeout = 30000 
                val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
                val output = socket.getOutputStream()
                
                val line = reader.readLine() ?: return@launch
                Log.d("Happwner:Server", "Request line: $line")
                val parts = line.split(" ")
                if (parts.size < 2) return@launch
                
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
                    val ua = params["ua"] ?: ""
                    
                    if (targetUrl != null) {
                        val response = fetchSubscription(targetUrl, hwid, ua)

                        val prefs = PrefsManager.getSafePrefs(this@SubscriptionService)
                        val processServer = prefs.getBoolean("process_server", false)
                        val finalBody = if (processServer) LinkConverter.convert(response.body) else response.body
                        
                        Log.d("Happwner:Server", "Sending response back. Final length: ${finalBody.length}")
                        Log.v("Happwner:Server", "Response content: $finalBody")
                        
                        sendResponse(output, finalBody, response.headers)
                    } else {
                        sendError(output, 400, "Missing URL")
                    }
                } else {
                    sendError(output, 404, "Not Found")
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

    private suspend fun fetchSubscription(url: String, hwid: String, ua: String): ProxyResponse = withContext(Dispatchers.IO) {
        var conn: HttpURLConnection? = null
        try {
            conn = URL(url).openConnection() as HttpURLConnection
            conn.apply {
                requestMethod = "GET"
                setRequestProperty("x-hwid", hwid)
                setRequestProperty("User-Agent", ua)
                connectTimeout = 15000
                readTimeout = 15000
            }
            
            val headers = conn.headerFields.filterKeys { it != null }
            val body = if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                conn.inputStream.bufferedReader().readText()
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

    private fun sendResponse(output: OutputStream, body: String, headers: Map<String, List<String>>) {
        val out = output.bufferedWriter(Charsets.UTF_8)
        out.write("HTTP/1.1 200 OK\r\n")
        out.write("Content-Type: text/plain; charset=utf-8\r\n")
        out.write("Content-Length: ${body.toByteArray(Charsets.UTF_8).size}\r\n")
        out.write("Access-Control-Allow-Origin: *\r\n")
        out.write("Connection: close\r\n")
        
        for ((key, values) in headers) {
            val k = key.lowercase(Locale.US)
            if (k == "subscription-userinfo" || k == "content-disposition" || k == "profile-update-interval" || k == "profile-title") {
                out.write("$key: ${values.joinToString(", ")}\r\n")
            }
        }
        
        out.write("\r\n")
        out.write(body)
        out.flush()
    }

    private fun sendError(output: OutputStream, code: Int, message: String) {
        val out = output.bufferedWriter(Charsets.UTF_8)
        out.write("HTTP/1.1 $code Error\r\n")
        out.write("Content-Type: text/plain; charset=utf-8\r\n")
        out.write("Connection: close\r\n")
        out.write("\r\n")
        out.write(message)
        out.flush()
    }

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

    override fun onDestroy() {
        isRunning = false
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
