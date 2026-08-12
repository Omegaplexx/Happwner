package com.happwner.crypto

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import android.util.Log
import com.happwner.data.ModuleIds
import java.io.File
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull

// Bridge to the optional companion app Happanion (com.happproxy), an independent app that can call
// liberror-code.so and return the plaintext for crypt5 links whose marker isn't in HappCrypto's
object HappanionBridge {
    private const val TAG = "Happwner:HappanionBridge"

    const val HAPPANION_PACKAGE = "com.happproxy"
    private const val HAPPANION_SERVICE = "com.happproxy.DecryptService"
    private const val ACTION_INSTALL_STATUS = ModuleIds.ACTION_HAPPANION_INSTALL_STATUS

    // Must stay identical to Protocol.kt inside the Happanion project.
    private object Protocol {
        const val VERSION = 1
        const val META_PROTOCOL_VERSION = "com.happproxy.protocol.version"

        const val MSG_DECRYPT_LINK = 1
        const val MSG_RESULT = 2
        const val KEY_LINK = "link"
        const val KEY_RESULT = "result"
        const val KEY_ERROR = "error"

        // Stable codes Happanion answers with. It never sends exception text: that changes between
        // builds and carries internal detail, so there is nothing here to parse - only to log.
        const val ERR_BAD_LINK = "bad_link"
        const val ERR_UNKNOWN_MARKER = "unknown_marker"
        const val ERR_NO_NATIVE_LIB = "no_native_lib"
        const val ERR_RATE_LIMITED = "rate_limited"
        const val ERR_BUSY = "busy"
        const val ERR_INTERNAL = "internal"
    }

    fun isInstalled(context: Context): Boolean {
        return try {
            context.packageManager.getPackageInfo(HAPPANION_PACKAGE, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    // Lowest Happanion protocol version this bridge can talk to.
    private const val MIN_PROTOCOL_VERSION = Protocol.VERSION

    // Protocol version Happanion declares, or -1 when absent/not installed.
    fun installedProtocolVersion(context: Context): Int {
        val app = try {
            context.packageManager.getApplicationInfo(
                HAPPANION_PACKAGE, PackageManager.GET_META_DATA
            )
        } catch (_: PackageManager.NameNotFoundException) {
            return -1
        } catch (_: Exception) {
            return -1
        }
        // Builds from before the meta-data was introduced declare nothing, and
        // are incompatible by definition.
        return app.metaData?.getInt(Protocol.META_PROTOCOL_VERSION, -1) ?: -1
    }

    fun isCompatibleVersionInstalled(context: Context): Boolean =
        installedProtocolVersion(context) >= MIN_PROTOCOL_VERSION

    // Tries to decrypt a link via Happanion. Null if the app isn't installed, is unreachable,
    // doesn't reply within timeoutMs, or returns an error. Call off the main thread.
    suspend fun tryDecrypt(context: Context, link: String, timeoutMs: Long = 4000L): String? {
        // Was isInstalled(), which bound to any installed build including one speaking a different
        // protocol - the version gate existed but only guarded the settings toggle, never the path
        if (!isCompatibleVersionInstalled(context)) return null

        return try {
            withTimeoutOrNull(timeoutMs) { requestDecrypt(context, link) }
        } catch (t: Throwable) {
            Log.w(TAG, "Happanion bridge failed: ${t.javaClass.simpleName}: ${t.message}")
            null
        }
    }

    private suspend fun requestDecrypt(context: Context, link: String): String? =
        suspendCancellableCoroutine { cont ->
            val appContext = context.applicationContext

            // Unbinding has to happen on every way out, exactly once: invokeOnCancellation only covers the
            // timeout, so a reply arriving in time used to leave a live connection per successful decrypt.
            val released = java.util.concurrent.atomic.AtomicBoolean(false)
            var connection: ServiceConnection? = null

            fun release() {
                val c = connection ?: return
                if (released.compareAndSet(false, true)) {
                    try {
                        appContext.unbindService(c)
                    } catch (_: Throwable) {
                    }
                }
            }

            // Releases the binding, then hands the result back once.
            fun finish(value: String?) {
                release()
                if (cont.isActive) cont.resume(value)
            }

            val replyHandler = object : Handler(Looper.getMainLooper()) {
                override fun handleMessage(msg: Message) {
                    if (msg.what != Protocol.MSG_RESULT) return
                    val error = msg.data?.getString(Protocol.KEY_ERROR)
                    val result = msg.data?.getString(Protocol.KEY_RESULT)
                    if (error != null) {
                        Log.w(TAG, "Happanion returned error: ${describeError(error)}")
                        finish(null)
                    } else {
                        finish(result)
                    }
                }
            }
            val replyMessenger = Messenger(replyHandler)

            connection = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName?, binder: IBinder) {
                    val messenger = Messenger(binder)
                    val msg = Message.obtain(null, Protocol.MSG_DECRYPT_LINK).apply {
                        data = Bundle().apply { putString(Protocol.KEY_LINK, link) }
                        replyTo = replyMessenger
                    }
                    try {
                        messenger.send(msg)
                    } catch (e: RemoteException) {
                        finish(null)
                    }
                }

                override fun onServiceDisconnected(name: ComponentName?) {
                    // The service process died.
                    finish(null)
                }
            }

            // Registered before binding, so a cancellation that lands between
            // the two still releases whatever bindService set up.
            cont.invokeOnCancellation { release() }

            val intent = Intent().setClassName(HAPPANION_PACKAGE, HAPPANION_SERVICE)
            val bound = try {
                appContext.bindService(intent, connection, Context.BIND_AUTO_CREATE)
            } catch (t: Throwable) {
                false
            }
            if (!bound) finish(null)
        }

    // Turns a wire code into something readable in logcat. Unknown codes are
    // passed through rather than swallowed: a newer Happanion may add one.
    private fun describeError(code: String): String = when (code) {
        Protocol.ERR_BAD_LINK -> "$code (link was rejected as not a crypt5 link)"
        Protocol.ERR_UNKNOWN_MARKER -> "$code (no key for this marker)"
        Protocol.ERR_NO_NATIVE_LIB -> "$code (native library missing for this device's ABI)"
        Protocol.ERR_RATE_LIMITED -> "$code (too many requests in a short window)"
        Protocol.ERR_BUSY -> "$code (work queue full)"
        Protocol.ERR_INTERNAL -> "$code (failure inside Happanion)"
        else -> code
    }

    // ---- install/uninstall Happanion as a regular independent package ----

    // Whether an install can even be started without the "allow install from this source" dialog.
    fun canRequestInstall(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.O ||
            context.packageManager.canRequestPackageInstalls()

    fun uninstallIntent(): Intent =
        Intent(Intent.ACTION_DELETE, Uri.parse("package:$HAPPANION_PACKAGE"))

    // Installs an already-downloaded Happanion APK via PackageInstaller, with one standard system
    // confirmation dialog.
    fun install(context: Context, apkFile: File, onResult: (success: Boolean, message: String?) -> Unit) {
        val appContext = context.applicationContext
        val installer = appContext.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)

        val sessionId = try {
            installer.createSession(params)
        } catch (t: Throwable) {
            onResult(false, t.message)
            return
        }

        val session = try {
            installer.openSession(sessionId)
        } catch (t: Throwable) {
            // The session exists even though it could not be opened, and an abandoned-in-name-only
            // session keeps its staged data until the system expires it.
            try { installer.abandonSession(sessionId) } catch (_: Throwable) {}
            onResult(false, t.message)
            return
        }

        try {
            session.openWrite("happanion", 0, apkFile.length()).use { out ->
                apkFile.inputStream().use { it.copyTo(out) }
                session.fsync(out)
            }
        } catch (t: Throwable) {
            session.abandon()
            onResult(false, t.message)
            return
        }

        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                val status = intent.getIntExtra(
                    PackageInstaller.EXTRA_STATUS,
                    PackageInstaller.STATUS_FAILURE
                )
                if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                    @Suppress("DEPRECATION")
                    val confirmIntent = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                    confirmIntent?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    confirmIntent?.let { appContext.startActivity(it) }
                    return
                }
                try {
                    appContext.unregisterReceiver(this)
                } catch (_: Throwable) {
                }
                val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
                onResult(status == PackageInstaller.STATUS_SUCCESS, message)
            }
        }

        val filter = IntentFilter(ACTION_INSTALL_STATUS)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            appContext.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            appContext.registerReceiver(receiver, filter)
        }

        val piFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val statusIntent = Intent(ACTION_INSTALL_STATUS).setPackage(appContext.packageName)
        val pendingIntent = PendingIntent.getBroadcast(appContext, sessionId, statusIntent, piFlags)

        // commit() gets the same try/abandon treatment as createSession and openWrite; without it a failure
        // left the receiver registered for good and never called onResult, so the caller waited forever.
        try {
            session.commit(pendingIntent.intentSender)
        } catch (t: Throwable) {
            try { appContext.unregisterReceiver(receiver) } catch (_: Throwable) {}
            try { session.abandon() } catch (_: Throwable) {}
            onResult(false, t.message)
            return
        } finally {
            session.close()
        }
    }
}
