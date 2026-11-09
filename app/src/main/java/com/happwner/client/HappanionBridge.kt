package com.happwner.client

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import android.util.Log
import androidx.core.content.FileProvider
import androidx.core.net.toUri
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import org.json.JSONObject

// Bridge to the optional companion app Happanion (com.happproxy): it runs Happ's own liberror-code.so,
// so it may open a Happ link the built-in keys cannot. Also fetches, installs and removes it.
object HappanionBridge {
	private const val TAG = "Happwner:Happanion"

	private const val HAPPANION_PACKAGE = "com.happproxy"
	private const val HAPPANION_SERVICE = "com.happanion.DecryptService"

	// Where a build is fetched from and where "Info" points to.
	private const val GITHUB_OWNER = "Omegaplexx"
	private const val GITHUB_REPO = "Happanion"
	private const val RELEASES_API_URL =
		"https://api.github.com/repos/$GITHUB_OWNER/$GITHUB_REPO/releases/latest"
	private const val PROJECT_URL = "https://github.com/$GITHUB_OWNER/$GITHUB_REPO"

	// The one cache folder the FileProvider shares, so an install exposes the APK and nothing else.
	private const val APK_CACHE_DIR = "happanion"

	// Must stay identical to Protocol.kt inside the Happanion project.
	private object Protocol {
		const val VERSION = 1
		const val META_PROTOCOL_VERSION = "com.happanion.protocol.version"

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
		} catch (_: Exception) {
			return -1
		}
		// A build that declares no version cannot speak this protocol.
		return app.metaData?.getInt(Protocol.META_PROTOCOL_VERSION, -1) ?: -1
	}

	fun isCompatibleVersionInstalled(context: Context): Boolean =
		installedProtocolVersion(context) >= MIN_PROTOCOL_VERSION

	// Tries to decrypt a link via Happanion. Null if the app isn't installed, is unreachable,
	// doesn't reply within timeoutMs, or returns an error.
	suspend fun tryDecrypt(context: Context, link: String, timeoutMs: Long = 4000L): String? {
		// Only a build speaking this protocol is bound to: any other would answer in a shape this
		// cannot read, and the settings toggle alone does not guard this path.
		if (!isCompatibleVersionInstalled(context)) return null

		return try {
			withTimeoutOrNull(timeoutMs) { requestDecrypt(context, link) }
		} catch (throwable: Throwable) {
			Log.w(TAG, "Happanion bridge failed: ${throwable.javaClass.simpleName}: ${throwable.message}")
			null
		}
	}

	private suspend fun requestDecrypt(context: Context, link: String): String? =
		suspendCancellableCoroutine { cont ->
			val appContext = context.applicationContext

			// Unbinding has to happen on every way out, exactly once: invokeOnCancellation only covers the
			// timeout, and a reply arriving in time would otherwise leave a live connection behind.
			val released = AtomicBoolean(false)
			var connection: ServiceConnection? = null

			fun release() {
				val liveConnection = connection ?: return
				if (released.compareAndSet(false, true)) {
					try {
						appContext.unbindService(liveConnection)
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
					} catch (_: RemoteException) {
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
			} catch (_: Throwable) {
				false
			}
			if (!bound) finish(null)
		}

	// Turns a wire code into something readable in logcat. Unknown codes are
	// passed through rather than swallowed: a newer Happanion may add one.
	private fun describeError(code: String): String = when (code) {
		Protocol.ERR_BAD_LINK -> "$code (the link was rejected)"
		Protocol.ERR_UNKNOWN_MARKER -> "$code (no key for this marker)"
		Protocol.ERR_NO_NATIVE_LIB -> "$code (native library missing for this device's ABI)"
		Protocol.ERR_RATE_LIMITED -> "$code (too many requests in a short window)"
		Protocol.ERR_BUSY -> "$code (work queue full)"
		Protocol.ERR_INTERNAL -> "$code (failure inside Happanion)"
		else -> code
	}

	// ACTION_UNINSTALL_PACKAGE, not ACTION_DELETE that other apps may answer: deprecated for
	// PackageInstaller sessions, it still reaches the system uninstaller on every version, and with
	// EXTRA_RETURN_RESULT the caller learns whether the uninstall went through.
	@Suppress("DEPRECATION")
	fun uninstallIntent(): Intent =
		Intent(Intent.ACTION_UNINSTALL_PACKAGE, "package:$HAPPANION_PACKAGE".toUri()).apply {
			putExtra(Intent.EXTRA_RETURN_RESULT, true)
		}

	// Something answers to this package name, but not a Happanion build this bridge can talk to -
	// the original Happ, most likely, since the two share a package id by design.
	fun originalHappInstalled(context: Context): Boolean =
		isInstalled(context) && !isCompatibleVersionInstalled(context)

	fun projectPageIntent(): Intent = Intent(Intent.ACTION_VIEW, PROJECT_URL.toUri())

	// A Happ link through the built-in keys, and through Happanion when they fail: it runs Happ's
	// own library, so it may open what the keys this build carries cannot, whatever the reason.
	internal suspend fun decryptWithFallback(
		link: String,
		builtIn: suspend (String) -> HappCrypto.HappLinkResult,
		happanion: suspend (String) -> String?
	): HappCrypto.HappLinkResult {
		val result = builtIn(link)
		if (result !is HappCrypto.HappLinkResult.Error) return result
		return happanion(link)?.let { HappCrypto.HappLinkResult.Decrypted(it, result.mode) } ?: result
	}

	// Downloads the latest release's APK into the cache, ready to install, on the IO dispatcher.
	// Null on any failure - no release yet, no APK among its assets, or the network not cooperating.
	suspend fun downloadLatestRelease(context: Context): File? = withContext(Dispatchers.IO) {
		try {
			val assetUrl = latestApkAssetUrl() ?: return@withContext null
			downloadToCache(context, assetUrl)
		} catch (throwable: Throwable) {
			Log.w(TAG, "Happanion download failed: ${throwable.javaClass.simpleName}: ${throwable.message}")
			null
		}
	}

	// The only two architectures Happanion ships for.
	private val HAPPANION_APK_ABIS = listOf("arm64-v8a", "armeabi-v7a")

	// The ABI a filename ends with, if any - anchored to the end rather than a bare contains(), so
	// a name that merely happens to embed one of these as a substring elsewhere doesn't match.
	private fun abiOf(assetName: String): String? {
		val base = if (assetName.endsWith(".apk", ignoreCase = true)) assetName.dropLast(4) else assetName
		return HAPPANION_APK_ABIS.firstOrNull { base.endsWith("-$it", ignoreCase = true) }
	}

	private fun latestApkAssetUrl(): String? {
		val connection = (URL(RELEASES_API_URL).openConnection() as HttpURLConnection).apply {
			connectTimeout = 10_000
			readTimeout = 10_000
			setRequestProperty("Accept", "application/vnd.github+json")
		}
		return try {
			if (connection.responseCode != 200) return null
			val body = connection.inputStream.bufferedReader().use { it.readText() }
			val assets = JSONObject(body).optJSONArray("assets") ?: return null
			apkAssetUrl(assets, Build.SUPPORTED_ABIS.toList())
		} finally {
			connection.disconnect()
		}
	}

	// The download of the APK a release offers a device with these ABIs, or null when it offers none.
	internal fun apkAssetUrl(assets: JSONArray, abis: List<String>): String? {
		val apks = (0 until assets.length()).mapNotNull { assets.optJSONObject(it) }
			.map { it.optString("name") to it.optString("browser_download_url") }
			.filter { (name, url) -> name.endsWith(".apk", ignoreCase = true) && url.isNotEmpty() }
		if (apks.isEmpty()) return null
		// The device's own ABIs, most preferred first - the first asset naming one of them wins.
		for (abi in abis) {
			apks.firstOrNull { (name, _) -> abiOf(name).equals(abi, ignoreCase = true) }
				?.let { return it.second }
		}
		// None of the device's ABIs are named by any asset: fall back to the one naming no ABI at all,
		// the universal build - or, failing that, whatever there is.
		return apks.firstOrNull { (name, _) -> abiOf(name) == null }?.second ?: apks.first().second
	}

	private fun downloadToCache(context: Context, url: String): File? {
		val connection = (URL(url).openConnection() as HttpURLConnection).apply {
			connectTimeout = 10_000
			readTimeout = 30_000
			instanceFollowRedirects = true
		}
		return try {
			if (connection.responseCode != 200) return null
			val dir = File(context.cacheDir, APK_CACHE_DIR).apply { mkdirs() }
			val file = File(dir, "happanion-latest.apk")
			connection.inputStream.use { input -> file.outputStream().use { input.copyTo(it) } }
			file
		} finally {
			connection.disconnect()
		}
	}

	// A content:// Uri through the app's own FileProvider: a plain file:// one is blocked from API 24 on.
	fun installApkIntent(context: Context, apkFile: File): Intent {
		val uri = FileProvider.getUriForFile(
			context, "${context.packageName}.fileprovider", apkFile
		)
		return Intent(Intent.ACTION_VIEW).apply {
			setDataAndType(uri, "application/vnd.android.package-archive")
			addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
			addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
		}
	}
}
