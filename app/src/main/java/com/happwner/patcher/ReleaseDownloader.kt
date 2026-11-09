package com.happwner.patcher

import android.content.Context
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import org.json.JSONObject

// sha256 is the asset's digest as GitHub reports it (lowercase hex); null for assets that predate it.
data class ReleaseInfo(val versionName: String, val downloadUrl: String, val sha256: String?)

// A GitHub repo ("owner/name") and the rule that picks the wanted asset from its latest release.
class ReleaseSource(val repo: String, val assetMatches: (String) -> Boolean)

object ReleaseDownloader {

	private const val CONNECT_TIMEOUT_MS = 3_000
	private const val READ_TIMEOUT_MS = 10_000
	private const val ATTEMPTS = 2

	// Returns an open 200 response, or null. Retries only on network errors.
	private fun connect(url: String, accept: String? = null): HttpURLConnection? {
		if (!url.startsWith("https://")) return null
		repeat(ATTEMPTS) {
			val connection = (URL(url).openConnection() as HttpURLConnection).apply {
				connectTimeout = CONNECT_TIMEOUT_MS
				readTimeout = READ_TIMEOUT_MS
				if (accept != null) setRequestProperty("Accept", accept)
			}
			try {
				if (connection.responseCode == 200) return connection
				connection.disconnect()
				return null
			} catch (_: IOException) {
				connection.disconnect()
			}
		}
		return null
	}

	// The latest release (GitHub never serves a prerelease here): version tag and the matching asset's URL.
	fun fetchLatest(source: ReleaseSource): ReleaseInfo? {
		val connection = connect(
			"https://api.github.com/repos/${source.repo}/releases/latest",
			"application/vnd.github+json"
		) ?: return null
		return try {
			val json = JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
			val version = json.optString("tag_name")
			val assets = json.optJSONArray("assets") ?: return null
			for (i in 0 until assets.length()) {
				val asset = assets.optJSONObject(i) ?: continue
				if (!source.assetMatches(asset.optString("name"))) continue
				val url = asset.optString("browser_download_url")
				if (url.isEmpty()) continue
				val digest = asset.optString("digest")
				val sha256 = digest.takeIf { it.startsWith("sha256:") }?.removePrefix("sha256:")?.lowercase()
				return ReleaseInfo(version, url, sha256)
			}
			null
		} catch (_: Throwable) {
			null
		} finally {
			connection.disconnect()
		}
	}

	suspend fun downloadLatest(
		context: Context,
		source: ReleaseSource,
		fileName: String,
		onProgress: (downloaded: Long, total: Long) -> Unit
	): File? {
		return try {
			val release = fetchLatest(source) ?: return null
			download(context, release.downloadUrl, release.sha256, fileName, onProgress)
		} catch (e: CancellationException) {
			throw e
		} catch (_: Throwable) {
			null
		}
	}

	// Saves url to fileName under the cache dir. Returns null, leaving no partial file, if the
	// transfer fails, ends short of Content-Length or does not match sha256 (when given).
	// Cancellation is checked every chunk.
	private suspend fun download(
		context: Context,
		url: String,
		sha256: String?,
		fileName: String,
		onProgress: (downloaded: Long, total: Long) -> Unit
	): File? {
		val connection = connect(url) ?: return null
		val file = File(context.cacheDir, fileName).apply { parentFile?.mkdirs() }
		var complete = false
		try {
			val total = connection.getHeaderField("Content-Length")?.toLongOrNull() ?: -1L
			connection.inputStream.use { input ->
				file.outputStream().use { output ->
					val buffer = ByteArray(8192)
					val hash = MessageDigest.getInstance("SHA-256")
					var downloaded = 0L
					while (true) {
						currentCoroutineContext().ensureActive()
						val read = input.read(buffer)
						if (read == -1) break
						output.write(buffer, 0, read)
						hash.update(buffer, 0, read)
						downloaded += read
						onProgress(downloaded, total)
					}
					complete = (total <= 0 || downloaded == total) &&
						(sha256 == null || hash.digest().joinToString("") { "%02x".format(it) } == sha256)
				}
			}
			return if (complete) file else null
		} finally {
			connection.disconnect()
			if (!complete) file.delete()
		}
	}
}
