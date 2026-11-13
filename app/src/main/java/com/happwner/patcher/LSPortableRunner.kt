package com.happwner.patcher

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.net.toUri
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

// Patches an apk with LSPortable (LSPatch as a dex classpath) run in an unprivileged app_process.
// LSPortable is a classpath zip, not an executable; it signs with its built-in key.
object LSPortableRunner {

	const val DEFAULT_SIG_BYPASS_LEVEL = 2

	private val LSPORTABLE_SOURCE = ReleaseSource.named("Omegaplexx/LSPortable") { it == "lsportable" }

	private const val LSPORTABLE_CACHE_NAME = "patcher/lsportable"
	private const val PATCH_TIMEOUT_MS = 3 * 60_000L

	class PatchFailure(message: String) : Exception(message)

	fun isInstalled(context: Context, packageName: String): Boolean =
		try {
			context.packageManager.getPackageInfo(packageName, 0)
			true
		} catch (_: PackageManager.NameNotFoundException) {
			false
		}

	// Deprecated in favour of PackageInstaller sessions, but it still reaches the system uninstaller on
	// every version, and with EXTRA_RETURN_RESULT the caller learns whether the uninstall went through.
	@Suppress("DEPRECATION")
	fun uninstallIntent(packageName: String): Intent =
		Intent(Intent.ACTION_UNINSTALL_PACKAGE, "package:$packageName".toUri()).apply {
			putExtra(Intent.EXTRA_RETURN_RESULT, true)
		}

	// moduleApk is Happwner's own apk (applicationInfo.sourceDir). The inputs are one app: its base
	// apk and any splits, which LSPatch patches as a set. Returns the patched apks, one per input.
	fun patch(
		context: Context,
		lsportable: File,
		inputs: List<File>,
		moduleApk: File,
		sigBypassLevel: Int,
		onProcessStarted: (Process) -> Unit
	): List<File> {
		val outDir = freshCacheDir(context, "patcher/out")
		// apkzlib creates temp dirs under java.io.tmpdir, which is /tmp by default and missing here
		val tmpDir = freshCacheDir(context, "patcher/tmp")

		val args = listOf(
			"/system/bin/app_process",
			"-Djava.io.tmpdir=${tmpDir.absolutePath}",
			// the default heap is too small for a 60+ MB apk; the symptom is a silent SIGKILL
			"-Xmx768m",
			"/system/bin", "LSPortableEntry",
			"-o", outDir.absolutePath,
			"-f",
			"-l", sigBypassLevel.toString(),
			"-m", moduleApk.absolutePath
		) + inputs.map { it.absolutePath }
		runWithTimeout(args, lsportable, onProcessStarted)

		val patched = outDir.listFiles { f -> f.extension.equals("apk", ignoreCase = true) }
			.orEmpty().sortedBy { it.name }
		if (patched.size != inputs.size) {
			throw PatchFailure("LSPortable wrote ${patched.size} apks for ${inputs.size} inputs")
		}
		return patched
	}

	private fun freshCacheDir(context: Context, name: String): File =
		File(context.cacheDir, name).apply {
			deleteRecursively()
			mkdirs()
		}

	// Throws PatchFailure with the process output on a non-zero exit or after PATCH_TIMEOUT_MS.
	private fun runWithTimeout(args: List<String>, classpath: File, onProcessStarted: (Process) -> Unit) {
		val process = ProcessBuilder(args).apply {
			environment()["CLASSPATH"] = classpath.absolutePath
			redirectErrorStream(true)
		}.start()
		onProcessStarted(process)

		// destroy() is SIGKILL on Android; it unblocks the read below
		val timedOut = AtomicBoolean(false)
		val watchdog = thread(isDaemon = true) {
			try {
				Thread.sleep(PATCH_TIMEOUT_MS)
				timedOut.set(true)
				process.destroy()
			} catch (_: InterruptedException) {
			}
		}
		val output: String
		val exitCode: Int
		try {
			output = process.inputStream.bufferedReader().use { it.readText() }
			exitCode = process.waitFor()
		} finally {
			watchdog.interrupt()
		}

		if (timedOut.get()) {
			throw PatchFailure("Patching timed out after ${PATCH_TIMEOUT_MS / 60_000} min")
		}
		if (exitCode != 0) {
			throw PatchFailure(output.ifBlank { "app_process exited with code $exitCode" })
		}
	}

	// Removes what a run leaves in the cache: the apks it downloaded, which are only ever its own, and
	// everything patching wrote. Safe after any outcome; an installed app's files are never in here.
	fun cleanupAllCache(context: Context) {
		PatchTarget.entries.forEach { File(context.cacheDir, it.cacheFileName).delete() }
		File(context.cacheDir, "patcher").deleteRecursively()
	}

	// Null if the download fails
	suspend fun downloadLSPortable(
		context: Context,
		onProgress: (downloaded: Long, total: Long) -> Unit
	): File? {
		// The copy from the last run is read-only, so the download could not overwrite it
		File(context.cacheDir, LSPORTABLE_CACHE_NAME).delete()
		// ART refuses to load a classpath file that the process can still write to
		return ReleaseDownloader.downloadLatest(context, LSPORTABLE_SOURCE, LSPORTABLE_CACHE_NAME, onProgress)
			?.also { it.setWritable(false) }
	}
}
