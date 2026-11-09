package com.happwner.patcher

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.annotation.VisibleForTesting
import java.io.File
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// One patch run, from the downloads to the install, kept apart from any screen. A change of theme or
// language rebuilds the activity in the middle of a run; the new screen reads the state from here and
// the run never notices. It holds the application context only, which lives as long as the process.
@SuppressLint("StaticFieldLeak")
object PatchSession {

	sealed interface Progress {
		class Downloading(val name: String, val downloaded: Long = 0, val total: Long = 0) : Progress
		object Patching : Progress
	}

	// How a run ended, held until a screen has shown it and the person has seen it.
	sealed interface Result {
		class Installed(val source: PatchSource) : Result
		class DownloadFailed(val name: String) : Result
		class InstallFailed(val message: String?) : Result
		class PatchFailed(val text: String) : Result
	}

	// A system screen to open, which only an activity can do.
	sealed interface Request {
		class Uninstall(val packageName: String) : Request
		class Confirm(val intent: Intent) : Request
	}

	private const val LSPORTABLE_NAME = "LSPortable"
	private const val PROGRESS_INTERVAL_MS = 50L

	private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

	private val progressState = MutableStateFlow<Progress?>(null)
	private val resultState = MutableStateFlow<Result?>(null)
	private val requestQueue = Channel<Request>(Channel.UNLIMITED)

	// Null when nothing is being downloaded or patched.
	val progress: StateFlow<Progress?> = progressState.asStateFlow()
	val result: StateFlow<Result?> = resultState.asStateFlow()
	val requests: Flow<Request> = requestQueue.receiveAsFlow()

	private class Pending(val source: PatchSource) {
		var patched: List<File> = emptyList()
	}

	// Main thread only, apart from the two below.
	private var app: Context? = null
	private var busy = false
	private var runId = 0
	private var job: Job? = null
	private var cleanup: Job? = null
	private var pending: Pending? = null
	// The app_process subprocess: cancelling the job cannot reach it, so a cancel kills it.
	@Volatile private var process: Process? = null
	@Volatile private var lastProgressMs = 0L

	fun start(context: Context, source: PatchSource, sigBypassLevel: Int) {
		if (busy) return
		val app = context.applicationContext.also { this.app = it }
		busy = true
		val id = ++runId
		resultState.value = null
		progressState.value = Progress.Downloading(LSPORTABLE_NAME)
		job = scope.launch {
			// The last run's leftovers are cleared first, not under this run's files.
			cleanup?.join()
			try {
				patch(app, source, sigBypassLevel)
			} catch (e: CancellationException) {
				throw e
			} catch (e: Throwable) {
				process = null
				// After a cancel the killed process surfaces here as a failure: not worth reporting.
				if (busy && id == runId) fail(Result.PatchFailed(e.message ?: e.javaClass.simpleName))
			}
		}
	}

	// Stops the run and kills the subprocess; what it left is cleared once the process is gone.
	fun cancel() {
		if (!busy) return
		progressState.value = null
		job?.cancel()
		job = null
		val killed = process
		process = null
		end(killed)
	}

	// The original is gone, so the patched app can go in. With nothing patched, nothing happens.
	fun install() {
		val apks = pending?.patched?.takeIf { it.isNotEmpty() } ?: return
		val app = app ?: return
		scope.launch {
			try {
				ApkInstaller.install(app, apks, { requestQueue.trySend(Request.Confirm(it)) }, ::installed)
			} catch (e: CancellationException) {
				throw e
			} catch (e: Exception) {
				installed(ApkInstaller.Outcome.FAILED, e.message)
			}
		}
	}

	// The person has seen this result; a newer one is left for its turn.
	fun acknowledge(seen: Result) {
		resultState.compareAndSet(seen, null)
	}

	// What a run cut short left in the cache, such as a process killed with a download half done.
	fun sweep(context: Context) {
		if (busy) return
		app = context.applicationContext
		end()
	}

	private suspend fun patch(app: Context, source: PatchSource, sigBypassLevel: Int) {
		val lsportable = download(LSPORTABLE_NAME) { LSPortableRunner.downloadLSPortable(app, it) } ?: return
		val inputs = when (source) {
			is PatchSource.Installed -> source.app.apks
			is PatchSource.Release -> {
				val target = source.target
				val apk = download(target.displayName) {
					ReleaseDownloader.downloadLatest(app, target.source, target.cacheFileName, it)
				} ?: return
				listOf(apk)
			}
		}
		val run = Pending(source).also { pending = it }
		progressState.value = Progress.Patching
		run.patched = withContext(Dispatchers.IO) {
			val moduleApk = File(app.applicationInfo.sourceDir)
			LSPortableRunner.patch(app, lsportable, inputs, moduleApk, sigBypassLevel) { process = it }
		}
		process = null
		progressState.value = null

		// Only after a successful patch, so the original is never removed for nothing.
		if (LSPortableRunner.isInstalled(app, source.packageName)) {
			requestQueue.trySend(Request.Uninstall(source.packageName))
		} else {
			install()
		}
	}

	// One download: its progress, and the failure path. Null if it failed.
	private suspend fun download(name: String, fetch: suspend ((Long, Long) -> Unit) -> File?): File? {
		lastProgressMs = 0
		progressState.value = Progress.Downloading(name)
		val file = withContext(Dispatchers.IO) {
			fetch { downloaded, total -> report(name, downloaded, total) }
		}
		if (file == null) fail(Result.DownloadFailed(name))
		return file
	}

	// Called from the download thread. One update per interval whatever the file size: a per-percent
	// rate made a small file's counter run far faster than a large one's.
	private fun report(name: String, downloaded: Long, total: Long) {
		val now = SystemClock.uptimeMillis()
		if (now - lastProgressMs < PROGRESS_INTERVAL_MS) return
		lastProgressMs = now
		// Only while downloading: a late update must not overwrite the patching that follows.
		progressState.update { if (it is Progress.Downloading) Progress.Downloading(name, downloaded, total) else it }
	}

	// The system confirms the install on its own screen; the clean-up is the same whatever the outcome.
	private fun installed(outcome: ApkInstaller.Outcome, message: String?) {
		val run = pending
		when (outcome) {
			ApkInstaller.Outcome.INSTALLED -> run?.let { resultState.value = Result.Installed(it.source) }
			ApkInstaller.Outcome.FAILED -> resultState.value = Result.InstallFailed(message)
			ApkInstaller.Outcome.CANCELLED -> Unit
		}
		if (run != null) end()
	}

	private fun fail(result: Result) {
		progressState.value = null
		resultState.value = result
		end()
	}

	// Ends the run and clears the cache of what it left, with a process first waited for so that
	// apkzlib doesn't lose a temp file it is still reading.
	private fun end(killed: Process? = null) {
		pending = null
		busy = false
		val app = app ?: return
		cleanup = scope.launch(Dispatchers.IO) {
			killed?.destroy()
			try {
				killed?.waitFor()
			} catch (_: InterruptedException) {
			}
			LSPortableRunner.cleanupAllCache(app)
		}
	}

	@VisibleForTesting
	internal fun reset() {
		job?.cancel()
		job = null
		busy = false
		pending = null
		progressState.value = null
		resultState.value = null
		while (requestQueue.tryReceive().isSuccess) Unit
	}

	@VisibleForTesting
	internal fun simulate(progress: Progress?, result: Result? = null) {
		busy = progress != null
		progressState.value = progress
		resultState.value = result
	}

	@VisibleForTesting
	internal val running: Boolean get() = busy
}
