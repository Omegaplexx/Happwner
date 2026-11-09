package com.happwner.patcher

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Build
import android.os.Process
import android.util.LruCache
import androidx.core.graphics.createBitmap
import com.happwner.R
import java.io.File
import java.text.Collator
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

// apks is the base apk first, then its splits: the set LSPatch patches and the installer takes.
data class InstalledApp(
	val packageName: String,
	val label: String,
	val versionName: String,
	val apks: List<File>,
	val updatedAt: Long
) {
	// What the search matches against, lowercased once instead of on every keystroke.
	val searchKey: String = "$label\n$packageName".lowercase()
}

// The person's own apps, read off the main thread by a small low-priority pool so that reading
// them in advance never competes with the screen.
object InstalledApps {

	internal val dispatcher = Executors.newFixedThreadPool(2) { task ->
		Thread({
			Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)
			task.run()
		}, "installed-apps").apply { isDaemon = true }
	}.asCoroutineDispatcher()

	private val scope = CoroutineScope(SupervisorJob() + dispatcher)
	private var latest: Deferred<List<InstalledApp>>? = null

	// Starts reading the list afresh; the warm-up and the list page then share this one read.
	@Synchronized
	fun refresh(context: Context): Deferred<List<InstalledApp>> {
		val app = context.applicationContext
		return scope.async { read(app) }.also { latest = it }
	}

	// An empty list if the read failed: the page then says nothing was found.
	suspend fun list(context: Context): List<InstalledApp> {
		val read = synchronized(this) { latest } ?: refresh(context)
		return try {
			read.await()
		} catch (e: CancellationException) {
			throw e
		} catch (_: Exception) {
			emptyList()
		}
	}

	private suspend fun read(context: Context): List<InstalledApp> = coroutineScope {
		val pm = context.packageManager
		val candidates = installedPackages(pm).mapNotNull { info ->
			val app = info.applicationInfo ?: return@mapNotNull null
			val own = info.packageName == context.packageName
			val isSystem = app.flags and ApplicationInfo.FLAG_SYSTEM != 0
			if (own || isSystem || !File(app.sourceDir).canRead()) null else info to app
		}
		val collator = Collator.getInstance()
		// Reading a label opens the app's own resources, the slow part, so it runs in parallel.
		candidates
			.map { (info, app) -> async { describe(pm, info, app) } }
			.awaitAll()
			.sortedWith { a, b -> collator.compare(a.label, b.label) }
	}

	private fun describe(pm: PackageManager, info: PackageInfo, app: ApplicationInfo) = InstalledApp(
		packageName = info.packageName,
		label = app.loadLabel(pm).toString(),
		versionName = info.versionName ?: "?",
		apks = (listOf(app.sourceDir) + app.splitSourceDirs.orEmpty()).map { File(it) },
		updatedAt = info.lastUpdateTime
	)

	@Suppress("DEPRECATION")
	private fun installedPackages(pm: PackageManager): List<PackageInfo> =
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
			pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
		} else {
			pm.getInstalledPackages(0)
		}
}

// Icons drawn once at the size of a row's icon and kept, so scrolling only sets a finished picture.
object AppIcons {

	private val cache = object : LruCache<String, Bitmap>(budgetBytes()) {
		override fun sizeOf(key: String, value: Bitmap) = value.byteCount
	}
	// One load per icon at a time: a row and the prefetch asking for the same one share the work.
	private val locks = ConcurrentHashMap<String, Mutex>()

	private fun budgetBytes() = minOf(Runtime.getRuntime().maxMemory() / 16, 8L * 1024 * 1024).toInt()

	// Tied to the app's last update, so a new icon replaces the old one.
	private fun key(app: InstalledApp) = "${app.packageName}:${app.updatedAt}"

	fun cached(app: InstalledApp): Bitmap? = cache.get(key(app))

	suspend fun load(context: Context, app: InstalledApp): Bitmap {
		val key = key(app)
		cache.get(key)?.let { return it }
		return locks.getOrPut(key) { Mutex() }.withLock {
			cache.get(key) ?: withContext(InstalledApps.dispatcher) {
				draw(context.applicationContext, app)
			}.also { cache.put(key, it) }
		}
	}

	// Loads the icons one after another, so a row on screen never waits behind more than one.
	suspend fun prefetch(context: Context, apps: List<InstalledApp>) {
		for (app in apps) load(context, app)
	}

	// An app removed since the list was read, or an icon that will not draw, leaves a blank square.
	private fun draw(context: Context, app: InstalledApp): Bitmap {
		val sizePx = context.resources.getDimensionPixelSize(R.dimen.app_icon_size)
		val bitmap = createBitmap(sizePx, sizePx)
		try {
			val icon = context.packageManager.getApplicationIcon(app.packageName)
			icon.setBounds(0, 0, sizePx, sizePx)
			icon.draw(Canvas(bitmap))
		} catch (_: PackageManager.NameNotFoundException) {
		} catch (_: RuntimeException) {
		}
		return bitmap
	}
}
