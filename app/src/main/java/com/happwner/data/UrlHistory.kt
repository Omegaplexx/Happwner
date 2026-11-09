package com.happwner.data

import android.content.Context
import android.util.Log
import androidx.core.content.edit
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile

// Store for captured subscription URLs: appended at the end, trimmed off the front at a cap.
object UrlHistory {

	private const val TAG = "Happwner:History"
	private const val FILE_NAME = "url_history.log"

	private const val LEGACY_KEY = "url_history_list"
	private const val LEGACY_DELIMITER = "|||"

	private const val READ_CHUNK_BYTES = 64 * 1024
	// Longest single entry accepted; see append.
	private const val MAX_ENTRY_CHARS = 8 * 1024

	// Anything can append through the settings provider, so this bounds growth: past it, the
	// oldest whole lines go. 15k matches max_display_chars, the profile screen's own limit.
	private const val MAX_TOTAL_CHARS = 15_000

	// ContentProvider.call runs on a binder thread and several hooked apps can capture at once,
	// while the UI reads on the main thread.
	private val lock = Any()

	// Bytes trimmed off the front in this process. Offsets handed out are logical - file offset
	// plus this - so a trim never moves one the screen holds; a new process just starts over.
	private var trimmedBytes = 0L

	private fun file(context: Context) = File(context.filesDir, FILE_NAME)

	// One page of history, newest first, plus the offset to continue from.
	data class Page(val entries: List<String>, val nextOffset: Long) {
		val hasMore: Boolean get() = nextOffset > 0L
	}

	// No valid URL contains a line break, and letting one through would split an entry in two.
	fun append(context: Context, rawUrl: String): Boolean {
		val url = rawUrl.trim()
		if (url.isEmpty()) return false
		if (url.any { it == '\n' || it == '\r' }) return false
		// A partial line is held in memory whole between chunks until its start is found, so an
		// unbounded entry here would be an unbounded read later.
		if (url.length > MAX_ENTRY_CHARS) return false

		synchronized(lock) {
			migrateLegacyIfNeeded(context)
			return try {
				trimmedBytes += appendTo(file(context), url)
				true
			} catch (error: Exception) {
				Log.w(TAG, "append failed: ${error.javaClass.simpleName}: ${error.message}")
				false
			}
		}
	}

	// Split out so the storage format can be tested without a Context.
	internal fun appendTo(file: File, url: String): Long {
		file.appendText(url + "\n", Charsets.UTF_8)
		return trimToCap(file)
	}

	// Drops whole lines off the front, oldest first, until back within the cap; returns bytes trimmed.
	private fun trimToCap(file: File): Long {
		// UTF-8 never takes fewer bytes than characters, so a file within the cap in bytes is
		// within it in characters too - the common path skips reading the file at all.
		val before = file.length()
		if (before <= MAX_TOTAL_CHARS) return 0L
		val tempFile = File(file.path + ".tmp")
		try {
			// Only a tail that can hold the cap is read (3 bytes/char worst case) - a file from
			// before the cap existed can be far larger than what survives. A character the window
			// starts inside of lands before the first newline, and goes with that line.
			val window = minOf(before, MAX_TOTAL_CHARS * 3L + 1)
			val bytes = ByteArray(window.toInt())
			RandomAccessFile(file, "r").use { it.seek(before - window); it.readFully(bytes) }
			val text = String(bytes, Charsets.UTF_8)
			if (text.length <= MAX_TOTAL_CHARS) return 0L
			// Cut after the first newline that leaves the rest within the cap - whole lines only.
			val kept = text.substring(text.indexOf('\n', text.length - MAX_TOTAL_CHARS - 1) + 1)
			// Written aside and renamed over, so being killed mid-write cannot cost the history.
			tempFile.writeText(kept, Charsets.UTF_8)
			if (tempFile.renameTo(file)) return before - file.length()
		} catch (_: IOException) {
			// The entry is already stored; the file just stays over the cap until the next append.
		} finally {
			tempFile.delete()
		}
		return 0L
	}

	// Pass endOffset = -1 for the newest page, then feed Page.nextOffset back in to page further back.
	fun readPage(context: Context, limit: Int, endOffset: Long): Page {
		if (limit <= 0) return Page(emptyList(), 0L)
		synchronized(lock) {
			migrateLegacyIfNeeded(context)
			val historyFile = file(context)
			if (!historyFile.exists()) return Page(emptyList(), 0L)

			return readPageAt(historyFile, limit, endOffset, trimmedBytes)
		}
	}

	// readPageFrom by a logical offset (file offset plus bytes trimmed so far). An offset from
	// before a trim that falls in what was trimmed has nothing older left to read.
	internal fun readPageAt(file: File, limit: Int, endOffset: Long, trimmed: Long): Page {
		if (endOffset >= 0L && endOffset <= trimmed) return Page(emptyList(), 0L)
		val page = readPageFrom(file, limit, if (endOffset < 0L) -1L else endOffset - trimmed)
		return if (page.nextOffset > 0L) page.copy(nextOffset = page.nextOffset + trimmed) else page
	}

	// Split out so the paging arithmetic can be tested without a Context.
	internal fun readPageFrom(file: File, limit: Int, endOffset: Long = -1L): Page {
		if (limit <= 0 || !file.exists()) return Page(emptyList(), 0L)
		return try {
			RandomAccessFile(file, "r").use { raf ->
				var end = if (endOffset < 0L) raf.length() else endOffset.coerceAtMost(raf.length())
				if (end <= 0L) return Page(emptyList(), 0L)

				val out = ArrayList<String>(limit)
				// Absolute file offset where the oldest returned line begins - where the next page ends.
				var oldestStart = end
				// A line whose start hasn't been reached yet - the chunk boundary can land mid-line.
				var carry = ByteArray(0)

				while (end > 0L && out.size < limit) {
					val size = minOf(READ_CHUNK_BYTES.toLong(), end).toInt()
					val start = end - size
					val buf = ByteArray(size)
					raf.seek(start)
					raf.readFully(buf)

					val merged = if (carry.isEmpty()) buf else buf + carry
					var position = merged.size - 1
					var lineEnd = merged.size
					while (position >= 0 && out.size < limit) {
						if (merged[position] == '\n'.code.toByte()) {
							val lineStart = position + 1
							if (lineEnd > lineStart) {
								out.add(String(merged, lineStart, lineEnd - lineStart, Charsets.UTF_8))
								oldestStart = start + lineStart
							}
							lineEnd = position
						}
						position--
					}
					carry = if (out.size >= limit) {
						ByteArray(0)
					} else {
						// Belongs to a line that continues into the previous chunk.
						merged.copyOfRange(0, lineEnd)
					}
					end = start

					if (end == 0L && out.size < limit && carry.isNotEmpty()) {
						// First line of the file has no newline before it.
						val first = String(carry, Charsets.UTF_8)
						if (first.isNotEmpty()) {
							out.add(first)
							oldestStart = 0L
						}
					}
				}

				Page(out, if (out.isEmpty()) 0L else oldestStart)
			}
		} catch (error: Exception) {
			Log.w(TAG, "read failed: ${error.javaClass.simpleName}: ${error.message}")
			Page(emptyList(), 0L)
		}
	}

	fun clear(context: Context) {
		synchronized(lock) {
			val historyFile = file(context)
			val length = historyFile.length()
			// Counted as trimmed, so an offset handed out before the clear reads as nothing older.
			if (historyFile.delete()) trimmedBytes += length
			try {
				PrefsManager.getSafePrefs(context).edit { remove(LEGACY_KEY) }
			} catch (_: Exception) {}
		}
	}

	// Moves a pre-existing "|||" history into the file, once, reversing order: the preference
	// kept newest first, the file keeps oldest first so appends stay at the end.
	private fun migrateLegacyIfNeeded(context: Context) {
		val prefs = try { PrefsManager.getSafePrefs(context) } catch (_: Exception) { return }
		val legacy = try { prefs.getString(LEGACY_KEY, null) } catch (_: Exception) { null }
		if (legacy.isNullOrEmpty()) return

		try {
			// Same rules as append, so the trim below can always keep the newest entry.
			val entries = legacy.split(LEGACY_DELIMITER)
				.map { it.trim() }
				.filter { it.isNotEmpty() && it.length <= MAX_ENTRY_CHARS }
				.filter { entry -> entry.none { it == '\n' || it == '\r' } }
			if (entries.isNotEmpty()) {
				val historyFile = file(context)
				val text = entries.asReversed().joinToString("\n", postfix = "\n")
				historyFile.appendText(text, Charsets.UTF_8)
				trimmedBytes += trimToCap(historyFile)
			}
			Log.i(TAG, "migrated ${entries.size} legacy history entries")
		} catch (error: Exception) {
			Log.w(TAG, "migration failed: ${error.javaClass.simpleName}: ${error.message}")
			// Leave the preference in place so nothing is lost; a later call retries.
			return
		}
		try { prefs.edit { remove(LEGACY_KEY) } } catch (_: Exception) {}
	}
}
