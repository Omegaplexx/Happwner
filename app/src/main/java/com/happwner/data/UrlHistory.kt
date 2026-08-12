package com.happwner.data

import android.content.Context
import android.util.Log
import java.io.File
import java.io.RandomAccessFile

// Append-only store for captured subscription URLs.
object UrlHistory {

    private const val TAG = "Happwner:History"
    private const val FILE_NAME = "url_history.log"

    // Legacy preference this store migrates from, and its separator.
    private const val LEGACY_KEY = "url_history_list"
    private const val LEGACY_DELIMITER = "|||"

    // How much of the file to pull in per backwards read.
    private const val READ_CHUNK_BYTES = 64 * 1024
    // Longest single entry accepted; see append.
    private const val MAX_ENTRY_CHARS = 8 * 1024

    // Guards the file against concurrent access: ContentProvider.call runs on a binder thread and
    // several hooked apps can capture at once, while the UI reads on the main thread.
    private val lock = Any()

    private fun file(context: Context) = File(context.filesDir, FILE_NAME)

    // One page of history, newest first, plus the byte offset to continue from.
    data class Page(val entries: List<String>, val nextOffset: Long) {
        val hasMore: Boolean get() = nextOffset > 0L
    }

    // Appends one URL. Rejects anything containing a line break rather than escaping it: no valid
    // URL contains one, and it would split one entry into two on the way out.
    fun append(context: Context, rawUrl: String): Boolean {
        val url = rawUrl.trim()
        if (url.isEmpty()) return false
        if (url.any { it == '\n' || it == '\r' }) return false
        // Anything may call this through the settings provider, and reading a page carries a
        // partial line between chunks until its start is found - so one enormous entry would be
        if (url.length > MAX_ENTRY_CHARS) return false

        synchronized(lock) {
            migrateLegacyIfNeeded(context)
            return try {
                appendTo(file(context), url)
                true
            } catch (e: Exception) {
                Log.w(TAG, "append failed: ${e.javaClass.simpleName}: ${e.message}")
                false
            }
        }
    }

    // File-level append, split out so the storage format can be tested without a Context.
    internal fun appendTo(f: File, url: String) {
        f.appendText(url + "\n", Charsets.UTF_8)
    }

    // Reads up to limit entries ending at endOffset, newest first. Pass `endOffset = -1` for the
    // newest page, then feed Page.nextOffset back in to page further back.
    fun readPage(context: Context, limit: Int, endOffset: Long = -1L): Page {
        if (limit <= 0) return Page(emptyList(), 0L)
        synchronized(lock) {
            migrateLegacyIfNeeded(context)
            val f = file(context)
            if (!f.exists()) return Page(emptyList(), 0L)

            return readPageFrom(f, limit, endOffset)
        }
    }

    // File-level backwards read, split out so the paging arithmetic can be tested without a
    // Context. At most limit lines ending at endOffset, newest first.
    internal fun readPageFrom(f: File, limit: Int, endOffset: Long = -1L): Page {
        if (limit <= 0 || !f.exists()) return Page(emptyList(), 0L)
        return try {
            RandomAccessFile(f, "r").use { raf ->
                var end = if (endOffset < 0L) raf.length() else endOffset.coerceAtMost(raf.length())
                if (end <= 0L) return Page(emptyList(), 0L)

                val out = ArrayList<String>(limit)
                // Where the oldest returned line begins, as an absolute file offset - exactly where
                // the next page has to end.
                var oldestStart = end
                // Bytes of a line whose start has not been reached yet: the chunk boundary can land
                // mid-line, so the head of one chunk has to be carried into the next read.
                var carry = ByteArray(0)

                while (end > 0L && out.size < limit) {
                    val size = minOf(READ_CHUNK_BYTES.toLong(), end).toInt()
                    val start = end - size
                    val buf = ByteArray(size)
                    raf.seek(start)
                    raf.readFully(buf)

                    // carry holds the bytes immediately after this chunk, so
                    // merged is contiguous and merged[i] sits at start + i.
                    val merged = if (carry.isEmpty()) buf else buf + carry
                    // Walk the buffer backwards, cutting at each newline.
                    var i = merged.size - 1
                    var lineEnd = merged.size
                    while (i >= 0 && out.size < limit) {
                        if (merged[i] == '\n'.code.toByte()) {
                            val lineStart = i + 1
                            if (lineEnd > lineStart) {
                                out.add(String(merged, lineStart, lineEnd - lineStart, Charsets.UTF_8))
                                oldestStart = start + lineStart
                            }
                            lineEnd = i
                        }
                        i--
                    }
                    carry = if (out.size >= limit) {
                        ByteArray(0)
                    } else {
                        // Everything before the last cut belongs to a line
                        // that continues into the previous chunk.
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
        } catch (e: Exception) {
            Log.w(TAG, "read failed: ${e.javaClass.simpleName}: ${e.message}")
            Page(emptyList(), 0L)
        }
    }

    // Drops the whole history, including anything left of the legacy preference.
    fun clear(context: Context) {
        synchronized(lock) {
            try { file(context).delete() } catch (_: Exception) {}
            try {
                PrefsManager.getSafePrefs(context).edit().remove(LEGACY_KEY).apply()
            } catch (_: Exception) {}
        }
    }

    // True when there is nothing to show, so the empty-state label can be decided without a read.
    fun isEmpty(context: Context): Boolean {
        synchronized(lock) {
            migrateLegacyIfNeeded(context)
            val f = file(context)
            return !f.exists() || f.length() == 0L
        }
    }

    // Moves a pre-existing "|||" history into the file, once. Order is reversed on the way in: the
    // preference kept newest first, the file keeps oldest first so appends stay at the end.
    private fun migrateLegacyIfNeeded(context: Context) {
        val prefs = try { PrefsManager.getSafePrefs(context) } catch (_: Exception) { return }
        val legacy = try { prefs.getString(LEGACY_KEY, null) } catch (_: Exception) { null }
        if (legacy.isNullOrEmpty()) return

        try {
            val entries = legacy.split(LEGACY_DELIMITER)
                .map { it.trim() }
                .filter { it.isNotEmpty() && it.none { c -> c == '\n' || c == '\r' } }
            if (entries.isNotEmpty()) {
                val f = file(context)
                // Oldest first, so the newest ends up at the end of the file.
                val text = entries.asReversed().joinToString("\n", postfix = "\n")
                f.appendText(text, Charsets.UTF_8)
            }
            Log.i(TAG, "migrated ${entries.size} legacy history entries")
        } catch (e: Exception) {
            Log.w(TAG, "migration failed: ${e.javaClass.simpleName}: ${e.message}")
            // Leave the preference in place so nothing is lost; a later call retries.
            return
        }
        try { prefs.edit().remove(LEGACY_KEY).apply() } catch (_: Exception) {}
    }
}
