package com.happwner.data

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// The paging arithmetic of the URL history. `appendTo` and `readPageFrom` are split out of the
// Context-taking API for exactly this - the backwards read is the part that can be subtly wrong.
class UrlHistoryPagingTest {

	private fun tempFile(): File =
		File.createTempFile("urlhistory", ".log").also { it.deleteOnExit(); it.delete() }

	// Lays entries into the file directly, newest appended last, so the reader can be exercised
	// against any content. The cap that appendTo enforces is covered by its own tests, below.
	private fun write(file: File, entries: List<String>) {
		file.writeText(entries.joinToString("\n", postfix = "\n"), Charsets.UTF_8)
	}

	// Walks every page from newest to oldest and returns them concatenated; each offset handed back
	// must lie on a line boundary.
	private fun readAll(file: File, pageSize: Int): List<String> {
		val out = ArrayList<String>()
		var offset = -1L
		var guard = 0
		while (true) {
			val page = UrlHistory.readPageFrom(file, pageSize, offset)
			out.addAll(page.entries)
			if (!page.hasMore || page.entries.isEmpty()) break
			offset = page.nextOffset
			val head = file.readBytes().copyOfRange(0, offset.toInt()).toString(Charsets.UTF_8)
			assertTrue("offset $offset cuts a line: ...${head.takeLast(12)}", head.isEmpty() || head.endsWith("\n"))
			if (++guard > 10_000) throw AssertionError("paging did not terminate")
		}
		return out
	}

	@Test
	fun `a file is read newest first whatever its shape`() {
		val file = tempFile()
		assertEquals(emptyList<String>(), UrlHistory.readPageFrom(file, 10).entries)
		file.writeText("")
		UrlHistory.readPageFrom(file, 10).let {
			assertEquals(emptyList<String>(), it.entries)
			assertFalse(it.hasMore)
		}
		write(file, listOf("http://a", "http://b", "http://c"))
		val page = UrlHistory.readPageFrom(file, 10)
		assertEquals(listOf("http://c", "http://b", "http://a"), page.entries)
		assertFalse("the whole file fitted in one page", page.hasMore)
		assertEquals(emptyList<String>(), UrlHistory.readPageFrom(file, 0).entries)
		assertEquals(emptyList<String>(), UrlHistory.readPageFrom(file, -1).entries)
		// Nothing this class writes ends without a newline, but a truncated write would, and losing
		// the newest entry there is worse than reading it. A blank line carries no entry and is skipped
		// without shifting the offsets.
		file.writeText("http://a\n\nhttp://b\n\n\nhttp://c", Charsets.UTF_8)
		assertEquals(listOf("http://c", "http://b", "http://a"), readAll(file, 1))
	}

	@Test
	fun `paging returns every entry exactly once, at any page size`() {
		val entries = (1..97).map { "https://host$it.example.com/sub?id=$it" }
		val file = tempFile()
		write(file, entries)
		val expected = entries.asReversed()
		for (pageSize in listOf(1, 2, 3, 5, 10, 96, 97, 98, 500)) {
			assertEquals("page size $pageSize", expected, readAll(file, pageSize))
		}
	}

	@Test
	fun `lines across a read chunk are rejoined, and so are characters wider than a byte`() {
		// The reader walks the file backwards 64 KiB at a time, so a file larger than one chunk
		// puts a line across the boundary; an entry longer than a chunk spans several.
		val entries = (1..800).map { "https://example.com/" + "p".repeat(101) + "/$it" }
		val file = tempFile()
		write(file, entries)
		assertTrue("the file must exceed one read chunk", file.length() > 64 * 1024)
		assertEquals(entries.asReversed(), readAll(file, 250))
		assertEquals(entries.asReversed(), UrlHistory.readPageFrom(file, 800).entries)
		val long = "https://example.com/" + "q".repeat(70_000)
		write(file, listOf("http://before", long, "http://after"))
		assertEquals(listOf("http://after", long, "http://before"), readAll(file, 2))
		// The reader cuts on the 0x0A byte, which no UTF-8 continuation byte collides with, but
		// nextOffset counts bytes, so a wider character is where an off-by-one would show.
		val wide = listOf(
			"https://пример.рф/путь?ключ=значение",
			"https://例え.jp/パス",
			"https://example.com/\uD83D\uDE00"
		)
		write(file, wide)
		assertEquals(wide.asReversed(), readAll(file, 1))
		assertEquals(wide.asReversed(), readAll(file, 2))
	}

	@Test
	fun `appending past the cap drops whole oldest entries and keeps the newest, a short file is not rewritten`() {
		// Append well past 15k characters as many small entries, then confirm the file is back
		// within the cap, no partial line is at the front, and the newest entry is still there.
		val file = tempFile()
		// The common path appends without trimming: a short file keeps exactly what was written.
		UrlHistory.appendTo(file, "http://a")
		UrlHistory.appendTo(file, "http://b")
		assertEquals("http://a\nhttp://b\n", file.readText(Charsets.UTF_8))
		file.delete()
		val entries = (0 until 4000).map { "http://example.com/subscription/$it" }
		for (e in entries) UrlHistory.appendTo(file, e)
		val text = file.readText(Charsets.UTF_8)
		assertTrue("file stays within the cap, was ${text.length}", text.length <= 15_000)
		assertTrue("no partial line at the front", text.startsWith("http://"))
		assertFalse("no temporary file is left behind", File(file.path + ".tmp").exists())
		val back = readAll(file, 10_000)
		assertEquals("newest entry is kept", entries.last(), back.first())
		assertTrue("older entries were dropped", back.size < entries.size)
		assertEquals("what remains is an unbroken newest-first tail",
			entries.subList(entries.size - back.size, entries.size).asReversed(), back)
	}

	@Test
	fun `an offset held across a trim still leads to the next older entry, one into what was trimmed to none`() {
		// The screen keeps the offset its last page ended at. A capture that trims the front in the
		// meantime must not turn that offset into the middle of some other line.
		val file = tempFile()
		var trimmed = 0L
		for (i in 0 until 1000) trimmed += UrlHistory.appendTo(file, "http://example.com/s/$i")
		val first = UrlHistory.readPageAt(file, 50, -1L, trimmed)
		assertEquals("http://example.com/s/950", first.entries.last())
		// Long enough that it has to trim, whatever the file held before it.
		val dropped = UrlHistory.appendTo(file, "http://example.com/new/" + "x".repeat(80))
		assertTrue("the capture must have trimmed the front", dropped > 0L)
		trimmed += dropped
		val next = UrlHistory.readPageAt(file, 50, first.nextOffset, trimmed)
		assertEquals("http://example.com/s/949", next.entries.first())
		assertEquals("http://example.com/s/900", next.entries.last())
		// An offset into what was trimmed has nothing older left.
		val gone = UrlHistory.readPageAt(file, 10, 5L, 100L)
		assertFalse(gone.hasMore)
		assertTrue(gone.entries.isEmpty())
	}

	@Test
	fun `a file grown large before the cap is cut down to the newest entries`() {
		// What a long-time user carries into the update: far more than the cap, written with no
		// trimming at all. Only a tail is read, and the newest entries come out whole.
		val file = tempFile()
		write(file, (0 until 100_000).map { "http://example.com/old/$it" })
		assertTrue("the file starts far over the cap", file.length() > 1_000_000)
		UrlHistory.appendTo(file, "http://example.com/newest")
		val text = file.readText(Charsets.UTF_8)
		assertTrue("back within the cap, was ${text.length}", text.length <= 15_000)
		val back = readAll(file, 10_000)
		assertEquals("http://example.com/newest", back.first())
		assertEquals("http://example.com/old/99999", back[1])
		assertTrue("every entry is whole", back.all { it.startsWith("http://example.com/") })
	}

	@Test
	fun `a window that starts inside a multi-byte character leaves no broken entry`() {
		// Two-byte Cyrillic makes the byte window land inside characters; whatever it cuts
		// through must go with the first, partial line and never show up as a broken entry.
		val file = tempFile()
		write(file, (0 until 3000).map { "http://пример.рф/подписка/$it" })
		// The newest entry's length sets where the window starts; pick one that puts the start on
		// a continuation byte (10xxxxxx), so the case is hit every run, not by luck.
		val old = file.readBytes()
		val newest = (0..15).map { "http://пример.рф/новая" + "x".repeat(it) }.first {
			val start = old.size + it.toByteArray(Charsets.UTF_8).size + 1 - (15_000 * 3 + 1)
			(old[start].toInt() and 0xC0) == 0x80
		}
		UrlHistory.appendTo(file, newest)
		val back = readAll(file, 10_000)
		assertEquals(newest, back.first())
		assertTrue("no replacement character anywhere", back.none { '\uFFFD' in it })
		assertTrue("every entry is whole", back.all { it.startsWith("http://пример.рф/") })
	}
}
