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

    private fun write(f: File, entries: List<String>) {
        for (e in entries) UrlHistory.appendTo(f, e)
    }

    // Walks every page from newest to oldest and returns them concatenated.
    private fun readAll(f: File, pageSize: Int): List<String> {
        val out = ArrayList<String>()
        var offset = -1L
        var guard = 0
        while (true) {
            val page = UrlHistory.readPageFrom(f, pageSize, offset)
            out.addAll(page.entries)
            if (!page.hasMore || page.entries.isEmpty()) break
            offset = page.nextOffset
            if (++guard > 10_000) throw AssertionError("paging did not terminate")
        }
        return out
    }

    // ------------------------------------------------------------- basics ----

    @Test
    fun `an empty or missing file yields an empty page`() {
        val f = tempFile()
        UrlHistory.readPageFrom(f, 10).let {
            assertEquals(emptyList<String>(), it.entries)
            assertFalse(it.hasMore)
        }
        f.writeText("")
        UrlHistory.readPageFrom(f, 10).let {
            assertEquals(emptyList<String>(), it.entries)
            assertFalse(it.hasMore)
        }
    }

    @Test
    fun `entries come back newest first`() {
        val f = tempFile()
        write(f, listOf("http://a", "http://b", "http://c"))
        val page = UrlHistory.readPageFrom(f, 10)
        assertEquals(listOf("http://c", "http://b", "http://a"), page.entries)
        assertFalse("the whole file fitted in one page", page.hasMore)
    }

    @Test
    fun `a limit of zero or less reads nothing`() {
        val f = tempFile()
        write(f, listOf("http://a"))
        assertEquals(emptyList<String>(), UrlHistory.readPageFrom(f, 0).entries)
        assertEquals(emptyList<String>(), UrlHistory.readPageFrom(f, -1).entries)
    }

    // -------------------------------------------------------------- paging ----

    @Test
    fun `paging returns every entry exactly once, at any page size`() {
        val entries = (1..97).map { "https://host$it.example.com/sub?id=$it" }
        val f = tempFile()
        write(f, entries)
        val expected = entries.asReversed()
        for (pageSize in listOf(1, 2, 3, 5, 10, 96, 97, 98, 500)) {
            assertEquals("page size $pageSize", expected, readAll(f, pageSize))
        }
    }

    @Test
    fun `the offset handed back lands on a line boundary`() {
        val entries = (1..20).map { "http://h$it" }
        val f = tempFile()
        write(f, entries)
        var offset = -1L
        repeat(4) {
            val page = UrlHistory.readPageFrom(f, 5, offset)
            offset = page.nextOffset
            // Everything before the offset must be whole lines.
            val head = f.readBytes().copyOfRange(0, offset.toInt()).toString(Charsets.UTF_8)
            assertTrue(
                "offset $offset cuts a line: ...${head.takeLast(12)}",
                head.isEmpty() || head.endsWith("\n")
            )
        }
        assertEquals("after four pages of five, nothing is left", 0L, offset)
    }

    // ----------------------------------------------- the chunk boundary ----

    @Test
    fun `lines spanning a read chunk are rejoined`() {
        // The reader walks the file backwards 64 KiB at a time, so a file larger than one chunk
        // puts a line across the boundary.
        val entries = (1..800).map { "https://example.com/" + "p".repeat(101) + "/$it" }
        val f = tempFile()
        write(f, entries)
        assertTrue("the file must exceed one read chunk", f.length() > 64 * 1024)
        assertEquals(entries.asReversed(), readAll(f, 250))
        // And a single page that reaches back across the boundary.
        assertEquals(entries.asReversed(), UrlHistory.readPageFrom(f, 800).entries)
    }

    @Test
    fun `an entry longer than a whole read chunk survives`() {
        val long = "https://example.com/" + "q".repeat(70_000)
        val f = tempFile()
        write(f, listOf("http://before", long, "http://after"))
        assertEquals(listOf("http://after", long, "http://before"), readAll(f, 2))
    }

    // ------------------------------------------------------------ unicode ----

    @Test
    fun `multi-byte characters are not split by the byte-level reader`() {
        // The reader cuts on the 0x0A byte, which no UTF-8 continuation byte collides with - but nextOffset
        // counts bytes, so a character wider than one byte is where an off-by-one would show.
        val entries = listOf(
            "https://пример.рф/путь?ключ=значение",
            "https://例え.jp/パス",
            "https://example.com/\uD83D\uDE00"
        )
        val f = tempFile()
        write(f, entries)
        assertEquals(entries.asReversed(), readAll(f, 1))
        assertEquals(entries.asReversed(), readAll(f, 2))
    }

    // ---------------------------------------------------------- robustness ----

    @Test
    fun `a file left without a trailing newline still reads`() {
        // Nothing this class writes ends without one, but a truncated write or a hand-edited file
        // would - and losing the newest entry there is worse than reading it.
        val f = tempFile()
        f.writeText("http://a\nhttp://b\nhttp://c", Charsets.UTF_8)
        assertEquals(listOf("http://c", "http://b", "http://a"), readAll(f, 10))
    }

    @Test
    fun `blank lines do not shift the paging offset`() {
        // A blank line carries no entry, so it is skipped on the way out. The offset arithmetic
        // derives from the entries returned, so a skipped line is a byte it does not account for.
        val f = tempFile()
        f.writeText("http://a\n\nhttp://b\n\n\nhttp://c\n", Charsets.UTF_8)
        assertEquals(listOf("http://c", "http://b", "http://a"), readAll(f, 1))
    }
}
