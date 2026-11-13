package com.happwner.bridge

import android.util.Log
import com.happwner.client.HappCrypto
import com.happwner.data.HappParams
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// How a subscription is fetched, for the bridge and the app's screen alike: x-hwid and User-Agent sent, redirects
// followed one hop at a time, a large body taking its turn, the answer decrypted, one repeat for a named User-Agent.
object SubscriptionFetch {
	private const val LOG_TAG = "Happwner:Fetch"

	// Largest subscription accepted; any real one is far smaller.
	private const val MAX_BODY_BYTES = 32L * 1024 * 1024

	// Past this size a subscription is large, and large ones take turns: whatever else is in
	// flight, only one at a time holds a large body and what converting it makes.
	internal const val LARGE_BODY_BYTES = 1L * 1024 * 1024

	// Longest a large subscription waits for its turn, download paused meanwhile. A server may give up on a stalled
	// reader (a minute is common) unseen in the body, so past this the request is refused and the client can ask again.
	private const val LARGE_TURN_WAIT_MS = 30_000L

	// How long the body of a single fetch may take to arrive in total, however it is paced.
	private const val FETCH_BUDGET_MS = 120_000L

	// How much of a refusal's page is read, and how much of its words are kept.
	private const val ERROR_BODY_BYTES = 8 * 1024
	private const val ERROR_TEXT_CHARS = 200

	// The number HttpURLConnection allowed itself, so a chain that works today still works.
	private const val MAX_REDIRECTS = 20

	// Not 304 (unchanged) or 305 (named a proxy, dead for twenty years).
	private val REDIRECT_CODES = setOf(300, 301, 302, 303, 307, 308)

	// The bridge's two timeouts; see Timeouts.
	private const val BRIDGE_CONNECT_MS = 15_000
	private const val BRIDGE_READ_MS = 60_000

	// Reaching the server, waiting for its first byte, the body's budget plus one read that may
	// run past it, and the wait for a turn (which the budget gives back).
	internal const val LONGEST_FETCH_MS =
		BRIDGE_CONNECT_MS + BRIDGE_READ_MS + FETCH_BUDGET_MS + BRIDGE_READ_MS + LARGE_TURN_WAIT_MS

	// Per read, not the whole download, so a large subscription arriving steadily never trips it.
	// The bridge's own; a screen a person is watching passes shorter ones.
	data class Timeouts(val connectMs: Int = BRIDGE_CONNECT_MS, val readMs: Int = BRIDGE_READ_MS)

	// status is the site's own, 0 when it never answered. An error's body is its text, "Error: " first.
	data class Response(
		val body: String,
		val headers: Map<String, List<String>>,
		val isError: Boolean,
		val status: Int
	)

	// What the bridge answers a failed fetch with: the site's own error status, else a bad gateway.
	fun bridgeStatusFor(response: Response): Int =
		if (response.status in 400..599) response.status else HttpURLConnection.HTTP_BAD_GATEWAY

	// Already decrypted, plus the subscription's own User-Agent once a request actually carried it.
	data class Result(val resp: Response, val decrypted: HappCrypto.Result, val subUa: String?)

	// A request's claim on the turn, taken past LARGE_BODY_BYTES and held until closed. One claim covers both fetches
	// of a User-Agent retry, so the second never waits on the first. Used from one place at a time.
	class LargeTurn(private val waitMs: Long = LARGE_TURN_WAIT_MS) : Closeable {
		@Volatile
		private var held = false

		// Blocks until the turn is this request's, and returns how long that took, in nanoseconds.
		internal fun take(): Long {
			if (held) return 0
			val asked = System.nanoTime()
			if (!turns.tryAcquire(waitMs, TimeUnit.MILLISECONDS)) {
				throw IOException("Another large subscription is being processed, try again")
			}
			held = true
			return System.nanoTime() - asked
		}

		// Closing twice lets go once: a second release would hand out a turn that is not there.
		override fun close() {
			if (!held) return
			held = false
			turns.release()
		}

		private companion object {
			// One turn, handed out in the order it was asked for.
			val turns = Semaphore(1, true)
		}
	}

	// A subscription can name the User-Agent it wants and give a shorter list to anything else, so the request is
	// repeated with that name and only the second answer kept. The caller closes the turn claim once the answer is out.
	suspend fun fetchHonouringSubUa(
		url: String,
		hwid: String,
		userAgent: String,
		preferSubscriptionUa: Boolean,
		fromNetwork: Boolean,
		turn: LargeTurn,
		timeouts: Timeouts = Timeouts()
	): Result {
		val first = fetch(url, hwid, userAgent, fromNetwork, timeouts, turn)
		var firstDecryption: HappCrypto.Result? = null
		suspend fun firstDecrypted(): HappCrypto.Result =
			firstDecryption ?: decrypt(url, first).also { firstDecryption = it }

		if (first.isError) return Result(first, HappCrypto.Result.NotEncrypted, null)
		if (!preferSubscriptionUa) return Result(first, firstDecrypted(), null)

		// The header is free to read; the body's parameter only surfaces after decryption, which
		// this needs anyway - so that work is kept for reuse.
		val wanted = HappParams.changeUserAgent(first.headers, null)
			?: subUaFromBody(firstDecrypted(), first.body)
			?: return Result(first, firstDecrypted(), null)

		// Byte for byte what already went out: nothing to repeat, but still reported. Anything less than exact is repeated -
		// a stray space is the kind of difference a provider checks for.
		if (wanted == userAgent) return Result(first, firstDecrypted(), wanted)

		Log.d(LOG_TAG, "Subscription asked for User-Agent \"$wanted\", repeating the request")
		val second = fetch(url, hwid, wanted, fromNetwork, timeouts, turn)
		// A retry that fails must not cost the answer that already arrived.
		if (second.isError || second.body.isEmpty()) {
			Log.w(LOG_TAG,
				"Retry with \"$wanted\" returned nothing usable, keeping the first response")
			return Result(first, firstDecrypted(), null)
		}
		return Result(second, decrypt(url, second), wanted)
	}

	// Runs to megabytes of CPU work - kept off whichever thread asked.
	private suspend fun decrypt(url: String, resp: Response): HappCrypto.Result =
		withContext(Dispatchers.Default) { HappCrypto.process(url, resp.body, resp.headers) }

	private suspend fun subUaFromBody(decrypted: HappCrypto.Result, rawBody: String): String? =
		withContext(Dispatchers.Default) {
			HappParams.changeUserAgent(null, HappCrypto.plaintextOf(decrypted, rawBody))
		}

	private suspend fun fetch(url: String, hwid: String, userAgent: String, fromNetwork: Boolean,
		timeouts: Timeouts, turn: LargeTurn): Response = withContext(Dispatchers.IO) {
		var conn: HttpURLConnection? = null
		try {
			conn = openFollowingRedirects(url, hwid, userAgent, fromNetwork, timeouts)

			val headers = conn.headerFields.filterKeys { it != null }
			val status = conn.responseCode
			if (status == HttpURLConnection.HTTP_OK) {
				Response(readBodyCapped(conn.inputStream, turn), headers, isError = false, status)
			} else {
				Response(errorText(status, conn), headers, isError = true, status)
			}
		} catch (error: Exception) {
			Response("Error: ${error.message}", emptyMap(), isError = true, status = 0)
		} finally {
			conn?.disconnect()
		}
	}

	// "Error: 403", and what the page said, if anything.
	private fun errorText(status: Int, conn: HttpURLConnection): String {
		val said = try {
			conn.errorStream?.use { errorSnippet(it.readUpTo(ERROR_BODY_BYTES)) }.orEmpty()
		} catch (_: IOException) {
			""
		}
		return if (said.isEmpty()) "Error: $status" else "Error: $status: $said"
	}

	private fun InputStream.readUpTo(limit: Int): ByteArray {
		val out = ByteArrayOutputStream()
		val chunk = ByteArray(1024)
		while (out.size() < limit) {
			val read = read(chunk, 0, minOf(chunk.size, limit - out.size()))
			if (read < 0) break
			out.write(chunk, 0, read)
		}
		return out.toByteArray()
	}

	// A script or style block, or else a tag, either to its end or to the end of what was read.
	private val MARKUP = Regex(
		"<(script|style)\\b.*?(</\\1\\s*>|$)|<[^>]*(>|$)",
		setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)
	)
	private val SPACES = Regex("\\s+")

	// The words of a page on one line: no markup, no control characters, cut short.
	internal fun errorSnippet(page: ByteArray): String {
		val text = String(page, Charsets.UTF_8)
			.replace(MARKUP, " ")
			.filter { it.isWhitespace() || !it.isISOControl() }
			// A character cut in half at the end of the read comes out as this.
			.trimEnd('\uFFFD')
			.replace(SPACES, " ")
			.trim()
		if (text.length <= ERROR_TEXT_CHARS) return text
		val end = if (text[ERROR_TEXT_CHARS - 1].isHighSurrogate()) ERROR_TEXT_CHARS - 1 else ERROR_TEXT_CHARS
		return text.take(end).trimEnd() + "..."
	}

	// Bounded by size and by time. Turn-wait time is this phone's own, not the server's, so it's
	// added back to the deadline - using the monotonic clock, which the phone's own time can't move.
	private fun readBodyCapped(input: InputStream, turn: LargeTurn): String {
		val out = ByteArrayOutputStream()
		val chunk = ByteArray(16 * 1024)
		var total = 0L
		var giveUpAt = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(FETCH_BUDGET_MS)
		input.use {
			while (true) {
				val readBytes = it.read(chunk)
				if (readBytes < 0) break
				total += readBytes
				if (total > MAX_BODY_BYTES) throw IOException("Response body exceeds size limit")
				if (total > LARGE_BODY_BYTES) giveUpAt += turn.take()
				if (System.nanoTime() - giveUpAt > 0) {
					throw IOException("Subscription took too long to arrive")
				}
				out.write(chunk, 0, readBytes)
			}
		}
		return out.toString("UTF-8")
	}

	// Redirects are followed one hop at a time so each address is checked before it's opened: one
	// leading back to the bridge would leave this fetch waiting on itself.
	private fun openFollowingRedirects(first: String, hwid: String,
		userAgent: String, fromNetwork: Boolean, timeouts: Timeouts): HttpURLConnection {
		var address = URL(first)
		var hops = 0
		while (true) {
			// Checked on every hop: the first address, each redirect, and a retry alike.
			if (address.protocol != "http" && address.protocol != "https") {
				throw IOException("Only http and https subscriptions are fetched")
			}
			if (fromNetwork) {
				val allowed = BridgeLink.forNetworkClient(address)
				if (allowed == null) {
					Log.w(LOG_TAG,
						"Refusing ${address.host} from the network: it is this device")
					throw IOException("That address is not allowed from the network")
				}
				address = allowed
			}
			// Also checked every hop - an address that resolves back here is the same loop risk.
			if (BridgeLink.resolvesToThisBridge(address)) {
				Log.w(LOG_TAG, "Refusing an address that leads back to the Bridge")
				throw IOException("Subscription leads back to the Bridge")
			}
			val conn = (address.openConnection() as HttpURLConnection).apply {
				requestMethod = "GET"
				instanceFollowRedirects = false
				setRequestProperty("x-hwid", hwid)
				if (userAgent.isNotBlank()) setRequestProperty("User-Agent", userAgent)
				connectTimeout = timeouts.connectMs
				readTimeout = timeouts.readMs
			}
			val next = redirectTakenFrom(conn, address) ?: return conn
			conn.disconnect()
			Log.d(LOG_TAG, "Subscription redirects to $next")
			if (++hops > MAX_REDIRECTS) throw IOException("Subscription redirects on and on")
			address = next
		}
	}

	// Null when there's nowhere to go: not a redirect, one naming nowhere, an address nothing here
	// opens, or one stepping out of https (which would put a private subscription in the clear).
	private fun redirectTakenFrom(conn: HttpURLConnection, from: URL): URL? {
		if (conn.responseCode !in REDIRECT_CODES) return null
		val location = conn.getHeaderField("Location")
		if (location.isNullOrBlank()) return null
		// Relative to the address that sent it, as a Location is allowed to be.
		val next = try {
			URL(from, asUriReference(location))
		} catch (_: Exception) {
			return null
		}
		return if (from.protocol == "https" && next.protocol != "https") null else next
	}

	// A server may put a raw space or its own alphabet's letters in a Location; HttpURLConnection
	// encoded those, java.net.URL doesn't and fails instead. Well-formed ones pass through untouched.
	private fun asUriReference(location: String): String = buildString {
		for (byte in location.trim().toByteArray(Charsets.UTF_8)) {
			val code = byte.toInt() and 0xFF
			if (code in 0x21..0x7E) {
				append(code.toChar())
			} else {
				append("%%%02X".format(Locale.US, code))
			}
		}
	}
}
