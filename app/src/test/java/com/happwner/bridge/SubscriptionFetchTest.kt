package com.happwner.bridge

import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SubscriptionFetchTest {
	// One request as the server saw it.
	private data class Seen(val path: String, val userAgent: String?, val hwid: String?)

	private data class Reply(
		val code: Int,
		val body: String = "",
		val headers: Map<String, String> = emptyMap()
	)

	private val seen = Collections.synchronizedList(mutableListOf<Seen>())
	private val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
	private val base = "http://127.0.0.1:${server.localPort}"

	// Plain HTTP/1.1 on loopback, a connection per request, each answered by its path on a thread
	// of its own, so requests can overlap as they do at the bridge.
	init {
		Thread {
			while (true) {
				val client = try { server.accept() } catch (_: IOException) { break }
				Thread { client.use { answer(it) } }.apply { isDaemon = true }.start()
			}
		}.apply { isDaemon = true }.start()
	}

	@After
	fun stop() = server.close()

	private fun answer(client: Socket) {
		val input = client.getInputStream().bufferedReader(Charsets.ISO_8859_1)
		val path = input.readLine()?.split(" ")?.getOrNull(1) ?: return
		val headers = mutableMapOf<String, String>()
		while (true) {
			val line = input.readLine() ?: break
			if (line.isEmpty()) break
			val colon = line.indexOf(':')
			if (colon <= 0) continue
			headers[line.take(colon).trim().lowercase()] = line.drop(colon + 1).trim()
		}
		seen += Seen(path, headers["user-agent"], headers["x-hwid"])
		val reply = route(path, headers["user-agent"])
		val body = reply.body.toByteArray(Charsets.UTF_8)
		val head = buildString {
			append("HTTP/1.1 ${reply.code} Status\r\n")
			reply.headers.forEach { (name, value) -> append("$name: $value\r\n") }
			append("Content-Length: ${body.size}\r\nConnection: close\r\n\r\n")
		}
		client.getOutputStream().apply {
			write(head.toByteArray(Charsets.ISO_8859_1))
			write(body)
			flush()
		}
	}

	private val bridge = SubscriptionService.BRIDGE_PORT

	// Just past the size at which a subscription is large.
	private val large = SubscriptionFetch.LARGE_BODY_BYTES.toInt() + 1

	private fun route(path: String, userAgent: String?): Reply {
		val asksForXray = mapOf("change-user-agent" to "xray")
		fun redirect(location: String) = Reply(302, headers = mapOf("Location" to location))
		return when (path) {
			"/plain" -> Reply(200, "vless://plain")
			"/large" -> Reply(200, "a".repeat(large))
			"/large-wants-xray" ->
				Reply(200, (if (userAgent == "xray") "x" else "s").repeat(large), asksForXray)
			"/missing" -> Reply(404)
			"/refused" -> Reply(403, "<html><head><title>Denied</title><style>p { color: red }</style>" +
				"</head><body><h1>Access   denied</h1>\r\n<p>Your address is blocked</p></body></html>")
			"/refused-in-script" -> Reply(503, "<script>var blocked = 1; if (a < b) { go() }")
			"/refused-long" -> Reply(500, "word ".repeat(4000))
			"/refused-wide" -> Reply(502, "\u00e9".repeat(5000))
			"/hop" -> redirect("/plain")
			"/loop" -> redirect("/loop")
			"/to-bridge" -> redirect("http://127.0.0.1:$bridge/x")
			"/to-bridge-as-number" -> redirect("http://2130706433:$bridge/x")
			"/to-bridge-short" -> redirect("http://127.1:$bridge/x")
			"/to-bridge-mapped" -> redirect("http://[::ffff:127.0.0.1]:$bridge/x")
			// As providers do, the name is sent whatever the request was asked with.
			"/wants-xray" ->
				if (userAgent == "xray") Reply(200, "vless://full", asksForXray)
				else Reply(200, "vless://short", asksForXray)
			"/wants-xray-then-fails" ->
				if (userAgent == "xray") Reply(500) else Reply(200, "vless://short", asksForXray)
			else -> Reply(404)
		}
	}

	// A test that holds the turn passes its own claim and closes it itself; otherwise the claim is
	// let go as soon as the answer is in, as the bridge lets go once it has replied.
	private fun fetch(
		path: String,
		userAgent: String = "happ/1",
		prefer: Boolean = true,
		fromNetwork: Boolean = false,
		turn: SubscriptionFetch.LargeTurn? = null
	) = runBlocking {
		val claim = turn ?: SubscriptionFetch.LargeTurn()
		try {
			SubscriptionFetch.fetchHonouringSubUa(
				"$base$path", "hwid-1", userAgent, prefer, fromNetwork, claim)
		} finally {
			if (turn == null) claim.close()
		}
	}

	@Test
	fun `a subscription comes back, asked for with the hwid and User-Agent`() {
		val result = fetch("/plain")
		assertFalse(result.resp.isError)
		assertEquals("vless://plain", result.resp.body)
		assertEquals(listOf(Seen("/plain", "happ/1", "hwid-1")), seen.toList())
	}

	@Test
	fun `an error comes back named by its code and status, says what the page said, and is not run as a subscription`() {
		val missing = fetch("/missing")
		assertTrue(missing.resp.isError)
		assertEquals("Error: 404", missing.resp.body)
		assertEquals(404, missing.resp.status)
		assertEquals(200, fetch("/plain").resp.status)

		val refused = fetch("/refused")
		assertTrue(refused.resp.isError)
		assertEquals("Error: 403: Denied Access denied Your address is blocked", refused.resp.body)
		assertEquals(com.happwner.client.HappCrypto.Result.NotEncrypted, refused.decrypted)
		assertNull(refused.subUa)

		// A script the page was cut in is not read as words.
		assertEquals("Error: 503", fetch("/refused-in-script").resp.body)

		// A long page is cut short, whole characters only.
		val long = fetch("/refused-long").resp.body
		assertTrue(long.startsWith("Error: 500: word word"))
		assertTrue(long.endsWith("word..."))
		// 200 characters of it, less the space the cut leaves at the end.
		assertTrue(long.length in ("Error: 500: ".length + 199 + "...".length)..("Error: 500: ".length + 200 + "...".length))
		val wide = fetch("/refused-wide").resp.body
		assertEquals("Error: 502: ".length + 200 + "...".length, wide.length)
		assertFalse(wide.contains('\uFFFD'))
	}

	@Test
	fun `the bridge answers an error with the site's own status, else a bad gateway`() {
		fun status(code: Int) = SubscriptionFetch.bridgeStatusFor(
			SubscriptionFetch.Response("Error: $code", emptyMap(), isError = true, status = code))
		assertEquals(403, status(403))
		assertEquals(404, status(404))
		assertEquals(503, status(503))
		// No answer to pass on, or one that is no error of the site's: a redirect it would not follow.
		assertEquals(502, status(0))
		assertEquals(502, status(302))
		assertEquals(502, status(204))
		assertEquals(0, fetch("/loop").resp.status)
		assertEquals(502, SubscriptionFetch.bridgeStatusFor(fetch("/loop").resp))
	}

	@Test
	fun `a redirect is followed to the subscription, and a chain that goes nowhere is given up on`() {
		assertEquals("vless://plain", fetch("/hop").resp.body)
		assertEquals(listOf("/hop", "/plain"), seen.map { it.path })
		seen.clear()
		val result = fetch("/loop")
		assertEquals("Error: Subscription redirects on and on", result.resp.body)
		assertEquals(21, seen.size)
	}

	@Test
	fun `a redirect back to the bridge is refused before it is opened, however it is written`() {
		val ways = listOf(
			"/to-bridge", "/to-bridge-as-number", "/to-bridge-short", "/to-bridge-mapped")
		for (path in ways) {
			seen.clear()
			val body = fetch(path).resp.body
			assertEquals(path, "Error: Subscription leads back to the Bridge", body)
			assertEquals(path, 1, seen.size)
		}
	}

	@Test
	fun `a first address that is the bridge in another form is refused before it is opened`() {
		val result = SubscriptionFetch.LargeTurn().use { turn ->
			runBlocking {
				SubscriptionFetch.fetchHonouringSubUa(
					"http://127.1:$bridge/x", "hwid-1", "happ/1", true, fromNetwork = false, turn)
			}
		}
		assertEquals("Error: Subscription leads back to the Bridge", result.resp.body)
	}

	@Test
	fun `the subscription's own User-Agent is asked with once, and a failed retry or no preference keeps the first answer`() {
		val asked = fetch("/wants-xray")
		assertEquals("vless://full", asked.resp.body)
		assertEquals("xray", asked.subUa)
		assertEquals(listOf("happ/1", "xray"), seen.map { it.userAgent })

		// Asked with that User-Agent already, one request is enough.
		seen.clear()
		val already = fetch("/wants-xray", userAgent = "xray")
		assertEquals("vless://full", already.resp.body)
		assertEquals("xray", already.subUa)
		assertEquals(1, seen.size)

		seen.clear()
		val failed = fetch("/wants-xray-then-fails")
		assertEquals("vless://short", failed.resp.body)
		assertNull(failed.subUa)
		assertEquals(2, seen.size)

		seen.clear()
		val unpreferred = fetch("/wants-xray", prefer = false)
		assertEquals("vless://short", unpreferred.resp.body)
		assertNull(unpreferred.subUa)
		assertEquals(1, seen.size)
	}

	@Test
	fun `a request from the network may not reach this phone`() {
		val result = fetch("/plain", fromNetwork = true)
		assertEquals("Error: That address is not allowed from the network", result.resp.body)
		assertTrue(seen.isEmpty())
	}

	@Test
	fun `a second large subscription waits until the first lets go of the turn`() {
		SubscriptionFetch.LargeTurn(waitMs = 10_000).use { first ->
			assertEquals(large, fetch("/large", turn = first).resp.body.length)
			val second = SubscriptionFetch.LargeTurn(waitMs = 10_000)
			val arrived = CountDownLatch(1)
			var body: String? = null
			Thread {
				body = fetch("/large", turn = second).resp.body
				arrived.countDown()
			}.start()
			try {
				assertFalse("fetched beside the first", arrived.await(500, TimeUnit.MILLISECONDS))
				first.close()
				assertTrue("still waiting once let go", arrived.await(10, TimeUnit.SECONDS))
				assertEquals(large, body?.length)
			} finally {
				arrived.await(10, TimeUnit.SECONDS)
				second.close()
			}
		}
	}

	@Test
	fun `a small subscription never waits for the turn`() {
		SubscriptionFetch.LargeTurn(waitMs = 10_000).use { held ->
			fetch("/large", turn = held)
			// Asking for the turn at all would fail within the millisecond.
			val small = fetch("/plain", turn = SubscriptionFetch.LargeTurn(waitMs = 1))
			assertEquals("vless://plain", small.resp.body)
		}
	}

	@Test
	fun `one request keeps one turn across both of its fetches`() {
		SubscriptionFetch.LargeTurn(waitMs = 2_000).use { turn ->
			val result = fetch("/large-wants-xray", turn = turn)
			assertEquals("xray", result.subUa)
			assertEquals(large, result.resp.body.length)
			assertEquals('x', result.resp.body.first())
			assertEquals(listOf("happ/1", "xray"), seen.map { it.userAgent })
		}
		SubscriptionFetch.LargeTurn(waitMs = 500).use { next ->
			assertEquals("free again once that request is done", large,
				fetch("/large", turn = next).resp.body.length)
		}
	}

	@Test
	fun `waiting for the turn has a limit, and the client is told`() {
		SubscriptionFetch.LargeTurn(waitMs = 10_000).use { held ->
			fetch("/large", turn = held)
			val refused = fetch("/large", turn = SubscriptionFetch.LargeTurn(waitMs = 300))
			assertEquals("Error: Another large subscription is being processed, try again",
				refused.resp.body)
		}
	}

	@Test
	fun `a claim closed twice lets go of the turn once`() {
		val once = SubscriptionFetch.LargeTurn(waitMs = 2_000)
		fetch("/large", turn = once)
		once.close()
		once.close()
		SubscriptionFetch.LargeTurn(waitMs = 2_000).use { holder ->
			fetch("/large", turn = holder)
			// Had the second close let go again, there would be a turn to spare here.
			val third = fetch("/large", turn = SubscriptionFetch.LargeTurn(waitMs = 300))
			assertTrue(third.resp.isError)
		}
	}

	@Test
	fun `under load one large subscription at a time holds the turn, fifteen rounds over`() {
		val holding = AtomicInteger()
		val most = AtomicInteger()
		val failures = Collections.synchronizedList(mutableListOf<String>())
		repeat(15) { round ->
			val threads = (0 until 12).map { i ->
				Thread {
					val isLarge = i % 3 == 0
					try {
						SubscriptionFetch.LargeTurn(waitMs = 20_000).use { turn ->
							val path = if (isLarge) "/large" else "/plain"
							val body = fetch(path, turn = turn).resp.body
							if (isLarge) {
								// Counted while the claim is open: the body is in, the turn held.
								val now = holding.incrementAndGet()
								synchronized(most) { if (now > most.get()) most.set(now) }
								Thread.sleep(20)
								holding.decrementAndGet()
								if (body.length != large) {
									failures += "round $round: ${body.take(80)}"
								}
							} else if (body != "vless://plain") {
								failures += "round $round: $body"
							}
						}
					} catch (error: Throwable) {
						failures += "round $round: $error"
					}
				}.apply { start() }
			}
			threads.forEach { it.join(60_000) }
			assertTrue("round $round never finished", threads.none { it.isAlive })
		}
		assertEquals(emptyList<String>(), failures.toList())
		assertEquals("large subscriptions held at once", 1, most.get())
		SubscriptionFetch.LargeTurn(waitMs = 500).use { after ->
			assertEquals("the turn is free at the end", large,
				fetch("/large", turn = after).resp.body.length)
		}
	}
}
