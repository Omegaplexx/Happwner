package com.happwner.client

import java.lang.reflect.InvocationTargetException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

// The cache that holds the decryption keys. Parsing a key is slow enough to be worth doing once,
// and the result is shared by threads that may all reach for it at the same moment.
class CryptKeyCacheTest {

	// Reaches the private crypt..crypt4 key loader as the app's own code calls it.
	private fun cryptKey(ordinal: Int): Any {
		val method = HappCrypto::class.java
			.getDeclaredMethod("loadCryptKey", Int::class.javaPrimitiveType)
			.apply { isAccessible = true }
		return checkNotNull(method.invoke(HappCrypto, ordinal)) { "loadCryptKey($ordinal) returned null" }
	}
	@Test
	fun `the key cache returns the same instance every time, and each ordinal caches its own key`() {
		val keys = (0..3).map { cryptKey(it) }
		for (ordinal in 0..3) {
			assertTrue("ordinal $ordinal re-parsed instead of caching", keys[ordinal] === cryptKey(ordinal))
		}
		// An array indexed wrongly would hand the same key to every ordinal,
		// and every crypt mode but one would then fail to decrypt.
		for (i in 0..3) for (j in 0..3) {
			if (i != j) assertTrue("ordinals $i and $j share a key", keys[i] !== keys[j])
		}
	}
	@Test
	fun `the cache refuses an ordinal outside the table`() {
		for (bad in listOf(-1, 4, 100)) {
			try {
				cryptKey(bad)
				fail("ordinal $bad was accepted")
			} catch (error: InvocationTargetException) {
				assertTrue(
					"expected a range complaint, got ${error.cause}",
					error.cause is IllegalArgumentException
				)
			}
		}
	}
	@Test
	fun `the cache holds under concurrent first use`() {
		// The cache reads without a lock: several threads arriving at a cold ordinal at once must all
		// agree on one key, and none may see a half-built one.
		val threads = 16
		val start = CountDownLatch(1)
		val done = CountDownLatch(threads)
		val seen = ConcurrentHashMap.newKeySet<Any>()
		val errors = AtomicInteger()
		repeat(threads) {
			Thread {
				try {
					start.await()
					repeat(50) { seen.add(cryptKey(it % 4)) }
				} catch (error: Throwable) {
					errors.incrementAndGet()
				} finally {
					done.countDown()
				}
			}.start()
		}
		start.countDown()
		done.await()
		assertEquals("threads threw", 0, errors.get())
		assertEquals("more than one key object per ordinal escaped", 4, seen.size)
	}
}
