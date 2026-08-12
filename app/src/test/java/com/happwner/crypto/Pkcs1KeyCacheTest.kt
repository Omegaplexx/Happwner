package com.happwner.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// The cache that holds the decryption keys. Parsing a key is slow enough to be worth doing once,
// and the result is shared by threads that may all reach for it at the same moment.
class Pkcs1KeyCacheTest {

    // --------------------------------------------- the PKCS#1 key cache ----

    // The cache behind crypt..crypt4 still caches.
    private fun `loadPkcs1`(ordinal: Int): Any {
        val m = HappCrypto::class.java
            .getDeclaredMethod("loadPkcs1Key", Int::class.javaPrimitiveType)
            .apply { isAccessible = true }
        return m.invoke(HappCrypto, ordinal)
    }
    @Test
    fun `the pkcs1 cache returns the same instance every time`() {
        for (ordinal in 0..3) {
            val first = loadPkcs1(ordinal)
            val second = loadPkcs1(ordinal)
            assertTrue("ordinal $ordinal re-parsed instead of caching", first === second)
        }
    }
    @Test
    fun `each ordinal caches its own key`() {
        // An array indexed wrongly would hand the same key to every ordinal,
        // and every crypt mode but one would then fail to decrypt.
        val keys = (0..3).map { loadPkcs1(it) }
        for (i in 0..3) for (j in 0..3) {
            if (i != j) assertTrue("ordinals $i and $j share a key", keys[i] !== keys[j])
        }
    }
    @Test
    fun `the cache refuses an ordinal outside the table`() {
        for (bad in listOf(-1, 4, 100)) {
            try {
                loadPkcs1(bad)
                org.junit.Assert.fail("ordinal $bad was accepted")
            } catch (e: java.lang.reflect.InvocationTargetException) {
                assertTrue(
                    "expected a range complaint, got ${e.cause}",
                    e.cause is IllegalArgumentException
                )
            }
        }
    }
    @Test
    fun `the cache holds under concurrent first use`() {
        // The unsynchronised read is the whole point of the change; several threads arriving at a
        // cold ordinal at once must still agree on one key and none may see a half-built one.
        val threads = 16
        val start = java.util.concurrent.CountDownLatch(1)
        val done = java.util.concurrent.CountDownLatch(threads)
        val seen = java.util.concurrent.ConcurrentHashMap.newKeySet<Any>()
        val errors = java.util.concurrent.atomic.AtomicInteger()
        repeat(threads) {
            Thread {
                try {
                    start.await()
                    repeat(50) { seen.add(loadPkcs1(it % 4)) }
                } catch (e: Throwable) {
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
