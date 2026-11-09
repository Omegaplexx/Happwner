package com.happwner.patcher

import android.content.Context
import java.io.File
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

// What a run cut short leaves in the cache is cleared, and only that.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class PatchSessionTest {
	private val context: Context get() = RuntimeEnvironment.getApplication()
	private val leftovers = listOf(
		File(context.cacheDir, PatchTarget.HAPP.cacheFileName),
		File(context.cacheDir, PatchTarget.V2RAYTUN.cacheFileName),
		File(context.cacheDir, "patcher/out/app.apk")
	)
	private val untouched get() = File(context.cacheDir, "other.bin")

	@Before
	fun setUp() {
		PatchSession.reset()
		leftovers.forEach { it.apply { parentFile?.mkdirs() }.writeText("half") }
		untouched.writeText("keep")
	}

	@After
	fun tearDown() {
		PatchSession.reset()
		untouched.delete()
	}

	@Test
	fun `a sweep clears the downloads and the patching a dead run left, and nothing else`() {
		PatchSession.sweep(context)
		// Cleared on a background thread, so in real time.
		val deadline = System.currentTimeMillis() + 5000
		while (leftovers.any { it.exists() } && System.currentTimeMillis() < deadline) Thread.sleep(20)
		assertTrue(leftovers.none { it.exists() })
		assertTrue(untouched.exists())
	}

	@Test
	fun `a sweep leaves a run that is going alone`() {
		PatchSession.simulate(PatchSession.Progress.Patching)
		PatchSession.sweep(context)
		Thread.sleep(300)
		assertTrue(leftovers.all { it.exists() })
		assertFalse(PatchSession.progress.value == null)
	}
}
