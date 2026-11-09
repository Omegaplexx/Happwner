package com.happwner.bridge

import com.happwner.data.PrefsManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

// A bridge up with its socket bound for the old choice of network is bound anew, by whoever asks
// for it, with the request carrying whether a person is there to hear of a refusal.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class BridgeRebindTest {
	private val app get() = RuntimeEnvironment.getApplication()

	private fun serving(state: String, value: Any) {
		val field = SubscriptionService::class.java.getDeclaredField(state)
		field.isAccessible = true
		field.set(null, value)
	}

	@Before
	fun setUp() {
		PrefsManager.getSafePrefs(app).edit()
			.putBoolean(PrefsManager.PREF_BRIDGE_ENABLED, true)
			.putBoolean(PrefsManager.PREF_BRIDGE_LAN_MODE, true)
			.commit()
		// Up, bound without the local network, its notification not dropped.
		serving("isServing", true)
		serving("servesLan", false)
		serving("dismissedByPerson", true)
		assertTrue(BridgeController.isUp(app))
		assertTrue(BridgeController.isLanModeOn(app))
	}

	@Test
	fun `the shade's check asks for the socket anew in silence, the screens with a person to tell`() {
		assertTrue(BridgeController.ensureServing(app, tellPerson = false))
		val quiet = shadowOf(app).nextStartedService
		assertNotNull(quiet)
		assertEquals(SubscriptionService.ACTION_REBIND, quiet.action)
		assertEquals(false, quiet.getBooleanExtra(SubscriptionService.EXTRA_TELL_PERSON, true))
		assertTrue(BridgeController.ensureServing(app))
		val told = shadowOf(app).nextStartedService
		assertEquals(SubscriptionService.ACTION_REBIND, told.action)
		assertEquals(true, told.getBooleanExtra(SubscriptionService.EXTRA_TELL_PERSON, false))
	}
}
