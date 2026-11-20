package com.happwner.data

import android.content.Context
import com.happwner.bridge.RequestIdentity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class IdentityStoreTest {

	private val prefs by lazy {
		RuntimeEnvironment.getApplication().getSharedPreferences("identities", Context.MODE_PRIVATE)
	}
	private val pixel = RequestIdentity("hwid-1", "Happ/4.10.1", "Pixel 5", "Android", "15", listOf("x-token" to "a:b"))
	private val iphone = RequestIdentity("", "INCY/3.9.7", "iPhone 15", "iOS", "18")

	@Test
	fun `identities are kept with every field, newest first, named apart, renamed, removed and moved`() {
		val store = IdentityStore(prefs)
		store.add("Pixel 5", pixel)
		store.add("Pixel 5", iphone)
		val reread = IdentityStore(prefs).all()
		assertEquals(listOf("Pixel 5 (2)", "Pixel 5"), reread.map { it.name })
		assertEquals(iphone, reread[0].identity)
		assertEquals(pixel, reread[1].identity)

		store.rename(reread[0].id, "Pixel 5")
		assertEquals(listOf("Pixel 5 (2)", "Pixel 5"), store.all().map { it.name })
		store.rename(reread[0].id, "Phone")
		store.remove(setOf(reread[1].id))
		assertEquals(listOf("Phone"), store.all().map { it.name })

		val phone = store.all().single()
		val first = store.add("Pixel", pixel)
		val second = store.add("iPhone", iphone)
		store.reorder(listOf(first.id, second.id, phone.id))
		assertEquals(listOf("Pixel", "iPhone", "Phone"), IdentityStore(prefs).all().map { it.name })
	}

	@Test
	fun `fields are taken for the identity they equal, or for the one they came from, changed`() {
		val store = IdentityStore(prefs)
		val first = store.add("Pixel", pixel)
		val second = store.add("iPhone", iphone)
		assertEquals(second.id, store.activeId)

		val equal = store.resolve(pixel)
		assertEquals(first.id, equal.saved?.id)
		assertFalse(equal.modified)
		assertEquals(first.id, store.activeId)

		val edited = store.resolve(pixel.copy(model = "Pixel 6"))
		assertEquals(first.id, edited.saved?.id)
		assertTrue(edited.modified)

		store.remove(setOf(first.id))
		assertNull(store.activeId)
		val none = store.resolve(pixel)
		assertNull(none.saved)
		assertFalse(none.modified)
		assertNotNull(store.find(second.id))
	}
}
