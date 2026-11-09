package com.happwner.hook

import android.app.Activity
import android.content.Intent
import androidx.core.net.toUri
import com.happwner.data.ModuleIds
import com.happwner.ui.MainActivity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

// A link another app opens in a patched app becomes a choice of apps; nothing else is touched.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class IntentRedirectTest {
	private val own = "com.example.client"
	private val link = "happ://crypt4/abc"

	private fun view(data: String? = link) = Intent(Intent.ACTION_VIEW, data?.toUri())

	private fun share(text: String?) =
		Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)

	@Test
	fun `a link from another app is redirected whatever its scheme or action, a launch and the app's own hops are not`() {
		assertEquals(link, IntentRedirect.linkOf(view()))
		assertEquals("https://example.com/s", IntentRedirect.linkOf(share(" https://example.com/s ")))
		assertNull(IntentRedirect.linkOf(view(null)))
		assertNull(IntentRedirect.linkOf(share("  ")))
		assertNull("only a share carries its link as text",
			IntentRedirect.linkOf(Intent(Intent.ACTION_EDIT).putExtra(Intent.EXTRA_TEXT, "x")))

		for (data in listOf(link, "https://example.com/a", "incy://add/x", "vless://id@host:443", "tg://resolve")) {
			assertTrue(data, IntentRedirect.shouldRedirect(view(data), own, "com.android.chrome"))
		}
		assertTrue(IntentRedirect.shouldRedirect(share("https://example.com"), own, "org.telegram.messenger"))
		assertTrue(IntentRedirect.shouldRedirect(Intent("custom.ACTION", link.toUri()), own, "x.y"))

		assertFalse(IntentRedirect.shouldRedirect(Intent(Intent.ACTION_MAIN), own, "com.android.launcher"))
		assertFalse(IntentRedirect.shouldRedirect(
			Intent(Intent.ACTION_VIEW, link.toUri()).addCategory(Intent.CATEGORY_LAUNCHER), own, "x"))
		assertFalse("sent by the app itself", IntentRedirect.shouldRedirect(view(), own, own))
		assertFalse(IntentRedirect.shouldRedirect(view(null), own, "com.android.chrome"))
		assertFalse("unknown sender, named component: an inner hop",
			IntentRedirect.shouldRedirect(view().setClassName(own, "$own.Inner"), own, null))
		assertTrue("unknown sender, no component: a link from outside",
			IntentRedirect.shouldRedirect(view(), own, null))
		// The app itself gets a plain launch in place of the link.
		val replacement = IntentRedirect.neutral()
		assertEquals(Intent.ACTION_MAIN, replacement.action)
		assertNull(replacement.data)
		assertFalse(IntentRedirect.shouldRedirect(replacement, own, "x"))
	}

	@Test
	fun `the chooser offers the link as it came, with Happwner added and no way back to the hook`() {
		val directed = view().setPackage(own).setClassName(own, "$own.Deep").putExtra("keep", 1)
		val chooser = IntentRedirect.chooserFor(directed, link)
		assertEquals(Intent.ACTION_CHOOSER, chooser.action)

		val forward = chooser.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)!!
		assertEquals(Intent.ACTION_VIEW, forward.action)
		assertEquals(link, forward.dataString)
		assertNull("not tied to the app that was hooked", forward.`package`)
		assertNull(forward.component)
		assertEquals(1, forward.getIntExtra("keep", 0))
		assertTrue(forward.getBooleanExtra(IntentRedirect.EXTRA_PASSED, false))

		val extra = chooser.getParcelableArrayExtra(Intent.EXTRA_INITIAL_INTENTS, Intent::class.java)!!
		assertEquals(1, extra.size)
		assertEquals(Intent.ACTION_VIEW, extra[0].action)
		assertEquals(link, extra[0].dataString)
		assertEquals(ModuleIds.PACKAGE, extra[0].component!!.packageName)
		assertEquals(MainActivity::class.java.name, extra[0].component!!.className)
		assertFalse("the original is untouched", directed.hasExtra(IntentRedirect.EXTRA_PASSED))

		// A shared text reaches Happwner as a link to open.
		val shared = IntentRedirect.chooserFor(share("https://example.com/s"), "https://example.com/s")
		val sharedExtra = shared.getParcelableArrayExtra(Intent.EXTRA_INITIAL_INTENTS, Intent::class.java)!!
		assertEquals("https://example.com/s", sharedExtra[0].dataString)
	}

	private fun activityOf(intent: Intent, from: String?): Activity {
		if (from != null) intent.putExtra(Intent.EXTRA_REFERRER, "android-app://$from".toUri() as android.os.Parcelable)
		return Robolectric.buildActivity(Activity::class.java, intent).create().get()
	}

	@Test
	fun `redirect opens the chooser for a link from outside and for nothing else`() {
		val outside = activityOf(view(), "com.android.chrome")
		assertTrue(IntentRedirect.redirect(outside, outside.intent))
		val started = shadowOf(outside).nextStartedActivity
		assertNotNull(started)
		assertEquals(Intent.ACTION_CHOOSER, started.action)

		val inner = activityOf(view(), outside.packageName)
		assertFalse(IntentRedirect.redirect(inner, inner.intent))
		assertNull(shadowOf(inner).nextStartedActivity)

		val launch = activityOf(Intent(Intent.ACTION_MAIN), "com.android.launcher")
		assertFalse(IntentRedirect.redirect(launch, launch.intent))
		assertNull(shadowOf(launch).nextStartedActivity)
		assertFalse(IntentRedirect.redirect(launch, null))

		// What the chooser sent on passes through, and the app never sees the mark.
		val chosen = activityOf(view().putExtra(IntentRedirect.EXTRA_PASSED, true), "com.android.chrome")
		assertFalse(IntentRedirect.redirect(chosen, chosen.intent))
		assertNull(shadowOf(chosen).nextStartedActivity)
		assertFalse("the app never sees the mark", chosen.intent.hasExtra(IntentRedirect.EXTRA_PASSED))
	}
}
