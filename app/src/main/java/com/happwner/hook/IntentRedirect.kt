package com.happwner.hook

import android.app.Activity
import android.content.Intent
import androidx.core.app.ActivityCompat
import androidx.core.net.toUri
import com.happwner.data.ModuleIds

// Turns a link another app opens in a patched app into a choice of apps, run inside that app's
// process. Kept apart from MainHook so the rules can be tested without Xposed.
internal object IntentRedirect {

	// Put on the intent handed to the chosen app, so a patched app picked there lets it through.
	const val EXTRA_PASSED = "${ModuleIds.PACKAGE}.REDIRECT_PASSED"

	// The link an intent carries: its data, or the text of a share.
	fun linkOf(intent: Intent): String? {
		val data = intent.dataString?.trim()
		if (!data.isNullOrEmpty()) return data
		if (intent.action != Intent.ACTION_SEND) return null
		return intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()?.trim()?.takeIf { it.isNotEmpty() }
	}

	// Launches and the app's own hops are left alone; so is anything without a link. A caller
	// that is unknown counts as outside unless the intent names its component, as inner hops do.
	fun shouldRedirect(intent: Intent, ownPackage: String, caller: String?): Boolean {
		if (intent.action == Intent.ACTION_MAIN || intent.hasCategory(Intent.CATEGORY_LAUNCHER)) return false
		if (caller == ownPackage) return false
		if (caller == null && intent.component != null) return false
		return linkOf(intent) != null
	}

	// The system's chooser for the intent as it came, with Happwner added, since it takes only
	// a few schemes of its own.
	fun chooserFor(intent: Intent, link: String): Intent {
		val forward = Intent(intent).apply {
			component = null
			`package` = null
			selector = null
			putExtra(EXTRA_PASSED, true)
		}
		val happwner = Intent(Intent.ACTION_VIEW, link.toUri()).setClassName(ModuleIds.PACKAGE, ModuleIds.MAIN_ACTIVITY)
		return Intent.createChooser(forward, null).apply {
			putExtra(Intent.EXTRA_INITIAL_INTENTS, arrayOf(happwner))
		}
	}

	// What the app gets in place of the link: a plain launch.
	fun neutral(): Intent = Intent(Intent.ACTION_MAIN)

	// Opens the chooser for this intent when it is a link from outside; false leaves it to the app.
	fun redirect(activity: Activity, intent: Intent?): Boolean {
		if (intent == null) return false
		if (intent.getBooleanExtra(EXTRA_PASSED, false)) {
			intent.removeExtra(EXTRA_PASSED)
			return false
		}
		if (!shouldRedirect(intent, activity.packageName, callerOf(activity))) return false
		val link = linkOf(intent) ?: return false
		activity.startActivity(chooserFor(intent, link))
		return true
	}

	private fun callerOf(activity: Activity): String? = try {
		ActivityCompat.getReferrer(activity)?.takeIf { it.scheme == "android-app" }?.host
	} catch (_: Throwable) {
		null
	}
}
