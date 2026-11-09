package com.happwner.ui

import android.app.Activity
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.os.Looper
import android.view.KeyEvent
import android.view.View
import android.view.Window
import android.view.WindowManager
import android.window.OnBackInvokedCallback
import androidx.appcompat.app.AlertDialog
import com.happwner.data.PrefsManager
import java.time.Duration
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.shadows.ShadowChoreographer

// What the screen tests share: a clock that advances a frame at a time, a rotation as the system
// delivers one to an activity that handles its own configuration changes, and a way to the private
// state the dialogs keep - the tests read it, never set it.
object UiTestSupport {
	const val FRAME_MS = 16L

	// Frames come only as the clock is advanced, so an animation is as far along as the clock says.
	fun pacedFrames() {
		ShadowChoreographer.setPaused(true)
		ShadowChoreographer.setFrameDelay(Duration.ofMillis(FRAME_MS))
		// The permission androidx.core merges into the manifest to keep a receiver to the app before
		// Android 13: an install grants the app its own signature permission, this environment does not.
		val app = RuntimeEnvironment.getApplication()
		shadowOf(app).grantPermissions(app.packageName + ".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")
	}

	// Advances the clock a frame at a time: a paused choreographer gives one frame per advance,
	// however large, so an animation only moves as frames are stepped through.
	fun idle(ms: Long) {
		var left = ms
		while (left > 0) {
			val step = minOf(left, FRAME_MS)
			shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(step))
			left -= step
		}
	}

	fun frames(count: Int) = repeat(count) { idle(FRAME_MS) }

	fun setAnimMode(context: Context, mode: Int) {
		PrefsManager.getSafePrefs(context).edit().putInt(PrefsManager.PREF_ANIM_MODE, mode).commit()
	}

	// A rotation: the resources take the new orientation, the activity hears of it as it does on a
	// device, and its window lays itself out for it - the system's part of the turn.
	fun <A : Activity> rotate(controller: ActivityController<A>, landscape: Boolean) {
		RuntimeEnvironment.setQualifiers(if (landscape) "+land" else "+port")
		val config = Configuration(RuntimeEnvironment.getApplication().resources.configuration)
		controller.configurationChange(config)
		controller.get().window.decorView.requestLayout()
	}

	// The focus a dropdown asks of its window before it opens, which this environment gives none of.
	fun focusWindow(window: View) {
		val root = View::class.java.getMethod("getViewRootImpl").invoke(window)
		val focusChanged = root.javaClass.declaredMethods.first {
			it.name == "windowFocusChanged" && it.parameterCount == 1
		}
		focusChanged.isAccessible = true
		focusChanged.invoke(root, true)
		idle(50)
	}

	// Steps frames until the condition holds or the budget runs out; false when it never did.
	fun settle(maxMs: Long = 3000, condition: () -> Boolean): Boolean {
		var spent = 0L
		while (spent < maxMs) {
			if (condition()) return true
			idle(FRAME_MS)
			spent += FRAME_MS
		}
		return condition()
	}

	@Suppress("UNCHECKED_CAST")
	fun <T> field(target: Any, name: String): T {
		var type: Class<*>? = target.javaClass
		while (type != null) {
			try {
				val field = type.getDeclaredField(name)
				field.isAccessible = true
				return field.get(target) as T
			} catch (_: NoSuchFieldException) {
				type = type.superclass
			}
		}
		throw NoSuchFieldException(name)
	}

	fun dims(dialog: AlertDialog): Boolean =
		(dialog.window!!.attributes.flags and WindowManager.LayoutParams.FLAG_DIM_BEHIND) != 0

	fun dimAmount(dialog: AlertDialog): Float = dialog.window!!.attributes.dimAmount

	fun decor(dialog: AlertDialog): View = dialog.window!!.decorView

	// A key pressed and released on the dialog's window, as the two results its callback gives.
	fun key(dialog: AlertDialog, code: Int): Pair<Boolean, Boolean> {
		val callback = dialog.window!!.callback
		val down = callback.dispatchKeyEvent(KeyEvent(KeyEvent.ACTION_DOWN, code))
		val up = callback.dispatchKeyEvent(KeyEvent(KeyEvent.ACTION_UP, code))
		return down to up
	}

	// The callback Back reaches first through the window's dispatcher - the one of the window's view
	// root, where the registrations end up - on the versions that have one.
	fun topBackCallback(window: Window): OnBackInvokedCallback? {
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return null
		val decor = window.decorView
		val root = decor.javaClass.getMethod("getViewRootImpl").invoke(decor) ?: return null
		val dispatcher = root.javaClass.getMethod("getOnBackInvokedDispatcher").invoke(root)
			?: return null
		val top = dispatcher.javaClass.getMethod("getTopCallback").invoke(dispatcher)
		return top as? OnBackInvokedCallback
	}
}
