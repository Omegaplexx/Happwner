package com.happwner.ui

import android.R as AndroidR
import android.content.Context
import android.content.DialogInterface
import android.graphics.Color
import android.graphics.drawable.Drawable
import android.graphics.drawable.InsetDrawable
import android.graphics.drawable.LayerDrawable
import android.os.Build
import android.os.SystemClock
import android.util.TypedValue
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowInsets
import android.view.WindowManager
import android.window.OnBackInvokedDispatcher
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.shape.MaterialShapeDrawable
import com.happwner.R

// Dialog with the app's own animations instead of the system's; button clicks are intercepted here.
class AnimatedDialogBuilder(context: Context) : MaterialAlertDialogBuilder(context) {
	private var posListener: DialogInterface.OnClickListener? = null
	private var negListener: DialogInterface.OnClickListener? = null
	private var neuListener: DialogInterface.OnClickListener? = null

	// Like setMessage and setView, only changes the type, so a chain ends in showAnimated().
	override fun setTitle(title: CharSequence?): AnimatedDialogBuilder {
		super.setTitle(title)
		return this
	}

	override fun setMessage(message: CharSequence?): AnimatedDialogBuilder {
		super.setMessage(message)
		return this
	}

	override fun setView(view: View?): AnimatedDialogBuilder {
		super.setView(view)
		return this
	}

	override fun setPositiveButton(text: CharSequence?,
		listener: DialogInterface.OnClickListener?): AnimatedDialogBuilder {
		posListener = listener
		super.setPositiveButton(text, null)
		return this
	}

	override fun setNegativeButton(text: CharSequence?,
		listener: DialogInterface.OnClickListener?): AnimatedDialogBuilder {
		negListener = listener
		super.setNegativeButton(text, null)
		return this
	}

	override fun setNeutralButton(text: CharSequence?,
		listener: DialogInterface.OnClickListener?): AnimatedDialogBuilder {
		neuListener = listener
		super.setNeutralButton(text, null)
		return this
	}

	fun showAnimated(): AlertDialog {
		return doShow(this)
	}

	private fun showAndWire(dialog: AlertDialog, builder: AnimatedDialogBuilder, mode: Int) {
		builder.context.hideKeyboard()
		dialog.show()
		dialog.setCanceledOnTouchOutside(false)
		dialog.dialogState.animMode = mode
		applyHappDialogStrokeIfNeeded(dialog)

		dialog.setOnDismissListenerDispatch()

		installCallbackWrapper(dialog)
		wireButton(dialog, AlertDialog.BUTTON_POSITIVE, builder.posListener)
		wireButton(dialog, AlertDialog.BUTTON_NEGATIVE, builder.negListener)
		wireButton(dialog, AlertDialog.BUTTON_NEUTRAL, builder.neuListener)
	}

	private fun doShow(builder: AnimatedDialogBuilder): AlertDialog {
		val builderContext = builder.context
		val mode = builderContext.animMode()
		val dialog = builder.create()
		dialog.window?.let { window ->
			// No field to type into: the keyboard goes as one comes up, and the window lays out for the whole screen.
			window.setSoftInputMode(
				WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN or
					WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING
			)
			// App-set fitting leaves the keyboard out: a system-fitted window is centred above the keyboard while it is up
			// and slid to the screen's middle when it leaves.
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
				window.attributes = window.attributes.also {
					it.setFitInsetsTypes(WindowInsets.Type.systemBars())
				}
			}
		}

		// System mode: the theme's window animations run and only the common wiring is done;
		// a dialog put back in place comes up that way too, without dim until it is in.
		if (mode == ANIM_MODE_SYSTEM) {
			val inPlace = putBackShows > 0
			if (inPlace) dialog.window?.clearFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
			showAndWire(dialog, builder, ANIM_MODE_SYSTEM)
			val window = dialog.window
			if (inPlace && window != null) dialog.takeDimOnceShown(window.attributes.dimAmount)
			return dialog
		}

		// Off and software modes: the system window animation is killed; the dim starts near zero, or full
		// with animations off. A dialog put back in place takes it once shown.
		val atOnce = mode == ANIM_MODE_OFF
		val inPlace = putBackShows > 0 && !atOnce
		dialog.window?.let { window ->
			window.setWindowAnimations(0)
			runCatching {
				val params = window.attributes
				params.dimAmount = if (atOnce) DIALOG_DIM_TARGET else DIALOG_DIM_NONE
				window.attributes = params
				if (inPlace) {
					window.clearFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
				} else {
					window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
				}
			}
		}
		showAndWire(dialog, builder, mode)

		val window = dialog.window
		val decor = window?.decorView
		if (window != null && decor != null) {
			if (atOnce) {
				window.setDim(DIALOG_DIM_TARGET)
				decor.alpha = 1f
				return dialog
			}
			if (inPlace) {
				dialog.holdHidden(DIALOG_DIM_TARGET)
				return dialog
			}
			val low = builderContext.isLowRam()
			dialog.animateDimIn(dialogEnterMs(low), low)
			decor.animateDialogIn(low)
		}

		return dialog
	}

	private fun wireButton(dialog: AlertDialog, which: Int, listener: DialogInterface.OnClickListener?) {
		val button = dialog.getButton(which) ?: return
		button.setOnClickListener {
			if (dialog.dialogState.stayOpenHook?.invoke(which) == true) return@setOnClickListener
			dialog.getButton(AlertDialog.BUTTON_POSITIVE)?.isEnabled = false
			dialog.getButton(AlertDialog.BUTTON_NEGATIVE)?.isEnabled = false
			dialog.getButton(AlertDialog.BUTTON_NEUTRAL)?.isEnabled = false
			dialog.dismissAnimated {
				listener?.onClick(dialog, which)
			}
		}
	}

	private fun installCallbackWrapper(dialog: AlertDialog) {
		val window = dialog.window ?: return
		val original = window.callback ?: return
		if (original is AnimatedDismissCallback) return
		val wrapper = AnimatedDismissCallback(original, dialog)
		window.callback = wrapper
		// From Android 16 Back reaches a window through its dispatcher, not as a key, and the system's callback behind
		// the app's closes it at once: this one comes first and takes the press as the key is taken.
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
			window.onBackInvokedDispatcher.registerOnBackInvokedCallback(
				OnBackInvokedDispatcher.PRIORITY_DEFAULT, wrapper::onBackInvoked
			)
		}
	}

	private fun applyHappDialogStrokeIfNeeded(dialog: AlertDialog) {
		try {
			val window = dialog.window ?: return
			val ctx = window.context
			val typedValue = TypedValue()
			if (!ctx.theme.resolveAttribute(R.attr.happDialogStroke, typedValue, true)) return
			val color = if (typedValue.resourceId != 0) {
				ContextCompat.getColor(ctx, typedValue.resourceId)
			} else {
				typedValue.data
			}
			if (color == 0 || Color.alpha(color) == 0) return
			val windowBackground = window.decorView.background ?: return
			val shape = unwrapMaterialShape(windowBackground) ?: return
			val strokeWidthPx = ctx.resources.displayMetrics.density * 1f
			shape.setStroke(strokeWidthPx, color)
			shape.invalidateSelf()
		} catch (_: Throwable) {}
	}

	private fun unwrapMaterialShape(candidate: Drawable): MaterialShapeDrawable? {
		return when (candidate) {
			is MaterialShapeDrawable -> candidate
			is InsetDrawable -> candidate.drawable?.let { unwrapMaterialShape(it) }
			is LayerDrawable -> {
				for (i in 0 until candidate.numberOfLayers) {
					val inner = candidate.getDrawable(i) ?: continue
					val shape = unwrapMaterialShape(inner)
					if (shape != null) return shape
				}
				null
			}
			else -> null
		}
	}
}

// Touch outside the card and Back both trigger the animated dismiss.
private class AnimatedDismissCallback(
	private val orig: Window.Callback,
	private val dialog: AlertDialog
) : Window.Callback by orig {

	private val createdAt = SystemClock.uptimeMillis()

	override fun dispatchTouchEvent(event: MotionEvent): Boolean {
		if (dialog.isInTransit()) return true
		if (dialog.isShowing) {
			// Ignores only a gesture that began before this dialog existed: the tap that opened it, arriving as
			// click-through. A time window would swallow genuine taps too.
			if (event.downTime < createdAt) {
				return orig.dispatchTouchEvent(event)
			}
			when (event.actionMasked) {
				MotionEvent.ACTION_OUTSIDE -> {
					if (!dialog.dialogState.blockOutsideTap) closeUnlessStayingOpen()
					return true
				}
				MotionEvent.ACTION_DOWN -> {
					if (isOutsideDialogContent(event)) {
						if (!dialog.dialogState.blockOutsideTap) closeUnlessStayingOpen()
						return true
					}
				}
			}
		}
		return orig.dispatchTouchEvent(event)
	}

	override fun dispatchKeyEvent(event: KeyEvent): Boolean {
		if (dialog.isInTransit()) {
			// Back and the keys that act on the dialog are held; system ones (volume, media) reach the window as ever.
			if (event.keyCode == KeyEvent.KEYCODE_BACK || !event.isSystem) return true
			return orig.dispatchKeyEvent(event)
		}
		if (event.keyCode == KeyEvent.KEYCODE_BACK
			&& event.action == KeyEvent.ACTION_UP
			&& dialog.isShowing
		) {
			closeUnlessStayingOpen()
			return true
		}
		return orig.dispatchKeyEvent(event)
	}

	// Given the focus, it takes the keyboard down again: a window with no field never takes the keyboard
	// over, which keeps answering to the activity's field.
	override fun onWindowFocusChanged(hasFocus: Boolean) {
		orig.onWindowFocusChanged(hasFocus)
		if (hasFocus) dialog.context.hideKeyboard()
	}

	// Back from the window's dispatcher, handled as the key is (a swap under way included).
	fun onBackInvoked() {
		if (!dialog.isInTransit() && dialog.isShowing) closeUnlessStayingOpen()
	}

	private fun closeUnlessStayingOpen() {
		if (dialog.dialogState.stayOpenHook?.invoke(null) != true) dialog.dismissAnimated()
	}

	private fun isOutsideDialogContent(event: MotionEvent): Boolean {
		val window = dialog.window ?: return false
		val decor = window.decorView
		val content = decor.findViewById<ViewGroup>(AndroidR.id.content)
		val card = content?.getChildAt(0)
		if (card != null && card.width > 0 && card.height > 0) {
			val loc = IntArray(2)
			card.getLocationInWindow(loc)
			val left = loc[0]
			val top = loc[1]
			val right = left + card.width
			val bottom = top + card.height
			return event.x < left || event.y < top ||
				   event.x > right || event.y > bottom
		}
		return event.x < 0 || event.y < 0 ||
			   event.x > decor.width || event.y > decor.height
	}
}
