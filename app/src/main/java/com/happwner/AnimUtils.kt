package com.happwner

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ValueAnimator
import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.content.ContextWrapper
import android.content.DialogInterface
import android.graphics.Color
import android.graphics.drawable.Drawable
import android.graphics.drawable.InsetDrawable
import android.graphics.drawable.LayerDrawable
import android.os.Build
import android.util.TypedValue
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowManager
import android.view.animation.Interpolator
import android.view.animation.PathInterpolator
import androidx.appcompat.app.AlertDialog
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.shape.MaterialShapeDrawable
import java.util.WeakHashMap

// --- Material timings & interpolators ---
private const val DIALOG_ENTER_MS = 180L
private const val DIALOG_EXIT_MS = 140L
private const val ACTIVITY_ENTER_MS = 260L
private const val ACTIVITY_EXIT_MS = 220L

private const val SETTINGS_OPEN_MS = 220L
private const val SETTINGS_CLOSE_MS = 180L
private const val MAIN_SLIDE_FRACTION = 0.10f
private const val SETTINGS_SLIDE_FRACTION = 0.33f
private const val SETTINGS_FADE_START = 0.7f

private const val LOWRAM_DIALOG_MS = 120L
private const val LOWRAM_ACTIVITY_MS = 100L
private const val LOWRAM_SETTINGS_MS = 140L

private const val DIALOG_DIM_TARGET = 0.35f

private val materialDecelerate: Interpolator = PathInterpolator(0.0f, 0.0f, 0.2f, 1.0f)
private val materialAccelerate: Interpolator = PathInterpolator(0.4f, 0.0f, 1.0f, 1.0f)
private val materialStandard: Interpolator = PathInterpolator(0.4f, 0.0f, 0.2f, 1.0f)

const val ANIM_MODE_OFF = 0
const val ANIM_MODE_SYSTEM = 1
const val ANIM_MODE_SOFTWARE = 2
const val PREF_ANIM_MODE = "anim_mode"

@Volatile private var lowRamCached: Boolean? = null
@Volatile private var perfConstrainedCached: Boolean? = null

// Resolve the animation mode: explicit pref, else the computed default
fun Context.animMode(): Int {
    val prefs = PrefsManager.getSafePrefs(this)
    return if (prefs.contains(PREF_ANIM_MODE)) {
        prefs.getInt(PREF_ANIM_MODE, ANIM_MODE_SOFTWARE)
    } else {
        computeDefaultAnimMode(this)
    }
}

fun Context.skipProgrammaticAnimations(): Boolean = animMode() == ANIM_MODE_OFF

fun Context.killSystemAnimations(): Boolean = animMode() == ANIM_MODE_OFF

// Default: off on low-RAM, system on a weak SoC / old API, otherwise software
fun computeDefaultAnimMode(context: Context): Int {
    val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
    if (am?.isLowRamDevice == true) return ANIM_MODE_OFF

    val cores = Runtime.getRuntime().availableProcessors()
    val mi = ActivityManager.MemoryInfo()
    try { am?.getMemoryInfo(mi) } catch (_: Throwable) {}
    val totalMemGb = mi.totalMem.toDouble() / (1024.0 * 1024.0 * 1024.0)
    val weakSoc = cores <= 4 && totalMemGb > 0.0 && totalMemGb <= 3.0
    val ancient = Build.VERSION.SDK_INT < Build.VERSION_CODES.N

    return if (weakSoc || ancient) ANIM_MODE_SYSTEM else ANIM_MODE_SOFTWARE
}

// Begin an auto-transition unless animations are off (system mode uses a short fixed one)
fun ViewGroup.beginDelayedTransitionIfEnabled(transition: android.transition.Transition? = null) {
    val mode = context.animMode()
    if (mode == ANIM_MODE_OFF) return
    if (transition != null) {
        android.transition.TransitionManager.beginDelayedTransition(this, transition)
        return
    }
    if (mode == ANIM_MODE_SYSTEM) {
        val systemTransition = android.transition.AutoTransition().apply {
            ordering = android.transition.TransitionSet.ORDERING_TOGETHER
            duration = context.resources.getInteger(android.R.integer.config_shortAnimTime).toLong()
        }
        android.transition.TransitionManager.beginDelayedTransition(this, systemTransition)
    } else {
        android.transition.TransitionManager.beginDelayedTransition(this)
    }
}

// Bounds + fade transition, used for adaptive expand/collapse
fun buildBoundsFadeTransition(
    durationMs: Long,
    smooth: Boolean = false,
    excludeFadeTargetId: Int = View.NO_ID
): android.transition.Transition {
    return android.transition.TransitionSet().apply {
        addTransition(android.transition.ChangeBounds())
        addTransition(android.transition.Fade().apply {
            if (excludeFadeTargetId != View.NO_ID) excludeTarget(excludeFadeTargetId, true)
        })
        ordering = android.transition.TransitionSet.ORDERING_TOGETHER
        duration = durationMs
        if (smooth) interpolator = materialStandard
    }
}

// Duration scales with the height delta (in dp)
fun adaptiveAnimDuration(deltaPx: Int, density: Float): Long {
    val deltaDp = kotlin.math.abs(deltaPx) / density
    return when {
        deltaDp <= 50f -> 180L
        deltaDp <= 150f -> 220L
        deltaDp <= 400f -> 270L
        deltaDp <= 800f -> 320L
        else -> 360L
    }
}

// Measure the wrap-content height of a currently-hidden view
private fun View.estimateExpandedHeight(): Int {
    if (visibility == View.VISIBLE) return height
    val p = parent as? ViewGroup ?: return height
    val lp = layoutParams ?: return height
    return try {
        val widthSpec = View.MeasureSpec.makeMeasureSpec(p.width, View.MeasureSpec.AT_MOST)
        val heightSpec = View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
        val saved = lp.height
        lp.height = ViewGroup.LayoutParams.WRAP_CONTENT
        measure(widthSpec, heightSpec)
        val h = measuredHeight
        lp.height = saved
        layoutParams = lp
        h
    } catch (_: Throwable) { height }
}

// Toggle a view with a duration scaled to its expanded height
fun ViewGroup.beginAdaptiveToggleTransition(toggledView: View, excludeFadeTargetId: Int = View.NO_ID) {
    val duration = adaptiveAnimDuration(toggledView.estimateExpandedHeight(), resources.displayMetrics.density)
    beginDelayedTransitionIfEnabled(buildBoundsFadeTransition(duration, smooth = true, excludeFadeTargetId = excludeFadeTargetId))
}

fun View.isDescendantOfView(ancestor: View): Boolean {
    var p: android.view.ViewParent? = this.parent
    while (p != null) {
        if (p === ancestor) return true
        p = p.parent
    }
    return false
}

private val activeDialogDismissals = WeakHashMap<AlertDialog, Boolean>()
private val activeActivityFinishes = WeakHashMap<Activity, Boolean>()
private val activeDimAnimators = WeakHashMap<Window, ValueAnimator>()
private val externalDismissListeners = WeakHashMap<AlertDialog, MutableList<DialogInterface.OnDismissListener>>()

fun AlertDialog.setOnExternalDismissListener(listener: DialogInterface.OnDismissListener) {
    val list = externalDismissListeners.getOrPut(this) { mutableListOf() }
    list.add(listener)
}

// Cached low-RAM-device check
private fun isLowRam(context: Context): Boolean {
    lowRamCached?.let { return it }
    val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
    val result = am?.isLowRamDevice ?: false
    lowRamCached = result
    return result
}

// Cached: low-RAM / weak SoC / old API counts as performance-constrained
fun Context.isPerformanceConstrained(): Boolean {
    perfConstrainedCached?.let { return it }
    val am = getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
    if (am?.isLowRamDevice == true) {
        perfConstrainedCached = true
        return true
    }
    val cores = Runtime.getRuntime().availableProcessors()
    val mi = ActivityManager.MemoryInfo()
    try { am?.getMemoryInfo(mi) } catch (_: Throwable) {}
    val totalMemGb = mi.totalMem.toDouble() / (1024.0 * 1024.0 * 1024.0)
    val weakSoc = cores <= 4 && totalMemGb > 0.0 && totalMemGb <= 3.0
    val ancient = Build.VERSION.SDK_INT < Build.VERSION_CODES.N
    val result = weakSoc || ancient
    perfConstrainedCached = result
    return result
}

// Unwrap the ContextWrapper chain down to the host Activity
private fun findActivity(ctx: Context): Activity? {
    var c: Context? = ctx
    while (c is ContextWrapper) {
        if (c is Activity) return c
        c = c.baseContext
    }
    return null
}

// Mute/restore the global ValueAnimator durationScale via reflection
fun resetAnimatorScale(context: Context? = null) {
    if (context == null) return
    val mode = context.animMode()
    val scale = if (mode == ANIM_MODE_OFF) 0.0f else 1.0f
    try {
        val method = ValueAnimator::class.java
            .getDeclaredMethod("setDurationScale", Float::class.javaPrimitiveType)
        method.isAccessible = true
        method.invoke(null, scale)
    } catch (_: Throwable) {}
}

// --- Activity enter / exit ---
// Fade the activity content in (skipped in off/system modes)
fun Activity.animateEntry() {
    val content = findViewById<View>(android.R.id.content) ?: return
    val mode = animMode()
    if (mode == ANIM_MODE_OFF) {
        try { disableActivityTransition() } catch (_: Throwable) {}
        content.alpha = 1f
        return
    }
    if (mode == ANIM_MODE_SYSTEM) {
        content.alpha = 1f
        return
    }
    val low = isLowRam(this)
    content.alpha = 0f
    content.post {
        val anim = content.animate()
            .alpha(1f)
            .setDuration(if (low) LOWRAM_ACTIVITY_MS else ACTIVITY_ENTER_MS)
            .setInterpolator(materialDecelerate)
        if (!low) anim.withLayer()
        anim.start()
    }
}

// Fade the content out, then finish() (idempotent per activity)
fun Activity.finishAnimated() {
    if (isFinishing || activeActivityFinishes[this] == true) return
    activeActivityFinishes[this] = true
    val content = findViewById<View>(android.R.id.content)
    if (content == null) {
        try { finish(); disableActivityTransition() } catch (_: Throwable) {}
        return
    }
    val mode = animMode()
    if (mode == ANIM_MODE_OFF) {
        try { finish() } catch (_: Throwable) {}
        try { disableActivityTransition() } catch (_: Throwable) {}
        return
    }
    if (mode == ANIM_MODE_SYSTEM) {
        try { finish() } catch (_: Throwable) {}
        return
    }
    val low = isLowRam(this)
    val anim = content.animate()
        .alpha(0f)
        .setDuration(if (low) LOWRAM_ACTIVITY_MS else ACTIVITY_EXIT_MS)
        .setInterpolator(materialAccelerate)
        .withEndAction {
            try { finish(); disableActivityTransition() } catch (_: Throwable) {}
        }
    if (!low) anim.withLayer()
    anim.start()
}

@Suppress("DEPRECATION")
// Fully suppress the system activity transition
fun Activity.disableActivityTransition() {
    if (Build.VERSION.SDK_INT >= 34) {
        try { Api34Transition.disable(this) } catch (_: Throwable) {}
    } else {
        try { overridePendingTransition(0, 0) } catch (_: Throwable) {}
    }
}

// API 34+ transition-override helper
private object Api34Transition {
    @androidx.annotation.RequiresApi(34)
    fun disable(activity: Activity) {
        activity.overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
        activity.overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
    }
}

// --- Settings screen slide-over on top of the main one ---
fun slideSettingsIn(host: View, container: View) {
    val ctx = host.context
    val low = isLowRam(ctx)
    val mode = ctx.animMode()
    val width = host.resources.displayMetrics.widthPixels
    val duration = if (low) LOWRAM_SETTINGS_MS else SETTINGS_OPEN_MS

    host.animate().cancel()
    container.animate().cancel()

    if (mode == ANIM_MODE_OFF || low) {
        host.translationX = -width.toFloat() * MAIN_SLIDE_FRACTION
        container.translationX = 0f
        container.alpha = 1f
        container.visibility = View.VISIBLE
        container.bringToFront()
        return
    }

    val mainTarget = -width.toFloat() * MAIN_SLIDE_FRACTION
    container.translationX = width.toFloat() * SETTINGS_SLIDE_FRACTION
    container.alpha = SETTINGS_FADE_START
    container.visibility = View.VISIBLE
    container.bringToFront()

    val mainAnim = host.animate()
        .translationX(mainTarget)
        .setDuration(duration)
        .setInterpolator(materialDecelerate)
        .withLayer()
    mainAnim.start()

    val containerAnim = container.animate()
        .translationX(0f)
        .alpha(1f)
        .setDuration(duration)
        .setInterpolator(materialDecelerate)
        .withLayer()
    containerAnim.start()
}

// Reverse slide: settings out to the right, main back to 0, then onEnd
fun slideSettingsOut(host: View, container: View, onEnd: () -> Unit) {
    val ctx = host.context
    val low = isLowRam(ctx)
    val mode = ctx.animMode()
    val width = host.resources.displayMetrics.widthPixels
    val duration = if (low) LOWRAM_SETTINGS_MS else SETTINGS_CLOSE_MS

    host.animate().cancel()
    container.animate().cancel()

    if (mode == ANIM_MODE_OFF || low) {
        host.translationX = 0f
        container.translationX = width.toFloat() * SETTINGS_SLIDE_FRACTION
        container.alpha = SETTINGS_FADE_START
        container.visibility = View.GONE
        try { onEnd() } catch (_: Throwable) {}
        return
    }

    val mainAnim = host.animate()
        .translationX(0f)
        .setDuration(duration)
        .setInterpolator(materialDecelerate)
        .withLayer()
    mainAnim.start()

    var ended = false
    val finish: () -> Unit = {
        if (!ended) {
            ended = true
            container.visibility = View.GONE
            container.translationX = width.toFloat() * SETTINGS_SLIDE_FRACTION
            container.alpha = SETTINGS_FADE_START
            host.translationX = 0f
            try { onEnd() } catch (_: Throwable) {}
        }
    }

    val containerAnim = container.animate()
        .translationX(width.toFloat() * SETTINGS_SLIDE_FRACTION)
        .alpha(0f)
        .setDuration(duration)
        .setInterpolator(materialDecelerate)
        .withLayer()
        .withEndAction(finish)
    containerAnim.start()
}

// Jump straight to the open state, no animation
fun applySettingsOpenStateInstantly(host: View, container: View) {
    val ctx = host.context
    val mode = ctx.animMode()
    val width = host.resources.displayMetrics.widthPixels
    if (mode == ANIM_MODE_SYSTEM) {
        host.translationX = 0f
        container.translationX = 0f
        container.alpha = 1f
        container.visibility = View.VISIBLE
        container.bringToFront()
        return
    }
    host.translationX = -width.toFloat() * MAIN_SLIDE_FRACTION
    container.translationX = 0f
    container.alpha = 1f
    container.visibility = View.VISIBLE
    container.bringToFront()
}

// --- Dialog scrim (background dim) animation ---
private fun animateDimIn(window: Window?, duration: Long, low: Boolean) {
    if (window == null) return
    try {
        window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
    } catch (_: Throwable) {}
    if (low) {
        try { window.setDimAmount(DIALOG_DIM_TARGET) } catch (_: Throwable) {}
        return
    }
    try { window.setDimAmount(0.001f) } catch (_: Throwable) { return }
    activeDimAnimators.remove(window)?.cancel()
    val anim = ValueAnimator.ofFloat(0f, DIALOG_DIM_TARGET).apply {
        this.duration = duration
        interpolator = materialDecelerate
        addUpdateListener {
            try { window.setDimAmount(it.animatedValue as Float) } catch (_: Throwable) {}
        }
        addListener(object : AnimatorListenerAdapter() {
            override fun onAnimationEnd(animation: Animator) { activeDimAnimators.remove(window) }
            override fun onAnimationCancel(animation: Animator) { activeDimAnimators.remove(window) }
        })
    }
    activeDimAnimators[window] = anim
    anim.start()
}

// Animate the scrim back down to 0
private fun animateDimOut(window: Window?, duration: Long, low: Boolean) {
    if (window == null) return
    if (low) {
        try { window.setDimAmount(0f) } catch (_: Throwable) {}
        return
    }
    val current = try { window.attributes?.dimAmount ?: DIALOG_DIM_TARGET } catch (_: Throwable) { DIALOG_DIM_TARGET }
    activeDimAnimators.remove(window)?.cancel()
    val anim = ValueAnimator.ofFloat(current, 0f).apply {
        this.duration = duration
        interpolator = materialAccelerate
        addUpdateListener {
            try { window.setDimAmount(it.animatedValue as Float) } catch (_: Throwable) {}
        }
        addListener(object : AnimatorListenerAdapter() {
            override fun onAnimationEnd(animation: Animator) { activeDimAnimators.remove(window) }
            override fun onAnimationCancel(animation: Animator) { activeDimAnimators.remove(window) }
        })
    }
    activeDimAnimators[window] = anim
    anim.start()
}

// Animated dialog dismiss (idempotent, runs once)
fun AlertDialog.dismissAnimated(after: (() -> Unit)? = null) {
    if (activeDialogDismissals[this] == true) return
    activeDialogDismissals[this] = true

    val externals = externalDismissListeners.remove(this)
    externals?.forEach { try { it.onDismiss(this) } catch (_: Throwable) {} }

    val w = window
    val v = w?.decorView
    if (w == null || v == null || !isShowing) {
        try { after?.invoke() } catch (_: Throwable) {}
        try { dismiss() } catch (_: Throwable) {}
        activeDialogDismissals.remove(this)
        return
    }
    val ctx = context
    val low = isLowRam(ctx)
    val tagged = try { v.getTag(R.id.tag_dialog_anim_mode) as? Int } catch (_: Throwable) { null }
    val mode = tagged ?: ctx.animMode()
    val duration = if (low) LOWRAM_DIALOG_MS else DIALOG_EXIT_MS

    if (mode == ANIM_MODE_OFF) {
        try { w.setDimAmount(0f) } catch (_: Throwable) {}
        try { after?.invoke() } catch (_: Throwable) {}
        try { dismiss() } catch (_: Throwable) {}
        activeDialogDismissals.remove(this)
        return
    }

    if (mode == ANIM_MODE_SYSTEM) {
        try { after?.invoke() } catch (_: Throwable) {}
        try { dismiss() } catch (_: Throwable) {}
        activeDialogDismissals.remove(this)
        return
    }

    animateDimOut(w, duration, low)

    val anim = v.animate()
        .alpha(0f)
        .setDuration(duration)
        .setInterpolator(materialAccelerate)
        .withLayer()
        .withEndAction {
            try { after?.invoke() } catch (_: Throwable) {}
            try { dismiss() } catch (_: Throwable) {}
            activeDialogDismissals.remove(this)
        }
    if (!low) anim.scaleX(0.94f).scaleY(0.94f)
    anim.start()
}

// Dialog with custom animations instead of the system ones; we intercept button clicks ourselves
class AnimatedDialogBuilder(context: Context) : MaterialAlertDialogBuilder(context) {
    private var posListener: DialogInterface.OnClickListener? = null
    private var negListener: DialogInterface.OnClickListener? = null
    private var neuListener: DialogInterface.OnClickListener? = null

    private var savedTitle: CharSequence? = null
    private var savedMessage: CharSequence? = null
    private var savedView: View? = null
    private var savedPosText: CharSequence? = null
    private var savedNegText: CharSequence? = null
    private var savedNeuText: CharSequence? = null

    override fun setTitle(title: CharSequence?): AnimatedDialogBuilder {
        savedTitle = title
        super.setTitle(title)
        return this
    }

    override fun setMessage(message: CharSequence?): AnimatedDialogBuilder {
        savedMessage = message
        super.setMessage(message)
        return this
    }

    override fun setView(view: View?): AnimatedDialogBuilder {
        savedView = view
        super.setView(view)
        return this
    }

    override fun setPositiveButton(text: CharSequence?, listener: DialogInterface.OnClickListener?): AnimatedDialogBuilder {
        savedPosText = text
        posListener = listener
        super.setPositiveButton(text, null)
        return this
    }

    override fun setNegativeButton(text: CharSequence?, listener: DialogInterface.OnClickListener?): AnimatedDialogBuilder {
        savedNegText = text
        negListener = listener
        super.setNegativeButton(text, null)
        return this
    }

    override fun setNeutralButton(text: CharSequence?, listener: DialogInterface.OnClickListener?): AnimatedDialogBuilder {
        savedNeuText = text
        neuListener = listener
        super.setNeutralButton(text, null)
        return this
    }

    fun showAnimated(): AlertDialog {
        return doShow(this)
    }

    private fun doShow(builder: AnimatedDialogBuilder): AlertDialog {
        val builderContext = builder.context
        val mode = builderContext.animMode()
        val dialog = builder.create()

        // System mode: show as-is, only wire our button interception
        if (mode == ANIM_MODE_SYSTEM) {
            dialog.show()
            try { dialog.setCanceledOnTouchOutside(false) } catch (_: Throwable) {}
            try { dialog.window?.decorView?.setTag(R.id.tag_dialog_anim_mode, ANIM_MODE_SYSTEM) } catch (_: Throwable) {}
            applyHappDialogStrokeIfNeeded(dialog)

            dialog.setOnDismissListener { d ->
                activeDialogDismissals.remove(dialog)
                val listeners = externalDismissListeners.remove(dialog)
                listeners?.forEach {
                    try { it.onDismiss(d) } catch (_: Throwable) {}
                }
            }

            installCallbackWrapper(dialog)
            wireButton(dialog, AlertDialog.BUTTON_POSITIVE, builder.posListener)
            wireButton(dialog, AlertDialog.BUTTON_NEGATIVE, builder.negListener)
            wireButton(dialog, AlertDialog.BUTTON_NEUTRAL, builder.neuListener)
            return dialog
        }

        // Software mode: kill the system window animation and start the dim near zero
        dialog.window?.let { w ->
            w.setWindowAnimations(0)
            try {
                val lp = w.attributes
                lp.dimAmount = if (mode == ANIM_MODE_OFF) DIALOG_DIM_TARGET else 0.001f
                w.attributes = lp
                w.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
            } catch (_: Throwable) {}
        }
        dialog.show()
        try { dialog.setCanceledOnTouchOutside(false) } catch (_: Throwable) {}
        try { dialog.window?.decorView?.setTag(R.id.tag_dialog_anim_mode, mode) } catch (_: Throwable) {}
        applyHappDialogStrokeIfNeeded(dialog)

        dialog.setOnDismissListener { d ->
            activeDimAnimators.remove(dialog.window)?.cancel()
            activeDialogDismissals.remove(dialog)
            val listeners = externalDismissListeners.remove(dialog)
            listeners?.forEach {
                try { it.onDismiss(d) } catch (_: Throwable) {}
            }
        }

        installCallbackWrapper(dialog)
        wireButton(dialog, AlertDialog.BUTTON_POSITIVE, builder.posListener)
        wireButton(dialog, AlertDialog.BUTTON_NEGATIVE, builder.negListener)
        wireButton(dialog, AlertDialog.BUTTON_NEUTRAL, builder.neuListener)

        // Animate the dialog in: fade plus a slight scale-up
        val window = dialog.window
        val v = window?.decorView
        if (window != null && v != null) {
            if (mode == ANIM_MODE_OFF) {
                try { window.setDimAmount(DIALOG_DIM_TARGET) } catch (_: Throwable) {}
                v.alpha = 1f
                return dialog
            }
            val low = isLowRam(builderContext)
            val duration = if (low) LOWRAM_DIALOG_MS else DIALOG_ENTER_MS

            animateDimIn(window, duration, low)

            v.alpha = 0f
            if (!low) {
                v.scaleX = 0.94f
                v.scaleY = 0.94f
            }

            val anim = v.animate()
                .alpha(1f)
                .setDuration(duration)
                .setInterpolator(materialDecelerate)
                .withLayer()
            if (!low) {
                anim.scaleX(1f).scaleY(1f)
            }
            anim.start()
        }

        return dialog
    }

    // Route a button tap through the animated dismiss, then the real listener
    private fun wireButton(dialog: AlertDialog, which: Int, listener: DialogInterface.OnClickListener?) {
        val button = dialog.getButton(which) ?: return
        button.setOnClickListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE)?.isEnabled = false
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE)?.isEnabled = false
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL)?.isEnabled = false
            dialog.dismissAnimated {
                listener?.onClick(dialog, which)
            }
        }
    }

    // Wrap the window callback so outside-touch / Back animate the dismiss
    private fun installCallbackWrapper(dialog: AlertDialog) {
        val window = dialog.window ?: return
        val original = window.callback ?: return
        if (original is AnimatedDismissCallback) return
        window.callback = AnimatedDismissCallback(original, dialog)
    }

    // Apply the themed 1dp stroke to the dialog's MaterialShape background
    private fun applyHappDialogStrokeIfNeeded(dialog: AlertDialog) {
        try {
            val window = dialog.window ?: return
            val ctx = window.context
            val tv = TypedValue()
            if (!ctx.theme.resolveAttribute(R.attr.happDialogStroke, tv, true)) return
            val color = if (tv.resourceId != 0) {
                androidx.core.content.ContextCompat.getColor(ctx, tv.resourceId)
            } else {
                tv.data
            }
            if (color == 0 || Color.alpha(color) == 0) return
            val bg = window.decorView.background ?: return
            val shape = unwrapMaterialShape(bg) ?: return
            val strokeWidthPx = ctx.resources.displayMetrics.density * 1f
            shape.setStroke(strokeWidthPx, color)
            shape.invalidateSelf()
        } catch (_: Throwable) {}
    }

    // Dig through Inset/Layer drawables to find the MaterialShapeDrawable
    private fun unwrapMaterialShape(d: Drawable): MaterialShapeDrawable? {
        return when (d) {
            is MaterialShapeDrawable -> d
            is InsetDrawable -> d.drawable?.let { unwrapMaterialShape(it) }
            is LayerDrawable -> {
                for (i in 0 until d.numberOfLayers) {
                    val inner = d.getDrawable(i) ?: continue
                    val r = unwrapMaterialShape(inner)
                    if (r != null) return r
                }
                null
            }
            else -> null
        }
    }
}

// Touch outside the dialog card and Back both trigger the animated dismiss
private class AnimatedDismissCallback(
    private val orig: Window.Callback,
    private val dialog: AlertDialog
) : Window.Callback by orig {

    private val createdAt = android.os.SystemClock.uptimeMillis()
    // Post-show window during which we swallow click-through
    private val touchGracePeriodMs = 150L

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if (dialog.isShowing) {
            val sinceCreate = android.os.SystemClock.uptimeMillis() - createdAt
            if (sinceCreate < touchGracePeriodMs) {
                return orig.dispatchTouchEvent(event)
            }
            when (event.actionMasked) {
                MotionEvent.ACTION_OUTSIDE -> {
                    dialog.dismissAnimated()
                    return true
                }
                MotionEvent.ACTION_DOWN -> {
                    if (isOutsideDialogContent(event)) {
                        dialog.dismissAnimated()
                        return true
                    }
                }
            }
        }
        return orig.dispatchTouchEvent(event)
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        if (event.keyCode == KeyEvent.KEYCODE_BACK
            && event.action == KeyEvent.ACTION_UP
            && dialog.isShowing
        ) {
            dialog.dismissAnimated()
            return true
        }
        return orig.dispatchKeyEvent(event)
    }

    private fun isOutsideDialogContent(event: MotionEvent): Boolean {
        val window = dialog.window ?: return false
        val decor = window.decorView
        val content = decor.findViewById<ViewGroup>(android.R.id.content)
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

// Crossfade a view's content with an automatic height animation
fun View.crossfadeContent(onEnd: (() -> Unit)? = null, action: () -> Unit) {
    val mode = context.animMode()
    if (mode == ANIM_MODE_OFF || isLowRam(context)) {
        action()
        alpha = 1f
        onEnd?.invoke()
        return
    }
    val lp = layoutParams

    val preHeight = if (visibility == View.GONE) 0 else height

    animate().cancel()
    (getTag(R.id.tag_crossfade_height_anim) as? ValueAnimator)?.let {
        it.removeAllListeners()
        it.cancel()
    }
    setTag(R.id.tag_crossfade_height_anim, null)

    if (lp != null && preHeight > 0) {
        lp.height = preHeight
        layoutParams = lp
    }

    try { action() } catch (_: Throwable) {}

    // Measure the new content height after the swap
    val targetHeight = if (lp != null) {
        val parentForMeasure = parent as? ViewGroup
        if (parentForMeasure != null) {
            try {
                val widthSpec = View.MeasureSpec.makeMeasureSpec(parentForMeasure.width, View.MeasureSpec.AT_MOST)
                val heightSpec = View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
                lp.height = ViewGroup.LayoutParams.WRAP_CONTENT
                measure(widthSpec, heightSpec)
                val h = measuredHeight
                lp.height = if (preHeight > 0) preHeight else h
                layoutParams = lp
                h
            } catch (_: Throwable) {
                preHeight
            }
        } else preHeight
    } else preHeight

    val duration = adaptiveAnimDuration(targetHeight - preHeight, resources.displayMetrics.density)

    alpha = 0f

    // Animate height old -> new, then settle on wrap-content
    if (lp != null && targetHeight != preHeight) {
        lp.height = preHeight
        layoutParams = lp
        val anim = ValueAnimator.ofInt(preHeight, targetHeight).apply {
            this.duration = duration
            interpolator = materialStandard
            addUpdateListener {
                try {
                    lp.height = it.animatedValue as Int
                    layoutParams = lp
                } catch (_: Throwable) {}
            }
            addListener(object : AnimatorListenerAdapter() {
                override fun onAnimationEnd(animation: Animator) {
                    try {
                        lp.height = ViewGroup.LayoutParams.WRAP_CONTENT
                        layoutParams = lp
                    } catch (_: Throwable) {}
                    setTag(R.id.tag_crossfade_height_anim, null)
                }
            })
        }
        setTag(R.id.tag_crossfade_height_anim, anim)
        anim.start()
    } else if (lp != null) {
        lp.height = ViewGroup.LayoutParams.WRAP_CONTENT
        layoutParams = lp
    }

    // Fade the new content back in
    animate()
        .alpha(1f)
        .setDuration(duration)
        .setInterpolator(materialStandard)
        .withLayer()
        .withEndAction {
            onEnd?.invoke()
        }
        .start()
}
