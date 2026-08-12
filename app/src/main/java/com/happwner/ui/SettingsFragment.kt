package com.happwner.ui

import android.animation.ArgbEvaluator
import android.animation.ValueAnimator
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.os.Build
import android.os.Bundle
import android.transition.ChangeBounds
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.PathInterpolator
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.Fragment
import com.google.android.material.card.MaterialCardView
import com.google.android.material.switchmaterial.SwitchMaterial
import com.happwner.R
import com.happwner.bridge.BridgeController
import com.happwner.bridge.SubscriptionService
import com.happwner.crypto.HappanionBridge
import com.happwner.data.PrefsManager
import com.happwner.hook.ModuleStatus

class SettingsFragment : Fragment() {

    companion object {
        private const val STATE_OPEN_DIALOG = "settings_open_dialog"
        private const val STATE_URI_OPTIONS_SCOPE = "settings_uri_options_scope"

        private const val DIALOG_LANGUAGE = "language"
        private const val DIALOG_THEME = "theme"
        private const val DIALOG_ANIMATIONS = "animations"
        private const val DIALOG_PROCESS_XRAY_INFO = "process_xray_info"
        private const val DIALOG_PROCESS_MIHOMO_INFO = "process_mihomo_info"
        private const val DIALOG_PROCESS_SCOPE_MANUAL = "process_scope_manual"
        private const val DIALOG_PROCESS_SCOPE_SERVER = "process_scope_server"
        private const val DIALOG_PROCESS_URI_OPTIONS = "process_uri_options"

        // Per-scope pref keys: "manual" is the paste/fetch flow, "server" the background Bridge
        // flow.
        private const val DIALOG_RESPONSE_HEADER_INFO = "response_header_info"
        private const val DIALOG_DECRYPTION_HEADER_INFO = "decryption_header_info"
        private const val DIALOG_BRIDGE_INFO = "bridge_info"
        private const val DIALOG_INFO = "info"
        private const val DIALOG_XPOSED = "xposed"
        private const val DIALOG_HAPPANION = "happanion"
    }

    private fun getSafePrefs(context: Context): SharedPreferences = PrefsManager.getSafePrefs(context)

    private var prefsListenerRegistered = false
    private var currentDialog: AlertDialog? = null
    private var currentDialogTag: String? = null

    // Which scope ("manual"/"server") the URI-options gear dialog was opened
    // for, so a rotation while it's showing restores it for the right one.
    private var uriOptionsScope: String = PrefsManager.SCOPE_MANUAL

    // Set while showXposedDialog()'s dialog is on screen, so prefsListener can refresh it in place
    // when Xposed/LSPatch/HWID state changes externally instead of only picking it up the next time
    private var xposedDialogRoot: View? = null

    // Same idea for the Happanion dialog, but driven by onResume rather than prefsListener: installing or
    // removing a package doesn't touch prefs, so there is nothing for the listener to fire on.
    private var happanionDialogRoot: View? = null

    // External settings changes (e.g. the bridge/HWID toggle) trigger a UI sync
    private val prefsListener = SharedPreferences.OnSharedPreferenceChangeListener { sharedPrefs, key ->
        if (key == "bridge_enabled") {
            val isEnabled = sharedPrefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)
            val v = view ?: return@OnSharedPreferenceChangeListener
            v.post {
                try {
                    v.findViewById<SwitchMaterial>(R.id.switchEnableBridge)?.isChecked = isEnabled
                } catch (_: Throwable) {}
            }
        } else if (key == "lspatch_mode" || key == "lspatch_apps") {
            val dv = xposedDialogRoot ?: return@OnSharedPreferenceChangeListener
            dv.post {
                try {
                    if (isAdded && !isHidden && currentDialogTag == DIALOG_XPOSED &&
                        currentDialog?.isShowing == true
                    ) {
                        populateXposedDialogContent(dv)
                    }
                } catch (_: Throwable) {}
            }
        } else if (key == PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION || key == PrefsManager.PREF_USE_CUSTOM_HWID_INPUT || key == PrefsManager.PREF_CUSTOM_HWID || key == PrefsManager.PREF_CAPTURED_ID) {
            val dv = xposedDialogRoot ?: return@OnSharedPreferenceChangeListener
            dv.post {
                try {
                    if (isAdded && !isHidden && currentDialogTag == DIALOG_XPOSED &&
                        currentDialog?.isShowing == true
                    ) {
                        dv.findViewById<SwitchMaterial>(R.id.switchHwidSpoof)?.isChecked =
                            PrefsManager.isHwidSpoofEnabled(dv.context)
                        updateHwidSpoofStatus(dv)
                    }
                } catch (_: Throwable) {}
            }
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_settings, container, false)
    }

    // Wire every settings row, then restore any open dialog
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        bindInsets(view)
        bindToolbar(view)
        bindHappanionCardItem(view)
        bindDecryptionHeaderInfoIcon(view)
        bindLanguageItem(view)
        bindThemeItem(view)
        bindAnimationsItem(view)
        bindProcessManualScopeItem(view)
        bindProcessServerScopeItem(view)
        bindResponseHeaderInfoIcon(view)
        bindEnableBridgeItem(view)
        bindBridgeInstructionIcon(view)
        bindBatteryOptItem(view)
        bindWatchdogItem(view)
        bindXposedCardItem(view)

        updateBatteryStatus()

        // Restore before restoreDialog() below: the URI-options dialog is per-scope, and reopening
        // it with the default would silently point the "Subscription" settings at "Profiles".
        savedInstanceState?.getString(STATE_URI_OPTIONS_SCOPE)?.let { uriOptionsScope = it }

        val restored = savedInstanceState?.getString(STATE_OPEN_DIALOG)
        if (restored != null) {
            view.post {
                if (isAdded && !isHidden) restoreDialog(restored)
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_OPEN_DIALOG, currentDialogTag)
        outState.putString(STATE_URI_OPTIONS_SCOPE, uriOptionsScope)
    }

    override fun onResume() {
        super.onResume()

        if (!isHidden) {
            registerPrefsListener()
            refreshDynamicState()
            // Coming back from the system installer/uninstaller lands here.
            refreshHappanionDialogIfShowing()
        }
    }

    override fun onPause() {
        super.onPause()
        unregisterPrefsListener()
    }

    // Shown/hidden by the slide: (un)register the pref listener and refresh
    override fun onHiddenChanged(hidden: Boolean) {
        super.onHiddenChanged(hidden)
        if (hidden) {

            dismissCurrentDialog()
            unregisterPrefsListener()
        } else {

            registerPrefsListener()
            refreshDynamicState()
        }
    }

    // Re-show any open dialog and animate the relayout on a config change
    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        if (isHidden) return
        if (!lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) return
        val ctx = context ?: return

        val openTag = currentDialogTag
        if (openTag != null) {
            dismissCurrentDialog()
            view?.post {
                if (isAdded && !isHidden && currentDialogTag == null) restoreDialog(openTag)
            }
        }

        if (ctx.skipProgrammaticAnimations()) return
        val root = view as? ViewGroup ?: return

        resetAnimatorScale(ctx)
        root.beginDelayedTransitionIfEnabled(
            ChangeBounds().apply {
                duration = 160L
                interpolator = PathInterpolator(0f, 0f, 0.2f, 1f)
            }
        )

    }

    override fun onDestroyView() {
        dismissCurrentDialog()
        super.onDestroyView()
    }

    private fun dismissCurrentDialog() {
        // The checkbox this animates lives inside the dialog view, so it must
        // not outlive it - onAnimationEnd would touch a detached view.
        checkboxTintAnimator?.cancel()
        checkboxTintAnimator = null

        // Cleared here as well as in each dialog's own dismiss listener, which only runs if dismiss() is
        // actually called - it isn't when the dialog is already gone, leaving a detached View held here.
        xposedDialogRoot = null
        happanionDialogRoot = null

        val d = currentDialog
        currentDialog = null
        currentDialogTag = null
        if (d != null && d.isShowing) {
            try { d.dismiss() } catch (_: Throwable) {}
        }
    }

    // Track the visible dialog so it can be restored or dismissed
    private fun trackDialog(tag: String, dialog: AlertDialog) {
        currentDialog = dialog
        currentDialogTag = tag
        dialog.setOnExternalDismissListener {
            if (currentDialog === dialog) {
                currentDialog = null
                currentDialogTag = null
            }
        }
    }

    // Restore the open dialog after a rotation/recreate
    private fun restoreDialog(tag: String) {
        when (tag) {
            DIALOG_LANGUAGE -> showLanguageDialog()
            DIALOG_THEME -> showThemeDialog()
            DIALOG_ANIMATIONS -> showAnimationsDialog()
            DIALOG_PROCESS_XRAY_INFO -> showProcessXrayInfoDialog()
            DIALOG_PROCESS_MIHOMO_INFO -> showProcessMihomoInfoDialog()
            DIALOG_PROCESS_SCOPE_MANUAL -> showProcessScopeDialog(PrefsManager.SCOPE_MANUAL)
            DIALOG_PROCESS_SCOPE_SERVER -> showProcessScopeDialog(PrefsManager.SCOPE_SERVER)
            DIALOG_PROCESS_URI_OPTIONS -> showUriOptionsDialog(uriOptionsScope)
            DIALOG_RESPONSE_HEADER_INFO -> showResponseHeaderInfoDialog()
            DIALOG_DECRYPTION_HEADER_INFO -> showDecryptionHeaderInfoDialog()
            DIALOG_BRIDGE_INFO -> showBridgeInfoDialog()
            DIALOG_INFO -> showInfoDialog()
            DIALOG_XPOSED -> showXposedDialog()
            DIALOG_HAPPANION -> showHappanionDialog()
            // Every tag passed to trackDialog needs a branch above.
            else -> android.util.Log.w(
                "Happwner:Settings",
                "no restore path for dialog tag \"$tag\" - it will not survive a rotation"
            )
        }
    }

    private fun registerPrefsListener() {
        if (prefsListenerRegistered) return
        val ctx = context ?: return
        try {
            getSafePrefs(ctx).registerOnSharedPreferenceChangeListener(prefsListener)
            prefsListenerRegistered = true
        } catch (_: Throwable) {}
    }

    private fun unregisterPrefsListener() {
        if (!prefsListenerRegistered) return
        val ctx = context ?: return
        try {
            getSafePrefs(ctx).unregisterOnSharedPreferenceChangeListener(prefsListener)
        } catch (_: Throwable) {}
        prefsListenerRegistered = false
    }

    // Re-reads the Happanion dialog against what is installed now. Called from onResume: a package
    // appearing or disappearing writes no preference, so prefsListener never fires for it.
    private fun refreshHappanionDialogIfShowing() {
        val dv = happanionDialogRoot ?: return
        val dialog = currentDialog ?: return
        if (currentDialogTag != DIALOG_HAPPANION || !dialog.isShowing) return
        populateHappanionDialogContent(dv)
        applyHappanionInstallButton(dialog)
    }

    // Re-read every toggle and label from prefs into the UI
    private fun refreshDynamicState() {
        val v = view ?: return
        val ctx = context ?: return
        val prefs = getSafePrefs(ctx)

        v.findViewById<SwitchMaterial>(R.id.switchEnableBridge)?.isChecked =
            prefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)
        v.findViewById<SwitchMaterial>(R.id.switchWatchdog)?.isChecked =
            prefs.getBoolean(PrefsManager.PREF_BRIDGE_WATCHDOG, false)

        val animationOptions = resources.getStringArray(R.array.animation_options)
        v.findViewById<TextView>(R.id.textAnimationsStatus)?.text =
            fromHtml(animationOptions.getOrElse(ctx.animMode()) { animationOptions[0] })

        updateBatteryStatus()
    }

    // Insets for the system bars, plus auto-scroll to the field when the keyboard appears
    private fun bindInsets(view: View) {
        val statusBarBackground = view.findViewById<View>(R.id.settingsStatusBarBackground)
        val settingsScrollView = view.findViewById<android.widget.ScrollView>(R.id.settingsScrollView)
        val toolbar = view.findViewById<View>(R.id.settingsToolbar)
        ViewCompat.setOnApplyWindowInsetsListener(view) { _, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            val imeInsets = insets.getInsets(WindowInsetsCompat.Type.ime())
            val imeVisible = insets.isVisible(WindowInsetsCompat.Type.ime())
            val bottomPadding = kotlin.math.max(systemBars.bottom, imeInsets.bottom)

            statusBarBackground.layoutParams.height = systemBars.top
            statusBarBackground.requestLayout()
            settingsScrollView.setPadding(systemBars.left, 0, systemBars.right, bottomPadding)
            toolbar?.setPadding(systemBars.left, toolbar.paddingTop, systemBars.right, toolbar.paddingBottom)

            if (imeVisible) {
                activity?.currentFocus?.let { focused ->
                    if (!focused.isDescendantOfView(settingsScrollView)) return@let
                    settingsScrollView.post {
                        val rect = android.graphics.Rect()
                        focused.getDrawingRect(rect)
                        settingsScrollView.offsetDescendantRectToMyCoords(focused, rect)
                        val density = resources.displayMetrics.density
                        val offset = (resources.getInteger(R.integer.scroll_offset_ime_dp) * density).toInt()
                        val targetScrollY = rect.bottom - (settingsScrollView.height - bottomPadding) + offset
                        if (targetScrollY > settingsScrollView.scrollY) {
                            settingsScrollView.smoothScrollTo(0, targetScrollY)
                        }
                    }
                }
            }

            insets
        }
        ViewCompat.requestApplyInsets(view)
    }

    private fun bindToolbar(view: View) {
        view.findViewById<View>(R.id.action_back).setOnClickListener {
            val act = activity
            when (act) {
                is MainActivity -> act.closeSettings()
                is SettingsActivity -> act.finish()
                else -> act?.finish()
            }
        }
        view.findViewById<View>(R.id.action_info).setOnClickListener {
            showInfoDialog()
        }
    }

    // Setting: Language
    private fun bindLanguageItem(view: View) {
        val textLanguageStatus = view.findViewById<TextView>(R.id.textLanguageStatus)
        val langOptionsRaw = resources.getStringArray(R.array.language_options)
        val ctx = requireContext()
        val currentLang = getSafePrefs(ctx).getString(PrefsManager.PREF_APP_LANG, "system") ?: "system"
        val currentLangIndex = when (currentLang) {
            "ru" -> 1
            "en" -> 2
            else -> 0
        }
        textLanguageStatus.text = fromHtml(langOptionsRaw[currentLangIndex])

        view.findViewById<MaterialCardView>(R.id.itemLanguage).setOnClickListener {
            showLanguageDialog()
        }
    }

    // Language picker; on choice restart the bridge and recreate for the new locale
    private fun showLanguageDialog() {
        val act = activity ?: return
        val ctx = context ?: return
        val prefs = getSafePrefs(ctx)
        val langOptionsRaw = resources.getStringArray(R.array.language_options)
        val langOptions = langOptionsRaw.map { fromHtml(it) }.toTypedArray()
        val currentLang = prefs.getString(PrefsManager.PREF_APP_LANG, "system") ?: "system"
        val currentLangIndex = when (currentLang) {
            "ru" -> 1
            "en" -> 2
            else -> 0
        }

        val dialogView = layoutInflater.inflate(R.layout.dialog_select_option, null)
        val rg = dialogView.findViewById<android.widget.RadioGroup>(R.id.dialogRadioGroup)
        val r1 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption1)
        val r2 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption2)
        val r3 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption3)

        r1.text = langOptions[0]
        r2.text = langOptions[1]
        r3.text = langOptions[2]
        when (currentLangIndex) {
            0 -> r1.isChecked = true
            1 -> r2.isChecked = true
            2 -> r3.isChecked = true
        }

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.label_language)))
            .setView(dialogView)
            .showAnimated()
        trackDialog(DIALOG_LANGUAGE, dialog)

        rg.setOnCheckedChangeListener { _, checkedId ->
            val newLang = when (checkedId) {
                R.id.radioOption2 -> "ru"
                R.id.radioOption3 -> "en"
                else -> "system"
            }
            prefs.edit().putString(PrefsManager.PREF_APP_LANG, newLang).apply()
            val service = Intent(act, SubscriptionService::class.java)
            if (prefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)) {
                try { act.stopService(service) } catch (_: Throwable) {}
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        act.startForegroundService(service)
                    } else {
                        act.startService(service)
                    }
                } catch (_: Throwable) {}
            }
            applyLocaleChange(act, newLang)
            currentDialog = null
            currentDialogTag = null
            try { dialog.dismiss() } catch (_: Throwable) {}
        }
    }

    // Setting: Theme
    private fun bindThemeItem(view: View) {
        val textThemeStatus = view.findViewById<TextView>(R.id.textThemeStatus)
        val ctx = requireContext()
        val themeOptionsRaw = resources.getStringArray(R.array.theme_options)
        val currentTheme = getSafePrefs(ctx).getInt(PrefsManager.PREF_THEME_MODE, 0)
        textThemeStatus.text = fromHtml(themeStatusText(ctx, currentTheme, themeOptionsRaw))

        view.findViewById<MaterialCardView>(R.id.itemTheme).setOnClickListener {
            showThemeDialog()
        }
    }

    // Theme label, with a Monet-accent suffix when enabled
    private fun themeStatusText(ctx: Context, themeIdx: Int, themeOptionsRaw: Array<String>): String {
        val base = themeOptionsRaw.getOrElse(themeIdx) { themeOptionsRaw[0] }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            getSafePrefs(ctx).getBoolean(PrefsManager.PREF_MONET_ACCENT, false)
        ) {
            "$base, ${getString(R.string.setting_monet_accent)}"
        } else {
            base
        }
    }

    // Theme picker (+ Monet switch on Android 12+); recreate on change
    private fun showThemeDialog() {
        val act = activity ?: return
        val ctx = context ?: return
        val prefs = getSafePrefs(ctx)
        val themeOptionsRaw = resources.getStringArray(R.array.theme_options)
        val themeOptions = themeOptionsRaw.map { fromHtml(it) }.toTypedArray()
        var currentTheme = prefs.getInt(PrefsManager.PREF_THEME_MODE, 0)
        val textThemeStatus = view?.findViewById<TextView>(R.id.textThemeStatus)

        val dialogView = layoutInflater.inflate(R.layout.dialog_theme_select, null)
        val rg = dialogView.findViewById<android.widget.RadioGroup>(R.id.dialogRadioGroup)
        val r1 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption1)
        val r2 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption2)
        val r3 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption3)
        val r4 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption4)
        val monetContainer = dialogView.findViewById<View>(R.id.monetContainer)
        val monetDivider = dialogView.findViewById<View>(R.id.monetDivider)
        val switchMonet = dialogView.findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switchMonetAccent)

        r1.text = themeOptions[0]
        r2.text = themeOptions[1]
        r3.text = themeOptions[2]
        r4.text = themeOptions[3]
        when (currentTheme) {
            0 -> r1.isChecked = true
            1 -> r2.isChecked = true
            2 -> r3.isChecked = true
            3 -> r4.isChecked = true
        }

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.label_theme)))
            .setView(dialogView)
            .showAnimated()
        trackDialog(DIALOG_THEME, dialog)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            monetContainer.visibility = View.VISIBLE
            monetDivider.visibility = View.VISIBLE
            switchMonet.isChecked = prefs.getBoolean(PrefsManager.PREF_MONET_ACCENT, false)
            val monetRowClick = View.OnClickListener { switchMonet.toggle() }
            monetContainer.setOnClickListener(monetRowClick)
            switchMonet.setOnCheckedChangeListener { _, isChecked ->
                if (prefs.getBoolean(PrefsManager.PREF_MONET_ACCENT, false) == isChecked) return@setOnCheckedChangeListener
                prefs.edit().putBoolean(PrefsManager.PREF_MONET_ACCENT, isChecked).apply()
                applyThemeChange(act)
                currentDialog = null
                currentDialogTag = null
                try { dialog.dismiss() } catch (_: Throwable) {}
            }
        }

        rg.setOnCheckedChangeListener { _, checkedId ->
            val which = when (checkedId) {
                R.id.radioOption1 -> 0
                R.id.radioOption2 -> 1
                R.id.radioOption3 -> 2
                R.id.radioOption4 -> 3
                else -> 0
            }
            if (which == currentTheme) {
                dialog.dismissAnimated()
                return@setOnCheckedChangeListener
            }
            currentTheme = which
            prefs.edit().putInt(PrefsManager.PREF_THEME_MODE, which).apply()
            textThemeStatus?.text = fromHtml(themeStatusText(ctx, which, themeOptionsRaw))
            applyThemeChange(act)
            currentDialog = null
            currentDialogTag = null
            try { dialog.dismiss() } catch (_: Throwable) {}
        }
    }

    // Recreate with a crossfade for a theme change
    private fun applyThemeChange(act: android.app.Activity) {
        ThemeTransition.captureAndRecreate(act, 440L)
    }

    // Recreate with a crossfade for a locale change
    private fun applyLocaleChange(act: android.app.Activity, @Suppress("UNUSED_PARAMETER") newLang: String) {
        ThemeTransition.captureAndRecreate(act, 360L)
    }

    // Setting: Animations
    private fun bindAnimationsItem(view: View) {
        val textAnimationsStatus = view.findViewById<TextView>(R.id.textAnimationsStatus)
        val ctx = requireContext()
        val animationOptionsRaw = resources.getStringArray(R.array.animation_options)
        textAnimationsStatus.text = fromHtml(animationOptionsRaw.getOrElse(ctx.animMode()) { animationOptionsRaw[0] })

        view.findViewById<MaterialCardView>(R.id.itemAnimations).setOnClickListener {
            showAnimationsDialog()
        }
    }

    // Animation-mode picker (off / system / software)
    private fun showAnimationsDialog() {
        val act = activity ?: return
        val ctx = context ?: return
        val prefs = getSafePrefs(ctx)
        val animationOptionsRaw = resources.getStringArray(R.array.animation_options)
        val animationOptions = animationOptionsRaw.map { fromHtml(it) }.toTypedArray()
        val currentMode = ctx.animMode()
        val textAnimationsStatus = view?.findViewById<TextView>(R.id.textAnimationsStatus)

        val dialogView = layoutInflater.inflate(R.layout.dialog_select_option, null)
        val rg = dialogView.findViewById<android.widget.RadioGroup>(R.id.dialogRadioGroup)
        val r1 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption1)
        val r2 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption2)
        val r3 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption3)

        r1.text = animationOptions[ANIM_MODE_OFF]
        r2.text = animationOptions[ANIM_MODE_SYSTEM]
        r3.text = animationOptions[ANIM_MODE_SOFTWARE]
        when (currentMode) {
            ANIM_MODE_OFF -> r1.isChecked = true
            ANIM_MODE_SYSTEM -> r2.isChecked = true
            ANIM_MODE_SOFTWARE -> r3.isChecked = true
        }

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.label_animations)))
            .setView(dialogView)
            .showAnimated()
        trackDialog(DIALOG_ANIMATIONS, dialog)

        rg.setOnCheckedChangeListener { _, checkedId ->
            val mode = when (checkedId) {
                R.id.radioOption1 -> ANIM_MODE_OFF
                R.id.radioOption2 -> ANIM_MODE_SYSTEM
                R.id.radioOption3 -> ANIM_MODE_SOFTWARE
                else -> ANIM_MODE_SOFTWARE
            }
            prefs.edit().putInt(PREF_ANIM_MODE, mode).apply()
            textAnimationsStatus?.text = fromHtml(animationOptionsRaw[mode])
            dialog.dismissAnimated {
                resetAnimatorScale(ctx)
            }
        }
    }

    // Setting: Xposed card under "Decryption" - opens straight to either the "not found"
    // explanation or the four options moved out of the old always-in-the-page Xposed section.
    private fun bindXposedCardItem(view: View) {
        view.findViewById<MaterialCardView>(R.id.itemXposed).setOnClickListener {
            showXposedDialog()
        }
    }

    private fun showXposedDialog() {
        val act = activity ?: return
        val dialogView = layoutInflater.inflate(R.layout.dialog_xposed, null)
        populateXposedDialogContent(dialogView)

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.setting_header_xposed)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
            .showAnimated()
        dialog.setOnDismissListener { xposedDialogRoot = null }
        xposedDialogRoot = dialogView
        trackDialog(DIALOG_XPOSED, dialog)
    }

    // Fills in dialog_xposed.xml for the current detection state.
    private fun populateXposedDialogContent(dialogView: View) {
        val ctx = context ?: return
        val xposedActive = PrefsManager.isXposedActive(ctx)

        dialogView.findViewById<View>(R.id.xposedNotFoundBlock)?.visibility =
            if (xposedActive) View.GONE else View.VISIBLE
        dialogView.findViewById<View>(R.id.xposedFoundBlock)?.visibility =
            if (xposedActive) View.VISIBLE else View.GONE

        if (!xposedActive) {
            val textNotFound = dialogView.findViewById<TextView>(R.id.textXposedNotFound)
            textNotFound?.text = fromHtml(getString(R.string.setting_xposed_not_found))
            textNotFound?.movementMethod = android.text.method.LinkMovementMethod.getInstance()
            dialogView.findViewById<TextView>(R.id.textXposedFeatures)?.text =
                fromHtml(getString(R.string.setting_xposed_not_found_features))
            return
        }

        // Show-duplicates first: bindInterceptLinksItem ends by applying the lock to that row, and
        // setOnClickListener sets clickable back to true, so the lock has to be the last thing to touch it.
        bindShowDuplicatesItem(dialogView)
        bindInterceptLinksItem(dialogView)
        bindHwidSpoofItem(dialogView)
        bindUnlockItem(dialogView)

        val unlockTargetActive = PrefsManager.isUnlockTargetActiveForModule(ctx)
        dialogView.findViewById<View>(R.id.itemUnlock)?.visibility =
            if (unlockTargetActive) View.VISIBLE else View.GONE
    }

    // Setting: Happanion card under "Decryption" - opens straight to either the "not compatible"
    // explanation or the Force-Happanion test toggle moved out of its old standalone card.
    private fun bindHappanionCardItem(view: View) {
        view.findViewById<MaterialCardView>(R.id.itemHappanion).setOnClickListener {
            showHappanionDialog()
        }
    }

    private fun showHappanionDialog() {
        val act = activity ?: return
        val ctx = context ?: return
        val dialogView = layoutInflater.inflate(R.layout.dialog_happanion, null)
        populateHappanionDialogContent(dialogView)

        // The label and listener are set again in applyHappanionInstallButton once the dialog
        // exists, so returning from the installer swaps "Install" for "Uninstall" in place.
        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.setting_header_happanion)))
            .setView(dialogView)
            .setNegativeButton(
                fromHtml(getString(
                    if (HappanionBridge.isInstalled(ctx)) R.string.btn_uninstall
                    else R.string.btn_install
                )),
                null
            )
            .setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
            .showAnimated()

        applyHappanionInstallButton(dialog)
        dialog.setOnDismissListener { happanionDialogRoot = null }
        happanionDialogRoot = dialogView
        trackDialog(DIALOG_HAPPANION, dialog)
    }

    // Points the dialog's negative button at whichever action fits what is installed. The listener is
    // attached to the button so the dialog does not close on tap; Install is deliberately inert for now.
    private fun applyHappanionInstallButton(dialog: AlertDialog) {
        val ctx = context ?: return
        val button = dialog.getButton(android.content.DialogInterface.BUTTON_NEGATIVE) ?: return
        val installed = HappanionBridge.isInstalled(ctx)

        button.text = fromHtml(getString(
            if (installed) R.string.btn_uninstall else R.string.btn_install
        ))
        button.isEnabled = installed
        button.setOnClickListener {
            if (!HappanionBridge.isInstalled(ctx)) return@setOnClickListener
            try {
                startActivity(HappanionBridge.uninstallIntent())
            } catch (_: Throwable) {}
        }
    }

    // Fills in dialog_happanion.xml: the Force-Happanion toggle only shows for the exact required build,
    // since an older or newer one might not speak the same protocol as HappanionBridge expects.
    private fun populateHappanionDialogContent(dialogView: View) {
        val ctx = context ?: return
        val compatible = HappanionBridge.isCompatibleVersionInstalled(ctx)

        dialogView.findViewById<View>(R.id.happanionNotFoundBlock)?.visibility =
            if (compatible) View.GONE else View.VISIBLE
        dialogView.findViewById<View>(R.id.happanionFoundBlock)?.visibility =
            if (compatible) View.VISIBLE else View.GONE

        if (!compatible) {
            dialogView.findViewById<TextView>(R.id.textHappanionNotFound)?.text =
                fromHtml(getString(R.string.setting_happanion_not_found))
            return
        }

        bindForceHapplibItem(dialogView)
    }

    // Setting: HWID spoof
    private fun bindHwidSpoofItem(view: View) {
        val row = view.findViewById<View>(R.id.rowHwidSpoofToggle)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchHwidSpoof)
        val ctx = requireContext()
        switch.isChecked = PrefsManager.isHwidSpoofEnabled(ctx)
        updateHwidSpoofStatus(view)
        row.setOnClickListener {
            val newState = !switch.isChecked
            getSafePrefs(ctx).edit().putBoolean(PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION, newState).apply()
            switch.isChecked = newState
            updateHwidSpoofStatus(view)
            PrefsManager.fixSharedPrefs(ctx)
        }
    }

    // Status line under HWID spoof: off / enter-field / current value
    private fun updateHwidSpoofStatus(view: View) {
        val status = view.findViewById<TextView>(R.id.textHwidSpoofStatus) ?: return
        val ctx = context ?: return
        val prefs = getSafePrefs(ctx)
        val toggleOn = PrefsManager.isHwidSpoofEnabled(ctx)
        val fieldActive = prefs.getBoolean(PrefsManager.PREF_USE_CUSTOM_HWID_INPUT, false)
        val custom = prefs.getString(PrefsManager.PREF_CUSTOM_HWID, "")?.trim().orEmpty()

        status.text = when {
            toggleOn && !fieldActive -> getString(R.string.label_hwid_spoof_enable_field)
            toggleOn && fieldActive && custom.isNotEmpty() ->
                getString(R.string.label_hwid_spoof_current, custom)
            else -> getString(R.string.label_hwid_spoof_off)
        }
    }

    // Setting: Unlock profiles in encrypted subscriptions
    private fun bindUnlockItem(view: View) {
        val item = view.findViewById<View>(R.id.itemUnlock)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchUnlock)
        val ctx = requireContext()
        switch.isChecked = PrefsManager.isUnlockHookEnabled(ctx)
        val update: (Boolean) -> Unit = { checked ->
            getSafePrefs(ctx).edit().putBoolean(PrefsManager.PREF_HOOK_HAPP_UNLOCK_SETTINGS, checked).apply()
            switch.isChecked = checked
            PrefsManager.fixSharedPrefs(ctx)
        }
        item.setOnClickListener { update(!switch.isChecked) }
    }

    // Setting: Show duplicates - locked while link interception (below) is off
    private fun bindShowDuplicatesItem(view: View) {
        val item = view.findViewById<View>(R.id.itemShowDuplicates)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchShowDuplicates)
        val ctx = requireContext()
        switch.isChecked = getSafePrefs(ctx).getBoolean(PrefsManager.PREF_SHOW_DUPLICATES, false)
        val update: (Boolean) -> Unit = { checked ->
            getSafePrefs(ctx).edit().putBoolean(PrefsManager.PREF_SHOW_DUPLICATES, checked).apply()
            switch.isChecked = checked
            PrefsManager.fixSharedPrefs(ctx)
        }
        item.setOnClickListener { update(!switch.isChecked) }
    }

    // "Show all links" only means anything while link interception is capturing, so it is locked
    // rather than merely greyed when that is off and a tap can't flip a setting with no effect.
    private fun applyShowDuplicatesLock(dialogView: View, interceptEnabled: Boolean) {
        val item = dialogView.findViewById<View>(R.id.itemShowDuplicates) ?: return
        item.isEnabled = interceptEnabled
        item.isClickable = interceptEnabled
        dialogView.findViewById<SwitchMaterial>(R.id.switchShowDuplicates)?.isEnabled = interceptEnabled
        dialogView.findViewById<TextView>(R.id.textShowDuplicatesTitle)?.isEnabled = interceptEnabled
        dialogView.findViewById<TextView>(R.id.textShowDuplicatesDesc)?.isEnabled = interceptEnabled
    }

    // Setting: force every happ:// link through Happanion (testing only, read
    // in-process by MainActivity - no need to broadcast to a hooked process)
    private fun bindForceHapplibItem(view: View) {
        val item = view.findViewById<View>(R.id.itemForceHapplib)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchForceHapplib)
        val ctx = requireContext()
        switch.isChecked = getSafePrefs(ctx).getBoolean(PrefsManager.PREF_FORCE_HAPPLIB, false)
        val update: (Boolean) -> Unit = { checked ->
            getSafePrefs(ctx).edit().putBoolean(PrefsManager.PREF_FORCE_HAPPLIB, checked).apply()
            switch.isChecked = checked
        }
        item.setOnClickListener { update(!switch.isChecked) }
    }

    // Setting: Link interception
    private fun bindInterceptLinksItem(view: View) {
        val item = view.findViewById<View>(R.id.itemInterceptLinks)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchInterceptLinks)
        val ctx = requireContext()
        switch.isChecked = getSafePrefs(ctx).getBoolean(PrefsManager.PREF_INTERCEPT_ENABLED, false)
        applyShowDuplicatesLock(view, switch.isChecked)
        val update: (Boolean) -> Unit = { checked ->
            getSafePrefs(ctx).edit().putBoolean(PrefsManager.PREF_INTERCEPT_ENABLED, checked).apply()
            switch.isChecked = checked
            PrefsManager.fixSharedPrefs(ctx)
            applyShowDuplicatesLock(view, checked)
        }
        item.setOnClickListener { update(!switch.isChecked) }
    }

    // Setting: conversion for manually pasted/fetched profiles ("Profiles")
    private fun bindProcessManualScopeItem(view: View) {
        setHtmlText(view.findViewById(R.id.textProcessManualScopeDesc), R.string.setting_process_scope_manual_desc)
        view.findViewById<MaterialCardView>(R.id.itemProcessManualScope).setOnClickListener {
            showProcessScopeDialog(PrefsManager.SCOPE_MANUAL)
        }
    }

    // Setting: conversion for the background Bridge subscription ("Subscription")
    private fun bindProcessServerScopeItem(view: View) {
        setHtmlText(view.findViewById(R.id.textProcessServerScopeDesc), R.string.setting_process_scope_server_desc)
        view.findViewById<MaterialCardView>(R.id.itemProcessServerScope).setOnClickListener {
            showProcessScopeDialog(PrefsManager.SCOPE_SERVER)
        }
    }

    // Base64 decoding + Xray output mode for one scope ("manual" or "server"), read and written
    // through process_b64_<scope> and process_mode_<scope>.
    private var checkboxTintAnimator: ValueAnimator? = null

    // Builds the state array a ColorStateList is queried with, so the target colours come from the
    // very same XML selectors the layout uses (dialog_control_selector / dialog_label_selector) -
    private fun controlState(enabled: Boolean, checked: Boolean): IntArray = intArrayOf(
        if (enabled) android.R.attr.state_enabled else -android.R.attr.state_enabled,
        if (checked) android.R.attr.state_checked else -android.R.attr.state_checked
    )

    // Fades the checkbox button tint, checkmark tint and label between the colours its
    // ColorStateLists resolve to for the old and new state.
    private fun animateCheckboxTint(
        check: com.google.android.material.checkbox.MaterialCheckBox,
        fromEnabled: Boolean,
        fromChecked: Boolean,
        toEnabled: Boolean,
        toChecked: Boolean,
        animate: Boolean
    ) {
        val ctx = context ?: return
        checkboxTintAnimator?.cancel()
        checkboxTintAnimator = null

        val tintCsl = androidx.core.content.ContextCompat.getColorStateList(ctx, R.color.dialog_control_selector)
        val labelCsl = androidx.core.content.ContextCompat.getColorStateList(ctx, R.color.dialog_label_selector)

        fun restoreStateLists() {
            check.buttonTintList = tintCsl
            check.buttonIconTintList = tintCsl
            if (labelCsl != null) check.setTextColor(labelCsl)
        }

        if (tintCsl == null || labelCsl == null) return

        val fromState = controlState(fromEnabled, fromChecked)
        val toState = controlState(toEnabled, toChecked)
        val tintFrom = tintCsl.getColorForState(fromState, tintCsl.defaultColor)
        val tintTo = tintCsl.getColorForState(toState, tintCsl.defaultColor)
        val labelFrom = labelCsl.getColorForState(fromState, labelCsl.defaultColor)
        val labelTo = labelCsl.getColorForState(toState, labelCsl.defaultColor)

        val nothingToDo = tintFrom == tintTo && labelFrom == labelTo
        if (!animate || nothingToDo || ctx.skipProgrammaticAnimations()) {
            restoreStateLists()
            return
        }

        val duration = if (ctx.animMode() == ANIM_MODE_SYSTEM) {
            resources.getInteger(android.R.integer.config_shortAnimTime).toLong()
        } else {
            resources.getInteger(R.integer.duration_standard_transition).toLong()
        }

        val argb = ArgbEvaluator()
        checkboxTintAnimator = ValueAnimator.ofFloat(0f, 1f).apply {
            this.duration = duration
            addUpdateListener { anim ->
                val f = anim.animatedFraction
                val tint = argb.evaluate(f, tintFrom, tintTo) as Int
                val label = argb.evaluate(f, labelFrom, labelTo) as Int
                check.buttonTintList = ColorStateList.valueOf(tint)
                check.buttonIconTintList = ColorStateList.valueOf(tint)
                check.setTextColor(label)
            }
            addListener(object : android.animation.AnimatorListenerAdapter() {
                override fun onAnimationEnd(animation: android.animation.Animator) {
                    // Hand control back to the XML selectors, so a later tap
                    // on the (re-enabled) checkbox recolours normally.
                    restoreStateLists()
                    checkboxTintAnimator = null
                }
            })
            start()
        }
    }

    private fun showProcessScopeDialog(scope: String) {
        val act = activity ?: return
        val ctx = context ?: return
        val prefs = getSafePrefs(ctx)

        val dialogView = layoutInflater.inflate(R.layout.dialog_process_scope, null)
        val checkB64 = dialogView.findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.checkDecodeBase64)
        val radioOff = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioModeOff)
        val radioSingBox = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioModeSingBox)
        val radioMihomo = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioModeMihomo)
        val radioUri = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioModeUri)
        val modeRadios = listOf(radioOff, radioSingBox, radioMihomo, radioUri)

        // process_b64_manual/_server already existed with these same defaults (true for manual,
        // false for server); reused as-is.
        var userB64Choice = PrefsManager.userBase64Choice(prefs, scope)

        // The checkbox says what the answer should look like, not what the input may be - the
        // converter reads a base64 subscription anyway - so it belongs to the person in every mode.
        fun applyModeLock(
            selected: com.google.android.material.radiobutton.MaterialRadioButton,
            animate: Boolean = true
        ) {
            val wasEnabled = checkB64.isEnabled
            val wasChecked = checkB64.isChecked

            modeRadios.forEach { it.isChecked = (it === selected) }
            checkB64.isEnabled = true
            checkB64.isChecked = userB64Choice

            animateCheckboxTint(
                checkB64,
                fromEnabled = wasEnabled, fromChecked = wasChecked,
                toEnabled = checkB64.isEnabled, toChecked = checkB64.isChecked,
                animate = animate
            )
        }

        val initialRadio = when (PrefsManager.resolveConversionMode(prefs, scope)) {
            PrefsManager.MODE_SINGBOX -> radioSingBox
            PrefsManager.MODE_MIHOMO -> radioMihomo
            PrefsManager.MODE_URI -> radioUri
            else -> radioOff
        }
        applyModeLock(initialRadio, animate = false)

        // isEnabled is always set before isChecked in applyModeLock, so during a lock it is already
        // false and the guard keeps a programmatic isChecked = true from corrupting the remembered
        checkB64.setOnCheckedChangeListener { _, isChecked ->
            if (checkB64.isEnabled) userB64Choice = isChecked
        }

        // Not a RadioGroup: two rows carry their own separately-clickable trailing icon
        // (Info/gear), so RadioGroup's direct-child-only auto-exclusion would not see them.
        modeRadios.forEach { radio ->
            radio.setOnClickListener { applyModeLock(radio) }
        }

        dialogView.findViewById<ImageView>(R.id.btnModeSingBoxInfo).setOnClickListener {
            showProcessXrayInfoDialog()
        }
        dialogView.findViewById<ImageView>(R.id.btnModeMihomoInfo).setOnClickListener {
            showProcessMihomoInfoDialog()
        }
        dialogView.findViewById<ImageView>(R.id.btnModeUriSettings).setOnClickListener {
            showUriOptionsDialog(scope)
        }

        val titleRes = if (scope == PrefsManager.SCOPE_MANUAL) R.string.setting_process_scope_manual else R.string.setting_process_scope_server
        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(titleRes)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok))) { _, _ ->
                val mode = when {
                    radioSingBox.isChecked -> PrefsManager.MODE_SINGBOX
                    radioMihomo.isChecked -> PrefsManager.MODE_MIHOMO
                    radioUri.isChecked -> PrefsManager.MODE_URI
                    else -> PrefsManager.MODE_OFF
                }
                prefs.edit()
                    // userB64Choice is what the box holds in every mode, since nothing locks it any more; the variable is
                    // kept as the single place the value is read from and written back.
                    .putBoolean("process_b64_$scope", userB64Choice)
                    .putString("process_mode_$scope", mode)
                    .apply()
                PrefsManager.fixSharedPrefs(ctx)
            }
            .showAnimated()
        trackDialog(if (scope == PrefsManager.SCOPE_MANUAL) DIALOG_PROCESS_SCOPE_MANUAL else DIALOG_PROCESS_SCOPE_SERVER, dialog)
    }

    // Info dialog explaining the Xray -> sing-box conversion
    private fun showProcessXrayInfoDialog() {
        val act = activity ?: return
        val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
        val textMsg = dialogView.findViewById<TextView>(R.id.dialogMessage)
        textMsg.text = fromHtml(getString(R.string.setting_process_xray_info_text))

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.setting_process_xray_info_title)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
            .showAnimated()
        trackDialog(DIALOG_PROCESS_XRAY_INFO, dialog)
    }

    // Info dialog explaining the Xray -> Mihomo conversion
    private fun showProcessMihomoInfoDialog() {
        val act = activity ?: return
        val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
        val textMsg = dialogView.findViewById<TextView>(R.id.dialogMessage)
        textMsg.text = fromHtml(getString(R.string.setting_process_mihomo_info_text))

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.setting_process_mihomo_info_title)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
            .showAnimated()
        trackDialog(DIALOG_PROCESS_MIHOMO_INFO, dialog)
    }

    // Gear next to "Xray to URI": whether to drop outbounds sing-box could not have converted,
    // before handing the rest to the URI pass.
    private fun showUriOptionsDialog(scope: String) {
        val act = activity ?: return
        val ctx = context ?: return
        val prefs = getSafePrefs(ctx)
        uriOptionsScope = scope

        val dialogView = layoutInflater.inflate(R.layout.dialog_uri_options, null)
        val checkDrop = dialogView.findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.checkDropIncompatible)
        // Idempotent: ensures a fresh migration has already happened even if this dialog is somehow
        // restored directly (e.g.
        PrefsManager.resolveConversionMode(prefs, scope)
        checkDrop.isChecked = prefs.getBoolean("process_uri_drop_incompatible_$scope", false)

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.setting_process_uri_options_title)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok))) { _, _ ->
                prefs.edit()
                    .putBoolean("process_uri_drop_incompatible_$scope", checkDrop.isChecked)
                    .apply()
                PrefsManager.fixSharedPrefs(ctx)
            }
            .showAnimated()
        trackDialog(DIALOG_PROCESS_URI_OPTIONS, dialog)
    }

    // Setting: Subscription Bridge
    private fun bindEnableBridgeItem(view: View) {
        val item = view.findViewById<MaterialCardView>(R.id.itemEnableBridge)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchEnableBridge)
        val ctx = requireContext()
        switch.isChecked = getSafePrefs(ctx).getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)

        // Enabling needs the notification permission on API 33+, otherwise just enable/disable
        val update: (Boolean) -> Unit = { checked ->
            if (checked && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                androidx.core.content.ContextCompat.checkSelfPermission(
                    ctx,
                    android.Manifest.permission.POST_NOTIFICATIONS
                ) != android.content.pm.PackageManager.PERMISSION_GRANTED
            ) {
                switch.isChecked = false
                notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            } else {
                if (checked) {
                    BridgeController.enable(ctx)
                } else {
                    BridgeController.disable(ctx)
                }
                switch.isChecked = checked
            }
        }
        item.setOnClickListener { update(!switch.isChecked) }
    }

    private fun bindBridgeInstructionIcon(view: View) {
        view.findViewById<ImageView>(R.id.iconBridgeInstruction).setOnClickListener {
            showBridgeInfoDialog()
        }
    }

    private fun bindResponseHeaderInfoIcon(view: View) {
        view.findViewById<ImageView>(R.id.iconResponseInfo).setOnClickListener {
            showResponseHeaderInfoDialog()
        }
    }

    private fun bindDecryptionHeaderInfoIcon(view: View) {
        view.findViewById<ImageView>(R.id.iconDecryptionInfo).setOnClickListener {
            showDecryptionHeaderInfoDialog()
        }
    }

    // Info dialog about the decryption section (placeholder wording for now)
    private fun showDecryptionHeaderInfoDialog() {
        val act = activity ?: return
        val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
        val textMsg = dialogView.findViewById<TextView>(R.id.dialogMessage)
        textMsg.text = fromHtml(getString(R.string.setting_header_decryption_info))

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.setting_header_decryption)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
            .showAnimated()
        trackDialog(DIALOG_DECRYPTION_HEADER_INFO, dialog)
    }

    // Info dialog about the forwarded response headers
    private fun showResponseHeaderInfoDialog() {
        val act = activity ?: return
        val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
        val textMsg = dialogView.findViewById<TextView>(R.id.dialogMessage)
        textMsg.text = fromHtml(getString(R.string.setting_header_response_info))

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.setting_header_response)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
            .showAnimated()
        trackDialog(DIALOG_RESPONSE_HEADER_INFO, dialog)
    }

    // Info dialog about the bridge service
    private fun showBridgeInfoDialog() {
        val act = activity ?: return
        val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
        val textMsg = dialogView.findViewById<TextView>(R.id.dialogMessage)
        textMsg.text = fromHtml(getString(R.string.msg_bridge_service_info))

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.setting_bridge_header)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
            .showAnimated()
        trackDialog(DIALOG_BRIDGE_INFO, dialog)
    }

    // Setting: Battery optimization
    private fun bindBatteryOptItem(view: View) {
        view.findViewById<MaterialCardView>(R.id.itemBatteryOpt).setOnClickListener {
            val act = activity ?: return@setOnClickListener
            try {
                val intent = Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = android.net.Uri.parse("package:${act.packageName}")
                }
                startActivity(intent)
            } catch (e: Exception) {
                try {
                    startActivity(Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                } catch (_: Throwable) {}
            }
        }
    }

    // Setting: Watchdog
    private fun bindWatchdogItem(view: View) {
        val item = view.findViewById<MaterialCardView>(R.id.itemWatchdog)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchWatchdog)
        val enableSwitch = view.findViewById<SwitchMaterial>(R.id.switchEnableBridge)
        val ctx = requireContext()
        val act = requireActivity()
        switch.isChecked = getSafePrefs(ctx).getBoolean(PrefsManager.PREF_BRIDGE_WATCHDOG, false)
        val update: (Boolean) -> Unit = { checked ->
            getSafePrefs(ctx).edit().putBoolean(PrefsManager.PREF_BRIDGE_WATCHDOG, checked).apply()
            switch.isChecked = checked
            if (enableSwitch.isChecked) {
                val serviceIntent = Intent(act, SubscriptionService::class.java)
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        act.startForegroundService(serviceIntent)
                    } else {
                        act.startService(serviceIntent)
                    }
                } catch (_: Throwable) {}
            }
        }
        item.setOnClickListener { update(!switch.isChecked) }
    }

    // Show the 'unrestricted' hint only when battery optimization is off
    private fun updateBatteryStatus() {
        val v = view ?: return
        val ctx = context ?: return
        val textBatteryStatus = v.findViewById<TextView>(R.id.textBatteryStatus) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val powerManager = ctx.getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
            val isIgnoring = powerManager.isIgnoringBatteryOptimizations(ctx.packageName)
            if (isIgnoring) {
                textBatteryStatus.text = getString(R.string.setting_battery_opt_unrestricted)
                textBatteryStatus.visibility = View.VISIBLE
            } else {
                textBatteryStatus.visibility = View.GONE
            }
        } else {
            textBatteryStatus.visibility = View.GONE
        }
    }

    // After notifications are granted, enable the bridge and tick the switch
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ ->
        val v = view ?: return@registerForActivityResult
        val ctx = context ?: return@registerForActivityResult
        BridgeController.enable(ctx)
        v.findViewById<SwitchMaterial>(R.id.switchEnableBridge)?.isChecked = true
    }

    private fun fromHtml(text: String): CharSequence {
        if (text.isEmpty()) return ""
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            android.text.Html.fromHtml(text, android.text.Html.FROM_HTML_MODE_LEGACY)
        } else {
            @Suppress("DEPRECATION")
            android.text.Html.fromHtml(text)
        }
    }

    private fun setHtmlText(textView: TextView, resId: Int) {
        textView.text = fromHtml(getString(resId))
    }

    // About dialog: version plus module status (Xposed / LSPatch / inactive)
    private fun showInfoDialog() {
        val act = activity ?: return
        val ctx = context ?: return
        val versionName = try {
            val pInfo = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
            pInfo.versionName
        } catch (e: Exception) {
            "Unknown"
        }

        val prefs = getSafePrefs(ctx)
        val lspatchMode = prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)
        val moduleActive = ModuleStatus.isModuleActive()

        val statusText = when {
            moduleActive -> getString(R.string.label_xposed_active)
            lspatchMode -> getString(R.string.label_lspatch_active)
            else -> getString(R.string.label_xposed_inactive)
        }

        val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
        val textInfo = dialogView.findViewById<TextView>(R.id.dialogMessage)
        val infoHtml = getString(R.string.about_app_text, versionName, statusText)
        textInfo.text = fromHtml(infoHtml)
        textInfo.movementMethod = android.text.method.LinkMovementMethod.getInstance()

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.about_app)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
            .showAnimated()
        trackDialog(DIALOG_INFO, dialog)
    }
}
