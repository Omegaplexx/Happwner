package com.happwner

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
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

class SettingsFragment : Fragment() {

    companion object {
        private const val STATE_OPEN_DIALOG = "settings_open_dialog"

        private const val DIALOG_LANGUAGE = "language"
        private const val DIALOG_THEME = "theme"
        private const val DIALOG_ANIMATIONS = "animations"
        private const val DIALOG_PROCESS_RESPONSE = "process_response"
        private const val DIALOG_PROCESS_B64 = "process_b64"
        private const val DIALOG_PROCESS_XRAY = "process_xray"
        private const val DIALOG_PROCESS_XRAY_INFO = "process_xray_info"
        private const val DIALOG_RESPONSE_HEADER_INFO = "response_header_info"
        private const val DIALOG_BRIDGE_INFO = "bridge_info"
        private const val DIALOG_INFO = "info"
    }

    private fun getSafePrefs(context: Context): SharedPreferences = PrefsManager.getSafePrefs(context)

    private var prefsListenerRegistered = false
    private var currentDialog: AlertDialog? = null
    private var currentDialogTag: String? = null

    // External settings changes (e.g. the bridge/HWID toggle) trigger a UI sync
    private val prefsListener = SharedPreferences.OnSharedPreferenceChangeListener { sharedPrefs, key ->
        if (key == "bridge_enabled") {
            val isEnabled = sharedPrefs.getBoolean("bridge_enabled", false)
            val v = view ?: return@OnSharedPreferenceChangeListener
            v.post {
                try {
                    v.findViewById<SwitchMaterial>(R.id.switchEnableBridge)?.isChecked = isEnabled
                } catch (_: Throwable) {}
            }
        } else if (key == "lspatch_mode" || key == "lspatch_apps") {
            val v = view ?: return@OnSharedPreferenceChangeListener
            v.post {
                try {
                    if (isAdded && !isHidden) {
                        updateXposedSectionVisibility(v)
                        refreshDynamicState()
                    }
                } catch (_: Throwable) {}
            }
        } else if (key == "use_custom_hwid_substitution" || key == "use_custom_hwid_input" || key == "custom_hwid" || key == "captured_id") {
            val v = view ?: return@OnSharedPreferenceChangeListener
            v.post {
                try {
                    if (isAdded && !isHidden) {
                        v.findViewById<SwitchMaterial>(R.id.switchHwidSpoof)?.isChecked =
                            PrefsManager.isHwidSpoofEnabled(v.context)
                        updateHwidSpoofStatus(v)
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
        bindLanguageItem(view)
        bindThemeItem(view)
        bindAnimationsItem(view)
        bindProcessResponseItem(view)
        bindProcessB64Item(view)
        bindProcessXrayItem(view)
        bindResponseHeaderInfoIcon(view)
        bindEnableBridgeItem(view)
        bindBridgeInstructionIcon(view)
        bindBatteryOptItem(view)
        bindWatchdogItem(view)
        bindHwidSpoofItem(view)
        bindHappUnlockItem(view)
        bindInterceptLinksItem(view)
        bindShowDuplicatesItem(view)

        updateBatteryStatus()
        updateXposedSectionVisibility(view)

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
    }

    override fun onResume() {
        super.onResume()

        if (!isHidden) {
            registerPrefsListener()
            refreshDynamicState()
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
            DIALOG_PROCESS_RESPONSE -> showProcessResponseDialog()
            DIALOG_PROCESS_B64 -> showProcessB64Dialog()
            DIALOG_PROCESS_XRAY -> showProcessXrayDialog()
            DIALOG_PROCESS_XRAY_INFO -> showProcessXrayInfoDialog()
            DIALOG_RESPONSE_HEADER_INFO -> showResponseHeaderInfoDialog()
            DIALOG_BRIDGE_INFO -> showBridgeInfoDialog()
            DIALOG_INFO -> showInfoDialog()
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

    fun requestRefresh() {
        if (!isAdded || isHidden) return
        val v = view ?: return
        try {
            refreshDynamicState()
            updateXposedSectionVisibility(v)
        } catch (_: Throwable) {}
    }

    // Re-read every toggle and label from prefs into the UI
    private fun refreshDynamicState() {
        val v = view ?: return
        val ctx = context ?: return
        val prefs = getSafePrefs(ctx)

        v.findViewById<SwitchMaterial>(R.id.switchEnableBridge)?.isChecked =
            prefs.getBoolean("bridge_enabled", false)
        v.findViewById<SwitchMaterial>(R.id.switchShowDuplicates)?.isChecked =
            prefs.getBoolean("show_duplicates", false)
        v.findViewById<SwitchMaterial>(R.id.switchInterceptLinks)?.isChecked =
            prefs.getBoolean("intercept_enabled", false)
        v.findViewById<SwitchMaterial>(R.id.switchWatchdog)?.isChecked =
            prefs.getBoolean("bridge_watchdog", false)
        v.findViewById<SwitchMaterial>(R.id.switchHwidSpoof)?.isChecked =
            PrefsManager.isHwidSpoofEnabled(ctx)
        v.findViewById<SwitchMaterial>(R.id.switchHappUnlock)?.isChecked =
            PrefsManager.isHappUnlockHookEnabled(ctx)

        updateHwidSpoofStatus(v)

        val animationOptions = resources.getStringArray(R.array.animation_options)
        v.findViewById<TextView>(R.id.textAnimationsStatus)?.text =
            fromHtml(animationOptions[ctx.animMode()])

        updateBatteryStatus()
        updateXposedSectionVisibility(v)
    }

    // The Xposed / "unlock Happ" section is shown only while the module is active
    private fun updateXposedSectionVisibility(view: View) {
        val ctx = context ?: return
        val xposedActive = PrefsManager.isXposedActive(ctx)
        val happActiveForModule = PrefsManager.isHappActiveForModule(ctx)
        view.findViewById<View>(R.id.xposedSection)?.visibility =
            if (xposedActive) View.VISIBLE else View.GONE
        view.findViewById<View>(R.id.itemHappUnlock)?.visibility =
            if (xposedActive && happActiveForModule) View.VISIBLE else View.GONE
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
        val currentLang = getSafePrefs(ctx).getString("app_lang", "system") ?: "system"
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
        val currentLang = prefs.getString("app_lang", "system") ?: "system"
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
            prefs.edit().putString("app_lang", newLang).apply()
            val service = Intent(act, SubscriptionService::class.java)
            if (prefs.getBoolean("bridge_enabled", false)) {
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
        val currentTheme = getSafePrefs(ctx).getInt("theme_mode", 0)
        textThemeStatus.text = fromHtml(themeStatusText(ctx, currentTheme, themeOptionsRaw))

        view.findViewById<MaterialCardView>(R.id.itemTheme).setOnClickListener {
            showThemeDialog()
        }
    }

    // Theme label, with a Monet-accent suffix when enabled
    private fun themeStatusText(ctx: Context, themeIdx: Int, themeOptionsRaw: Array<String>): String {
        val base = themeOptionsRaw[themeIdx]
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            getSafePrefs(ctx).getBoolean("monet_accent", false)
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
        var currentTheme = prefs.getInt("theme_mode", 0)
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
            switchMonet.isChecked = prefs.getBoolean("monet_accent", false)
            val monetRowClick = View.OnClickListener { switchMonet.toggle() }
            monetContainer.setOnClickListener(monetRowClick)
            switchMonet.setOnCheckedChangeListener { _, isChecked ->
                if (prefs.getBoolean("monet_accent", false) == isChecked) return@setOnCheckedChangeListener
                prefs.edit().putBoolean("monet_accent", isChecked).apply()
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
            prefs.edit().putInt("theme_mode", which).apply()
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
        textAnimationsStatus.text = fromHtml(animationOptionsRaw[ctx.animMode()])

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

    // Setting: HWID spoof
    private fun bindHwidSpoofItem(view: View) {
        val row = view.findViewById<View>(R.id.rowHwidSpoofToggle)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchHwidSpoof)
        val ctx = requireContext()
        switch.isChecked = PrefsManager.isHwidSpoofEnabled(ctx)
        updateHwidSpoofStatus(view)
        row.setOnClickListener {
            val newState = !switch.isChecked
            getSafePrefs(ctx).edit().putBoolean("use_custom_hwid_substitution", newState).apply()
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
        val fieldActive = prefs.getBoolean("use_custom_hwid_input", false)
        val custom = prefs.getString("custom_hwid", "")?.trim().orEmpty()

        status.text = when {
            toggleOn && !fieldActive -> getString(R.string.label_hwid_spoof_enable_field)
            toggleOn && fieldActive && custom.isNotEmpty() ->
                getString(R.string.label_hwid_spoof_current, custom)
            else -> getString(R.string.label_hwid_spoof_off)
        }
    }

    // Setting: Unlock Happ settings
    private fun bindHappUnlockItem(view: View) {
        val item = view.findViewById<MaterialCardView>(R.id.itemHappUnlock)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchHappUnlock)
        val ctx = requireContext()
        switch.isChecked = PrefsManager.isHappUnlockHookEnabled(ctx)
        val update: (Boolean) -> Unit = { checked ->
            getSafePrefs(ctx).edit().putBoolean("hook_happ_unlock_settings", checked).apply()
            switch.isChecked = checked
            PrefsManager.fixSharedPrefs(ctx)
        }
        item.setOnClickListener { update(!switch.isChecked) }
    }

    // Setting: Show duplicates
    private fun bindShowDuplicatesItem(view: View) {
        val item = view.findViewById<MaterialCardView>(R.id.itemShowDuplicates)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchShowDuplicates)
        val ctx = requireContext()
        switch.isChecked = getSafePrefs(ctx).getBoolean("show_duplicates", false)
        val update: (Boolean) -> Unit = { checked ->
            getSafePrefs(ctx).edit().putBoolean("show_duplicates", checked).apply()
            switch.isChecked = checked
            PrefsManager.fixSharedPrefs(ctx)
        }
        item.setOnClickListener { update(!switch.isChecked) }
    }

    // Setting: Link interception
    private fun bindInterceptLinksItem(view: View) {
        val item = view.findViewById<MaterialCardView>(R.id.itemInterceptLinks)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchInterceptLinks)
        val ctx = requireContext()
        switch.isChecked = getSafePrefs(ctx).getBoolean("intercept_enabled", false)
        val update: (Boolean) -> Unit = { checked ->
            getSafePrefs(ctx).edit().putBoolean("intercept_enabled", checked).apply()
            switch.isChecked = checked
            PrefsManager.fixSharedPrefs(ctx)
        }
        item.setOnClickListener { update(!switch.isChecked) }
    }

    // Setting: Parse JSON response
    private fun bindProcessResponseItem(view: View) {
        setHtmlText(view.findViewById(R.id.textProcessResponseDesc), R.string.setting_process_json_desc)
        view.findViewById<MaterialCardView>(R.id.itemProcessResponse).setOnClickListener {
            showProcessResponseDialog()
        }
    }

    // JSON-parse settings: apply to manual fetch and/or the bridge
    private fun showProcessResponseDialog() {
        val act = activity ?: return
        val ctx = context ?: return
        val prefs = getSafePrefs(ctx)

        val dialogView = layoutInflater.inflate(R.layout.dialog_process_response, null)
        val checkManual = dialogView.findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.checkProcessManual)
        val checkServer = dialogView.findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.checkProcessServer)
        checkManual.isChecked = prefs.getBoolean("process_manual", true)
        checkServer.isChecked = prefs.getBoolean("process_server", false)

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.setting_process_json)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok))) { _, _ ->
                prefs.edit()
                    .putBoolean("process_manual", checkManual.isChecked)
                    .putBoolean("process_server", checkServer.isChecked)
                    .apply()
                PrefsManager.fixSharedPrefs(ctx)
            }
            .showAnimated()
        trackDialog(DIALOG_PROCESS_RESPONSE, dialog)
    }

    // Setting: Decode Base64
    private fun bindProcessB64Item(view: View) {
        setHtmlText(view.findViewById(R.id.textProcessB64Desc), R.string.setting_process_b64_desc)
        view.findViewById<MaterialCardView>(R.id.itemProcessB64).setOnClickListener {
            showProcessB64Dialog()
        }
    }

    // Base64-decode settings: apply to manual fetch and/or the bridge
    private fun showProcessB64Dialog() {
        val act = activity ?: return
        val ctx = context ?: return
        val prefs = getSafePrefs(ctx)

        val dialogView = layoutInflater.inflate(R.layout.dialog_process_response, null)
        val checkManual = dialogView.findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.checkProcessManual)
        val checkServer = dialogView.findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.checkProcessServer)
        checkManual.isChecked = prefs.getBoolean("process_b64_manual", true)
        checkServer.isChecked = prefs.getBoolean("process_b64_server", false)

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.setting_process_b64)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok))) { _, _ ->
                prefs.edit()
                    .putBoolean("process_b64_manual", checkManual.isChecked)
                    .putBoolean("process_b64_server", checkServer.isChecked)
                    .apply()
                PrefsManager.fixSharedPrefs(ctx)
            }
            .showAnimated()
        trackDialog(DIALOG_PROCESS_B64, dialog)
    }

    // Setting: Xray to sing-box
    private fun bindProcessXrayItem(view: View) {
        setHtmlText(view.findViewById(R.id.textProcessXrayDesc), R.string.setting_process_xray_desc)
        view.findViewById<MaterialCardView>(R.id.itemProcessXray).setOnClickListener {
            showProcessXrayDialog()
        }
        view.findViewById<ImageView>(R.id.btnProcessXrayInfo).setOnClickListener {
            showProcessXrayInfoDialog()
        }
    }

    // Xray -> sing-box settings: apply to manual fetch and/or the bridge
    private fun showProcessXrayDialog() {
        val act = activity ?: return
        val ctx = context ?: return
        val prefs = getSafePrefs(ctx)

        val dialogView = layoutInflater.inflate(R.layout.dialog_process_xray, null)
        val checkManual = dialogView.findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.checkProcessManual)
        val checkServer = dialogView.findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.checkProcessServer)

        checkManual.isChecked = prefs.getBoolean("process_xray_manual", false)
        checkServer.isChecked = prefs.getBoolean("process_xray_server", false)

        val dialog = AnimatedDialogBuilder(act)
            .setTitle(fromHtml(getString(R.string.setting_process_xray)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok))) { _, _ ->
                prefs.edit()
                    .putBoolean("process_xray_manual", checkManual.isChecked)
                    .putBoolean("process_xray_server", checkServer.isChecked)
                    .apply()
                PrefsManager.fixSharedPrefs(ctx)
            }
            .showAnimated()
        trackDialog(DIALOG_PROCESS_XRAY, dialog)
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

    // Setting: Subscription Bridge
    private fun bindEnableBridgeItem(view: View) {
        val item = view.findViewById<MaterialCardView>(R.id.itemEnableBridge)
        val switch = view.findViewById<SwitchMaterial>(R.id.switchEnableBridge)
        val ctx = requireContext()
        switch.isChecked = getSafePrefs(ctx).getBoolean("bridge_enabled", false)

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
        switch.isChecked = getSafePrefs(ctx).getBoolean("bridge_watchdog", false)
        val update: (Boolean) -> Unit = { checked ->
            getSafePrefs(ctx).edit().putBoolean("bridge_watchdog", checked).apply()
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
        val lspatchMode = prefs.getBoolean("lspatch_mode", false)
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
