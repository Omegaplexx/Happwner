package com.happwner

import android.content.*
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.text.Html
import android.text.InputFilter
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.TextUtils
import android.text.style.ForegroundColorSpan
import android.transition.ChangeBounds
import android.transition.Fade
import android.transition.TransitionManager
import android.transition.TransitionSet
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.*
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsAnimationCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.color.MaterialColors
import com.google.android.material.textfield.TextInputLayout
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

class MainActivity : AppCompatActivity() {

    private lateinit var prefs: SharedPreferences
    private var lastLayoutOrientation: Int = android.content.res.Configuration.ORIENTATION_UNDEFINED
    private var lastKnownLang: String? = null
    private var lastKnownTheme: Int? = null
    private var lastKnownMonet: Boolean? = null
    private var currentDialog: AlertDialog? = null
    private var currentDialogTag: String? = null
    private var currentDialogInfoTitle: String? = null
    private var currentDialogInfoMessage: String? = null
    private var currentImportLink: String? = null
    private var pendingImportLink: String? = null
    private lateinit var capturedUrlsContainer: LinearLayout
    private lateinit var inputUrl: LockableScrollEditText
    private lateinit var inputHwid: EditText
    private lateinit var inputUserAgent: LockableScrollEditText
    private lateinit var hwidHint: TextView
    private lateinit var mainContainer: ViewGroup
    private lateinit var islandIntercept: View
    private lateinit var historyHeader: View
    private lateinit var historyContent: View
    private lateinit var btnExpandHistory: ImageView
    private lateinit var btnExpandOutput: ImageView
    private lateinit var btnClearHistory: ImageButton
    private lateinit var emptyHistoryText: TextView
    private lateinit var layoutHwid: TextInputLayout
    private lateinit var layoutUrl: TextInputLayout
    private lateinit var layoutUserAgent: TextInputLayout
    private lateinit var urlErrorText: TextView

    private val fieldColorMap = mutableMapOf<Int, Int>()
    private val fieldUnfocusedColorMap = mutableMapOf<Int, Int>()
    private val fieldAnimatorMap = mutableMapOf<Int, android.animation.ValueAnimator>()
    private var hwidHintAnim: android.animation.ValueAnimator? = null
    private var hwidHintAnimTarget: Boolean? = null
    private var hintAnimationSuppressed: Boolean = false
    private var pendingStartHeight: Int = -1
    private var pendingHintAnimAfterImeClose: Boolean = false

    private lateinit var output: TextView
    private lateinit var btnGetSub: Button
    private lateinit var btnPasteUrlManual: ImageButton

    private var fullResponseText: String = ""
    private val MAX_DISPLAY_CHARS by lazy { resources.getInteger(R.integer.max_display_chars) }
    private var lastFetchTapMs = 0L
    private var lastGetSubTapMs = 0L
    private var fetchGeneration = 0
    private var loadingPhaseRunning = false
    private var pendingConfigText: CharSequence? = null

    private val fastTransition by lazy {
        buildBoundsFadeTransition(
            resources.getInteger(R.integer.duration_fast_transition).toLong(),
            excludeFadeTargetId = R.id.hwidHint
        )
    }

    // Signals from the module: captured ANDROID_ID, a new URL for history, refresh UI
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                "${packageName}.ID_CAPTURED" -> {
                    val originalId = intent.getStringExtra("original_id")
                    if (originalId != null) {
                        val safePrefs = getSafePrefs(context!!)
                        safePrefs.edit().putString("captured_id", originalId).apply()
                        updateHwidDisplay(originalId)
                        PrefsManager.broadcastSettings(context)
                    }
                }
                "${packageName}.URL_CAPTURED" -> {
                    val url = intent.getStringExtra("url")
                    if (url != null) {
                        runOnUiThread {
                            mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
                            loadUrlHistory()
                        }
                    }
                }
                "${packageName}.REFRESH_UI" -> {
                    runOnUiThread { updateUiState() }
                }
            }
        }
    }

    private fun getSafePrefs(context: Context): SharedPreferences = PrefsManager.getSafePrefs(context)

    // Can we read the system Monet palette? (Android 12+)
    private fun isMonetPaletteAvailable(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return false
        return try {
            resources.getColor(android.R.color.system_accent1_500, theme)
            true
        } catch (_: Throwable) {
            false
        }
    }

    // Apply the selected language before the context is created
    override fun attachBaseContext(newBase: Context) {
        val safePrefs = getSafePrefs(newBase)
        val lang = safePrefs.getString("app_lang", "system") ?: "system"
        val config = newBase.resources.configuration

        val locale = if (lang == "system") {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                android.content.res.Resources.getSystem().configuration.locales.get(0)
            } else {
                @Suppress("DEPRECATION")
                android.content.res.Resources.getSystem().configuration.locale
            }
        } else {
            java.util.Locale.forLanguageTag(lang)
        }

        java.util.Locale.setDefault(locale)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            config.setLocale(locale)
        } else {
            @Suppress("DEPRECATION")
            config.locale = locale
        }
        super.attachBaseContext(newBase.createConfigurationContext(config))
    }

    // Set up theme, window, every view and listener, then start the services
    override fun onCreate(savedInstanceState: Bundle?) {
        val safePrefs = getSafePrefs(this)
        val themeMode = safePrefs.getInt("theme_mode", 0)
        AppCompatDelegate.setDefaultNightMode(when(themeMode) {
            1 -> AppCompatDelegate.MODE_NIGHT_NO
            2, 3 -> AppCompatDelegate.MODE_NIGHT_YES
            else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        })
        if (savedInstanceState == null && ThemeTransition.pendingOverlay == null) {
            try { installSplashScreen() } catch (_: Throwable) {}
        }
        setTheme(R.style.Theme_Happwner)
        if (themeMode == 3) {
            setTheme(R.style.Theme_Happwner_Amoled)
        }
        super.onCreate(savedInstanceState)

        resetAnimatorScale(this)

        prefs = safePrefs

        // Apply the Monet accent overlay if it's enabled and available
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && safePrefs.getBoolean("monet_accent", false)) {
            if (isMonetPaletteAvailable()) {
                try { theme.applyStyle(R.style.ThemeOverlay_Happwner_Monet, true) } catch (_: Throwable) {}
            }
        }

        androidx.core.view.WindowCompat.setDecorFitsSystemWindows(window, false)

        window.apply {
            addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS)
            @Suppress("DEPRECATION")
            statusBarColor = Color.TRANSPARENT
            @Suppress("DEPRECATION")
            navigationBarColor = Color.TRANSPARENT
        }
        val isNightMode = (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) == android.content.res.Configuration.UI_MODE_NIGHT_YES
        WindowInsetsControllerCompat(window, window.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = !isNightMode
        }

        // Cold start vs recreate after a theme change, which decides the intro animation
        val wasInThemeTransition = ThemeTransition.pendingOverlay != null
        val isColdStart = savedInstanceState == null && !wasInThemeTransition
        ThemeTransition.preApplyBackground(this)
        setContentView(R.layout.activity_main)
        lastLayoutOrientation = resources.configuration.orientation
        ThemeTransition.consumeOverlay(this)

        if (isColdStart || wasInThemeTransition) {
            findViewById<View>(android.R.id.content)?.alpha = 1f
        } else {
            animateEntry()
        }

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)

        mainContainer = findViewById(R.id.mainContainer)
        val statusBarBackground = findViewById<View>(R.id.statusBarBackground)

        // Insets for the system bars, plus auto-scroll to the focused field when the keyboard appears
        ViewCompat.setOnApplyWindowInsetsListener(window.decorView) { _, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            val imeInsets = insets.getInsets(WindowInsetsCompat.Type.ime())
            val imeVisible = insets.isVisible(WindowInsetsCompat.Type.ime())

            statusBarBackground.layoutParams.height = systemBars.top
            statusBarBackground.requestLayout()

            val scrollView = findViewById<ScrollView>(R.id.mainScrollView)
            val bottomPadding = kotlin.math.max(systemBars.bottom, imeInsets.bottom)

            toolbar.setPadding(systemBars.left, toolbar.paddingTop, systemBars.right, toolbar.paddingBottom)

            if (scrollView.paddingBottom != bottomPadding ||
                scrollView.paddingLeft != systemBars.left ||
                scrollView.paddingRight != systemBars.right) {
                scrollView.setPadding(systemBars.left, 0, systemBars.right, bottomPadding)

                if (imeVisible) {
                    currentFocus?.let { focused ->
                        if (!focused.isDescendantOfView(scrollView)) return@let
                        scrollView.post {
                            val rect = android.graphics.Rect()
                            focused.getDrawingRect(rect)
                            scrollView.offsetDescendantRectToMyCoords(focused, rect)
                            val density = resources.displayMetrics.density
                            val offset = (resources.getInteger(R.integer.scroll_offset_ime_dp) * density).toInt()

                            val targetScrollY = rect.bottom - (scrollView.height - bottomPadding) + offset
                            if (targetScrollY > scrollView.scrollY) {
                                scrollView.smoothScrollTo(0, targetScrollY)
                            }
                        }
                    }
                }
            }

            insets
        }

        ViewCompat.setWindowInsetsAnimationCallback(
            window.decorView,
            object : WindowInsetsAnimationCompat.Callback(WindowInsetsAnimationCompat.Callback.DISPATCH_MODE_STOP) {
                override fun onProgress(
                    insets: WindowInsetsCompat,
                    runningAnimations: MutableList<WindowInsetsAnimationCompat>
                ): WindowInsetsCompat {
                    try {
                        val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
                        val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
                        val bottomPadding = kotlin.math.max(systemBars.bottom, ime.bottom)
                        val scrollView = findViewById<ScrollView>(R.id.mainScrollView)
                        scrollView?.setPadding(systemBars.left, 0, systemBars.right, bottomPadding)
                    } catch (_: Throwable) {}
                    return insets
                }

                override fun onEnd(animation: WindowInsetsAnimationCompat) {
                    super.onEnd(animation)
                    if (pendingHintAnimAfterImeClose && !isFinishing && !isDestroyed) {
                        pendingHintAnimAfterImeClose = false
                        updateHwidHintVisibility(inputHwid.text?.toString())
                    }
                }
            }
        )

        // Grab all the views
        inputUrl = findViewById(R.id.inputUrl)
        inputHwid = findViewById(R.id.inputHwid)
        inputUserAgent = findViewById(R.id.inputUserAgent)
        layoutHwid = findViewById(R.id.layoutHwid)
        layoutUrl = findViewById(R.id.layoutUrl)
        layoutUserAgent = findViewById(R.id.layoutUserAgent)
        urlErrorText = findViewById(R.id.urlErrorText)
        output = findViewById(R.id.output)
        btnGetSub = findViewById(R.id.btnGetSub)
        btnPasteUrlManual = findViewById(R.id.btnPasteUrlManual)
        val button = findViewById<Button>(R.id.btnGet)
        hwidHint = findViewById(R.id.hwidHint)

        islandIntercept = findViewById(R.id.islandIntercept)
        historyHeader = findViewById(R.id.historyHeader)
        historyContent = findViewById(R.id.historyContent)
        btnExpandHistory = findViewById(R.id.btnExpandHistory)
        btnExpandOutput = findViewById(R.id.btnExpandOutput)
        btnClearHistory = findViewById(R.id.btnClearHistory)
        emptyHistoryText = findViewById(R.id.emptyHistoryText)
        capturedUrlsContainer = findViewById(R.id.capturedUrlsContainer)

        val btnClearOutput = findViewById<ImageButton>(R.id.btnClearOutput)
        val btnCopyOutput = findViewById<ImageButton>(R.id.btnCopyOutput)
        val infoUrl = findViewById<ImageButton>(R.id.infoUrl)
        val infoHwid = findViewById<ImageButton>(R.id.infoHwid)
        val infoUserAgent = findViewById<ImageButton>(R.id.infoUserAgent)
        val btnEditHwidManual = findViewById<ImageButton>(R.id.btnEditHwidManual)
        val btnEditUaManual = findViewById<ImageButton>(R.id.btnEditUaManual)
        val outputHeader = findViewById<View>(R.id.outputHeader)

        findViewById<View>(R.id.action_settings).setOnClickListener {
            openSettings()
        }

        // Set the static HTML texts
        setHtmlText(findViewById<TextView>(R.id.labelResultHeader), R.string.label_result)

        // Paste / edit-toggle buttons for the URL, HWID and UA fields
        btnPasteUrlManual.setOnClickListener { handlePasteUrl() }
        btnEditHwidManual.setOnClickListener {
            val isModuleActive = ModuleStatus.isModuleActive() || getSafePrefs(this).getBoolean("lspatch_mode", false)
            if (isModuleActive) {
                handleToggleHwidEdit(!inputHwid.isEnabled)
            } else {
                handlePasteHwid()
            }
        }
        btnEditUaManual.setOnClickListener { handleToggleUaEdit(!inputUserAgent.isEnabled) }

        val blockEnterFilter = InputFilter { source, _, _, _, _, _ ->
            source.toString().replace("\n", "").replace("\r", "")
        }
        inputUrl.filters = arrayOf(blockEnterFilter)
        inputUserAgent.filters = arrayOf(blockEnterFilter)

        val inputs = listOf(inputUrl, inputHwid, inputUserAgent)
        inputs.forEach { input ->
            input.setOnEditorActionListener { v, actionId, event ->
                val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
                imm.hideSoftInputFromWindow(v.windowToken, 0)
                v.clearFocus()
                true
            }

            input.setOnTouchListener { _, _ ->
                val layout = when(input.id) {
                    R.id.inputUrl -> layoutUrl
                    R.id.inputHwid -> layoutHwid
                    else -> layoutUserAgent
                }
                refreshFieldStyle(layout, input, animate = false)
                false
            }
        }

        refreshAllFieldsStyle(false)

        // Text-change and focus listeners
        inputUrl.addTextChangedListener(object : android.text.TextWatcher {
            private var lastLineCount = 1
            private var wasError = false
            private var wasEncrypted = false

            override fun afterTextChanged(s: android.text.Editable?) {
                val text = s.toString().trim()
                prefs.edit().putString("last_url", text).apply()
                updateUrlActionIcon(text)

                val isEncrypted = text.startsWith("happ://crypt")
                val isAddLink = text.startsWith("happ://add/")
                val hasError = !text.isEmpty() && !isEncrypted && !isAddLink && !text.startsWith("http://") && !text.startsWith("https://")
                val currentLineCount = inputUrl.lineCount

                if (hasError != wasError || isEncrypted != wasEncrypted || currentLineCount != lastLineCount) {
                    val transitionDurationMs = resources.getInteger(R.integer.duration_standard_transition).toLong()
                    if (currentLineCount != lastLineCount) {
                        inputUrl.acquireScrollLock()
                        inputUrl.postDelayed({
                            inputUrl.releaseScrollLock()
                            inputUrl.requestLayout()
                            layoutUrl.requestLayout()
                        }, transitionDurationMs + 100L)
                    }
                    mainContainer.beginDelayedTransitionIfEnabled(TransitionSet().apply {
                        addTransition(ChangeBounds())
                        addTransition(Fade()
                            .excludeTarget(R.id.hwidHint, true))
                        duration = transitionDurationMs
                    })

                    if (hasError) {
                        urlErrorText.text = getString(R.string.error_invalid_format)
                        urlErrorText.visibility = View.VISIBLE
                    } else {
                        urlErrorText.visibility = View.GONE
                    }
                }

                refreshFieldStyle(layoutUrl, inputUrl)

                wasError = hasError
                wasEncrypted = isEncrypted
                lastLineCount = currentLineCount
            }
            override fun beforeTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
            override fun onTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
        })

        inputHwid.addTextChangedListener(object : android.text.TextWatcher {
            override fun afterTextChanged(s: android.text.Editable?) {
                val text = s.toString()
                if (inputHwid.isEnabled) {
                    prefs.edit().putString("custom_hwid", text).apply()
                    fixSharedPrefs()
                }
                updateHwidHintVisibility(text)
            }
            override fun beforeTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
            override fun onTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
        })

        inputUserAgent.addTextChangedListener(object : android.text.TextWatcher {
            private var lastLineCount = 1

            override fun afterTextChanged(s: android.text.Editable?) {
                if (inputUserAgent.isEnabled) {
                    prefs.edit().putString("custom_user_agent", s.toString()).apply()
                }
                val currentLineCount = inputUserAgent.lineCount
                if (currentLineCount != lastLineCount) {
                    val transitionDurationMs = resources.getInteger(R.integer.duration_fast_transition).toLong()
                    inputUserAgent.acquireScrollLock()
                    inputUserAgent.postDelayed({
                        inputUserAgent.releaseScrollLock()
                        inputUserAgent.requestLayout()
                        layoutUserAgent.requestLayout()
                    }, transitionDurationMs + 100L)
                    mainContainer.beginDelayedTransitionIfEnabled(TransitionSet().apply {
                        addTransition(ChangeBounds())
                        addTransition(Fade()
                            .excludeTarget(R.id.hwidHint, true))
                        ordering = TransitionSet.ORDERING_TOGETHER
                        duration = transitionDurationMs
                    })
                    lastLineCount = currentLineCount
                }
            }
            override fun beforeTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
            override fun onTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
        })

        inputUrl.onFocusChangeListener = View.OnFocusChangeListener { _, _ -> refreshFieldStyle(layoutUrl, inputUrl) }
        inputHwid.onFocusChangeListener = View.OnFocusChangeListener { _, _ -> refreshFieldStyle(layoutHwid, inputHwid) }
        inputUserAgent.onFocusChangeListener = View.OnFocusChangeListener { _, _ -> refreshFieldStyle(layoutUserAgent, inputUserAgent) }

        // Collapse / expand the history section
        historyHeader.setOnClickListener {
            currentFocus?.clearFocus()
            mainContainer.beginAdaptiveToggleTransition(historyContent, R.id.hwidHint)
            if (historyContent.visibility == View.VISIBLE) {
                historyContent.visibility = View.GONE
                btnExpandHistory.setImageResource(R.drawable.ic_expand_more)
            } else {
                historyContent.visibility = View.VISIBLE
                btnExpandHistory.setImageResource(R.drawable.ic_expand_less)
            }
        }

        // Collapse / expand the output section
        outputHeader.setOnClickListener {
            currentFocus?.clearFocus()
            mainContainer.beginAdaptiveToggleTransition(output, R.id.hwidHint)
            if (output.visibility == View.VISIBLE) {
                output.visibility = View.GONE
                btnExpandOutput.setImageResource(R.drawable.ic_expand_more)
            } else {
                output.visibility = View.VISIBLE
                btnExpandOutput.setImageResource(R.drawable.ic_expand_less)
            }
        }

        // Clear the captured-URL history
        btnClearHistory.setOnClickListener {
            mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
            prefs.edit().remove("url_history_list").apply()
            capturedUrlsContainer.removeAllViews()
            updateEmptyHistoryVisibility()
        }

        // Restore the last URL into the field
        val savedUrl = prefs.getString("last_url", "")
        inputUrl.setText(savedUrl)
        updateUrlActionIcon(savedUrl ?: "")
        refreshAllFieldsStyle(false)

        // Copy / clear the output
        btnCopyOutput.setOnClickListener {
            if (fullResponseText.isNotEmpty() && fullResponseText != getString(R.string.label_result_default) && fullResponseText != getString(R.string.msg_loading)) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("Happwner Result", fullResponseText)
                clipboard.setPrimaryClip(clip)
            }
        }

        btnClearOutput.setOnClickListener {
            mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
            fullResponseText = ""
            setHtmlText(output, R.string.label_result_default)
            output.setTextIsSelectable(false)
            if (output.visibility == View.VISIBLE) {
                output.visibility = View.GONE
                btnExpandOutput.setImageResource(R.drawable.ic_expand_more)
            }
        }

        setHtmlText(output, R.string.label_result_default)
        output.setTextIsSelectable(false)
        updateTextViewHandlesColor(output, MaterialColors.getColor(
            output, R.attr.happAccent,
            ContextCompat.getColor(this, R.color.brand_purple_secondary)
        ))

        // "Get subscription" button: copies the bridge URL (enabling the bridge if needed)
        btnGetSub.setOnClickListener {
            val nowMs = android.os.SystemClock.elapsedRealtime()
            if (nowMs - lastGetSubTapMs < 500) return@setOnClickListener
            lastGetSubTapMs = nowMs
            val urlString = inputUrl.text.toString().replace("\n", "").replace("\r", "").trim()
            val hwid = inputHwid.text.toString().trim()
            val userAgent = inputUserAgent.text.toString().replace("\n", "").replace("\r", "").trim()

            if (urlString.startsWith("happ://crypt")) {
                Toast.makeText(this, getString(R.string.error_decrypt_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (HappCrypto.extractEmbeddedHappLink(urlString) != null) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (urlString.startsWith("happ://add/")) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (urlString.startsWith("http://127.0.0.1:8166")) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (urlString.isEmpty()) {
                Toast.makeText(this, getString(R.string.msg_enter_url), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (urlErrorText.visibility == View.VISIBLE) {
                Toast.makeText(this, getString(R.string.error_invalid_link), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val showCopiedAction = {
                btnGetSub.text = getString(R.string.btn_copied)
                btnGetSub.postDelayed({
                    btnGetSub.text = getString(R.string.btn_get_sub)
                }, 1000)
            }

            val copyAction = {
                try {
                    val encodedUrl = URLEncoder.encode(urlString, "UTF-8")
                    val encodedHwid = URLEncoder.encode(hwid, "UTF-8")
                    val encodedUa = URLEncoder.encode(userAgent, "UTF-8")
                    val bridgeUrl = "http://127.0.0.1:8166/url=$encodedUrl&hwid=$encodedHwid&ua=$encodedUa"
                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = ClipData.newPlainText("Happwner Bridge URL", bridgeUrl)
                    clipboard.setPrimaryClip(clip)
                    showCopiedAction()
                } catch (e: Exception) {
                    Toast.makeText(this, "Error copying URL", Toast.LENGTH_SHORT).show()
                }
            }

            // Enable the bridge (asking for notification permission first), then copy
            val enableBridgeAndCopy = {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                    notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                } else {
                    prefs.edit().putBoolean("bridge_enabled", true).apply()
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        startForegroundService(Intent(this, SubscriptionService::class.java))
                    } else {
                        startService(Intent(this, SubscriptionService::class.java))
                    }
                    copyAction()
                }
            }

            // First time -> show the hint; otherwise enable if needed, then copy
            val bridgeEnabled = prefs.getBoolean("bridge_enabled", false)
            val hintShown = prefs.getBoolean("bridge_hint_shown", false)

            if (!hintShown) {
                showBridgeHintDialog()
            } else if (!bridgeEnabled) {
                enableBridgeAndCopy()
            } else {
                copyAction()
            }
        }

        infoUrl.setOnClickListener { showInfoDialog(getString(R.string.info_url_title), getString(R.string.info_url_msg)) }
        infoHwid.setOnClickListener { showInfoDialog(getString(R.string.info_hwid_title), getString(R.string.info_hwid_msg)) }
        infoUserAgent.setOnClickListener { showInfoDialog(getString(R.string.info_ua_title), getString(R.string.info_ua_msg)) }

        button.setOnClickListener {
            val nowMs = android.os.SystemClock.elapsedRealtime()
            // Fetch button: pull the subscription directly, decrypt/convert, then show the result
            if (nowMs - lastFetchTapMs < 500) return@setOnClickListener
            lastFetchTapMs = nowMs
            currentFocus?.clearFocus()
            val urlString = inputUrl.text.toString().replace("\n", "").replace("\r", "")
            val hwid = inputHwid.text.toString()
            val userAgent = inputUserAgent.text.toString().replace("\n", "").replace("\r", "")

            if (urlString.startsWith("happ://crypt")) {
                Toast.makeText(this, getString(R.string.error_decrypt_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (HappCrypto.extractEmbeddedHappLink(urlString) != null) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (urlString.startsWith("happ://add/")) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (urlString.startsWith("http://127.0.0.1:8166")) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (urlString.isEmpty()) {
                Toast.makeText(this, getString(R.string.msg_enter_url), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val gen = ++fetchGeneration
            pendingConfigText = null
            loadingPhaseRunning = true
            fullResponseText = ""

            output.crossfadeContent(onEnd = {
                if (gen != fetchGeneration) return@crossfadeContent
                loadingPhaseRunning = false
                val pending = pendingConfigText
                if (pending != null) {
                    pendingConfigText = null
                    output.crossfadeContent {
                        output.visibility = View.VISIBLE
                        btnExpandOutput.setImageResource(R.drawable.ic_expand_less)
                        output.text = pending
                        if (!output.isTextSelectable) {
                            output.setTextIsSelectable(true)
                        }
                    }
                }
            }) {
                output.visibility = View.VISIBLE
                btnExpandOutput.setImageResource(R.drawable.ic_expand_less)
                output.text = getString(R.string.msg_loading)
                output.setTextIsSelectable(false)
            }

            // Off the main thread: fetch, decrypt, convert, then render with labels
            lifecycleScope.launch {
                val resp = makeRequest(urlString, hwid, userAgent)
                val jsonToUri = prefs.getBoolean("process_manual", true)
                val tryB64 = prefs.getBoolean("process_b64_manual", true)
                val xrayToSb = prefs.getBoolean("process_xray_manual", false)

                var wasDecrypted = false
                val stats = when (val r = HappCrypto.process(urlString, resp.body, resp.headers)) {
                    is HappCrypto.Result.Success -> {
                        wasDecrypted = true
                        LinkConverter.convertWithStats(r.plaintext, jsonToUri, tryB64, xrayToSb)
                    }
                    is HappCrypto.Result.Failed -> {
                        Toast.makeText(
                            this@MainActivity,
                            getString(R.string.toast_decrypt_failed, r.keyName, r.reason),
                            Toast.LENGTH_LONG
                        ).show()
                        LinkConverter.convertWithStats(r.originalBody, jsonToUri, tryB64, xrayToSb)
                    }
                    HappCrypto.Result.NotEncrypted ->
                        LinkConverter.convertWithStats(resp.body, jsonToUri, tryB64, xrayToSb)
                }
                val converted = stats.text
                val xraySkipped = stats.xraySkipped

                val displayedBody = if (converted.length > MAX_DISPLAY_CHARS) {
                    converted.take(MAX_DISPLAY_CHARS) + getString(R.string.msg_text_truncated)
                } else {
                    converted
                }

                // Prefix the '[Decrypted]' / skipped-count labels when relevant
                val newText: CharSequence = if (wasDecrypted || xraySkipped > 0) {
                    val accent = MaterialColors.getColor(
                        this@MainActivity, R.attr.happAccent,
                        ContextCompat.getColor(this@MainActivity, R.color.brand_purple_secondary)
                    )
                    val decryptedLabel = if (wasDecrypted) getString(R.string.msg_decrypted) else null
                    val skipLabel = if (xraySkipped > 0) {
                        resources.getQuantityString(R.plurals.msg_xray_skipped, xraySkipped, xraySkipped)
                    } else null
                    SpannableStringBuilder().apply {
                        if (decryptedLabel != null) {
                            val start = length
                            append(decryptedLabel)
                            setSpan(ForegroundColorSpan(accent), start, start + decryptedLabel.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                        }
                        if (skipLabel != null) {
                            if (length > 0) append("\n")
                            val start = length
                            append(skipLabel)
                            setSpan(ForegroundColorSpan(accent), start, start + skipLabel.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                        }
                        append("\n\n")
                        append(displayedBody)
                    }
                } else {
                    displayedBody
                }

                if (gen != fetchGeneration) return@launch
                fullResponseText = converted

                if (loadingPhaseRunning) {
                    pendingConfigText = newText
                } else {
                    output.crossfadeContent {
                        output.visibility = View.VISIBLE
                        btnExpandOutput.setImageResource(R.drawable.ic_expand_less)
                        output.text = newText
                        if (!output.isTextSelectable) {
                            output.setTextIsSelectable(true)
                        }
                    }
                }
            }
        }

        // Register for the module's ID / URL / refresh broadcasts
        val filter = IntentFilter().apply {
            addAction("${packageName}.ID_CAPTURED")
            addAction("${packageName}.URL_CAPTURED")
            addAction("${packageName}.REFRESH_UI")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(receiver, filter, RECEIVER_EXPORTED)
        } else {
            registerReceiver(receiver, filter)
        }

        // Auto-start the bridge service if it was left on
        if (prefs.getBoolean("bridge_enabled", false)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(Intent(this, SubscriptionService::class.java))
            } else {
                startService(Intent(this, SubscriptionService::class.java))
            }
        }

        BridgeController.refreshSurfaces(this)

        // Fresh start vs restore: settings fragment, intent, dialogs
        if (savedInstanceState == null) {
            preAttachSettingsFragment()
            handleHappViewIntent(intent)
        } else {
            restoreSettingsStateIfNeeded()
            restoreMainDialogIfNeeded(savedInstanceState)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleHappViewIntent(intent)
    }

    // External happ:// link (ACTION_VIEW): offer to import it
    private fun handleHappViewIntent(intent: Intent?) {
        if (intent == null || intent.action != Intent.ACTION_VIEW) return
        val link = intent.dataString?.trim()
        intent.data = null
        if (link.isNullOrEmpty() || !HappCrypto.isOpenableHappLink(link)) return
        pendingImportLink = link
    }

    // Show the deferred import dialog once we're at least STARTED
    private fun showPendingImportLink() {
        val link = pendingImportLink ?: return
        pendingImportLink = null
        window.decorView.post {
            if (isFinishing || isDestroyed) return@post
            if (!lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)) {
                pendingImportLink = link
                return@post
            }
            try { currentDialog?.dismiss() } catch (_: Throwable) {}
            currentDialog = null
            currentDialogTag = null
            showImportConfirmDialog(link)
        }
    }

    // Ask before importing an external happ:// link
    private fun showImportConfirmDialog(link: String) {
        val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
        val textMsg = dialogView.findViewById<TextView>(R.id.dialogMessage)
        textMsg.text = fromHtml(getString(R.string.import_confirm_msg, TextUtils.htmlEncode(link)))

        val dlg = AnimatedDialogBuilder(this)
            .setTitle(fromHtml(getString(R.string.import_confirm_title)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_yes))) { _, _ ->
                applyImportedLink(link)
            }
            .setNegativeButton(fromHtml(getString(R.string.btn_no)), null)
            .showAnimated()

        currentDialog = dlg
        currentDialogTag = DIALOG_IMPORT_CONFIRM
        currentImportLink = link
        dlg.setOnExternalDismissListener {
            if (currentDialog === dlg) {
                currentDialog = null
                currentDialogTag = null
                currentImportLink = null
            }
        }
    }

    // Put the imported link into the URL field
    private fun applyImportedLink(link: String) {
        mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
        inputUrl.setText(link.replace("\n", "").replace("\r", ""))
    }

    // Re-open whichever dialog was showing before the recreate
    private fun restoreMainDialogIfNeeded(savedInstanceState: Bundle) {
        val tag = savedInstanceState.getString(STATE_OPEN_DIALOG_TAG) ?: return
        when (tag) {
            DIALOG_INFO -> {
                val title = savedInstanceState.getString(STATE_OPEN_DIALOG_TITLE) ?: return
                val message = savedInstanceState.getString(STATE_OPEN_DIALOG_MESSAGE) ?: return
                window.decorView.post {
                    if (isFinishing || isDestroyed) return@post
                    if (!lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)) return@post
                    try { currentDialog?.dismiss() } catch (_: Throwable) {}
                    currentDialog = null
                    currentDialogTag = null
                    try { showInfoDialog(title, message) } catch (_: Throwable) {}
                }
            }
            DIALOG_BRIDGE_HINT -> {
                window.decorView.post {
                    if (isFinishing || isDestroyed) return@post
                    if (!lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)) return@post
                    if (getSafePrefs(this).getBoolean("bridge_hint_shown", false)) return@post
                    try { currentDialog?.dismiss() } catch (_: Throwable) {}
                    currentDialog = null
                    currentDialogTag = null
                    try { showBridgeHintDialog() } catch (_: Throwable) {}
                }
            }
            DIALOG_IMPORT_CONFIRM -> {
                val link = savedInstanceState.getString(STATE_IMPORT_LINK) ?: return
                window.decorView.post {
                    if (isFinishing || isDestroyed) return@post
                    if (!lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)) return@post
                    try { currentDialog?.dismiss() } catch (_: Throwable) {}
                    currentDialog = null
                    currentDialogTag = null
                    try { showImportConfirmDialog(link) } catch (_: Throwable) {}
                }
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        when (val tag = currentDialogTag) {
            DIALOG_INFO -> {
                outState.putString(STATE_OPEN_DIALOG_TAG, tag)
                currentDialogInfoTitle?.let { outState.putString(STATE_OPEN_DIALOG_TITLE, it) }
                currentDialogInfoMessage?.let { outState.putString(STATE_OPEN_DIALOG_MESSAGE, it) }
            }
            DIALOG_BRIDGE_HINT -> {
                outState.putString(STATE_OPEN_DIALOG_TAG, tag)
            }
            DIALOG_IMPORT_CONFIRM -> {
                outState.putString(STATE_OPEN_DIALOG_TAG, tag)
                currentImportLink?.let { outState.putString(STATE_IMPORT_LINK, it) }
            }
        }
    }

    // Set an HTML string resource on a TextView
    private fun setHtmlText(textView: TextView?, resId: Int) {
        if (textView == null) return
        val msg = getString(resId)
        textView.text = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            Html.fromHtml(msg, Html.FROM_HTML_MODE_LEGACY)
        } else {
            @Suppress("DEPRECATION")
            Html.fromHtml(msg)
        }
    }

    // React to orientation / language / theme / Monet / anim-mode changes
    override fun onResume() {
        super.onResume()
        val currentOrientation = resources.configuration.orientation
        if (lastLayoutOrientation != android.content.res.Configuration.ORIENTATION_UNDEFINED &&
            currentOrientation != lastLayoutOrientation) {
            lastLayoutOrientation = currentOrientation
            recreate()
            return
        }
        lastLayoutOrientation = currentOrientation
        updateUiState()

        val prefs = getSafePrefs(this)
        val savedLang = prefs.getString("app_lang", "system") ?: "system"
        if (lastKnownLang != null && lastKnownLang != savedLang) {
            lastKnownLang = savedLang
            ThemeTransition.captureAndRecreate(this, 340L)
            return
        }
        lastKnownLang = savedLang

        val savedTheme = prefs.getInt("theme_mode", 0)
        if (lastKnownTheme != null && lastKnownTheme != savedTheme) {
            lastKnownTheme = savedTheme
            ThemeTransition.captureAndRecreate(this, 430L)
            return
        }
        lastKnownTheme = savedTheme

        val savedMonet = prefs.getBoolean("monet_accent", false)
        if (lastKnownMonet != null && lastKnownMonet != savedMonet) {
            lastKnownMonet = savedMonet
            ThemeTransition.captureAndRecreate(this, 430L)
            return
        }
        lastKnownMonet = savedMonet

        val savedAnimMode = animMode().toString()
        if (System.getProperty("happwner_current_anim_mode") != null &&
            System.getProperty("happwner_current_anim_mode") != savedAnimMode) {
            System.setProperty("happwner_current_anim_mode", savedAnimMode)
            resetAnimatorScale(this)
        } else {
            System.setProperty("happwner_current_anim_mode", savedAnimMode)
        }

        showPendingImportLink()
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ ->
        // On denial, still start the bridge (like the tile/shortcut): the FGS runs without a visible notification
        val prefs = getSafePrefs(this)
        prefs.edit().putBoolean("bridge_enabled", true).apply()

        val serviceIntent = Intent(this, SubscriptionService::class.java)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(serviceIntent)
            } else {
                startService(serviceIntent)
            }
        } catch (_: Throwable) {}

        val urlString = inputUrl.text.toString().replace("\n", "").replace("\r", "").trim()
        val hwid = inputHwid.text.toString().trim()
        val userAgent = inputUserAgent.text.toString().replace("\n", "").replace("\r", "").trim()

        try {
            val encodedUrl = URLEncoder.encode(urlString, "UTF-8")
            val encodedHwid = URLEncoder.encode(hwid, "UTF-8")
            val encodedUa = URLEncoder.encode(userAgent, "UTF-8")
            val bridgeUrl = "http://127.0.0.1:8166/url=$encodedUrl&hwid=$encodedHwid&ua=$encodedUa"
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Happwner Bridge URL", bridgeUrl)
            clipboard.setPrimaryClip(clip)
        } catch (_: Throwable) {}
    }

    // Keep orientation and the nav-bar appearance in sync
    override fun onConfigurationChanged(newConfig: android.content.res.Configuration) {
        super.onConfigurationChanged(newConfig)
        if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) {
            lastLayoutOrientation = newConfig.orientation
        }
        val isNightMode = (newConfig.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) ==
            android.content.res.Configuration.UI_MODE_NIGHT_YES
        WindowInsetsControllerCompat(window, window.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = !isNightMode
        }
    }

    // Swap the field's action icon by URL type (paste / decrypt / unwrap / revert)
    private fun updateUrlActionIcon(text: String) {
        when {
            text.startsWith("happ://crypt") -> {
                btnPasteUrlManual.setImageResource(R.drawable.ic_key)
                btnPasteUrlManual.setOnClickListener { handleDecryptUrl(text) }
            }
            text.startsWith("happ://add/") -> {
                btnPasteUrlManual.setImageResource(R.drawable.revert)
                btnPasteUrlManual.setOnClickListener { handleParseAddUrl(text) }
            }
            text.startsWith("http://127.0.0.1:8166") -> {
                btnPasteUrlManual.setImageResource(R.drawable.revert)
                btnPasteUrlManual.setOnClickListener { parseAndApplyBridgeUrl(text) }
            }
            HappCrypto.extractEmbeddedHappLink(text) != null -> {
                btnPasteUrlManual.setImageResource(R.drawable.revert)
                btnPasteUrlManual.setOnClickListener { handleUnwrapUrl(text) }
            }
            else -> {
                btnPasteUrlManual.setImageResource(R.drawable.ic_paste)
                btnPasteUrlManual.setOnClickListener { handlePasteUrl() }
            }
        }
    }

    private fun handlePasteUrl() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip
        if (clip != null && clip.itemCount > 0) {
            val pasteText = clip.getItemAt(0).text.toString().trim()
            inputUrl.setText(pasteText.replace("\n", "").replace("\r", ""))
        } else {
            Toast.makeText(this, getString(R.string.msg_clipboard_empty), Toast.LENGTH_SHORT).show()
        }
    }

    // Pull the bare happ:// link out of an http carrier
    private fun handleUnwrapUrl(carrierUrl: String) {
        val bare = HappCrypto.extractEmbeddedHappLink(carrierUrl)
        if (bare != null) {
            inputUrl.setText(bare)
        }
    }

    // Strip happ://add/ down to the inner link
    private fun handleParseAddUrl(addUrl: String) {
        val bare = HappCrypto.stripAddPrefix(addUrl) ?: return
        mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
        inputUrl.setText(bare.replace("\n", "").replace("\r", ""))
    }

    // Decrypt a happ://cryptN link off-thread, then show it (or the error)
    private fun handleDecryptUrl(cryptUrl: String) {
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                HappCrypto.decryptHappLink(cryptUrl)
            }
            when (result) {
                is HappCrypto.HappLinkResult.Decrypted -> {
                    mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
                    inputUrl.setText(result.plaintext)
                }
                is HappCrypto.HappLinkResult.Error -> {
                    val safeDetail = TextUtils.htmlEncode("${result.mode}: ${result.reason}")
                    showInfoDialog(
                        getString(R.string.title_decryption_error),
                        safeDetail
                    )
                }
                HappCrypto.HappLinkResult.NotHappLink -> {
                    showInfoDialog(
                        getString(R.string.title_decryption_error),
                        getString(R.string.error_url_not_found)
                    )
                }
            }
        }
    }

    // Parse the bridge URL back into the url/hwid/ua fields
    private fun parseAndApplyBridgeUrl(bridgeUrl: String) {
        try {
            mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
            val queryPart = if (bridgeUrl.contains("/url=")) {
                bridgeUrl.substringAfter("/url=")
            } else return

            val pairs = ("url=" + queryPart).split("&")
            var url: String? = null
            var hwid: String? = null
            var ua: String? = null

            for (pairStr in pairs) {
                val pair = pairStr.split("=", limit = 2)
                if (pair.size < 2) continue
                val key = pair[0]
                val value = android.net.Uri.decode(pair[1])
                when (key) {
                    "url" -> url = value
                    "hwid" -> hwid = value
                    "ua" -> ua = value
                }
            }

            url?.let { inputUrl.setText(it) }
            hwid?.let {
                if (!inputHwid.isEnabled) handleToggleHwidEdit(true)
                inputHwid.setText(it)
            }
            ua?.let {
                if (!inputUserAgent.isEnabled) handleToggleUaEdit(true)
                inputUserAgent.setText(it)
            }
        } catch (e: Exception) {}
    }

    private fun handlePasteHwid() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip
        if (clip != null && clip.itemCount > 0) {
            val pasteText = clip.getItemAt(0).text.toString().replace("\n", "").replace("\r", "")
            inputHwid.setText(pasteText)
        } else {
            Toast.makeText(this, getString(R.string.msg_clipboard_empty), Toast.LENGTH_SHORT).show()
        }
    }

    private fun fixSharedPrefs() = PrefsManager.fixSharedPrefs(this)

    // Toggle manual HWID entry; gracefully dismiss the keyboard and the hint animation
    private fun handleToggleHwidEdit(enabled: Boolean) {
        val prefs = getSafePrefs(this)

        val hadFocus = inputHwid.hasFocus()
        val isImeVisible = try {
            ViewCompat.getRootWindowInsets(window.decorView)
                ?.isVisible(WindowInsetsCompat.Type.ime()) ?: false
        } catch (_: Throwable) { false }

        val stableHintHeight = if (hadFocus && hwidHint.visibility == View.VISIBLE) {
            hwidHint.height.coerceAtLeast(0)
        } else -1

        if (hadFocus) {
            val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
            imm.hideSoftInputFromWindow(inputHwid.windowToken, 0)
            inputHwid.clearFocus()
        }

        inputHwid.isEnabled = enabled
        prefs.edit().putBoolean("use_custom_hwid_input", enabled).apply()

        if (!enabled) {
            val captured = prefs.getString("captured_id", "") ?: ""
            if (hadFocus) {
                hintAnimationSuppressed = true
                inputHwid.setText(captured)
                hintAnimationSuppressed = false
                if (stableHintHeight > 0) {
                    pendingStartHeight = stableHintHeight
                }
                if (isImeVisible) {
                    pendingHintAnimAfterImeClose = true
                    inputHwid.postDelayed({
                        if (pendingHintAnimAfterImeClose && !isFinishing && !isDestroyed) {
                            pendingHintAnimAfterImeClose = false
                            updateHwidHintVisibility(inputHwid.text?.toString())
                        }
                    }, 500L)
                } else {
                    inputHwid.postDelayed({
                        if (!isFinishing && !isDestroyed) {
                            updateHwidHintVisibility(inputHwid.text?.toString())
                        }
                    }, 50L)
                }
            } else {
                inputHwid.setText(captured)
                updateHwidHintVisibility(captured)
            }
        } else {
            val custom = prefs.getString("custom_hwid", "") ?: ""
            if (custom.isNotEmpty()) {
                inputHwid.setText(custom)
            } else {
                val captured = prefs.getString("captured_id", "") ?: ""
                inputHwid.setText(captured)
            }
        }
        refreshFieldStyle(layoutHwid, inputHwid)
        PrefsManager.broadcastSettings(this)
    }

    // Toggle manual UA entry; restore the default UA when turning it off
    private fun handleToggleUaEdit(enabled: Boolean) {
        val prefs = getSafePrefs(this)
        inputUserAgent.isEnabled = enabled
        prefs.edit().putBoolean("use_custom_ua_input", enabled).apply()

        if (!enabled) {
            inputUserAgent.setText(getHappDefaultUa())
        } else {
            val custom = prefs.getString("custom_user_agent", "")
            if (!custom.isNullOrEmpty()) {
                inputUserAgent.setText(custom)
            }
            inputUserAgent.clearFocus()
        }
        refreshFieldStyle(layoutUserAgent, inputUserAgent)
    }

    // On start: reconcile LSPatch, reload history, refresh the UI
    override fun onStart() {
        super.onStart()
        checkLSPatchStatus()
        loadUrlHistory()
        updateUiState()
    }

    // Drop manual UA editing if it's just the default
    override fun onStop() {
        super.onStop()
        val prefs = getSafePrefs(this)

        if (inputUserAgent.isEnabled) {
            val currentUa = inputUserAgent.text.toString()
            val defaultUa = getHappDefaultUa()
            if (currentUa == defaultUa || currentUa.isEmpty()) {
                handleToggleUaEdit(false)
            }
        }
    }

    // Reconcile LSPatch apps (signatures / installed state) and toggle lspatch_mode
    private fun checkLSPatchStatus() {
        val prefs = getSafePrefs(this)

        if (ModuleStatus.isModuleActive()) {
            if (prefs.getBoolean("lspatch_mode", false)) {
                Log.i("Happwner:LSP", "Xposed active, clearing lspatch_mode flag (lspatch_apps retained)")
                prefs.edit().putBoolean("lspatch_mode", false).apply()
            }
            return
        }

        val lspatchApps = prefs.getStringSet("lspatch_apps", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        val sigMapJson = prefs.getString("lspatch_signatures", "{}") ?: "{}"
        val sigMap = org.json.JSONObject(sigMapJson)

        Log.d("Happwner:LSP", "Checking status. Apps in list: ${lspatchApps.size}")

        val userChoice = prefs.getInt("lspatch_mode_v2", 0)
        if (userChoice == 1) {
            prefs.edit().putBoolean("lspatch_mode", true).apply()
            return
        }
        if (userChoice == 2) {
            prefs.edit().putBoolean("lspatch_mode", false).apply()
            return
        }

        val iterator = lspatchApps.iterator()
        var changed = false

        while (iterator.hasNext()) {
            val pkgName = iterator.next()
            val savedCrc = sigMap.optLong(pkgName, -1L)
            val currentCrc = PrefsManager.getSignatureCrc32(this, pkgName)

            Log.d("Happwner:LSP", "Validating $pkgName: SavedCRC=$savedCrc, CurrentCRC=$currentCrc")

            val isInstalled = PrefsManager.isPackageInstalled(this, pkgName)

            if (!isInstalled) {
                Log.w("Happwner:LSP", "Removing $pkgName: App not installed")
                iterator.remove()
                sigMap.remove(pkgName)
                changed = true
            } else if (currentCrc == null) {
                Log.w("Happwner:LSP", "Keeping $pkgName: CRC failed but app installed (signature query unavailable)")
            } else if (savedCrc != -1L && currentCrc != savedCrc) {
                Log.w("Happwner:LSP", "Removing $pkgName: Signature mismatch (reinstalled?)")
                iterator.remove()
                sigMap.remove(pkgName)
                changed = true
            }
        }

        if (changed) {
            Log.d("Happwner:LSP", "Saving updated app list. New count: ${lspatchApps.size}")
            prefs.edit()
                .putStringSet("lspatch_apps", lspatchApps)
                .putString("lspatch_signatures", sigMap.toString())
                .apply()
        }

        val hasValidApp = lspatchApps.isNotEmpty()
        val currentMode = prefs.getBoolean("lspatch_mode", false)

        if (currentMode != hasValidApp) {
            Log.i("Happwner:LSP", "Toggling lspatch_mode: $currentMode -> $hasValidApp")
            prefs.edit().putBoolean("lspatch_mode", hasValidApp).apply()
        }
    }

    // Redraw the UI for the current mode (Xposed / LSPatch / plain)
    private fun updateUiState() {
        val prefs = getSafePrefs(this)
        val lspatchMode = prefs.getBoolean("lspatch_mode", false)
        val moduleActive = ModuleStatus.isModuleActive()
        val isFullActive = moduleActive || lspatchMode

        mainContainer.beginDelayedTransitionIfEnabled(fastTransition)

        val isInterceptionEnabled = prefs.getBoolean("intercept_enabled", false)
        islandIntercept.visibility = if (isInterceptionEnabled && isFullActive) View.VISIBLE else View.GONE

        findViewById<ImageButton>(R.id.btnEditHwidManual).setImageResource(
            if (isFullActive) R.drawable.ic_edit else R.drawable.ic_paste
        )

        val isInputEnabled = prefs.getBoolean("use_custom_hwid_input", false)
        inputHwid.isEnabled = if (isFullActive) isInputEnabled else true

        val displayId = if (isFullActive && !isInputEnabled) {
            prefs.getString("captured_id", "") ?: ""
        } else {
            val custom = prefs.getString("custom_hwid", "") ?: ""
            if (custom.isNotEmpty()) custom else prefs.getString("captured_id", "") ?: ""
        }

        if (inputHwid.text?.toString() != displayId && displayId.isNotEmpty()) {
            inputHwid.setText(displayId)
        }
        updateHwidHintVisibility(inputHwid.text?.toString())

        val isUaInputEnabled = prefs.getBoolean("use_custom_ua_input", false)
        inputUserAgent.isEnabled = isUaInputEnabled

        if (isUaInputEnabled) {
            inputUserAgent.setText(prefs.getString("custom_user_agent", getHappDefaultUa()))
        } else {
            inputUserAgent.setText(getHappDefaultUa())
        }

        refreshAllFieldsStyle(false)
    }

    // "HWID unknown" hint animation (manual height calc to avoid jitter under the IME)
    private fun updateHwidHintVisibility(id: String?) {
        if (hintAnimationSuppressed) return
        val prefs = getSafePrefs(this)
        val lspatchMode = prefs.getBoolean("lspatch_mode", false)
        val moduleActive = ModuleStatus.isModuleActive()
        val isFullActive = moduleActive || lspatchMode

        val shouldShow = id.isNullOrEmpty() && isFullActive
        val rowHwid = findViewById<View>(R.id.rowHwid)
        val rowLp = rowHwid.layoutParams as? ViewGroup.MarginLayoutParams ?: return
        val hintLp = hwidHint.layoutParams as? ViewGroup.MarginLayoutParams

        val standardHintMargin = resources.getDimensionPixelSize(R.dimen.island_margin_bottom)
        val targetRowMargin = if (shouldShow) {
            resources.getDimensionPixelSize(R.dimen.spacing_tiny)
        } else {
            resources.getDimensionPixelSize(R.dimen.island_margin_bottom)
        }
        val targetVisibility = if (shouldShow) View.VISIBLE else View.GONE
        val targetAlpha = if (shouldShow) 1f else 0f
        val targetHintMargin = if (shouldShow) standardHintMargin else 0

        // Bail out if we're already in the target state
        val alreadyFinal = hwidHintAnim?.isRunning != true &&
            hwidHint.visibility == targetVisibility &&
            kotlin.math.abs(hwidHint.alpha - 1f) < 0.01f &&
            rowLp.bottomMargin == targetRowMargin &&
            hwidHint.layoutParams.height == ViewGroup.LayoutParams.WRAP_CONTENT &&
            (hintLp?.bottomMargin ?: standardHintMargin) == standardHintMargin
        if (alreadyFinal) return

        if (hwidHintAnim?.isRunning == true && hwidHintAnimTarget == shouldShow) {
            return
        }

        if (shouldShow) {
            hwidHint.text = getString(R.string.label_hwid_unknown)
        }

        hwidHintAnim?.cancel()
        hwidHintAnimTarget = shouldShow

        val applyFinalState = {
            hwidHint.visibility = targetVisibility
            hwidHint.alpha = 1f
            val lpFinal = hwidHint.layoutParams
            lpFinal.height = ViewGroup.LayoutParams.WRAP_CONTENT
            if (lpFinal is ViewGroup.MarginLayoutParams) {
                lpFinal.bottomMargin = standardHintMargin
            }
            hwidHint.layoutParams = lpFinal
            rowLp.bottomMargin = targetRowMargin
            rowHwid.layoutParams = rowLp
        }

        val mode = animMode()
        if (mode == ANIM_MODE_OFF) {
            applyFinalState()
            return
        }

        val duration = if (mode == ANIM_MODE_SYSTEM) {
            resources.getInteger(android.R.integer.config_shortAnimTime).toLong()
        } else {
            resources.getInteger(R.integer.duration_fast_transition).toLong()
        }

        if (shouldShow && hwidHint.visibility != View.VISIBLE) {
            hwidHint.alpha = 0f
            hwidHint.visibility = View.VISIBLE
            hwidHint.layoutParams.height = 0
            if (hintLp != null) hintLp.bottomMargin = 0
            hwidHint.layoutParams = hwidHint.layoutParams
        }

        // Measure the hint's target height for the animation
        val measuredTargetHeight = if (shouldShow) {
            val parent = hwidHint.parent as? ViewGroup
            val parentWidth = parent?.width ?: 0
            val savedHeight = hwidHint.layoutParams.height
            hwidHint.layoutParams.height = ViewGroup.LayoutParams.WRAP_CONTENT
            val widthSpec = View.MeasureSpec.makeMeasureSpec(parentWidth, View.MeasureSpec.AT_MOST)
            val heightSpec = View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
            hwidHint.measure(widthSpec, heightSpec)
            val mh = hwidHint.measuredHeight
            hwidHint.layoutParams.height = savedHeight
            hwidHint.layoutParams = hwidHint.layoutParams
            mh
        } else 0

        val startRowMargin = rowLp.bottomMargin
        val startAlpha = hwidHint.alpha
        val startHeight = if (pendingStartHeight > 0) {
            val h = pendingStartHeight
            pendingStartHeight = -1
            h
        } else {
            hwidHint.height.coerceAtLeast(0)
        }
        val startHintMargin = hintLp?.bottomMargin ?: 0

        // Animate row margin, alpha and height together
        val anim = android.animation.ValueAnimator.ofFloat(0f, 1f).apply {
            this.duration = duration
            addUpdateListener { a ->
                val f = a.animatedFraction
                rowLp.bottomMargin = (startRowMargin + (targetRowMargin - startRowMargin) * f).toInt()
                rowHwid.layoutParams = rowLp
                hwidHint.alpha = startAlpha + (targetAlpha - startAlpha) * f
                val hLp = hwidHint.layoutParams
                hLp.height = (startHeight + (measuredTargetHeight - startHeight) * f).toInt()
                if (hLp is ViewGroup.MarginLayoutParams) {
                    hLp.bottomMargin = (startHintMargin + (targetHintMargin - startHintMargin) * f).toInt()
                }
                hwidHint.layoutParams = hLp
            }
            addListener(object : android.animation.AnimatorListenerAdapter() {
                var ended = false
                override fun onAnimationEnd(animation: android.animation.Animator) {
                    if (ended) return
                    ended = true
                    applyFinalState()
                    if (hwidHintAnim === animation) hwidHintAnim = null
                }
                override fun onAnimationCancel(animation: android.animation.Animator) {
                    ended = true
                }
            })
        }
        hwidHintAnim = anim
        anim.start()
    }

    // Rebuild the history list (optionally de-duplicated)
    private fun loadUrlHistory() {
        capturedUrlsContainer.removeAllViews()
        val prefs = getSafePrefs(this)
        val showDuplicates = prefs.getBoolean("show_duplicates", false)
        val historyList = prefs.getString("url_history_list", "") ?: ""

        if (historyList.isNotEmpty()) {
            var items = historyList.split("|||")
            if (!showDuplicates) {
                items = items.distinct()
            }
            items.reversed().forEach { addUrlToUi(it) }
        }
        updateEmptyHistoryVisibility()
        updateUiState()
    }

    // One tappable history row that refills the URL field
    private fun addUrlToUi(url: String) {
        val tv = TextView(this).apply {
            text = url
            val pV = resources.getDimensionPixelSize(R.dimen.padding_history_vertical)
            setPadding(0, pV, 0, pV)
            setTextColor(MaterialColors.getColor(
                this, R.attr.happAccent,
                ContextCompat.getColor(context, R.color.brand_purple_secondary)
            ))
            textSize = 14f

            val outValue = android.util.TypedValue()
            context.theme.resolveAttribute(android.R.attr.selectableItemBackground, outValue, true)
            setBackgroundResource(R.drawable.bg_row_ripple)
            isClickable = true
            isFocusable = true

            setOnClickListener {
                inputUrl.setText(url)
            }
        }
        capturedUrlsContainer.addView(tv, 0)
        updateEmptyHistoryVisibility()
    }

    private fun updateEmptyHistoryVisibility() {
        if (capturedUrlsContainer.childCount == 0) {
            emptyHistoryText.visibility = View.VISIBLE
            val msg = getString(R.string.label_history_empty)
            emptyHistoryText.text = fromHtml(msg)
        } else {
            emptyHistoryText.visibility = View.GONE
        }
    }

    // Default UA from the installed Happ version, else a fallback
    private fun getHappDefaultUa(): String {
        for (pkg in arrayOf(PrefsManager.HAPP_PKG_PRIMARY, PrefsManager.HAPP_PKG_SECONDARY)) {
            try {
                val packageInfo = packageManager.getPackageInfo(pkg, 0)
                val v = packageInfo.versionName
                if (!v.isNullOrEmpty()) return "Happ/$v"
            } catch (_: PackageManager.NameNotFoundException) {
            } catch (_: Throwable) {}
        }
        return "Happ/1.0.0"
    }

    private fun fromHtml(text: String): CharSequence {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            Html.fromHtml(text, Html.FROM_HTML_MODE_LEGACY)
        } else {
            @Suppress("DEPRECATION")
            Html.fromHtml(text)
        }
    }

    // Generic info dialog (tracked so it survives a recreate)
    private fun showInfoDialog(title: String, htmlMessage: String) {
        val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
        val textMsg = dialogView.findViewById<TextView>(R.id.dialogMessage)
        textMsg.text = fromHtml(htmlMessage)

        val dlg = AnimatedDialogBuilder(this)
            .setTitle(fromHtml(title))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
            .showAnimated()

        currentDialog = dlg
        currentDialogTag = DIALOG_INFO
        currentDialogInfoTitle = title
        currentDialogInfoMessage = htmlMessage
        dlg.setOnExternalDismissListener {
            if (currentDialog === dlg) {
                currentDialog = null
                currentDialogTag = null
                currentDialogInfoTitle = null
                currentDialogInfoMessage = null
            }
        }
    }

    // First-time bridge explainer; on OK mark it shown and re-tap Get
    private fun showBridgeHintDialog() {
        val msg = getString(R.string.msg_bridge_service_enable)
        val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
        val textMsg = dialogView.findViewById<TextView>(R.id.dialogMessage)
        textMsg.text = fromHtml(msg)

        val dlg = AnimatedDialogBuilder(this)
            .setTitle(fromHtml(getString(R.string.setting_bridge_header)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok))) { _, _ ->
                getSafePrefs(this).edit().putBoolean("bridge_hint_shown", true).apply()
                btnGetSub.performClick()
            }
            .showAnimated()

        currentDialog = dlg
        currentDialogTag = DIALOG_BRIDGE_HINT
        dlg.setOnExternalDismissListener {
            if (currentDialog === dlg) {
                currentDialog = null
                currentDialogTag = null
            }
        }
    }

    // Reflect a captured android_id into the HWID field
    private fun updateHwidDisplay(id: String) {
        if (!inputHwid.isEnabled) {
            inputHwid.setText(id)
            updateHwidHintVisibility(id)
            return
        }
        val current = inputHwid.text?.toString()?.trim().orEmpty()
        if (current.isEmpty() || current == id.trim()) {
            handleToggleHwidEdit(false)
        }
    }

    private var settingsBackCallback: OnBackPressedCallback? = null
    private var isClosingSettings = false

    private fun isSettingsVisible(): Boolean {
        val f = supportFragmentManager.findFragmentByTag(SETTINGS_FRAGMENT_TAG) ?: return false
        return !f.isHidden
    }

    // Pre-attach the settings fragment hidden, so the slide-in opens instantly
    private fun preAttachSettingsFragment() {
        val container = findViewById<View>(R.id.settingsFragmentContainer) ?: return
        container.postDelayed({
            if (isFinishing || isDestroyed) return@postDelayed
            if (supportFragmentManager.findFragmentByTag(SETTINGS_FRAGMENT_TAG) != null) return@postDelayed
            try {
                val fragment = SettingsFragment()
                supportFragmentManager.beginTransaction()
                    .add(R.id.settingsFragmentContainer, fragment, SETTINGS_FRAGMENT_TAG)
                    .hide(fragment)
                    .commitNowAllowingStateLoss()
            } catch (_: Throwable) {}
        }, 100L)
    }

    // Open settings with a slide (a separate activity when system animations are on)
    fun openSettings() {
        if (isSettingsVisible() || isClosingSettings) return

        try {
            val focused = currentFocus
            if (focused != null) {
                val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as? android.view.inputmethod.InputMethodManager
                imm?.hideSoftInputFromWindow(focused.windowToken, 0)
                focused.clearFocus()
            }
        } catch (_: Throwable) {}

        val host = findViewById<View>(R.id.rootLayout) ?: return
        val container = findViewById<View>(R.id.settingsFragmentContainer) ?: return
        val mode = animMode()

        if (mode == ANIM_MODE_SYSTEM) {
            try {
                startActivity(Intent(this, SettingsActivity::class.java))
            } catch (_: Throwable) {}
            return
        }

        val existing = supportFragmentManager.findFragmentByTag(SETTINGS_FRAGMENT_TAG)

        try {
            if (existing == null) {
                val fragment = SettingsFragment()
                supportFragmentManager.beginTransaction()
                    .add(R.id.settingsFragmentContainer, fragment, SETTINGS_FRAGMENT_TAG)
                    .commitNow()
            } else if (existing.isHidden) {
                supportFragmentManager.beginTransaction()
                    .show(existing)
                    .commitNow()
            }
        } catch (_: Throwable) {
            return
        }

        slideSettingsIn(host, container)
        ensureSettingsBackCallback().isEnabled = true
    }

    // Slide settings out, then hide the fragment
    fun closeSettings() {
        if (isClosingSettings) return
        val fragment = supportFragmentManager.findFragmentByTag(SETTINGS_FRAGMENT_TAG) ?: return
        if (fragment.isHidden) return
        val host = findViewById<View>(R.id.rootLayout) ?: return
        val container = findViewById<View>(R.id.settingsFragmentContainer) ?: return

        isClosingSettings = true

        slideSettingsOut(host, container) {
            isClosingSettings = false
            settingsBackCallback?.isEnabled = false
            if (!isFinishing && !isDestroyed) {
                try {
                    supportFragmentManager.beginTransaction()
                        .hide(fragment)
                        .commitNowAllowingStateLoss()
                } catch (_: Throwable) {}
            }
            updateUiState()
        }
    }

    // Lazily wire a Back handler that closes settings
    private fun ensureSettingsBackCallback(): OnBackPressedCallback {
        settingsBackCallback?.let { return it }
        val cb = object : OnBackPressedCallback(false) {
            override fun handleOnBackPressed() {
                closeSettings()
            }
        }
        onBackPressedDispatcher.addCallback(this, cb)
        settingsBackCallback = cb
        return cb
    }

    // After a recreate, snap settings back to the open state
    private fun restoreSettingsStateIfNeeded() {
        if (!isSettingsVisible()) return
        val host = findViewById<View>(R.id.rootLayout) ?: return
        val container = findViewById<View>(R.id.settingsFragmentContainer) ?: return
        applySettingsOpenStateInstantly(host, container)
        ensureSettingsBackCallback().isEnabled = true
    }

    // Dialog tags and saved-state keys
    companion object {
        private const val SETTINGS_FRAGMENT_TAG = "settings_fragment"
        private const val STATE_OPEN_DIALOG_TAG = "main_open_dialog_tag"
        private const val STATE_OPEN_DIALOG_TITLE = "main_open_dialog_title"
        private const val STATE_OPEN_DIALOG_MESSAGE = "main_open_dialog_message"
        private const val STATE_IMPORT_LINK = "main_import_link"
        private const val DIALOG_INFO = "info"
        private const val DIALOG_BRIDGE_HINT = "bridge_hint"
        private const val DIALOG_IMPORT_CONFIRM = "import_confirm"
    }

    // Unregister the broadcast receiver
    override fun onDestroy() {
        super.onDestroy()
        try { unregisterReceiver(receiver) } catch (e: Exception) {}
    }

    private data class HappResp(val body: String, val headers: Map<String, List<String>>)

    // Read the body with explicit UTF-8 and a size cap, to guard against OOM on a huge response
    private fun readBodyCapped(input: java.io.InputStream): String {
        val maxBytes = 32L * 1024 * 1024 // 32 MB; any real subscription is far smaller
        val out = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(16 * 1024)
        var total = 0L
        input.use {
            while (true) {
                val n = it.read(chunk)
                if (n < 0) break
                total += n
                if (total > maxBytes) throw java.io.IOException("Response body exceeds size limit")
                out.write(chunk, 0, n)
            }
        }
        return out.toString("UTF-8")
    }

    // GET the subscription: x-hwid + User-Agent, grab the body and headers
    private suspend fun makeRequest(url: String, hwid: String, ua: String): HappResp = withContext(Dispatchers.IO) {
        var conn: HttpURLConnection? = null
        val timeout = resources.getInteger(R.integer.network_timeout_ms)
        try {
            conn = URL(url).openConnection() as HttpURLConnection
            conn.apply {
                requestMethod = "GET"
                setRequestProperty("x-hwid", hwid)
                setRequestProperty("User-Agent", ua)
                connectTimeout = timeout
                readTimeout = timeout
            }
            val headers = conn.headerFields.filterKeys { it != null }
            val body = if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                readBodyCapped(conn.inputStream)
            } else "Error: ${conn.responseCode}"
            HappResp(body, headers)
        } catch (e: Exception) { HappResp("Error: ${e.message}", emptyMap()) }
        finally { conn?.disconnect() }
    }

    // Pick the URL field color by state (error / encrypted / normal)
    private fun getUrlCurrentColor(): Int {
        val text = inputUrl.text.toString().trim()
        val isEncrypted = text.startsWith("happ://crypt")
        val isAddLink = text.startsWith("happ://add/")
        val hasError = !text.isEmpty() && !isEncrypted && !isAddLink && !text.startsWith("http://") && !text.startsWith("https://")

        return when {
            hasError -> ContextCompat.getColor(this, R.color.error_red)
            isEncrypted || isAddLink -> {
                val isNight = (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) == android.content.res.Configuration.UI_MODE_NIGHT_YES
                if (isNight) Color.WHITE else Color.BLACK
            }
            else -> MaterialColors.getColor(
                this, R.attr.happAccent,
                ContextCompat.getColor(this, R.color.brand_purple_secondary)
            )
        }
    }

    private fun refreshAllFieldsStyle(animate: Boolean = true) {
        refreshFieldStyle(layoutUrl, inputUrl, animate)
        refreshFieldStyle(layoutHwid, inputHwid, animate)
        refreshFieldStyle(layoutUserAgent, inputUserAgent, animate)
    }

    // Field border/cursor/text color for its state (focused / error / disabled)
    private fun refreshFieldStyle(layout: TextInputLayout, editText: EditText, animate: Boolean = true) {
        val isEnabled = editText.isEnabled
        val purple = MaterialColors.getColor(
            editText, R.attr.happAccent,
            ContextCompat.getColor(this, R.color.brand_purple_secondary)
        )
        val gray = ContextCompat.getColor(this, R.color.text_secondary)
        val disabledColor = ContextCompat.getColor(this, R.color.text_disabled)

        val focusedColor: Int
        val unfocusedColor: Int

        if (!isEnabled) {
            focusedColor = disabledColor
            unfocusedColor = disabledColor
        } else if (editText.id == R.id.inputUrl) {
            focusedColor = getUrlCurrentColor()
            unfocusedColor = if (focusedColor == purple) gray else focusedColor
        } else {
            focusedColor = purple
            unfocusedColor = gray
        }

        if (animate) {

            if (isEnabled) layout.isEnabled = true
            animateFieldColor(layout, editText, focusedColor, unfocusedColor)
        } else {
            layout.isEnabled = isEnabled
            syncFieldColorDirect(layout, editText, focusedColor, unfocusedColor)
        }
    }

    // Apply the field colors immediately, no animation
    private fun syncFieldColorDirect(layout: TextInputLayout, editText: EditText, color: Int, unfocusedColor: Int) {
        val disabledColor = ContextCompat.getColor(this, R.color.text_disabled)
        val colorList = android.content.res.ColorStateList(
            arrayOf(
                intArrayOf(-android.R.attr.state_enabled),
                intArrayOf(android.R.attr.state_focused),
                intArrayOf()
            ),
            intArrayOf(disabledColor, color, unfocusedColor)
        )

        layout.setBoxStrokeColorStateList(colorList)
        layout.hintTextColor = colorList
        layout.defaultHintTextColor = colorList

        if (Build.VERSION.SDK_INT >= 29) {
            layout.setCursorColor(android.content.res.ColorStateList.valueOf(color))
        }

        updateTextViewHandlesColor(editText, if (editText.isEnabled) color else disabledColor)
        editText.setTextColor(targetEditTextColor(editText))

        fieldColorMap[layout.id] = color
        fieldUnfocusedColorMap[layout.id] = unfocusedColor
    }

    private fun targetEditTextColor(editText: EditText): Int {
        val attr = if (editText.isEnabled) R.color.text_primary else R.color.text_disabled
        return ContextCompat.getColor(this, attr)
    }

    // Crossfade the field colors (stroke / hint / cursor / text)
    private fun animateFieldColor(layout: TextInputLayout, editText: EditText, targetColor: Int, targetUnfocusedColor: Int) {
        val layoutId = layout.id
        val startColor = fieldColorMap[layoutId] ?: layout.boxStrokeColor
        val startUnfocusedColor = fieldUnfocusedColorMap[layoutId] ?: ContextCompat.getColor(this, R.color.text_secondary)
        val startTextColor = editText.currentTextColor
        val targetTextColor = targetEditTextColor(editText)

        if (startColor == targetColor &&
            startUnfocusedColor == targetUnfocusedColor &&
            startTextColor == targetTextColor) {
            if (!editText.isEnabled) layout.isEnabled = false
            updateTextViewHandlesColor(editText, if (editText.isEnabled) targetColor else ContextCompat.getColor(this, R.color.text_disabled))
            return
        }

        val mode = animMode()
        if (mode == ANIM_MODE_OFF) {
            fieldAnimatorMap[layoutId]?.cancel()
            syncFieldColorDirect(layout, editText, targetColor, targetUnfocusedColor)
            if (!editText.isEnabled) layout.isEnabled = false
            return
        }

        val animDuration = if (mode == ANIM_MODE_SYSTEM) {
            resources.getInteger(android.R.integer.config_shortAnimTime).toLong()
        } else {
            resources.getInteger(R.integer.duration_standard_transition).toLong()
        }

        fieldAnimatorMap[layoutId]?.cancel()
        val argb = android.animation.ArgbEvaluator()
        val animator = android.animation.ValueAnimator.ofFloat(0f, 1f).apply {
            duration = animDuration
            addUpdateListener { anim ->
                val fraction = anim.animatedFraction
                val color = argb.evaluate(fraction, startColor, targetColor) as Int
                val unfocused = argb.evaluate(fraction, startUnfocusedColor, targetUnfocusedColor) as Int
                val textColor = argb.evaluate(fraction, startTextColor, targetTextColor) as Int

                val disabledColor = ContextCompat.getColor(this@MainActivity, R.color.text_disabled)
                val colorList = android.content.res.ColorStateList(
                    arrayOf(
                        intArrayOf(-android.R.attr.state_enabled),
                        intArrayOf(android.R.attr.state_focused),
                        intArrayOf()
                    ),
                    intArrayOf(disabledColor, color, unfocused)
                )
                layout.setBoxStrokeColorStateList(colorList)
                layout.hintTextColor = colorList
                layout.defaultHintTextColor = colorList

                if (Build.VERSION.SDK_INT >= 29) {
                    layout.setCursorColor(android.content.res.ColorStateList.valueOf(color))
                }
                updateTextViewHandlesColor(editText, if (editText.isEnabled) color else disabledColor)
                editText.setTextColor(textColor)
                fieldColorMap[layoutId] = color
                fieldUnfocusedColorMap[layoutId] = unfocused
            }
            addListener(object : android.animation.AnimatorListenerAdapter() {
                override fun onAnimationEnd(animation: android.animation.Animator) {

                    if (!editText.isEnabled) layout.isEnabled = false
                }
            })
        }
        fieldAnimatorMap[layoutId] = animator
        animator.start()
    }

    // Tint the text-selection handles and highlight
    private fun updateTextViewHandlesColor(view: TextView, color: Int) {
        if (color == 0) return

        val alpha = 115 // ~45% opacity
        val highlightColor = Color.argb(
            alpha,
            Color.red(color),
            Color.green(color),
            Color.blue(color)
        )

        view.highlightColor = highlightColor

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val colorStateList = android.content.res.ColorStateList.valueOf(color)
            try {
                if (view is EditText) {
                    view.textCursorDrawable?.mutate()?.setTintList(colorStateList)
                }
                view.textSelectHandle?.mutate()?.setTintList(colorStateList)
                view.textSelectHandleLeft?.mutate()?.setTintList(colorStateList)
                view.textSelectHandleRight?.mutate()?.setTintList(colorStateList)
            } catch (e: Exception) {}
        }
    }
}
