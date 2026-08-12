package com.happwner.ui

import android.content.*
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.text.Html
import android.text.InputFilter
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.TextPaint
import android.text.TextUtils
import android.text.style.ClickableSpan
import android.text.style.ForegroundColorSpan
import android.transition.ChangeBounds
import android.transition.Fade
import android.transition.TransitionSet
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.view.ViewTreeObserver
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
import androidx.core.text.PrecomputedTextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsAnimationCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.widget.TextViewCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.color.MaterialColors
import com.google.android.material.textfield.TextInputLayout
import com.happwner.R
import com.happwner.bridge.BridgeController
import com.happwner.bridge.SubscriptionService
import com.happwner.convert.IncyLinks
import com.happwner.convert.LinkConverter
import com.happwner.crypto.HappCrypto
import com.happwner.crypto.HappanionBridge
import com.happwner.crypto.IncyCrypto
import com.happwner.crypto.V2RayTunCrypto
import com.happwner.data.AppLocale
import com.happwner.data.ModuleIds
import com.happwner.data.PrefsManager
import com.happwner.data.SettingsProvider
import com.happwner.data.UrlHistory
import com.happwner.hook.ModuleStatus
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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

    // Windowed history: rows are drawn newest-first in pages, so a history of any size only ever
    // inflates the handful of TextViews near the top plus whatever the person has scrolled to.
    private val HISTORY_PAGE = 300
    private var historyNextOffset = -1L
    private var historyLoadingPage = false
    private var historyReachedEnd = false
    // URLs currently drawn, for view-level de-duplication when the toggle is off.
    private var shownHistoryUrls = HashSet<String>()

    // Which "show_duplicates" value the rows on screen were built with, so the listener below can
    // tell a real change from a rewrite of the same value.
    private var historyShowDuplicates = false

    // Reacts to "show_duplicates" being flipped, wherever it is flipped from.
    private val historyPrefsListener =
        SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key != "show_duplicates") return@OnSharedPreferenceChangeListener
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (getSafePrefs(this).getBoolean(PrefsManager.PREF_SHOW_DUPLICATES, false) != historyShowDuplicates) {
                    loadUrlHistory()
                }
            }
        }

    private var historyPrefsListenerRegistered = false
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
    private lateinit var outputWaitLabel: TextView
    private var outputExpanding = false
    private var blockOutputTouch = false
    private var outputExpandAborted = false
    private var expandJob: kotlinx.coroutines.Job? = null
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
            // The platform always hands one over; the parameter is nullable because the Java
            // signature is. Saying so once here is what lets the branches below use it plainly.
            if (context == null) return
            when (intent?.action) {
                ModuleIds.ACTION_ID_CAPTURED -> {
                    val originalId = intent.getStringExtra(SettingsProvider.EXTRA_ORIGINAL_ID)
                    if (originalId != null) {
                        val safePrefs = getSafePrefs(context)
                        safePrefs.edit().putString(PrefsManager.PREF_CAPTURED_ID, originalId).apply()
                        updateHwidDisplay(originalId)
                        PrefsManager.broadcastSettings(context)
                    }
                }
                ModuleIds.ACTION_URL_CAPTURED -> {
                    val url = intent.getStringExtra(SettingsProvider.EXTRA_URL)
                    if (!url.isNullOrEmpty()) {
                        runOnUiThread {
                            // Insert the one new row at the top rather than rebuilding the list:
                            // the URL is already in the broadcast and persisted, so only the view
                            prependCapturedUrl(url)
                        }
                    }
                }
                ModuleIds.ACTION_REFRESH_UI -> {
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
        super.attachBaseContext(AppLocale.wrap(newBase, setProcessDefault = true))
    }

    // Set up theme, window, every view and listener, then start the services
    override fun onCreate(savedInstanceState: Bundle?) {
        val safePrefs = getSafePrefs(this)
        val themeMode = safePrefs.getInt(PrefsManager.PREF_THEME_MODE, 0)
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && safePrefs.getBoolean(PrefsManager.PREF_MONET_ACCENT, false)) {
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
        outputWaitLabel = findViewById(R.id.outputWaitLabel)
        // Swallow touches on the result only while the wait label is shown, so the invisible text can't be selected
        output.setOnTouchListener { _, _ -> blockOutputTouch }
        (findViewById<View>(R.id.mainScrollView) as? NoAutoScrollView)?.let { sv ->
            sv.selectionView = output
            sv.onNearBottom = { maybeLoadMoreHistory() }
        }
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
            val isModuleActive = ModuleStatus.isModuleActive() || getSafePrefs(this).getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)
            if (isModuleActive) {
                handleToggleHwidEdit(!inputHwid.isEnabled)
            } else {
                handlePasteHwid()
            }
        }
        btnEditUaManual.setOnClickListener { showUaSelectDialog() }

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

                val isEncrypted = isCryptLinkWithPayload(text)
                val isAddLink = text.startsWith("happ://add/") || V2RayTunCrypto.isImportLink(text) || IncyLinks.isIncyLink(text)
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
                    prefs.edit().putString(PrefsManager.PREF_CUSTOM_HWID, text).apply()
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
                prefs.edit().putString("custom_user_agent", s.toString()).apply()
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
            outputExpandAborted = true
            expandJob?.cancel()
            output.animate().cancel()
            output.alpha = 1f
            hideWaitLabel()
            mainContainer.beginAdaptiveToggleTransition(output, R.id.hwidHint)
            if (output.visibility == View.VISIBLE) {
                output.visibility = View.GONE
                btnExpandOutput.setImageResource(R.drawable.ic_expand_more)
            } else {
                output.visibility = View.VISIBLE
                btnExpandOutput.setImageResource(R.drawable.ic_expand_less)
            }
            // Collapsing the result falls back to the stock scrollbar; expanding a large one restores the custom thumb
            applyOutputScrollbar()
        }

        // Clear the captured-URL history
        btnClearHistory.setOnClickListener {
            mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
            UrlHistory.clear(this)
            resetHistoryView()
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
            outputExpandAborted = true
            expandJob?.cancel()
            outputExpanding = false
            output.animate().cancel()
            output.alpha = 1f
            hideWaitLabel()
            setHtmlText(output, R.string.label_result_default)
            output.setTextIsSelectable(false)
            applyOutputScrollbar()
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

            if (urlString.startsWith("v2raytun://crypt")) {
                Toast.makeText(this, getString(R.string.error_decrypt_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (urlString.startsWith("incy://crypt")) {
                Toast.makeText(this, getString(R.string.error_decrypt_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (HappCrypto.extractEmbeddedHappLink(urlString) != null) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (V2RayTunCrypto.extractEmbeddedV2RayLink(urlString) != null) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (IncyLinks.extractEmbeddedIncyLink(urlString) != null) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (urlString.startsWith("happ://add/")) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (V2RayTunCrypto.isImportLink(urlString)) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (IncyLinks.isIncyLink(urlString)) {
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
                    prefs.edit().putBoolean(PrefsManager.PREF_BRIDGE_ENABLED, true).apply()
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        startForegroundService(Intent(this, SubscriptionService::class.java))
                    } else {
                        startService(Intent(this, SubscriptionService::class.java))
                    }
                    copyAction()
                }
            }

            // First time -> show the hint; otherwise enable if needed, then copy
            val bridgeEnabled = prefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)
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

            if (urlString.startsWith("v2raytun://crypt")) {
                Toast.makeText(this, getString(R.string.error_decrypt_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (urlString.startsWith("incy://crypt")) {
                Toast.makeText(this, getString(R.string.error_decrypt_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (HappCrypto.extractEmbeddedHappLink(urlString) != null) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (V2RayTunCrypto.extractEmbeddedV2RayLink(urlString) != null) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (IncyLinks.extractEmbeddedIncyLink(urlString) != null) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (urlString.startsWith("happ://add/")) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (V2RayTunCrypto.isImportLink(urlString)) {
                Toast.makeText(this, getString(R.string.error_convert_first), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (IncyLinks.isIncyLink(urlString)) {
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
            outputExpandAborted = true
            expandJob?.cancel()
            outputExpanding = false
            hideWaitLabel()

            output.crossfadeContent(onEnd = {
                if (gen != fetchGeneration) return@crossfadeContent
                loadingPhaseRunning = false
                val pending = pendingConfigText
                if (pending != null) {
                    pendingConfigText = null
                    output.crossfadeContent { showOutputText(pending) }
                }
            }) {
                output.visibility = View.VISIBLE
                btnExpandOutput.setImageResource(R.drawable.ic_expand_less)
                output.text = getString(R.string.msg_loading)
                output.setTextIsSelectable(false)
                applyOutputScrollbar()
            }

            // Off the main thread: fetch, decrypt, convert, then render with labels
            lifecycleScope.launch {
                val resp = makeRequest(urlString, hwid, userAgent)
                // Derived from process_mode_manual (with a one-time migration from the old
                // process_manual/process_xray_manual/ process_mihomo_manual flags) - see
                val flags = PrefsManager.conversionFlagsFor(prefs, PrefsManager.SCOPE_MANUAL)
                val jsonToUri = flags.jsonToUri
                val base64Result = flags.base64Result
                val xrayToSb = flags.xrayToSb
                val xrayToMihomo = flags.xrayToMihomo

                // Decryption and conversion are pure CPU work on a body that can run to megabytes.
                val decrypted = withContext(Dispatchers.Default) {
                    HappCrypto.process(urlString, resp.body, resp.headers)
                }

                var wasDecrypted = false
                val bodyToConvert: String = when (decrypted) {
                    is HappCrypto.Result.Success -> {
                        wasDecrypted = true
                        decrypted.plaintext
                    }
                    is HappCrypto.Result.Failed -> {
                        Toast.makeText(
                            this@MainActivity,
                            getString(R.string.toast_decrypt_failed, decrypted.keyName, decrypted.reason),
                            Toast.LENGTH_LONG
                        ).show()
                        decrypted.originalBody
                    }
                    HappCrypto.Result.NotEncrypted -> resp.body
                }

                val stats = withContext(Dispatchers.Default) {
                    try {
                        LinkConverter.convertWithStats(bodyToConvert, jsonToUri, base64Result, xrayToSb, xrayToMihomo)
                    } catch (e: Throwable) {
                        // Last-resort boundary: ordinary converter bugs are caught there as
                        // Exception and hostile input is refused by the depth gate, so reaching
                        Log.e("Happwner:Convert", "Conversion crashed (${e.javaClass.simpleName}): ${e.message}")
                        LinkConverter.ConversionStats(bodyToConvert, 0)
                    }
                }
                val converted = stats.text
                val xraySkipped = stats.xraySkipped

                // The user only sees the skipped-count label below; the reason for each drop goes to logcat only.
                // Both the mihomo and sing-box passes can populate this.
                if (stats.notes.isNotEmpty()) {
                    for (note in stats.notes) Log.d("Happwner:Convert", note)
                }

                val isTruncated = converted.length > MAX_DISPLAY_CHARS
                val accent = MaterialColors.getColor(
                    this@MainActivity, R.attr.happAccent,
                    ContextCompat.getColor(this@MainActivity, R.color.brand_purple_secondary)
                )

                // Build the optional '[Decrypted]' / skipped-count label prefix
                val prefix = SpannableStringBuilder()
                if (wasDecrypted) {
                    val label = getString(R.string.msg_decrypted)
                    val start = prefix.length
                    prefix.append(label)
                    prefix.setSpan(ForegroundColorSpan(accent), start, prefix.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                }
                if (xraySkipped > 0) {
                    if (prefix.isNotEmpty()) prefix.append("\n")
                    val plural =
                        if (stats.mihomo) R.plurals.msg_mihomo_skipped else R.plurals.msg_xray_skipped
                    val label = resources.getQuantityString(plural, xraySkipped, xraySkipped)
                    val start = prefix.length
                    prefix.append(label)
                    prefix.setSpan(ForegroundColorSpan(accent), start, prefix.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                }
                if (prefix.isNotEmpty()) prefix.append("\n\n")

                // Full result captured for the expand handler (shown via one setText on tap)
                val expandPrefix: CharSequence = SpannableStringBuilder(prefix)
                val expandBody: String = converted

                // Initial text: truncated body with a clickable "show full", or the full text if short enough
                val newText: CharSequence = if (isTruncated) {
                    val showFullSpan = object : ClickableSpan() {
                        override fun onClick(widget: View) {
                            if (gen != fetchGeneration) return
                            expandOutputToFull(expandPrefix, expandBody, gen)
                        }
                        override fun updateDrawState(ds: TextPaint) {
                            ds.color = accent
                            ds.isUnderlineText = true
                        }
                    }
                    SpannableStringBuilder(prefix)
                        .append(converted.take(MAX_DISPLAY_CHARS))
                        .append(getString(R.string.msg_text_truncated))
                        .apply {
                            val start = length
                            append(getString(R.string.msg_show_full))
                            setSpan(showFullSpan, start, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                        }
                } else {
                    SpannableStringBuilder(prefix).append(converted)
                }

                if (gen != fetchGeneration) return@launch
                fullResponseText = converted

                if (loadingPhaseRunning) {
                    pendingConfigText = newText
                } else {
                    output.crossfadeContent { showOutputText(newText) }
                }
            }
        }

        // Register for the module's ID / URL / refresh broadcasts
        val filter = IntentFilter().apply {
            addAction(ModuleIds.ACTION_ID_CAPTURED)
            addAction(ModuleIds.ACTION_URL_CAPTURED)
            addAction(ModuleIds.ACTION_REFRESH_UI)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(receiver, filter, RECEIVER_EXPORTED)
        } else {
            registerReceiver(receiver, filter)
        }

        // Auto-start the bridge service if it was left on
        if (prefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)) {
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
        if (link.isNullOrEmpty() ||
            !(HappCrypto.isOpenableHappLink(link) || V2RayTunCrypto.isCryptLink(link) ||
              V2RayTunCrypto.isImportLink(link) || IncyLinks.isIncyLink(link) ||
              IncyCrypto.isCryptLink(link))) return
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
        val savedLang = prefs.getString(PrefsManager.PREF_APP_LANG, "system") ?: "system"
        if (lastKnownLang != null && lastKnownLang != savedLang) {
            lastKnownLang = savedLang
            ThemeTransition.captureAndRecreate(this, 340L)
            return
        }
        lastKnownLang = savedLang

        val savedTheme = prefs.getInt(PrefsManager.PREF_THEME_MODE, 0)
        if (lastKnownTheme != null && lastKnownTheme != savedTheme) {
            lastKnownTheme = savedTheme
            ThemeTransition.captureAndRecreate(this, 430L)
            return
        }
        lastKnownTheme = savedTheme

        val savedMonet = prefs.getBoolean(PrefsManager.PREF_MONET_ACCENT, false)
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
        prefs.edit().putBoolean(PrefsManager.PREF_BRIDGE_ENABLED, true).apply()

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

    // Swap the field's action icon by URL type (paste / decrypt / unwrap / revert).
    private fun updateUrlActionIcon(text: String) {
        when {
            hasCryptPayload(text, "happ://crypt") -> {
                btnPasteUrlManual.setImageResource(R.drawable.ic_key)
                btnPasteUrlManual.setOnClickListener { handleDecryptUrl(text) }
            }
            hasCryptPayload(text, "v2raytun://crypt") -> {
                btnPasteUrlManual.setImageResource(R.drawable.ic_key)
                btnPasteUrlManual.setOnClickListener { handleDecryptV2RayTunUrl(text) }
            }
            hasCryptPayload(text, "incy://crypt") -> {
                btnPasteUrlManual.setImageResource(R.drawable.ic_key)
                btnPasteUrlManual.setOnClickListener { handleDecryptIncyUrl(text) }
            }
            text.startsWith("happ://add/") -> {
                btnPasteUrlManual.setImageResource(R.drawable.revert)
                btnPasteUrlManual.setOnClickListener { handleParseAddUrl(text) }
            }
            V2RayTunCrypto.isImportLink(text) -> {
                btnPasteUrlManual.setImageResource(R.drawable.revert)
                btnPasteUrlManual.setOnClickListener { handleParseImportUrl(text) }
            }
            IncyLinks.isIncyLink(text) -> {
                btnPasteUrlManual.setImageResource(R.drawable.revert)
                btnPasteUrlManual.setOnClickListener { handleParseIncyUrl(text) }
            }
            text.startsWith("http://127.0.0.1:8166") -> {
                btnPasteUrlManual.setImageResource(R.drawable.revert)
                btnPasteUrlManual.setOnClickListener { parseAndApplyBridgeUrl(text) }
            }
            HappCrypto.extractEmbeddedHappLink(text) != null -> {
                btnPasteUrlManual.setImageResource(R.drawable.revert)
                btnPasteUrlManual.setOnClickListener { handleUnwrapUrl(text) }
            }
            V2RayTunCrypto.extractEmbeddedV2RayLink(text) != null -> {
                btnPasteUrlManual.setImageResource(R.drawable.revert)
                btnPasteUrlManual.setOnClickListener { handleUnwrapV2RayUrl(text) }
            }
            IncyLinks.extractEmbeddedIncyLink(text) != null -> {
                btnPasteUrlManual.setImageResource(R.drawable.revert)
                btnPasteUrlManual.setOnClickListener { handleUnwrapIncyUrl(text) }
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
        val pasteText = if (clip != null && clip.itemCount > 0) clip.getItemAt(0).text?.toString() else null
        if (pasteText != null) {
            inputUrl.setText(pasteText.trim().replace("\n", "").replace("\r", ""))
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

    // Pull the bare v2raytun:// link out of an http carrier
    private fun handleUnwrapV2RayUrl(carrierUrl: String) {
        val bare = V2RayTunCrypto.extractEmbeddedV2RayLink(carrierUrl)
        if (bare != null) {
            inputUrl.setText(bare)
        }
    }

    // Pull the bare incy:// link out of an http carrier
    private fun handleUnwrapIncyUrl(carrierUrl: String) {
        val bare = IncyLinks.extractEmbeddedIncyLink(carrierUrl)
        if (bare != null) {
            inputUrl.setText(bare)
        }
    }

    // Strip v2raytun://import* down to the inner link
    private fun handleParseImportUrl(importUrl: String) {
        val bare = V2RayTunCrypto.stripImportPrefix(importUrl) ?: return
        mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
        inputUrl.setText(bare.replace("\n", "").replace("\r", ""))
    }

    // Strip incy://add/ or incy://import/ down to the inner link
    private fun handleParseIncyUrl(incyUrl: String) {
        val bare = IncyLinks.stripIncyPrefix(incyUrl) ?: return
        mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
        inputUrl.setText(bare.replace("\n", "").replace("\r", ""))
    }

    // Decrypt a happ://cryptN link off-thread, then show it (or the error)
    private fun handleDecryptUrl(cryptUrl: String) {
        lifecycleScope.launch {
            val forceHappanion = PrefsManager.getSafePrefs(this@MainActivity)
                .getBoolean(PrefsManager.PREF_FORCE_HAPPLIB, false)

            val finalResult: HappCrypto.HappLinkResult = if (forceHappanion) {
                // "Force Happanion" means the bundled keys are not consulted at all.
                val mode = HappCrypto.happLinkMode(cryptUrl)
                if (mode == null) {
                    HappCrypto.HappLinkResult.NotHappLink
                } else {
                    val viaHappanion = withContext(Dispatchers.IO) {
                        HappanionBridge.tryDecrypt(this@MainActivity, cryptUrl)
                    }
                    if (viaHappanion != null) {
                        HappCrypto.HappLinkResult.Decrypted(viaHappanion, mode)
                    } else {
                        HappCrypto.HappLinkResult.Error(
                            mode,
                            getString(R.string.error_happanion_unreachable)
                        )
                    }
                }
            } else {
                val builtIn = withContext(Dispatchers.IO) {
                    HappCrypto.decryptHappLink(cryptUrl)
                }
                // Happanion is consulted for one failure only: a crypt5 marker this build has no
                // key for.
                if (builtIn is HappCrypto.HappLinkResult.Error && builtIn.unknownCrypt5Marker) {
                    val viaHappanion = withContext(Dispatchers.IO) {
                        HappanionBridge.tryDecrypt(this@MainActivity, cryptUrl)
                    }
                    if (viaHappanion != null) {
                        HappCrypto.HappLinkResult.Decrypted(viaHappanion, builtIn.mode)
                    } else {
                        builtIn
                    }
                } else {
                    builtIn
                }
            }

            when (finalResult) {
                is HappCrypto.HappLinkResult.Decrypted -> {
                    mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
                    inputUrl.setText(finalResult.plaintext)
                }
                is HappCrypto.HappLinkResult.Error -> {
                    val safeDetail = TextUtils.htmlEncode("${finalResult.mode}: ${finalResult.reason}")
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

    // Hide the centered wait label and stop any of its animations
    private fun hideWaitLabel() {
        blockOutputTouch = false
        outputWaitLabel.animate().cancel()
        outputWaitLabel.alpha = 0f
        outputWaitLabel.visibility = View.GONE
    }

    // Expand to full text: fade the result out, swap text (keeping scroll, no jump), fade back in
    private fun expandOutputToFull(prefix: CharSequence, body: String, gen: Int) {
        if (outputExpanding) return
        outputExpanding = true
        outputExpandAborted = false

        // Label prefix (if any) + full body
        val fullText: CharSequence = if (prefix.isEmpty()) body else SpannableStringBuilder(prefix).append(body)
        val duration = resources.getInteger(R.integer.duration_standard_transition).toLong()
        val animate = !skipProgrammaticAnimations()

        // Swap text + restore scroll, then fade the full text in
        val swapAndReveal = {
            if (!outputExpandAborted && gen == fetchGeneration && output.visibility == View.VISIBLE) {
                val scrollView = findViewById<ScrollView>(R.id.mainScrollView)
                val keepY = scrollView?.scrollY ?: 0

                val hadFocusable = output.isFocusableInTouchMode
                output.isFocusableInTouchMode = false
                output.animate().cancel()
                try {
                    output.text = fullText
                } catch (_: Throwable) {
                }
                if (!output.isTextSelectable) {
                    output.setTextIsSelectable(true)
                }
                output.movementMethod = OutputLinkMovementMethod.getInstance()
                (output.text as? Spannable)?.let { android.text.Selection.removeSelection(it) }
                output.isFocusableInTouchMode = hadFocusable
                applyOutputScrollbar()

                if (scrollView != null) {
                    scrollView.viewTreeObserver.addOnPreDrawListener(object : ViewTreeObserver.OnPreDrawListener {
                        override fun onPreDraw(): Boolean {
                            scrollView.viewTreeObserver.removeOnPreDrawListener(this)
                            scrollView.scrollY = keepY
                            return true
                        }
                    })
                }

                if (animate) {
                    output.alpha = 0f
                    // The wait label fades out as the full text fades in; the full text is now interactive
                    blockOutputTouch = false
                    outputWaitLabel.animate().cancel()
                    outputWaitLabel.animate().alpha(0f).setDuration(duration).withLayer().withEndAction {
                        outputWaitLabel.visibility = View.GONE
                    }.start()
                    output.animate().alpha(1f).setDuration(duration).withLayer().withEndAction {
                        outputExpanding = false
                    }.start()
                } else {
                    output.alpha = 1f
                    hideWaitLabel()
                    outputExpanding = false
                }
            } else {
                output.alpha = 1f
                hideWaitLabel()
                outputExpanding = false
            }
        }

        // Start the fade-out immediately on tap; the heavy work runs under it
        var fadeDone = !animate
        var warmDone = false
        val proceed = { if (fadeDone && warmDone) swapAndReveal() }

        if (animate) {
            output.animate().cancel()
            outputWaitLabel.animate().cancel()
            // The wait label fades in over the visible result area as the truncated text fades out
            blockOutputTouch = true
            outputWaitLabel.alpha = 0f
            outputWaitLabel.visibility = View.VISIBLE
            outputWaitLabel.animate().alpha(1f).setDuration(duration).withLayer().start()
            output.animate().alpha(0f).setDuration(duration).withLayer().withEndAction {
                fadeDone = true
                proceed()
            }.start()
        } else {
            // No animations: show the wait label instantly while the heavy work runs
            output.animate().cancel()
            blockOutputTouch = true
            output.alpha = 0f
            outputWaitLabel.animate().cancel()
            outputWaitLabel.alpha = 1f
            outputWaitLabel.visibility = View.VISIBLE
        }

        expandJob?.cancel()
        expandJob = lifecycleScope.launch {
            // Warm the text-layout cache off the UI thread (helps setText where supported)
            withContext(Dispatchers.Default) {
                try {
                    val params = TextViewCompat.getTextMetricsParams(output)
                    PrecomputedTextCompat.create(fullText, params)
                } catch (_: Throwable) {
                }
            }
            if (gen != fetchGeneration) {
                outputExpanding = false
                return@launch
            }
            warmDone = true
            proceed()
        }
        // If the job is cancelled mid-warm (collapse/new fetch), never leave the flag stuck or label shown
        expandJob?.invokeOnCompletion { cause ->
            if (cause != null) output.post {
                outputExpanding = false
                hideWaitLabel()
            }
        }
    }

    // Show result text in the output view: visible, selectable, with link taps enabled
    private fun showOutputText(text: CharSequence) {
        output.visibility = View.VISIBLE
        btnExpandOutput.setImageResource(R.drawable.ic_expand_less)
        output.text = text
        if (!output.isTextSelectable) {
            output.setTextIsSelectable(true)
        }
        output.movementMethod = OutputLinkMovementMethod.getInstance()
        applyOutputScrollbar()
    }

    // Pick the scrollbar mode: custom thumb only for a large result that's expanded on screen, otherwise stock
    private fun applyOutputScrollbar() {
        val large = fullResponseText.length > MAX_DISPLAY_CHARS && output.visibility == View.VISIBLE
        (findViewById<View>(R.id.mainScrollView) as? NoAutoScrollView)?.setFastScrollActive(large)
    }

    // Decrypt a v2raytun://crypt link off-thread, then show it (or the error)
    private fun handleDecryptV2RayTunUrl(cryptUrl: String) {
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                V2RayTunCrypto.decryptCryptLink(cryptUrl)
            }
            when (result) {
                is V2RayTunCrypto.Result.Decrypted -> {
                    mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
                    inputUrl.setText(result.plaintext)
                }
                is V2RayTunCrypto.Result.Error -> {
                    val safeDetail = TextUtils.htmlEncode("v2raytun: ${result.reason}")
                    showInfoDialog(
                        getString(R.string.title_decryption_error),
                        safeDetail
                    )
                }
                V2RayTunCrypto.Result.NotCryptLink -> {
                    showInfoDialog(
                        getString(R.string.title_decryption_error),
                        getString(R.string.error_url_not_found)
                    )
                }
            }
        }
    }

    // Decrypt an incy://crypt1 link off-thread, then show it (or the error)
    private fun handleDecryptIncyUrl(cryptUrl: String) {
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                IncyCrypto.decryptCryptLink(cryptUrl)
            }
            when (result) {
                is IncyCrypto.Result.Decrypted -> {
                    mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
                    inputUrl.setText(result.plaintext)
                }
                is IncyCrypto.Result.Error -> {
                    val safeDetail = TextUtils.htmlEncode("incy: ${result.reason}")
                    showInfoDialog(
                        getString(R.string.title_decryption_error),
                        safeDetail
                    )
                }
                IncyCrypto.Result.NotCryptLink -> {
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
            ua?.let { inputUserAgent.setText(it) }
        } catch (e: Exception) {}
    }

    private fun handlePasteHwid() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip
        val pasteText = if (clip != null && clip.itemCount > 0) clip.getItemAt(0).text?.toString() else null
        if (pasteText != null) {
            inputHwid.setText(pasteText.replace("\n", "").replace("\r", ""))
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
        prefs.edit().putBoolean(PrefsManager.PREF_USE_CUSTOM_HWID_INPUT, enabled).apply()

        if (!enabled) {
            val captured = prefs.getString(PrefsManager.PREF_CAPTURED_ID, "") ?: ""
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
            val custom = prefs.getString(PrefsManager.PREF_CUSTOM_HWID, "") ?: ""
            if (custom.isNotEmpty()) {
                inputHwid.setText(custom)
            } else {
                val captured = prefs.getString(PrefsManager.PREF_CAPTURED_ID, "") ?: ""
                inputHwid.setText(captured)
            }
        }
        refreshFieldStyle(layoutHwid, inputHwid)
        PrefsManager.broadcastSettings(this)
    }

    // On start: reconcile LSPatch, reload history, refresh the UI
    override fun onStart() {
        super.onStart()
        checkLSPatchStatus()
        loadUrlHistory()
        updateUiState()
        if (!historyPrefsListenerRegistered) {
            try {
                getSafePrefs(this).registerOnSharedPreferenceChangeListener(historyPrefsListener)
                historyPrefsListenerRegistered = true
            } catch (_: Throwable) {}
        }
    }

    override fun onStop() {
        if (historyPrefsListenerRegistered) {
            try {
                getSafePrefs(this).unregisterOnSharedPreferenceChangeListener(historyPrefsListener)
            } catch (_: Throwable) {}
            historyPrefsListenerRegistered = false
        }
        super.onStop()
    }

    // Reconcile LSPatch apps (signatures / installed state) and toggle lspatch_mode
    private fun checkLSPatchStatus() {
        val prefs = getSafePrefs(this)

        if (ModuleStatus.isModuleActive()) {
            if (prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)) {
                Log.i("Happwner:LSP", "Xposed active, clearing lspatch_mode flag (lspatch_apps retained)")
                prefs.edit().putBoolean(PrefsManager.PREF_LSPATCH_MODE, false).apply()
            }
            return
        }

        val lspatchApps = prefs.getStringSet("lspatch_apps", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        val sigMapJson = prefs.getString(PrefsManager.PREF_LSPATCH_SIGNATURES, "{}") ?: "{}"
        val sigMap = try { org.json.JSONObject(sigMapJson) } catch (_: Throwable) { org.json.JSONObject() }

        Log.d("Happwner:LSP", "Checking status. Apps in list: ${lspatchApps.size}")

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
                .putString(PrefsManager.PREF_LSPATCH_SIGNATURES, sigMap.toString())
                .apply()
        }

        val hasValidApp = lspatchApps.isNotEmpty()
        val currentMode = prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)

        if (currentMode != hasValidApp) {
            Log.i("Happwner:LSP", "Toggling lspatch_mode: $currentMode -> $hasValidApp")
            prefs.edit().putBoolean(PrefsManager.PREF_LSPATCH_MODE, hasValidApp).apply()
        }
    }

    // Redraw the UI for the current mode (Xposed / LSPatch / plain)
    private fun updateUiState() {
        val prefs = getSafePrefs(this)
        val lspatchMode = prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)
        val moduleActive = ModuleStatus.isModuleActive()
        val isFullActive = moduleActive || lspatchMode

        mainContainer.beginDelayedTransitionIfEnabled(fastTransition)

        val isInterceptionEnabled = prefs.getBoolean(PrefsManager.PREF_INTERCEPT_ENABLED, false)
        islandIntercept.visibility = if (isInterceptionEnabled && isFullActive) View.VISIBLE else View.GONE

        findViewById<ImageButton>(R.id.btnEditHwidManual).setImageResource(
            if (isFullActive) R.drawable.ic_edit else R.drawable.ic_paste
        )

        val isInputEnabled = prefs.getBoolean(PrefsManager.PREF_USE_CUSTOM_HWID_INPUT, false)
        inputHwid.isEnabled = if (isFullActive) isInputEnabled else true

        val displayId = if (isFullActive && !isInputEnabled) {
            prefs.getString(PrefsManager.PREF_CAPTURED_ID, "") ?: ""
        } else {
            val custom = prefs.getString(PrefsManager.PREF_CUSTOM_HWID, "") ?: ""
            if (custom.isNotEmpty()) custom else prefs.getString(PrefsManager.PREF_CAPTURED_ID, "") ?: ""
        }

        if (inputHwid.text?.toString() != displayId && displayId.isNotEmpty()) {
            inputHwid.setText(displayId)
        }
        updateHwidHintVisibility(inputHwid.text?.toString())

        val targetUa = getCurrentUa()
        if (inputUserAgent.text.toString() != targetUa) {
            inputUserAgent.setText(targetUa)
        }

        refreshAllFieldsStyle(false)
    }

    // "HWID unknown" hint animation (manual height calc to avoid jitter under the IME)
    private fun updateHwidHintVisibility(id: String?) {
        if (hintAnimationSuppressed) return
        val prefs = getSafePrefs(this)
        val lspatchMode = prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)
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

    // Load the first (newest) page of history from scratch.
    // Clears the rows on screen and everything that describes them.
    private fun resetHistoryView() {
        capturedUrlsContainer.removeAllViews()
        shownHistoryUrls = HashSet()
        historyNextOffset = -1L
        historyReachedEnd = false
        historyLoadingPage = false
        historyShowDuplicates = getSafePrefs(this).getBoolean(PrefsManager.PREF_SHOW_DUPLICATES, false)
    }

    private fun loadUrlHistory() {
        resetHistoryView()

        val page = UrlHistory.readPage(this, HISTORY_PAGE, historyNextOffset)
        renderHistoryRows(page.entries)
        historyNextOffset = page.nextOffset
        historyReachedEnd = !page.hasMore

        updateEmptyHistoryVisibility()
        updateUiState()
    }

    // Pull the next older page in when the scroll nears the bottom. Called from
    // NoAutoScrollView.onScrollChanged, so it must stay cheap and re-entrant.
    fun maybeLoadMoreHistory() {
        if (historyLoadingPage || historyReachedEnd) return
        historyLoadingPage = true
        try {
            val page = UrlHistory.readPage(this, HISTORY_PAGE, historyNextOffset)
            renderHistoryRows(page.entries)
            historyNextOffset = page.nextOffset
            historyReachedEnd = !page.hasMore
        } finally {
            historyLoadingPage = false
        }
    }

    // De-duplication is a view concern now that storage keeps everything: skip a URL already on
    // screen while the toggle is off.
    private fun renderHistoryRows(rows: List<String>) {
        if (rows.isEmpty()) return
        // The set is kept up to date in both modes, so flipping the toggle and
        // reloading starts from a correct picture either way.
        for (url in rows) {
            val firstTime = shownHistoryUrls.add(url)
            if (!firstTime && !historyShowDuplicates) continue
            addUrlToUi(url)
        }
    }

    // Newest row on top, animated on its own. Keeps de-dup honest against what
    // is currently on screen.
    private fun prependCapturedUrl(url: String) {
        // add() first and unconditionally: writing it as !showDuplicates && !add(url) short-circuits the add
        // away whenever duplicates are shown, so the set stops tracking what is on screen.
        val firstTime = shownHistoryUrls.add(url)
        if (!firstTime && !historyShowDuplicates) return
        capturedUrlsContainer.beginDelayedTransitionIfEnabled(fastTransition)
        addUrlToUi(url, atTop = true)
        updateEmptyHistoryVisibility()
    }

    // One tappable history row that refills the URL field.
    private fun addUrlToUi(url: String, atTop: Boolean = false) {
        val tv = TextView(this).apply {
            text = url
            val pV = resources.getDimensionPixelSize(R.dimen.padding_history_vertical)
            setPadding(0, pV, 0, pV)
            setTextColor(MaterialColors.getColor(
                this, R.attr.happAccent,
                ContextCompat.getColor(context, R.color.brand_purple_secondary)
            ))
            textSize = 14f

            // The ripple comes from the drawable below; a selectableItemBackground theme lookup used to sit here
            // and its result was never read - an attribute resolution per row, three hundred to a page.
            setBackgroundResource(R.drawable.bg_row_ripple)
            isClickable = true
            isFocusable = true

            setOnClickListener {
                inputUrl.setText(url)
            }
        }
        if (atTop) capturedUrlsContainer.addView(tv, 0) else capturedUrlsContainer.addView(tv)
        updateEmptyHistoryVisibility()
    }

    private fun updateEmptyHistoryVisibility() {
        // childCount, not the store: with duplicates hidden the store may hold entries that are all
        // collapsed away, and the label should reflect what is actually on screen.
        if (capturedUrlsContainer.childCount == 0) {
            emptyHistoryText.visibility = View.VISIBLE
            val msg = getString(R.string.label_history_empty)
            emptyHistoryText.text = fromHtml(msg)
        } else {
            emptyHistoryText.visibility = View.GONE
        }
    }

    // Compare version names numerically so 3.22.1 > 3.9.0; pulls digit groups, ignores the rest
    private fun compareVersionNames(a: String, b: String): Int {
        val rx = Regex("\\d+")
        val pa = rx.findAll(a).map { it.value.toLongOrNull() ?: 0L }.toList()
        val pb = rx.findAll(b).map { it.value.toLongOrNull() ?: 0L }.toList()
        for (i in 0 until maxOf(pa.size, pb.size)) {
            val x = pa.getOrElse(i) { 0L }
            val y = pb.getOrElse(i) { 0L }
            if (x != y) return x.compareTo(y)
        }
        return 0
    }

    // Build a preset UA "<brand>/<version>" from the newest installed package; else strings.xml default
    private fun buildPresetUa(defaultRes: Int, pkgs: Array<String>?): String {
        val default = getString(defaultRes)
        if (pkgs == null) return default
        var best: String? = null
        for (pkg in pkgs) {
            try {
                val v = packageManager.getPackageInfo(pkg, 0).versionName
                if (!v.isNullOrEmpty() && (best == null || compareVersionNames(v, best) > 0)) {
                    best = v
                }
            } catch (_: PackageManager.NameNotFoundException) {
            } catch (_: Throwable) {}
        }
        return if (best != null) default.substringBefore("/") + "/" + best else default
    }

    // The UA string for a given preset (version filled from the installed app when present)
    private fun uaForMode(mode: String): String = when (mode) {
        "v2raytun" -> getString(R.string.ua_default_v2raytun)
        "incy" -> buildPresetUa(R.string.ua_default_incy, arrayOf(PrefsManager.INCY_PKG))
        else -> buildPresetUa(R.string.ua_default_happ, arrayOf(PrefsManager.HAPP_PKG_PRIMARY, PrefsManager.HAPP_PKG_SECONDARY))
    }

    // UA to show on startup: whatever the user last had; empty by default (then UA is omitted)
    private fun getCurrentUa(): String {
        return getSafePrefs(this).getString("custom_user_agent", "") ?: ""
    }

    // Dialog to pick one of 3 preset User-Agents; the field stays editable for manual tweaks
    private fun showUaSelectDialog() {
        val current = inputUserAgent.text.toString().trim()
        val dialogView = layoutInflater.inflate(R.layout.dialog_select_option, null)
        val rg = dialogView.findViewById<android.widget.RadioGroup>(R.id.dialogRadioGroup)
        val r1 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption1)
        val r2 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption2)
        val r3 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption3)
        val happUa = uaForMode("happ")
        val v2rayUa = uaForMode("v2raytun")
        val incyUa = uaForMode("incy")
        r1.text = happUa
        r2.text = v2rayUa
        r3.text = incyUa
        when (current) {
            v2rayUa -> r2.isChecked = true
            incyUa -> r3.isChecked = true
            happUa -> r1.isChecked = true
        }
        val dialog = AnimatedDialogBuilder(this)
            .setTitle(getString(R.string.ua_select_title))
            .setView(dialogView)
            .showAnimated()
        rg.setOnCheckedChangeListener { _, checkedId ->
            val picked = when (checkedId) {
                R.id.radioOption2 -> v2rayUa
                R.id.radioOption3 -> incyUa
                else -> happUa
            }
            inputUserAgent.crossfadeText(picked) { refreshFieldStyle(layoutUserAgent, inputUserAgent) }
            try { dialog.dismiss() } catch (_: Throwable) {}
        }
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
                if (ua.isNotBlank()) setRequestProperty("User-Agent", ua)
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

    // A crypt link only counts as complete once it carries its payload slash: "happ://crypt5/..."
    // yes, bare "happ://crypt" or "happ://crypt5" no.
    private fun isCryptLinkWithPayload(text: String): Boolean =
        hasCryptPayload(text, "happ://crypt") ||
            hasCryptPayload(text, "v2raytun://crypt") ||
            hasCryptPayload(text, "incy://crypt")

    // Matches <prefix><optional scheme digits>/ - the slash is what makes it a real payload rather
    // than a half-typed link.
    private fun hasCryptPayload(text: String, prefix: String): Boolean {
        if (!text.regionMatches(0, prefix, 0, prefix.length, ignoreCase = true)) return false
        var i = prefix.length
        while (i < text.length && text[i].isDigit()) i++
        return i < text.length && text[i] == '/'
    }

    // Pick the URL field color by state (error / encrypted / normal)
    private fun getUrlCurrentColor(): Int {
        val text = inputUrl.text.toString().trim()
        val isCrypt = isCryptLinkWithPayload(text)
        val isAddLink = text.startsWith("happ://add/") || V2RayTunCrypto.isImportLink(text) || IncyLinks.isIncyLink(text)
        val hasError = !text.isEmpty() && !isCrypt && !isAddLink && !text.startsWith("http://") && !text.startsWith("https://")

        return when {
            hasError -> ContextCompat.getColor(this, R.color.error_red)
            isCrypt -> {
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
