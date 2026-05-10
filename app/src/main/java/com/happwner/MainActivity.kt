package com.happwner

import android.content.*
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.text.Html
import android.text.InputFilter
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
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.switchmaterial.SwitchMaterial
import com.google.android.material.textfield.TextInputLayout
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

class MainActivity : AppCompatActivity() {

    private lateinit var prefs: SharedPreferences
    private lateinit var capturedUrlsContainer: LinearLayout
    private lateinit var inputUrl: EditText
    private lateinit var inputHwid: EditText
    private lateinit var inputUserAgent: EditText
    private lateinit var hwidHint: TextView
    private lateinit var emptyHistoryText: TextView
    private lateinit var mainContainer: ViewGroup
    private lateinit var statusText: TextView
    private lateinit var historyHeader: View
    private lateinit var historyContent: View
    private lateinit var btnExpandHistory: ImageView
    private lateinit var btnExpandOutput: ImageView
    private lateinit var islandIntercept: View
    private lateinit var switchInterceptLinks: SwitchMaterial
    private lateinit var switchInterceptHwid: SwitchMaterial
    private lateinit var layoutHwid: TextInputLayout
    private lateinit var layoutUrl: TextInputLayout
    private lateinit var urlErrorText: TextView
    private lateinit var output: TextView
    private lateinit var btnGetSub: Button
    
    private var fullResponseText: String = ""
    private val MAX_DISPLAY_CHARS by lazy { resources.getInteger(R.integer.max_display_chars) }

    private val fastTransition by lazy {
        TransitionSet().apply {
            addTransition(ChangeBounds())
            addTransition(Fade())
            ordering = TransitionSet.ORDERING_TOGETHER
            duration = resources.getInteger(R.integer.duration_fast_transition).toLong()
        }
    }

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                "${packageName}.ID_CAPTURED" -> {
                    val originalId = intent.getStringExtra("original_id")
                    if (originalId != null) {
                        val safePrefs = getSafePrefs(context!!)
                        safePrefs.edit().putString("captured_id", originalId).apply()
                        updateHwidDisplay(originalId)
                    }
                }
                "${packageName}.URL_CAPTURED" -> {
                    val url = intent.getStringExtra("url")
                    if (url != null) {
                        runOnUiThread {
                            TransitionManager.beginDelayedTransition(mainContainer, fastTransition)
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSafePrefs(this)
        val themeMode = prefs.getInt("theme_mode", 0)
        AppCompatDelegate.setDefaultNightMode(when(themeMode) {
            1 -> AppCompatDelegate.MODE_NIGHT_NO
            2 -> AppCompatDelegate.MODE_NIGHT_YES
            else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        })

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

        setContentView(R.layout.activity_main)

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)

        mainContainer = findViewById(R.id.mainContainer)
        val statusBarBackground = findViewById<View>(R.id.statusBarBackground)

        ViewCompat.setOnApplyWindowInsetsListener(window.decorView) { _, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            val imeInsets = insets.getInsets(WindowInsetsCompat.Type.ime())
            val imeVisible = insets.isVisible(WindowInsetsCompat.Type.ime())
            
            statusBarBackground.layoutParams.height = systemBars.top
            statusBarBackground.requestLayout()
            
            val scrollView = findViewById<ScrollView>(R.id.mainScrollView)
            val bottomPadding = kotlin.math.max(systemBars.bottom, imeInsets.bottom)
            
            if (scrollView.paddingBottom != bottomPadding) {
                val root = findViewById<ViewGroup>(R.id.rootLayout)
                TransitionManager.beginDelayedTransition(root, TransitionSet().apply {
                    addTransition(ChangeBounds())
                    duration = resources.getInteger(R.integer.duration_standard_transition).toLong()
                })
                scrollView.setPadding(0, 0, 0, bottomPadding)
                
                if (imeVisible) {
                    currentFocus?.let { focused ->
                        scrollView.post {
                            val rect = android.graphics.Rect()
                            focused.getDrawingRect(rect)
                            scrollView.offsetDescendantRectToMyCoords(focused, rect)
                            val offset = resources.getDimensionPixelSize(R.dimen.scroll_offset_ime)
                            
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

        inputUrl = findViewById(R.id.inputUrl)
        inputHwid = findViewById(R.id.inputHwid)
        inputUserAgent = findViewById(R.id.inputUserAgent)
        layoutHwid = findViewById(R.id.layoutHwid)
        layoutUrl = findViewById(R.id.layoutUrl)
        urlErrorText = findViewById(R.id.urlErrorText)
        output = findViewById(R.id.output)
        btnGetSub = findViewById(R.id.btnGetSub)
        val button = findViewById<Button>(R.id.btnGet)
        statusText = findViewById(R.id.statusText)
        btnExpandOutput = findViewById(R.id.btnExpandOutput)
        capturedUrlsContainer = findViewById(R.id.capturedUrlsContainer)
        btnExpandHistory = findViewById(R.id.btnExpandHistory)
        historyHeader = findViewById(R.id.historyHeader)
        historyContent = findViewById(R.id.historyContent)
        emptyHistoryText = findViewById(R.id.emptyHistoryText)
        hwidHint = findViewById(R.id.hwidHint)
        islandIntercept = findViewById(R.id.islandIntercept)
        switchInterceptLinks = findViewById(R.id.switchInterceptLinks)
        switchInterceptHwid = findViewById(R.id.switchInterceptHwid)
        
        val btnClearOutput = findViewById<ImageButton>(R.id.btnClearOutput)
        val btnCopyOutput = findViewById<ImageButton>(R.id.btnCopyOutput)
        val btnClearHistory = findViewById<ImageButton>(R.id.btnClearHistory)
        val infoUrl = findViewById<ImageButton>(R.id.infoUrl)
        val infoHwid = findViewById<ImageButton>(R.id.infoHwid)
        val infoUserAgent = findViewById<ImageButton>(R.id.infoUserAgent)
        val btnPasteUrlManual = findViewById<ImageButton>(R.id.btnPasteUrlManual)
        val btnEditHwidManual = findViewById<ImageButton>(R.id.btnEditHwidManual)
        val btnEditUaManual = findViewById<ImageButton>(R.id.btnEditUaManual)
        val outputHeader = findViewById<View>(R.id.outputHeader)

        findViewById<View>(R.id.action_settings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        // Set static HTML texts
        setHtmlText(findViewById<TextView>(R.id.labelInterceptLinks), R.string.label_intercept_links)
        setHtmlText(findViewById<TextView>(R.id.labelInterceptHwid), R.string.label_intercept_hwid)
        setHtmlText(findViewById<TextView>(R.id.labelCapturedUrls), R.string.label_captured_urls)
        setHtmlText(findViewById<TextView>(R.id.labelResultHeader), R.string.label_result)

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

        val rowInterceptLinks = findViewById<View>(R.id.rowInterceptLinks)
        val rowInterceptHwid = findViewById<View>(R.id.rowInterceptHwid)

        switchInterceptLinks.isChecked = prefs.getBoolean("intercept_enabled", false)
        val updateInterceptLinks = { checked: Boolean ->
            switchInterceptLinks.isChecked = checked
            prefs.edit().putBoolean("intercept_enabled", checked).apply()
            PrefsManager.broadcastSettings(this)
        }
        rowInterceptLinks.setOnClickListener { updateInterceptLinks(!switchInterceptLinks.isChecked) }

        switchInterceptHwid.isChecked = prefs.getBoolean("use_custom_hwid_substitution", false)
        val updateInterceptHwid = { checked: Boolean ->
            switchInterceptHwid.isChecked = checked
            prefs.edit().putBoolean("use_custom_hwid_substitution", checked).apply()
            fixSharedPrefs() // Устанавливаем права доступа для Xposed и рассылаем настройки
            if (checked && !inputHwid.isEnabled) {
                handleToggleHwidEdit(true)
            }
        }
        rowInterceptHwid.setOnClickListener { 
            updateInterceptHwid(!switchInterceptHwid.isChecked)
            fixSharedPrefs() // Принудительно обновляем права после каждого изменения
        }

        val blockEnterFilter = InputFilter { source, _, _, _, _, _ ->
            source.toString().replace("\n", "").replace("\r", "")
        }
        inputUrl.filters = arrayOf(blockEnterFilter)
        inputUserAgent.filters = arrayOf(blockEnterFilter)

        val inputs = listOf(inputUrl, inputHwid, inputUserAgent)
        inputs.forEach { input ->
            input.setOnEditorActionListener { v, actionId, event ->
                if (input == inputUrl) {
                    val text = inputUrl.text.toString().trim()
                    if (text.startsWith("http://127.0.0.1:8166")) {
                        parseAndApplyBridgeUrl(text)
                    }
                }
                val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
                imm.hideSoftInputFromWindow(v.windowToken, 0)
                v.clearFocus()
                true
            }
        }

        inputUrl.onFocusChangeListener = View.OnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) {
                val text = inputUrl.text.toString().trim()
                if (text.startsWith("http://127.0.0.1:8166")) {
                    parseAndApplyBridgeUrl(text)
                }
            }
        }

        inputHwid.addTextChangedListener(object : android.text.TextWatcher {
            override fun afterTextChanged(s: android.text.Editable?) {
                if (inputHwid.isEnabled) {
                    prefs.edit().putString("custom_hwid", s.toString()).apply()
                    fixSharedPrefs()
                }
            }
            override fun beforeTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
            override fun onTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
        })

        inputUserAgent.addTextChangedListener(object : android.text.TextWatcher {
            override fun afterTextChanged(s: android.text.Editable?) {
                if (inputUserAgent.isEnabled) {
                    prefs.edit().putString("custom_user_agent", s.toString()).apply()
                }
            }
            override fun beforeTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
            override fun onTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
        })

        historyHeader.setOnClickListener {
            currentFocus?.clearFocus()
            TransitionManager.beginDelayedTransition(mainContainer, fastTransition)
            if (historyContent.visibility == View.VISIBLE) {
                historyContent.visibility = View.GONE
                btnExpandHistory.setImageResource(R.drawable.ic_expand_more)
            } else {
                historyContent.visibility = View.VISIBLE
                btnExpandHistory.setImageResource(R.drawable.ic_expand_less)
            }
        }

        outputHeader.setOnClickListener {
            currentFocus?.clearFocus()
            TransitionManager.beginDelayedTransition(mainContainer, fastTransition)
            if (output.visibility == View.VISIBLE) {
                output.visibility = View.GONE
                btnExpandOutput.setImageResource(R.drawable.ic_expand_more)
            } else {
                output.visibility = View.VISIBLE
                btnExpandOutput.setImageResource(R.drawable.ic_expand_less)
            }
        }

        btnClearHistory.setOnClickListener {
            TransitionManager.beginDelayedTransition(mainContainer, fastTransition)
            prefs.edit().remove("url_history_list").apply()
            capturedUrlsContainer.removeAllViews()
            updateEmptyHistoryVisibility()
        }

        val savedUrl = prefs.getString("last_url", "")
        inputUrl.setText(savedUrl)

        inputUrl.addTextChangedListener(object : android.text.TextWatcher {
            private var lastLineCount = 1
            private var wasError = false

            override fun afterTextChanged(s: android.text.Editable?) {
                val rawText = s.toString().trim()
                val text = rawText
                prefs.edit().putString("last_url", text).apply()

                val currentLineCount = inputUrl.lineCount
                val errorMsg = when {
                    text.isEmpty() -> null
                    text.contains("happ://crypt") -> getString(R.string.error_unsupported_happ_link)
                    !text.startsWith("https://") && !text.startsWith("http://") -> getString(R.string.error_invalid_format)
                    else -> null
                }

                val hasError = errorMsg != null
                
                if (hasError != wasError || currentLineCount != lastLineCount) {
                    // Используем Fade для текста ошибки, но ChangeBounds для плавного расширения карточки
                    TransitionManager.beginDelayedTransition(findViewById(R.id.rootLayout), TransitionSet().apply {
                        addTransition(ChangeBounds().excludeTarget(inputUrl, true))
                        addTransition(Fade())
                        duration = resources.getInteger(R.integer.duration_standard_transition).toLong()
                    })
                }

                if (hasError) {
                    urlErrorText.text = errorMsg
                    urlErrorText.visibility = View.VISIBLE
                    val redColor = ContextCompat.getColor(this@MainActivity, R.color.error_red)
                    val redHighlight = ContextCompat.getColor(this@MainActivity, R.color.error_red_highlight)
                    val colorList = android.content.res.ColorStateList.valueOf(redColor)
                    layoutUrl.setBoxStrokeColor(redColor)
                    layoutUrl.hintTextColor = colorList
                    layoutUrl.defaultHintTextColor = colorList
                    if (android.os.Build.VERSION.SDK_INT >= 29) {
                        layoutUrl.setCursorColor(colorList)
                    }
                    inputUrl.highlightColor = redHighlight
                    inputUrl.isActivated = true
                } else {
                    urlErrorText.visibility = View.GONE
                    val purpleColor = ContextCompat.getColor(this@MainActivity, R.color.brand_purple_secondary)
                    val purpleHighlight = ContextCompat.getColor(this@MainActivity, R.color.brand_purple_secondary_highlight)
                    val purpleList = ContextCompat.getColorStateList(this@MainActivity, R.color.brand_purple_secondary_selector)
                    val hintList = ContextCompat.getColorStateList(this@MainActivity, R.color.text_input_hint_selector)
                    
                    layoutUrl.setBoxStrokeColorStateList(purpleList!!)
                    layoutUrl.hintTextColor = hintList
                    layoutUrl.defaultHintTextColor = hintList
                    if (android.os.Build.VERSION.SDK_INT >= 29) {
                        layoutUrl.setCursorColor(android.content.res.ColorStateList.valueOf(purpleColor))
                    }
                    inputUrl.highlightColor = purpleHighlight
                    inputUrl.isActivated = false
                }

                wasError = hasError
                lastLineCount = currentLineCount
            }
            override fun beforeTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
            override fun onTextChanged(s: CharSequence?, s1: Int, s2: Int, s3: Int) {}
        })

        btnCopyOutput.setOnClickListener {
            if (fullResponseText.isNotEmpty() && fullResponseText != getString(R.string.label_result_default) && fullResponseText != getString(R.string.msg_loading)) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("Happwner Result", fullResponseText)
                clipboard.setPrimaryClip(clip)
            }
        }

        btnClearOutput.setOnClickListener {
            TransitionManager.beginDelayedTransition(mainContainer, fastTransition)
            fullResponseText = ""
            setHtmlText(output, R.string.label_result_default)
            if (output.visibility == View.VISIBLE) {
                output.visibility = View.GONE
                btnExpandOutput.setImageResource(R.drawable.ic_expand_more)
            }
        }
        
        setHtmlText(output, R.string.label_result_default)

        btnGetSub.setOnClickListener {
            val urlString = inputUrl.text.toString().replace("\n", "").replace("\r", "").trim()
            val hwid = inputHwid.text.toString().trim()
            val userAgent = inputUserAgent.text.toString().replace("\n", "").replace("\r", "").trim()

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

            if (!prefs.getBoolean("bridge_enabled", false)) {
                val msg = getString(R.string.msg_bridge_service_enable)
                val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
                val textMsg = dialogView.findViewById<TextView>(R.id.dialogMessage)
                textMsg.text = fromHtml(msg)

                MaterialAlertDialogBuilder(this)
                    .setTitle(fromHtml(getString(R.string.setting_bridge_header)))
                    .setView(dialogView)
                    .setPositiveButton(fromHtml(getString(R.string.btn_ok))) { _, _ ->
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                            ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), resources.getInteger(R.integer.request_code_notifications))
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
                    .show()
            } else {
                copyAction()
            }
        }

        infoUrl.setOnClickListener { showInfoDialog(getString(R.string.info_url_title), getString(R.string.info_url_msg)) }
        infoHwid.setOnClickListener { showInfoDialog(getString(R.string.info_hwid_title), getString(R.string.info_hwid_msg)) }
        infoUserAgent.setOnClickListener { showInfoDialog(getString(R.string.info_ua_title), getString(R.string.info_ua_msg)) }

        button.setOnClickListener {
            currentFocus?.clearFocus()
            val urlString = inputUrl.text.toString().replace("\n", "").replace("\r", "")
            val hwid = inputHwid.text.toString()
            val userAgent = inputUserAgent.text.toString().replace("\n", "").replace("\r", "")

            if (urlString.isEmpty()) {
                Toast.makeText(this, getString(R.string.msg_enter_url), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            TransitionManager.beginDelayedTransition(mainContainer, fastTransition)
            if (output.visibility == View.GONE) {
                output.visibility = View.VISIBLE
                btnExpandOutput.setImageResource(R.drawable.ic_expand_less)
            }
            output.text = getString(R.string.msg_loading)
            fullResponseText = ""

            lifecycleScope.launch {
                val resp = makeRequest(urlString, hwid, userAgent)
                val processManual = prefs.getBoolean("process_manual", true)
                val converted = if (processManual) LinkConverter.convert(resp) else resp
                fullResponseText = converted

                if (converted.length > MAX_DISPLAY_CHARS) {
                    output.text = converted.take(MAX_DISPLAY_CHARS) + getString(R.string.msg_text_truncated)
                } else {
                    output.text = converted
                }
            }
        }

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

        if (prefs.getBoolean("bridge_enabled", false)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(Intent(this, SubscriptionService::class.java))
            } else {
                startService(Intent(this, SubscriptionService::class.java))
            }
        }
    }

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

    override fun onResume() {
        super.onResume()
        updateUiState() // Обновляем UI, так как LSPatch мог включиться автоматически
        
        // Bug 1: Проверка смены языка
        val prefs = getSafePrefs(this)
        val savedLang = prefs.getString("app_lang", "system") ?: "system"
        if (System.getProperty("happwner_current_lang") != null && 
            System.getProperty("happwner_current_lang") != savedLang) {
            System.setProperty("happwner_current_lang", savedLang)
            recreate()
            return
        }
        System.setProperty("happwner_current_lang", savedLang)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == resources.getInteger(R.integer.request_code_notifications)) {
            val prefs = getSafePrefs(this)
            prefs.edit().putBoolean("bridge_enabled", true).apply()
            
            val serviceIntent = Intent(this, SubscriptionService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(serviceIntent)
            } else {
                startService(serviceIntent)
            }
            
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
            } catch (e: Exception) {}
        }
    }

    private fun handlePasteUrl() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip
        if (clip != null && clip.itemCount > 0) {
            val pasteText = clip.getItemAt(0).text.toString().trim()
            if (pasteText.startsWith("http://127.0.0.1:8166")) {
                parseAndApplyBridgeUrl(pasteText)
            } else {
                inputUrl.setText(pasteText.replace("\n", "").replace("\r", ""))
            }
        } else {
            Toast.makeText(this, getString(R.string.msg_clipboard_empty), Toast.LENGTH_SHORT).show()
        }
    }

    private fun parseAndApplyBridgeUrl(bridgeUrl: String) {
        try {
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

    private fun handleToggleHwidEdit(enabled: Boolean) {
        val prefs = getSafePrefs(this)
        inputHwid.isEnabled = enabled
        layoutHwid.isEnabled = enabled
        prefs.edit().putBoolean("use_custom_hwid_input", enabled).apply()
        
        if (!enabled) {
            if (switchInterceptHwid.isChecked) {
                switchInterceptHwid.isChecked = false
                prefs.edit().putBoolean("use_custom_hwid_substitution", false).apply()
            }
            
            val captured = prefs.getString("captured_id", "")
            inputHwid.setText(captured)
            TransitionManager.beginDelayedTransition(mainContainer, fastTransition)
            updateHwidHintVisibility(captured)
        } else {
            val custom = prefs.getString("custom_hwid", "")
            if (custom != null && custom.isNotEmpty()) {
                inputHwid.setText(custom)
            }
            inputHwid.clearFocus()
        }
    }

    private fun handleToggleUaEdit(enabled: Boolean) {
        val prefs = getSafePrefs(this)
        inputUserAgent.isEnabled = enabled
        val layoutUa = inputUserAgent.parent.parent as? TextInputLayout
        layoutUa?.isEnabled = enabled
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
    }

    override fun onStart() {
        super.onStart()
        checkLSPatchStatus()
        updateUiState()
        loadUrlHistory()
    }

    override fun onStop() {
        super.onStop()
        val prefs = getSafePrefs(this)
        
        if (inputHwid.isEnabled) {
            val currentHwid = inputHwid.text.toString()
            val capturedHwid = prefs.getString("captured_id", "")
            if (currentHwid == capturedHwid || currentHwid.isEmpty()) {
                handleToggleHwidEdit(false)
            }
        }

        if (inputUserAgent.isEnabled) {
            val currentUa = inputUserAgent.text.toString()
            val defaultUa = getHappDefaultUa()
            if (currentUa == defaultUa || currentUa.isEmpty()) {
                handleToggleUaEdit(false)
            }
        }
    }

    private fun checkLSPatchStatus() {
        if (ModuleStatus.isModuleActive()) return

        val prefs = getSafePrefs(this)
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
            
            if (currentCrc == null) {
                Log.w("Happwner:LSP", "Removing $pkgName: App not found or CRC failed")
                iterator.remove()
                sigMap.remove(pkgName)
                changed = true
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

    private fun updateUiState() {
        val prefs = getSafePrefs(this)
        val lspatchMode = prefs.getBoolean("lspatch_mode", false)
        val moduleActive = ModuleStatus.isModuleActive()
        
        // В режиме LSPatch (без рута) модуль не видит сам себя, 
        // поэтому мы доверяем сохраненному статусу lspatch_mode
        val isFullActive = moduleActive || lspatchMode

        TransitionManager.beginDelayedTransition(mainContainer, fastTransition)

        if (isFullActive) {
            islandIntercept.visibility = View.VISIBLE
            statusText.visibility = View.VISIBLE
            if (lspatchMode && !moduleActive) {
                statusText.text = getString(R.string.label_lspatch_mode)
                statusText.setTextColor(ContextCompat.getColor(this, R.color.brand_purple_secondary))
            } else {
                statusText.visibility = View.GONE
            }
            
            findViewById<ImageButton>(R.id.btnEditHwidManual).setImageResource(R.drawable.ic_edit)
        } else {
            islandIntercept.visibility = View.GONE
            statusText.visibility = View.VISIBLE
            statusText.text = getString(R.string.label_xposed_inactive)
            statusText.setTextColor(ContextCompat.getColor(this, R.color.brand_purple_secondary))
            
            findViewById<ImageButton>(R.id.btnEditHwidManual).setImageResource(R.drawable.ic_paste)
        }

        val isSubstitutionEnabled = prefs.getBoolean("use_custom_hwid_substitution", false)
        switchInterceptHwid.isChecked = isSubstitutionEnabled

        val isInputEnabled = prefs.getBoolean("use_custom_hwid_input", false)
        inputHwid.isEnabled = if (isFullActive) isInputEnabled else true
        layoutHwid.isEnabled = inputHwid.isEnabled

        val displayId = if (isFullActive && !isInputEnabled) {
            prefs.getString("captured_id", "") ?: ""
        } else {
            prefs.getString("custom_hwid", "") ?: ""
        }

        val hwidSpacer = findViewById<View>(R.id.hwidSpacer)
        inputHwid.setText(displayId)
        
        if (displayId.isNotEmpty()) {
            hwidHint.visibility = View.GONE
            hwidSpacer.visibility = View.VISIBLE
        } else {
            updateHwidHintVisibility("")
        }

        val isUaInputEnabled = prefs.getBoolean("use_custom_ua_input", false)
        val layoutUa = inputUserAgent.parent.parent as? TextInputLayout
        inputUserAgent.isEnabled = isUaInputEnabled
        layoutUa?.isEnabled = isUaInputEnabled
        
        if (isUaInputEnabled) {
            inputUserAgent.setText(prefs.getString("custom_user_agent", getHappDefaultUa()))
        } else {
            inputUserAgent.setText(getHappDefaultUa())
        }
    }

    private fun updateHwidHintVisibility(id: String?) {
        val prefs = getSharedPreferences("happ_prefs", Context.MODE_PRIVATE)
        val lspatchMode = prefs.getBoolean("lspatch_mode", false)
        val moduleActive = ModuleStatus.isModuleActive()
        val isFullActive = moduleActive || lspatchMode
        val hwidSpacer = findViewById<View>(R.id.hwidSpacer)

        if (id.isNullOrEmpty() && isFullActive) {
            hwidHint.text = getString(R.string.label_hwid_unknown)
            hwidHint.visibility = View.VISIBLE
            hwidSpacer.visibility = View.GONE
        } else {
            hwidHint.visibility = View.GONE
            hwidSpacer.visibility = View.VISIBLE
        }
    }

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
            items.reversed().forEach { addUrlToUi(it, false) }
        }
        updateEmptyHistoryVisibility()
    }

    private fun addUrlToUi(url: String, addToHistory: Boolean = true) {
        val tv = TextView(this).apply {
            text = url
            val pV = resources.getDimensionPixelSize(R.dimen.padding_history_vertical)
            setPadding(0, pV, 0, pV)
            setTextColor(ContextCompat.getColor(context, R.color.brand_purple_secondary))
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
            emptyHistoryText.text = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                Html.fromHtml(msg, Html.FROM_HTML_MODE_LEGACY)
            } else {
                @Suppress("DEPRECATION")
                Html.fromHtml(msg)
            }
        } else {
            emptyHistoryText.visibility = View.GONE
        }
    }

    private fun getHappDefaultUa(): String {
        return try {
            val packageInfo = packageManager.getPackageInfo("com.happproxy", 0)
            "Happ/${packageInfo.versionName}"
        } catch (e: PackageManager.NameNotFoundException) {
            "Happ/1.0.0"
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

    private fun showInfoDialog(title: String, htmlMessage: String) {
        val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
        val textMsg = dialogView.findViewById<TextView>(R.id.dialogMessage)
        textMsg.text = fromHtml(htmlMessage)

        MaterialAlertDialogBuilder(this)
            .setTitle(fromHtml(title))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok))) { d, _ -> d.dismiss() }
            .show()
    }

    private fun updateHwidDisplay(id: String) {
        if (!inputHwid.isEnabled) {
            inputHwid.setText(id)
            hwidHint.visibility = View.GONE
            findViewById<View>(R.id.hwidSpacer).visibility = View.VISIBLE
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        try { unregisterReceiver(receiver) } catch (e: Exception) {}
    }

    private suspend fun makeRequest(url: String, hwid: String, ua: String): String = withContext(Dispatchers.IO) {
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
            if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            } else "Error: ${conn.responseCode}"
        } catch (e: Exception) { "Error: ${e.message}" }
        finally { conn?.disconnect() }
    }
}
