package com.happwner.ui

import android.R as AndroidR
import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ArgbEvaluator
import android.animation.ValueAnimator
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Rect
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.InputFilter
import android.text.Selection
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.TextPaint
import android.text.TextWatcher
import android.text.style.ClickableSpan
import android.text.style.ForegroundColorSpan
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.core.text.PrecomputedTextCompat
import androidx.core.text.htmlEncode
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsAnimationCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isEmpty
import androidx.core.view.isVisible
import androidx.core.widget.TextViewCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.color.MaterialColors
import com.google.android.material.radiobutton.MaterialRadioButton
import com.google.android.material.textfield.TextInputLayout
import com.happwner.R
import com.happwner.bridge.BridgeController
import com.happwner.bridge.BridgeLink
import com.happwner.bridge.SubscriptionFetch
import com.happwner.client.CryptLinkResult
import com.happwner.client.HappCrypto
import com.happwner.client.HappLinks
import com.happwner.client.HappanionBridge
import com.happwner.client.IncyCrypto
import com.happwner.client.IncyLinks
import com.happwner.client.V2RayTunCrypto
import com.happwner.client.V2RayTunLinks
import com.happwner.convert.SubscriptionConverter
import com.happwner.data.ModuleIds
import com.happwner.data.ModuleStatus
import com.happwner.data.PrefsManager
import com.happwner.data.PublicSuffixList
import com.happwner.data.SettingsProvider
import com.happwner.data.UrlHistory
import java.net.URI
import kotlin.math.abs
import kotlin.math.max
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class MainActivity : ThemedActivity() {

	override val showsSplash = true
	private lateinit var prefs: SharedPreferences
	private var lastLayoutOrientation: Int = Configuration.ORIENTATION_UNDEFINED
	private var lastKnownLang: String? = null
	private var lastKnownTheme: Int? = null
	private var lastKnownMonet: Boolean? = null
	private var currentDialog: AlertDialog? = null
	private var currentDialogTag: String? = null
	private var currentDialogInfoTitle: String? = null
	private var currentDialogInfoMessage: String? = null
	private var currentImportLink: String? = null
	private var pendingImportLink: String? = null
	// The page the User-Agent picker shows, null for its presets - a recreate reopens it there.
	private var uaPage: String? = null
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

	private var historyNextOffset = -1L
	private var historyLoadingPage = false
	private var historyReachedEnd = false
	// URLs currently drawn, for view-level de-duplication when the toggle is off.
	private var shownHistoryUrls = HashSet<String>()

	// Which "show_duplicates" value the rows on screen were built with, so the listener below can
	// tell a real change from a rewrite of the same value.
	private var historyShowDuplicates = false

	// Rows put on top since the list was last drawn from the file.
	private var historyPrepends = 0

	// Reacts to settings being flipped elsewhere - the settings screen can be an in-place panel, so
	// onStart does not always fire to pick the change up.
	private val historyPrefsListener =
		SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
			when (key) {
				PrefsManager.PREF_SHOW_DUPLICATES -> runOnUiThread {
					if (isFinishing || isDestroyed) return@runOnUiThread
					if (PrefsManager.getSafePrefs(this).getBoolean(PrefsManager.PREF_SHOW_DUPLICATES,
						false) != historyShowDuplicates) {
						loadUrlHistory()
					}
				}
				// Turning HWID spoofing off sends the field back to its unhooked behaviour.
				PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION -> runOnUiThread {
					if (isFinishing || isDestroyed) return@runOnUiThread
					updateUiState()
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
	private val fieldAnimatorMap = mutableMapOf<Int, ValueAnimator>()
	private var hwidHintAnim: ValueAnimator? = null
	private var hwidHintAnimTarget: Boolean? = null
	private var hintAnimationSuppressed: Boolean = false
	private var pendingStartHeight: Int = -1
	private var pendingHintAnimAfterImeClose: Boolean = false

	private lateinit var output: TextView
	private lateinit var outputWaitLabel: TextView
	private lateinit var outputHeader: ViewGroup
	private lateinit var btnClearOutput: ImageButton
	private lateinit var btnCopyOutput: ImageButton
	private lateinit var btnSaveOutput: ImageButton
	private var outputExpanding = false
	private var blockOutputTouch = false
	private var outputExpandAborted = false
	private var expandJob: Job? = null
	private lateinit var btnGetSubscription: Button
	private lateinit var btnPasteUrlManual: ImageButton

	private var fullResponseText: String = ""
	// True only while the Result area actually displays a fetched response - not during
	// loading, and not while it shows the placeholder. Drives the button visibility.
	private var outputShowsResponse = false
	private var lastResponseWasError = false
	// Set while the placeholder swap after a Delete is still waiting for the collapse to finish,
	// so it can be applied early (on re-expand) or dropped (on a new fetch) instead of racing.
	private var pendingPlaceholderReset: Runnable? = null
	// Domain of the currently-shown result, captured at fetch time (not re-read from inputUrl later).
	private var lastFetchedDomain: String = ""
	// The file-name tail of the mode the shown result was converted in, kept with it: a change of
	// mode afterwards does not make it another result.
	private var lastResponseSuffix: String = ""

	// The settings pane closes through its own back callback, and the flag keeps a second close
	// from starting while the first is still animating.
	private var settingsBackCallback: OnBackPressedCallback? = null
	private var isClosingSettings = false
	private val MAX_DISPLAY_CHARS by lazy { resources.getInteger(R.integer.max_display_chars) }
	private val fetchTap = TapDebounce()
	private val getSubTap = TapDebounce()
	private val settingsTap = TapDebounce()
	private val saveTap = TapDebounce()
	private var fetchGeneration = 0
	private var loadingPhaseRunning = false
	private var pendingConfigText: CharSequence? = null

	// A person waits on this screen for the answer, so it gives up sooner than the bridge does.
	private val fetchTimeouts by lazy {
		val timeout = resources.getInteger(R.integer.network_timeout_ms)
		SubscriptionFetch.Timeouts(timeout, timeout)
	}

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
					val originalId = SettingsProvider.readUntrustedExtras {
						intent.getStringExtra(SettingsProvider.EXTRA_ORIGINAL_ID)
					}
					if (originalId != null && PrefsManager.isPlausibleId(originalId)) {
						val safePrefs = PrefsManager.getSafePrefs(context)
						safePrefs.edit { putString(PrefsManager.PREF_CAPTURED_ID, originalId) }
						updateHwidDisplay(originalId)
						PrefsManager.broadcastSettings(context)
					}
				}
				ModuleIds.ACTION_URL_CAPTURED -> {
					val url = intent.getStringExtra(SettingsProvider.EXTRA_URL)
					if (!url.isNullOrEmpty()) {
						runOnUiThread {
							// The URL is already in the broadcast and persisted: only the new row goes on top,
							// the list is not rebuilt.
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

	// Why the field's URL cannot be sent as it is (nothing typed, encrypted, wrapped or importable, or the bridge's
	// own address). Null when it can be sent.
	private fun unusableUrlReason(urlString: String): Int? = when {
		urlString.isEmpty() -> R.string.msg_enter_url
		urlString.startsWith("happ://crypt") || urlString.startsWith("v2raytun://crypt") ||
			urlString.startsWith("incy://crypt") -> R.string.error_decrypt_first
		// A link the bridge handed out, or an address that is the bridge: sending either one to it
		// is a loop through this phone, and neither is a subscription to convert.
		BridgeLink.matches(urlString) || BridgeLink.leadsHere(urlString) ->
			R.string.error_bridge_address
		HappLinks.extractEmbeddedHappLink(urlString) != null ||
			V2RayTunLinks.extractEmbeddedV2RayLink(urlString) != null ||
			IncyLinks.extractEmbeddedIncyLink(urlString) != null ||
			urlString.startsWith("happ://add/") ||
			V2RayTunLinks.isImportLink(urlString) ||
			IncyLinks.isIncyLink(urlString) -> R.string.error_convert_first
		else -> null
	}

	// Set up every view and listener, then start the services
	override fun onCreate(savedInstanceState: Bundle?) {
		super.onCreate(savedInstanceState)
		prefs = PrefsManager.getSafePrefs(this)
		// Turns "send every link to Happanion" off at once when Happanion is gone, not at the next link.
		PrefsManager.isForceHappanionEnabled(this)

		// Cold start vs recreate after a theme change, which decides the intro animation
		val wasInThemeTransition = ThemeTransition.pendingOverlay != null
		val isColdStart = savedInstanceState == null && !wasInThemeTransition
		ThemeTransition.preApplyBackground(this)
		setContentView(R.layout.activity_main)
		lastLayoutOrientation = resources.configuration.orientation
		ThemeTransition.consumeOverlay(this)

		if (isColdStart || wasInThemeTransition) {
			findViewById<View>(AndroidR.id.content)?.alpha = 1f
		} else {
			animateEntry()
		}

		val toolbar = findViewById<Toolbar>(R.id.toolbar)
		setSupportActionBar(toolbar)

		mainContainer = findViewById(R.id.mainContainer)
		val statusBarBackground = findViewById<View>(R.id.statusBarBackground)

		inputUrl = findViewById(R.id.inputUrl)
		inputHwid = findViewById(R.id.inputHwid)
		inputUserAgent = findViewById(R.id.inputUserAgent)
		layoutHwid = findViewById(R.id.layoutHwid)
		layoutUrl = findViewById(R.id.layoutUrl)
		layoutUserAgent = findViewById(R.id.layoutUserAgent)
		urlErrorText = findViewById(R.id.urlErrorText)
		output = findViewById(R.id.output)
		outputWaitLabel = findViewById(R.id.outputWaitLabel)
		(findViewById<View>(R.id.mainScrollView) as? NoAutoScrollView)?.let { scrollView ->
			scrollView.selectionView = output
			scrollView.onNearBottom = { maybeLoadMoreHistory() }
		}
		btnGetSubscription = findViewById(R.id.btnGetSubscription)
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

		// Registered once the views exist: the callback reads the fields above, and it first runs
		// on the next insets dispatch, after this method returns.
		applyWindowInsets(toolbar, statusBarBackground)

		btnClearOutput = findViewById(R.id.btnClearOutput)
		btnCopyOutput = findViewById(R.id.btnCopyOutput)
		btnSaveOutput = findViewById(R.id.btnSaveOutput)
		val infoUrl = findViewById<ImageButton>(R.id.infoUrl)
		val infoHwid = findViewById<ImageButton>(R.id.infoHwid)
		val infoUserAgent = findViewById<ImageButton>(R.id.infoUserAgent)
		val btnEditHwidManual = findViewById<ImageButton>(R.id.btnEditHwidManual)
		val btnEditUaManual = findViewById<ImageButton>(R.id.btnEditUaManual)
		outputHeader = findViewById(R.id.outputHeader)

		findViewById<View>(R.id.action_settings).setOnClickListener {
			openSettings()
		}

		findViewById<TextView>(R.id.labelResultHeader)?.setHtmlText(R.string.label_result)

		wireEditToggles(btnEditHwidManual, btnEditUaManual)
		wireFieldListeners()
		wireSectionToggles()
		wireOutputActions()
		wireGetSubscriptionButton()
		wireInfoButtons(infoUrl, infoHwid, infoUserAgent)

		wireFetchButton(button)
		registerModuleBroadcasts()
		BridgeController.refreshSurfaces(this)

		// Fresh start vs restore: settings fragment, intent, dialogs
		if (savedInstanceState == null) {
			preAttachSettingsFragment()
			handleViewIntent(intent)
			SwitchBack.remember(intent)
		} else {
			restoreSettingsStateIfNeeded()
			restoreMainDialogIfNeeded(savedInstanceState)
		}
	}

	// Insets for the system bars, plus auto-scroll to the focused field when the keyboard appears
	private fun applyWindowInsets(toolbar: Toolbar, statusBarBackground: View) {
		ViewCompat.setOnApplyWindowInsetsListener(window.decorView) { _, insets ->
			val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
			val imeInsets = insets.getInsets(WindowInsetsCompat.Type.ime())
			val imeVisible = insets.isVisible(WindowInsetsCompat.Type.ime())

			statusBarBackground.layoutParams.height = systemBars.top
			statusBarBackground.requestLayout()

			// Keep the backdrop's status bar strip the same height, so the two line up exactly.
			findViewById<View>(R.id.backdropStatusBar)?.let { backdrop ->
				backdrop.layoutParams.height = systemBars.top
				backdrop.requestLayout()
			}

			val scrollView = findViewById<ScrollView>(R.id.mainScrollView)
			val bottomPadding = max(systemBars.bottom, imeInsets.bottom)

			toolbar.setPadding(systemBars.left, toolbar.paddingTop, systemBars.right, toolbar.paddingBottom)

			if (scrollView.paddingBottom != bottomPadding ||
				scrollView.paddingLeft != systemBars.left ||
				scrollView.paddingRight != systemBars.right) {
				scrollView.setPadding(systemBars.left, 0, systemBars.right, bottomPadding)

				if (imeVisible) {
					currentFocus?.let { focused ->
						if (!focused.isDescendantOfView(scrollView)) return@let
						scrollView.post {
							val rect = Rect()
							focused.getDrawingRect(rect)
							scrollView.offsetDescendantRectToMyCoords(focused, rect)
							val density = resources.displayMetrics.density
							val offset = (resources.getInteger(
								R.integer.scroll_offset_ime_dp) * density).toInt()

							val targetScrollY = rect.bottom - (scrollView.height - bottomPadding) + offset
							if (targetScrollY > scrollView.scrollY) {
								scrollView.smoothScrollToIfEnabled(targetScrollY)
							}
						}
					}
				}
			}

			insets
		}

		ViewCompat.setWindowInsetsAnimationCallback(
			window.decorView,
			object : WindowInsetsAnimationCompat.Callback(
				WindowInsetsAnimationCompat.Callback.DISPATCH_MODE_STOP) {
				override fun onProgress(
					insets: WindowInsetsCompat,
					runningAnimations: MutableList<WindowInsetsAnimationCompat>
				): WindowInsetsCompat {
					try {
						val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
						val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
						val bottomPadding = max(systemBars.bottom, ime.bottom)
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
	}

	// Paste / edit-toggle buttons for the URL, HWID and UA fields. The fields' touch listener only
	// restyles them and lets the touch through.
	private fun wireEditToggles(btnEditHwidManual: ImageButton, btnEditUaManual: ImageButton) {
		btnPasteUrlManual.setOnClickListener { handlePasteUrl() }
		btnEditHwidManual.setOnClickListener {
			if (isHwidFieldHooked()) {
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
			input.setOnEditorActionListener { view, _, _ ->
				view.hideKeyboard()
				view.clearFocus()
				true
			}

			input.setOnTouchListener { _, _ ->
				val layout = when (input.id) {
					R.id.inputUrl -> layoutUrl
					R.id.inputHwid -> layoutHwid
					else -> layoutUserAgent
				}
				refreshFieldStyle(layout, input, animate = false)
				false
			}
		}

		refreshAllFieldsStyle()
	}

	// Keeps a field's scroll still while its height animates, then lets it and its layout settle.
	private fun holdScrollWhileResizing(field: LockableScrollEditText, layout: View, durationMs: Long) {
		field.acquireScrollLock()
		field.postDelayed({
			field.releaseScrollLock()
			field.requestLayout()
			layout.requestLayout()
		}, durationMs + SCROLL_UNLOCK_GRACE_MS)
	}

	// Text-change and focus listeners
	private fun wireFieldListeners() {
		inputUrl.addTextChangedListener(object : TextWatcher {
			private var lastLineCount = 1
			private var wasError = false
			private var wasEncrypted = false

			override fun afterTextChanged(editable: Editable?) {
				val text = editable.toString().trim()
				prefs.edit { putString(PrefsManager.PREF_LAST_URL, text) }
				updateUrlActionIcon(text)

				val (isEncrypted, hasError) = urlLook(text)
				val currentLineCount = inputUrl.lineCount

				if (hasError != wasError || isEncrypted != wasEncrypted ||
					currentLineCount != lastLineCount) {
					val transitionDurationMs = resources.getInteger(
						R.integer.duration_standard_transition).toLong()
					if (currentLineCount != lastLineCount) {
						holdScrollWhileResizing(inputUrl, layoutUrl, transitionDurationMs)
					}
					mainContainer.beginDelayedTransitionIfEnabled(
						buildBoundsFadeTransition(transitionDurationMs, excludeFadeTargetId = R.id.hwidHint))

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
			override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) {}
			override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) {}
		})

		inputHwid.addTextChangedListener(object : TextWatcher {
			override fun afterTextChanged(editable: Editable?) {
				val text = editable.toString()
				if (inputHwid.isEnabled) {
					prefs.edit { putString(PrefsManager.PREF_CUSTOM_HWID, text) }
					PrefsManager.broadcastSettings(this@MainActivity)
				}
				updateHwidHintVisibility(text)
			}
			override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) {}
			override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) {}
		})

		inputUserAgent.addTextChangedListener(object : TextWatcher {
			private var lastLineCount = 1

			override fun afterTextChanged(editable: Editable?) {
				prefs.edit { putString(PrefsManager.PREF_CUSTOM_USER_AGENT, editable.toString()) }
				val currentLineCount = inputUserAgent.lineCount
				if (currentLineCount != lastLineCount) {
					val transitionDurationMs = resources.getInteger(
						R.integer.duration_fast_transition).toLong()
					holdScrollWhileResizing(inputUserAgent, layoutUserAgent, transitionDurationMs)
					mainContainer.beginDelayedTransitionIfEnabled(
						buildBoundsFadeTransition(transitionDurationMs, excludeFadeTargetId = R.id.hwidHint))
					lastLineCount = currentLineCount
				}
			}
			override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) {}
			override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) {}
		})

		inputUrl.onFocusChangeListener = View.OnFocusChangeListener { _,
			_ -> refreshFieldStyle(layoutUrl, inputUrl) }
		inputHwid.onFocusChangeListener = View.OnFocusChangeListener { _,
			_ -> refreshFieldStyle(layoutHwid, inputHwid) }
		inputUserAgent.onFocusChangeListener = View.OnFocusChangeListener { _,
			_ -> refreshFieldStyle(layoutUserAgent, inputUserAgent) }
	}

	// Collapse / expand the history section
	private fun wireSectionToggles() {
		historyHeader.setOnClickListener {
			currentFocus?.clearFocus()
			mainContainer.beginAdaptiveToggleTransition(historyContent, R.id.hwidHint)
			if (historyContent.isVisible) {
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
			settleOutput()
			mainContainer.beginAdaptiveToggleTransition(output, R.id.hwidHint)
			if (output.isVisible) {
				output.visibility = View.GONE
				btnExpandOutput.setImageResource(R.drawable.ic_expand_more)
			} else {
				// A Delete may still be waiting out the collapse; apply it now so the deleted
				// response can't come back on screen when the area re-opens.
				if (pendingPlaceholderReset != null) applyPlaceholderReset()
				output.visibility = View.VISIBLE
				btnExpandOutput.setImageResource(R.drawable.ic_expand_less)
			}
			// Collapsing the result falls back to the stock scrollbar; expanding a large one
			// restores the custom thumb
			applyOutputScrollbar()
		}

		// Clear the captured-URL history, collapsing the section with it
		btnClearHistory.setOnClickListener {
			// Same transition the chevron uses, so clearing and collapsing animate as one move
			// instead of the generic fastTransition fighting the section's height change.
			mainContainer.beginAdaptiveToggleTransition(historyContent, R.id.hwidHint)
			UrlHistory.clear(this)
			resetHistoryView()
			updateEmptyHistoryVisibility()
			if (historyContent.isVisible) {
				historyContent.visibility = View.GONE
				btnExpandHistory.setImageResource(R.drawable.ic_expand_more)
			}
		}

		// Restore the last URL into the field
		val savedUrl = prefs.getString(PrefsManager.PREF_LAST_URL, "")
		inputUrl.setText(savedUrl)
		updateUrlActionIcon(savedUrl ?: "")
		refreshAllFieldsStyle()
	}

	// Copy / save / clear the output
	private fun wireOutputActions() {
		// Swallow touches on the result only while the wait label is shown, so the invisible text
		// can't be selected
		output.setOnTouchListener { _, _ -> blockOutputTouch }
		btnCopyOutput.setOnClickListener {
			if (fullResponseText.isNotEmpty() &&
				fullResponseText != getString(R.string.label_result_default) &&
					fullResponseText != getString(R.string.msg_loading)) {
				// The whole result goes to the clipboard in one binder call, and one too large
				// for it makes setPrimaryClip throw; then the file is the way to take it.
				try {
					copyToClipboard("Happwner Result", fullResponseText)
				} catch (_: Exception) {
					Toast.makeText(this, getString(R.string.error_copy_result_failed),
						Toast.LENGTH_LONG).show()
				}
			}
		}

		btnSaveOutput.setOnClickListener {
			if (!saveTap.accept()) return@setOnClickListener
			// The domain names the file when there is one to name it with; without it the file is
			// just the response and its mode.
			val named = if (lastFetchedDomain.isEmpty()) "" else "_$lastFetchedDomain"
			val fileName = getString(R.string.filename_result_template, named, lastResponseSuffix)
			try {
				saveOutputLauncher.launch(fileName)
			} catch (error: Throwable) {
				Log.e(LOG_SAVE, "No document picker available: ${error.message}")
				Toast.makeText(this, getString(R.string.error_save_failed), Toast.LENGTH_SHORT).show()
			}
		}

		btnClearOutput.setOnClickListener {
			mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
			fullResponseText = ""
			outputShowsResponse = false
			updateOutputButtonsVisibility()
			settleOutput()

			// The response stays on screen while the area collapses so the transition's Fade carries it out; swapping to the
			// placeholder first would fade the placeholder and make the text change look instant.
			val wasVisible = output.isVisible
			if (wasVisible) {
				output.visibility = View.GONE
				btnExpandOutput.setImageResource(R.drawable.ic_expand_more)
			}
			if (!wasVisible || skipProgrammaticAnimations()) {
				applyPlaceholderReset()
			} else {
				cancelPlaceholderReset()
				val reset = Runnable { applyPlaceholderReset() }
				pendingPlaceholderReset = reset
				output.postDelayed(
					reset,
					resources.getInteger(R.integer.duration_fast_transition).toLong()
				)
			}
		}

		output.setHtmlText(R.string.label_result_default)
		output.setTextIsSelectable(false)
		updateTextViewHandlesColor(output, MaterialColors.getColor(
			output, R.attr.happAccent,
			ContextCompat.getColor(this, R.color.brand_purple_secondary)
		))
	}

	// Stops what the result area is doing, so a collapse starts from a settled view.
	private fun settleOutput() {
		abortOutputExpansion()
		output.animate().cancel()
		output.alpha = 1f
		hideWaitLabel()
	}

	// The "Subscription" button, with the debounce a double tap needs
	private fun wireGetSubscriptionButton() {
		btnGetSubscription.setOnClickListener {
			if (!getSubTap.accept()) return@setOnClickListener
			copySubscriptionLink()
		}
	}

	// Copies the bridge URL for what the fields hold, enabling the bridge if needed.
	private fun copySubscriptionLink() {
		val (urlString, hwid, userAgent) = readFields()

		unusableUrlReason(urlString)?.let {
			Toast.makeText(this, getString(it), Toast.LENGTH_SHORT).show()
			return
		}

		if (urlErrorText.isVisible) {
			Toast.makeText(this, getString(R.string.error_invalid_link), Toast.LENGTH_SHORT).show()
			return
		}

		// The first time, what this is for comes before anything is copied; the dialog comes back
		// here when it is read.
		if (!prefs.getBoolean(PrefsManager.PREF_BRIDGE_HINT_SHOWN, false)) {
			showBridgeHintDialog()
			return
		}

		if (prefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)) {
			// The address handed out has to answer: an update leaves the preference on over a
			// dead service, and this brings it back before the address is copied.
			BridgeController.ensureServing(this)
			copyLinkAndSaySo(urlString, hwid, userAgent)
			return
		}

		bridgePermissions.enableBridge()
	}

	// Turns the bridge on and copies the link, once bridgePermissions has asked what it had to.
	private fun finishEnablingBridge() {
		BridgeController.enable(this)
		val (urlString, hwid, userAgent) = readFields()
		copyLinkAndSaySo(urlString, hwid, userAgent)
	}

	private fun wireInfoButtons(infoUrl: ImageButton, infoHwid: ImageButton, infoUserAgent: ImageButton) {
		infoUrl.setOnClickListener { showInfoDialog(getString(R.string.info_url_title),
			getString(R.string.info_url_msg)) }
		infoHwid.setOnClickListener { showInfoDialog(getString(R.string.info_hwid_title),
			getString(R.string.info_hwid_msg)) }
		infoUserAgent.setOnClickListener { showInfoDialog(getString(R.string.info_ua_title),
			getString(R.string.info_ua_msg)) }
	}

	private fun wireFetchButton(button: Button) {
		button.setOnClickListener {
			// Fetch button: pull the subscription directly, decrypt/convert, then show the result
			if (!fetchTap.accept()) return@setOnClickListener
			currentFocus?.clearFocus()
			val (urlString, hwid, userAgent) = readFields()

			unusableUrlReason(urlString)?.let {
				Toast.makeText(this, getString(it), Toast.LENGTH_SHORT).show()
				return@setOnClickListener
			}

			val gen = ++fetchGeneration
			pendingConfigText = null
			loadingPhaseRunning = true
			fullResponseText = ""
			outputShowsResponse = false
			cancelPlaceholderReset()
			lastFetchedDomain = extractDomainForFilename(urlString)
			updateOutputButtonsVisibility()
			abortOutputExpansion()
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
				// Held from when a body grows large until this coroutine is done with it, whichever
				// way it ends; see LargeTurn.
				val turn = SubscriptionFetch.LargeTurn()
				coroutineContext.job.invokeOnCompletion { turn.close() }
				val fetched = SubscriptionFetch.fetchHonouringSubUa(urlString, hwid, userAgent,
					PrefsManager.preferSubscriptionUa(prefs), fromNetwork = false, turn = turn,
					timeouts = fetchTimeouts)
				val resp = fetched.resp
				lastResponseWasError = resp.isError
				// Derived from process_mode_manual, with a one-time migration from the old
				// process_manual / process_xray_manual / process_mihomo_manual flags.
				val flags = PrefsManager.conversionFlagsFor(prefs, PrefsManager.SCOPE_MANUAL)
				val suffix = when (PrefsManager.resolveConversionMode(prefs, PrefsManager.SCOPE_MANUAL)) {
					PrefsManager.MODE_SINGBOX -> getString(R.string.filename_suffix_singbox)
					PrefsManager.MODE_MIHOMO -> getString(R.string.filename_suffix_mihomo)
					PrefsManager.MODE_URI -> getString(R.string.filename_suffix_uri)
					else -> ""
				}

				// The fetch above already decrypted the shown response off the main thread: decryption and conversion are
				// pure CPU work on a body that can run to megabytes.
				val decrypted = fetched.decrypted
				val wasDecrypted = decrypted is HappCrypto.Result.Success
				val bodyToConvert = HappCrypto.plaintextOf(decrypted, resp.body)
				if (decrypted is HappCrypto.Result.Failed) {
					Toast.makeText(
						this@MainActivity,
						getString(R.string.toast_decrypt_failed, decrypted.keyName, decrypted.reason),
						Toast.LENGTH_LONG
					).show()
				}

				val stats = withContext(Dispatchers.Default) {
					try {
						SubscriptionConverter.convertWithStats(bodyToConvert, flags)
					} catch (error: Throwable) {
						// Last-resort boundary: converter bugs are caught inside and the depth gate refuses hostile input;
						// the text is shown as it came.
						Log.e(LOG_CONVERT,
							"Conversion crashed (${error.javaClass.simpleName}): ${error.message}")
						SubscriptionConverter.ConversionResult(bodyToConvert, 0)
					}
				}
				val converted = stats.text

				// The user only sees the skipped-count label below; the reason for each drop goes
				// to logcat only. Any of the three passes can populate this.
				for (note in stats.notes) Log.d(LOG_CONVERT, note)

				val accent = MaterialColors.getColor(
					this@MainActivity, R.attr.happAccent,
					ContextCompat.getColor(this@MainActivity, R.color.brand_purple_secondary)
				)

				val prefix = resultLabels(wasDecrypted, stats, fetched.subUa, accent)

				val newText = measured(resultText(prefix, converted, gen, accent))

				if (gen != fetchGeneration) return@launch
				fullResponseText = converted
				lastResponseSuffix = suffix

				if (loadingPhaseRunning) {
					pendingConfigText = newText
				} else {
					output.crossfadeContent { showOutputText(newText) }
				}
			}
		}
	}

	// Labels above a fetched result, in the accent colour: decrypted, nodes left out, and the User-Agent sent
	// when the subscription named it. Empty when there is nothing to say.
	private fun resultLabels(
		wasDecrypted: Boolean,
		stats: SubscriptionConverter.ConversionResult,
		subUa: String?,
		accent: Int
	): SpannableStringBuilder {
		val prefix = SpannableStringBuilder()
		fun label(text: String) {
			if (prefix.isNotEmpty()) prefix.append("\n")
			val start = prefix.length
			prefix.append(text)
			prefix.setSpan(ForegroundColorSpan(accent), start, prefix.length,
				Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
		}
		if (wasDecrypted) label(getString(R.string.msg_decrypted))
		if (stats.xraySkipped > 0) {
			val plural = when {
				stats.mihomo -> R.plurals.msg_mihomo_skipped
				stats.uri -> R.plurals.msg_uri_skipped
				else -> R.plurals.msg_xray_skipped
			}
			label(resources.getQuantityString(plural, stats.xraySkipped, stats.xraySkipped))
		}
		subUa?.let { label(getString(R.string.msg_used_ua, it)) }
		if (prefix.isNotEmpty()) prefix.append("\n\n")
		return prefix
	}

	// The result as first shown: the whole text when it is short enough, otherwise its head with a
	// "show full" that expands it on tap - as long as no newer fetch has replaced this one.
	private fun resultText(
		prefix: SpannableStringBuilder,
		converted: String,
		gen: Int,
		accent: Int
	): CharSequence {
		if (converted.length <= MAX_DISPLAY_CHARS) return SpannableStringBuilder(prefix).append(converted)
		val expandPrefix: CharSequence = SpannableStringBuilder(prefix)
		val showFullSpan = object : ClickableSpan() {
			override fun onClick(widget: View) {
				if (gen != fetchGeneration) return
				expandOutputToFull(expandPrefix, converted, gen)
			}
			override fun updateDrawState(drawState: TextPaint) {
				drawState.color = accent
				drawState.isUnderlineText = true
			}
		}
		return SpannableStringBuilder(prefix)
			.append(converted.take(MAX_DISPLAY_CHARS))
			.append(getString(R.string.msg_text_truncated))
			.apply {
				val start = length
				append(getString(R.string.msg_show_full))
				setSpan(showFullSpan, start, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
			}
	}

	// Register for the module's ID / URL / refresh broadcasts
	private fun registerModuleBroadcasts() {
		// Only the captured-id action is open to other apps: the hook runs inside one. The others come from this app,
		// and left open would let any app plant a subscription in the list.
		ContextCompat.registerReceiver(this, receiver,
			IntentFilter(ModuleIds.ACTION_ID_CAPTURED), ContextCompat.RECEIVER_EXPORTED)
		ContextCompat.registerReceiver(this, receiver, IntentFilter().apply {
			addAction(ModuleIds.ACTION_URL_CAPTURED)
			addAction(ModuleIds.ACTION_REFRESH_UI)
		}, ContextCompat.RECEIVER_NOT_EXPORTED)
	}

	override fun onNewIntent(intent: Intent) {
		super.onNewIntent(intent)
		setIntent(intent)
		handleViewIntent(intent)
		SwitchBack.remember(intent)
	}

	// A link another app opens here (ACTION_VIEW), set aside for the import dialog when it is
	// one Happwner takes.
	private fun handleViewIntent(intent: Intent?) {
		if (intent == null || intent.action != Intent.ACTION_VIEW) return
		val link = intent.dataString?.trim()
		intent.data = null
		if (link.isNullOrEmpty() || link.length > MAX_IMPORT_LINK_CHARS ||
			!(HappLinks.isOpenableHappLink(link) || V2RayTunLinks.isCryptLink(link) ||
			  V2RayTunLinks.isImportLink(link) || IncyLinks.isIncyLink(link) ||
			  IncyLinks.isCryptLink(link))) return
		pendingImportLink = link
	}

	// Show the deferred import dialog once we're at least STARTED
	private fun showPendingImportLink() {
		val link = pendingImportLink ?: return
		pendingImportLink = null
		window.decorView.post {
			if (isFinishing || isDestroyed) return@post
			if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
				pendingImportLink = link
				return@post
			}
			try { currentDialog?.dismiss() } catch (_: Throwable) {}
			currentDialog = null
			currentDialogTag = null
			showImportConfirmDialog(link)
		}
	}

	// A second tap, or a second delivery of the same link, can arrive before the first dialog
	// covers the screen: the same dialog is not opened twice, and the one showing stays tracked.
	private fun alreadyShowing(tag: String): Boolean =
		currentDialogTag == tag && currentDialog?.isShowing == true

	// Asks before importing a link another app opened here
	private fun showImportConfirmDialog(link: String) {
		if (alreadyShowing(DIALOG_IMPORT_CONFIRM) && currentImportLink == link) return
		val message = getString(R.string.import_confirm_msg, link.htmlEncode())
		val dialogView = layoutInflater.infoView(message)

		val dlg = AnimatedDialogBuilder(this)
			.setTitle(fromHtml(getString(R.string.import_confirm_title)))
			.setView(dialogView)
			.setPositiveButton(fromHtml(getString(R.string.btn_yes))) { _, _ ->
				putLink(link)
			}
			.setNeutralButton(fromHtml(getString(R.string.btn_copy)), null)
			.setNegativeButton(fromHtml(getString(R.string.btn_no)), null)
			.showAnimated()

		// Own listener, so Copy leaves the dialog open; the button says so for a moment.
		dlg.getButton(DialogInterface.BUTTON_NEUTRAL)?.let { button ->
			val label = button.text
			button.setOnClickListener {
				try {
					copyToClipboard("Happwner link", link)
				} catch (_: Exception) {
					Toast.makeText(this, getString(R.string.error_copy_failed), Toast.LENGTH_SHORT).show()
					return@setOnClickListener
				}
				button.text = getString(R.string.btn_copied)
				button.postDelayed({ button.text = label }, 1000)
			}
		}

		currentImportLink = link
		track(dlg, DIALOG_IMPORT_CONFIRM) { currentImportLink = null }
	}

	// Re-open whichever dialog was showing before the recreate, or before a rotation
	private fun restoreMainDialogIfNeeded(savedInstanceState: Bundle, now: Boolean = false) {
		val tag = savedInstanceState.getString(STATE_OPEN_DIALOG_TAG) ?: return
		when (tag) {
			DIALOG_INFO -> {
				val title = savedInstanceState.getString(STATE_OPEN_DIALOG_TITLE) ?: return
				val message = savedInstanceState.getString(STATE_OPEN_DIALOG_MESSAGE) ?: return
				reopenDialog(now) { showInfoDialog(title, message) }
			}
			DIALOG_BRIDGE_HINT -> reopenDialog(
				now,
				stillWanted = { !prefs.getBoolean(PrefsManager.PREF_BRIDGE_HINT_SHOWN, false) }
			) { showBridgeHintDialog() }
			DIALOG_IMPORT_CONFIRM -> {
				val link = savedInstanceState.getString(STATE_IMPORT_LINK) ?: return
				reopenDialog(now) { showImportConfirmDialog(link) }
			}
			DIALOG_UA_SELECT -> reopenDialog(now) {
				showUaSelectDialog(savedInstanceState.getString(STATE_UA_PAGE))
			}
		}
	}

	// Closes the showing dialog and lets show put the restored one up, unless stillWanted says the moment has passed:
	// after a recreate once the window is up, after a rotation at once. A failure leaves nothing half-open.
	private fun reopenDialog(now: Boolean, stillWanted: () -> Boolean = { true }, show: () -> Unit) {
		val reopen = Runnable {
			if (isFinishing || isDestroyed) return@Runnable
			if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return@Runnable
			if (!stillWanted()) return@Runnable
			try { currentDialog?.dismiss() } catch (_: Throwable) {}
			currentDialog = null
			currentDialogTag = null
			try { show() } catch (_: Throwable) {}
		}
		if (now) reopen.run() else window.decorView.post(reopen)
	}

	override fun onSaveInstanceState(outState: Bundle) {
		super.onSaveInstanceState(outState)
		saveOpenDialog(outState)
	}

	// What restoreMainDialogIfNeeded needs to put the open dialog back as it was.
	private fun saveOpenDialog(outState: Bundle) {
		val tag = currentDialogTag ?: return
		outState.putString(STATE_OPEN_DIALOG_TAG, tag)
		when (tag) {
			DIALOG_INFO -> {
				currentDialogInfoTitle?.let { outState.putString(STATE_OPEN_DIALOG_TITLE, it) }
				currentDialogInfoMessage?.let { outState.putString(STATE_OPEN_DIALOG_MESSAGE, it) }
			}
			DIALOG_IMPORT_CONFIRM ->
				currentImportLink?.let { outState.putString(STATE_IMPORT_LINK, it) }
			DIALOG_UA_SELECT -> uaPage?.let { outState.putString(STATE_UA_PAGE, it) }
		}
	}

	// A preference the screen is built on (language, theme, accent) changed since last seen: remembered, and the screen
	// is recreated through a transition. True then, so the caller stops; the first sighting only remembers.
	private fun <T> recreateIfChanged(
		saved: T,
		lastKnown: T?,
		remember: (T) -> Unit,
		durationMs: Long
	): Boolean {
		remember(saved)
		if (lastKnown == null || lastKnown == saved) return false
		ThemeTransition.captureAndRecreate(this, durationMs)
		return true
	}

	// React to orientation / language / theme / Monet / anim-mode changes
	override fun onResume() {
		super.onResume()
		// Brings back a bridge left on but not answering, as after an update. Once per return: not
		// in onCreate, which this always follows, nor while the open settings pane does it.
		if (!isSettingsVisible()) BridgeController.ensureServing(this)
		val currentOrientation = resources.configuration.orientation
		if (lastLayoutOrientation != Configuration.ORIENTATION_UNDEFINED &&
			currentOrientation != lastLayoutOrientation) {
			lastLayoutOrientation = currentOrientation
			recreate()
			return
		}
		lastLayoutOrientation = currentOrientation
		updateUiState()

		val prefs = PrefsManager.getSafePrefs(this)
		val savedLang = prefs.getString(PrefsManager.PREF_APP_LANG, "system") ?: "system"
		if (recreateIfChanged(savedLang, lastKnownLang, { lastKnownLang = it }, 340L)) return
		val savedTheme = prefs.getInt(PrefsManager.PREF_THEME_MODE, 0)
		if (recreateIfChanged(savedTheme, lastKnownTheme, { lastKnownTheme = it }, THEME_RECREATE_MS)) return
		val savedMonet = prefs.getBoolean(PrefsManager.PREF_MONET_ACCENT, false)
		if (recreateIfChanged(savedMonet, lastKnownMonet, { lastKnownMonet = it }, THEME_RECREATE_MS)) return

		val savedAnimMode = animMode().toString()
		val previousAnimMode = System.setProperty("happwner_current_anim_mode", savedAnimMode)
		if (previousAnimMode != null && previousAnimMode != savedAnimMode) resetAnimatorScale(this)

		showPendingImportLink()
	}

	// Declared here rather than with the other fields: registerForActivityResult must run before
	// the activity starts, and the registration order is what the framework keys the results by.
	private val bridgePermissions =
		BridgeController.Permissions(this, { this }) { finishEnablingBridge() }

	// The copy and what the person sees of it. The address carries this subscription, device id and user agent,
	// and leads where the settings say: this phone, or its network address.
	private fun copyLinkAndSaySo(urlString: String, hwid: String, userAgent: String) {
		val lanMode = BridgeController.isLanModeOn(this)
		val address = BridgeLink.addressFor(lanMode)
		try {
			val link = BridgeLink.build(urlString, hwid, userAgent, address)
			copyToClipboard("Happwner Bridge URL", link)
		} catch (_: Exception) {
			Toast.makeText(this, getString(R.string.error_copy_failed), Toast.LENGTH_SHORT).show()
			return
		}
		// LAN mode with no network to name falls back to loopback, which reaches this phone only.
		if (lanMode && address == BridgeLink.addressFor(lanMode = false)) {
			Toast.makeText(this, getString(R.string.toast_lan_link_no_network),
				Toast.LENGTH_LONG).show()
		}
		btnGetSubscription.text = getString(R.string.btn_copied)
		btnGetSubscription.postDelayed({
			btnGetSubscription.text = getString(R.string.btn_get_subscription)
		}, 1000)
	}

	// What the three fields hold, as a request carries it. The URL and User-Agent fields keep line
	// breaks out through their own filter.
	private data class Fields(val url: String, val hwid: String, val userAgent: String)

	private fun readFields() = Fields(
		inputUrl.text.toString().trim(),
		inputHwid.text.toString().trim(),
		inputUserAgent.text.toString().trim()
	)

	private val clipboard: ClipboardManager
		get() = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

	// The text on the clipboard, or null once the person has been told there is none.
	private fun clipboardTextOrSaySo(): String? {
		val clip = clipboard.primaryClip?.takeIf { it.itemCount > 0 }
		val text = clip?.getItemAt(0)?.text?.toString()
		if (text == null) {
			Toast.makeText(this, getString(R.string.msg_clipboard_empty), Toast.LENGTH_SHORT).show()
		}
		return text
	}

	private fun copyToClipboard(label: String, text: String) {
		clipboard.setPrimaryClip(ClipData.newPlainText(label, text))
	}

	// Writes fullResponseText to the picked file; silent on cancel, a failed write is said, as a failed copy is.
	// Registered here, for the same reason as above.
	private val saveOutputLauncher = registerForActivityResult(
		ActivityResultContracts.CreateDocument("text/plain")
	) { uri ->
		if (uri == null) return@registerForActivityResult
		// SAF targets can be network-backed, so the write stays off the main thread. The payload is
		// captured up front: a later Clear must not empty it mid-write.
		val payload = fullResponseText
		lifecycleScope.launch {
			val written = withContext(Dispatchers.IO) {
				try {
					contentResolver.openOutputStream(uri)?.use {
						it.write(payload.toByteArray(Charsets.UTF_8))
						true
					} ?: false
				} catch (error: Throwable) {
					Log.e(LOG_SAVE, "Failed to write result to $uri", error)
					false
				}
			}
			// A silent failure looks exactly like a successful save, so say so.
			if (!written) Toast.makeText(this@MainActivity, getString(R.string.error_save_failed),
				Toast.LENGTH_SHORT).show()
		}
	}

	// Keep the recorded layout orientation in sync; an open dialog laid out for the old screen is put
	// back for the new one, and the screen glides into its new bounds, as the settings do.
	override fun onConfigurationChanged(newConfig: Configuration) {
		super.onConfigurationChanged(newConfig)
		if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
		lastLayoutOrientation = newConfig.orientation
		// Under the open settings pane the screen isn't seen, and the settings glide on their own.
		if (!isSettingsVisible() || isClosingSettings) {
			findViewById<ViewGroup>(R.id.rootLayout)?.beginResizeTransition {
				// The history glides as one piece, its rows - pages of HISTORY_PAGE - taking their new
				// width inside it; the scroll thumb is placed by measurements taken after the layout.
				excludeChildren(capturedUrlsContainer, true)
				excludeTarget(R.id.fastScrollThumb, true)
			}
		}
		// After the glide is begun: a dialog put back waits for that glide to end.
		reshowOpenDialog()
	}

	// Put back for the new screen, to take exactly the size a fresh one gets, morphing into it once the
	// screen has glided.
	private fun reshowOpenDialog() {
		val dialog = currentDialog ?: return
		val tag = currentDialogTag
		dialog.putBackForNewScreen {
			// A screen gone in the meantime puts nothing back: the open one stays, as it is.
			if (isFinishing || isDestroyed || !lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
				return@putBackForNewScreen null
			}
			val state = Bundle().also { saveOpenDialog(it) }
			currentDialog = null
			currentDialogTag = null
			showInPlace { restoreMainDialogIfNeeded(state, now = true) }
			val next = currentDialog
			// Nothing put back after all: the open one stays, tracked as it was.
			if (next == null) {
				currentDialog = dialog
				currentDialogTag = tag
			}
			next
		}
	}

	// The URL field's button does what the text in the field calls for: its icon is set together
	// with the action, so the two never disagree.
	private fun setPasteAction(icon: Int, label: Int, action: () -> Unit) {
		btnPasteUrlManual.setImageResource(icon)
		btnPasteUrlManual.contentDescription = getString(label)
		btnPasteUrlManual.setOnClickListener { action() }
	}

	// Swap the field's action - icon and handler - by URL type (paste / decrypt / unwrap).
	private fun updateUrlActionIcon(text: String) {
		when {
			hasCryptPayload(text, "happ://crypt") -> decryptAction { handleDecryptUrl(text) }
			hasCryptPayload(text, "v2raytun://crypt") ->
				decryptAction { handleDecryptCryptLink("v2raytun", text, V2RayTunCrypto::decryptCryptLink) }
			hasCryptPayload(text, "incy://crypt") ->
				decryptAction { handleDecryptCryptLink("incy", text, IncyCrypto::decryptCryptLink) }
			text.startsWith("happ://add/") -> unwrapAction { HappLinks.stripAddPrefix(text) }
			V2RayTunLinks.isImportLink(text) ->
				unwrapAction { V2RayTunLinks.stripImportPrefix(text) }
			IncyLinks.isIncyLink(text) -> unwrapAction { IncyLinks.stripIncyPrefix(text) }
			BridgeLink.matches(text) -> setPasteAction(R.drawable.revert, R.string.cd_fill_from_bridge) {
				parseAndApplyBridgeUrl(text)
			}
			HappLinks.extractEmbeddedHappLink(text) != null ->
				unwrapAction { HappLinks.extractEmbeddedHappLink(text) }
			V2RayTunLinks.extractEmbeddedV2RayLink(text) != null ->
				unwrapAction { V2RayTunLinks.extractEmbeddedV2RayLink(text) }
			IncyLinks.extractEmbeddedIncyLink(text) != null ->
				unwrapAction { IncyLinks.extractEmbeddedIncyLink(text) }
			else -> setPasteAction(R.drawable.ic_paste, R.string.cd_paste_link) { handlePasteUrl() }
		}
	}

	private fun decryptAction(decrypt: () -> Unit) =
		setPasteAction(R.drawable.ic_key, R.string.cd_decrypt_link, decrypt)

	// The link inside, worked out on the tap, goes into the field.
	private fun unwrapAction(inner: () -> String?) =
		setPasteAction(R.drawable.revert, R.string.cd_unwrap_link) { putLink(inner()) }

	private fun handlePasteUrl() {
		clipboardTextOrSaySo()?.let { putLink(it.trim()) }
	}

	// A decrypt can take seconds through Happanion; a field changed meanwhile makes it stale.
	private fun fieldStillHolds(link: String): Boolean =
		inputUrl.text.toString().trim() == link.trim()

	// Puts a link into the URL field. The field's own filter keeps line breaks out of it.
	private fun putLink(link: String?) {
		if (link == null) return
		mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
		inputUrl.setText(link)
	}

	// What a decrypt came to, whichever client's link it was.
	private sealed interface DecryptOutcome {
		class Plain(val link: String) : DecryptOutcome
		// note: a line shown under the reason - here, a word about Happanion.
		class Failed(val detail: String, val note: String? = null) : DecryptOutcome
		object NotALink : DecryptOutcome
	}

	// Runs a decrypt and shows what it came to: the link in the field, or why not. An answer that
	// arrives after the field changed is dropped.
	private fun decryptInto(link: String, decrypt: suspend () -> DecryptOutcome) {
		lifecycleScope.launch {
			val outcome = decrypt()
			if (!fieldStillHolds(link)) return@launch
			when (outcome) {
				is DecryptOutcome.Plain -> putLink(outcome.link)
				is DecryptOutcome.Failed -> showDecryptError(
					listOfNotNull(outcome.detail, outcome.note)
						.joinToString("<br/><br/>") { it.htmlEncode() }
				)
				DecryptOutcome.NotALink -> showDecryptError(getString(R.string.error_url_not_found))
			}
		}
	}

	private fun showDecryptError(htmlMessage: String) =
		showInfoDialog(getString(R.string.title_decryption_error), htmlMessage)

	private suspend fun viaHappanion(link: String): String? =
		withContext(Dispatchers.IO) { HappanionBridge.tryDecrypt(this@MainActivity, link) }

	// Decrypt a happ://cryptN link off-thread, then show it (or the error)
	private fun handleDecryptUrl(cryptUrl: String) = decryptInto(cryptUrl) {
		val forceHappanion = PrefsManager.isForceHappanionEnabled(this)
		val result: HappCrypto.HappLinkResult = if (forceHappanion) {
			// "Send every link": the built-in keys are not consulted at all.
			val mode = HappLinks.happLinkMode(cryptUrl)
			if (mode == null) {
				HappCrypto.HappLinkResult.NotHappLink
			} else {
				viaHappanion(cryptUrl)?.let { HappCrypto.HappLinkResult.Decrypted(it, mode) }
					?: HappCrypto.HappLinkResult.Error(
						mode, getString(R.string.error_happanion_unreachable))
			}
		} else {
			HappanionBridge.decryptWithFallback(
				cryptUrl, { withContext(Dispatchers.IO) { HappCrypto.decryptHappLink(it) } }, ::viaHappanion
			)
		}
		when (result) {
			is HappCrypto.HappLinkResult.Decrypted -> DecryptOutcome.Plain(result.plaintext)
			is HappCrypto.HappLinkResult.Error -> DecryptOutcome.Failed(
				"${result.mode}: ${result.reason}", happanionNote(forceHappanion)
			)
			HappCrypto.HappLinkResult.NotHappLink -> DecryptOutcome.NotALink
		}
	}

	// Says that Happanion failed too; not when forced, whose reason already names it.
	private fun happanionNote(forced: Boolean): String? =
		if (!forced && HappanionBridge.isCompatibleVersionInstalled(this)) {
			getString(R.string.msg_happanion_failed_too)
		} else {
			null
		}

	// Hide the centred wait label and stop any of its animations
	private fun hideWaitLabel() {
		blockOutputTouch = false
		outputWaitLabel.animate().cancel()
		outputWaitLabel.alpha = 0f
		outputWaitLabel.visibility = View.GONE
	}

	// Stops a running expansion of the result: the swap it queued is skipped, and the next tap on
	// "show full" may start one again.
	private fun abortOutputExpansion() {
		outputExpandAborted = true
		expandJob?.cancel()
		outputExpanding = false
	}

	// Puts the full text in the result without moving its scroll, selectable and with its links alive.
	private fun swapInOutputText(text: CharSequence) {
		val scrollView = findViewById<ScrollView>(R.id.mainScrollView)
		val keepY = scrollView?.scrollY ?: 0
		val hadFocusable = output.isFocusableInTouchMode
		output.isFocusableInTouchMode = false
		output.animate().cancel()
		runCatching { setOutputText(text) }
		if (!output.isTextSelectable) {
			output.setTextIsSelectable(true)
		}
		output.movementMethod = OutputLinkMovementMethod.getInstance()
		(output.text as? Spannable)?.let { Selection.removeSelection(it) }
		output.isFocusableInTouchMode = hadFocusable
		applyOutputScrollbar()
		scrollView?.onNextPreDraw { scrollView.scrollY = keepY }
	}

	// Ends an expansion with the result shown whole and the wait label gone.
	private fun endExpansion() {
		output.alpha = 1f
		hideWaitLabel()
		outputExpanding = false
	}

	// Expand to full text: fade the result out, swap text (keeping scroll, no jump), fade back in
	private fun expandOutputToFull(prefix: CharSequence, body: String, gen: Int) {
		if (outputExpanding) return
		outputExpanding = true
		outputExpandAborted = false

		val fullText: CharSequence = if (prefix.isEmpty()) body else SpannableStringBuilder(
			prefix).append(body)
		val duration = stateChangeDuration(R.integer.duration_standard_transition)
		val animate = !skipProgrammaticAnimations()
		// The text as laid out off the UI thread, for the swap to take as it is
		var shown = fullText

		// Swap the text in, then fade the full text in
		val swapAndReveal = {
			if (!outputExpandAborted && gen == fetchGeneration && output.isVisible) {
				swapInOutputText(shown)
				if (animate) {
					output.alpha = 0f
					// The wait label fades out as the full text fades in; the full text is now interactive
					blockOutputTouch = false
					outputWaitLabel.animate().cancel()
					outputWaitLabel.animate().alpha(0f).setDuration(duration).withLayer().withEndAction {
						outputWaitLabel.visibility = View.GONE
					}.start()
					output.animate().alpha(1f).setDuration(duration).withLayerIfFits(output).withEndAction {
						outputExpanding = false
					}.start()
				} else {
					endExpansion()
				}
			} else {
				endExpansion()
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
			outputWaitLabel.fadeIn(duration)
			output.animate().alpha(0f).setDuration(duration).withLayerIfFits(output).withEndAction {
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
			shown = measured(fullText)
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

	// Puts the placeholder back after a Delete. Safe to call early: it cancels its own
	// scheduled run, so the text lands exactly once however the collapse ends.
	private fun applyPlaceholderReset() {
		pendingPlaceholderReset?.let { output.removeCallbacks(it) }
		pendingPlaceholderReset = null
		output.setHtmlText(R.string.label_result_default)
		output.setTextIsSelectable(false)
		applyOutputScrollbar()
	}

	private fun cancelPlaceholderReset() {
		pendingPlaceholderReset?.let { output.removeCallbacks(it) }
		pendingPlaceholderReset = null
	}

	// The text laid out off the UI thread, so setting it there costs the animation no frames.
	private suspend fun measured(text: CharSequence): CharSequence {
		val params = TextViewCompat.getTextMetricsParams(output)
		return withContext(Dispatchers.Default) {
			try {
				PrecomputedTextCompat.create(text, params)
			} catch (_: Throwable) {
				text
			}
		}
	}

	// A measured text goes in as it is; one whose metrics no longer match the view's takes it as plain.
	private fun setOutputText(text: CharSequence) {
		val taken = text is PrecomputedTextCompat &&
			runCatching { TextViewCompat.setPrecomputedText(output, text) }.isSuccess
		if (!taken) output.text = text
	}

	private fun showOutputText(text: CharSequence) {
		output.visibility = View.VISIBLE
		btnExpandOutput.setImageResource(R.drawable.ic_expand_less)
		setOutputText(text)
		if (!output.isTextSelectable) {
			output.setTextIsSelectable(true)
		}
		output.movementMethod = OutputLinkMovementMethod.getInstance()
		applyOutputScrollbar()
		outputShowsResponse = true
		updateOutputButtonsVisibility()
	}

	// A direct alpha animation, not TransitionManager: the view stays VISIBLE while it fades, so a tap's ripple finishes,
	// and crossfadeContent re-measuring or an ancestor transition cannot disturb it.
	private fun fadeIconButton(btn: View, visible: Boolean) {
		val target = if (visible) View.VISIBLE else View.GONE
		if (btn.visibility == target && (!visible || btn.alpha == 1f)) return
		btn.animate().cancel()
		if (skipProgrammaticAnimations()) {
			btn.alpha = if (visible) 1f else 0f
			btn.visibility = target
			return
		}
		val duration = stateChangeDuration(R.integer.duration_standard_transition)
		if (visible) {
			btn.fadeIn(duration)
		} else {
			btn.animate().alpha(0f).setDuration(duration).withLayer().withEndAction {
				btn.visibility = View.GONE
			}.start()
		}
	}

	// Strictly tied to what the Result area shows: nothing displayed -> no buttons; an error
	// response -> Delete only; a real response -> all three.
	private fun updateOutputButtonsVisibility() {
		val hasResponse = outputShowsResponse && fullResponseText.isNotEmpty()
		val showActions = hasResponse && !lastResponseWasError
		fadeIconButton(btnClearOutput, hasResponse)
		fadeIconButton(btnCopyOutput, showActions)
		fadeIconButton(btnSaveOutput, showActions)
	}

	// Domain for Happwneresp_<domain>[_suffix].txt, via PublicSuffixList (compound TLDs resolve
	// correctly). An IP host is used whole - it has no domain to extract.
	private fun extractDomainForFilename(urlString: String): String {
		val host = try {
			URI(urlString).host
		} catch (_: Throwable) {
			null
		} ?: return ""
		val isIpLike = host.contains(":") || host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))
		val name = if (isIpLike) {
			host
		} else {
			PublicSuffixList.registrableLabel(this, host) ?: host
		}
		return name.replace(Regex("[^A-Za-z0-9_-]"), "_")
	}

	// Pick the scrollbar mode: custom thumb only for a large result that's expanded on screen,
	// otherwise stock
	private fun applyOutputScrollbar() {
		val large = fullResponseText.length > MAX_DISPLAY_CHARS && output.isVisible
		(findViewById<View>(R.id.mainScrollView) as? NoAutoScrollView)?.setFastScrollActive(large)
	}

	// Decrypt a v2raytun:// or incy:// crypt link off-thread, then show it (or the error)
	private fun handleDecryptCryptLink(
		app: String, cryptUrl: String, decrypt: (String) -> CryptLinkResult
	) = decryptInto(cryptUrl) {
		when (val result = withContext(Dispatchers.IO) { decrypt(cryptUrl) }) {
			is CryptLinkResult.Decrypted -> DecryptOutcome.Plain(result.plaintext)
			is CryptLinkResult.Error -> DecryptOutcome.Failed("$app: ${result.reason}")
			CryptLinkResult.NotCryptLink -> DecryptOutcome.NotALink
		}
	}

	// Parse the bridge URL back into the url/hwid/ua fields. What the link does not carry is left
	// as the fields have it, so a link from someone else does not wipe this phone's id and agent.
	private fun parseAndApplyBridgeUrl(bridgeUrl: String) {
		val parts = BridgeLink.parse(bridgeUrl) ?: return
		mainContainer.beginDelayedTransitionIfEnabled(fastTransition)
		parts.url?.let { inputUrl.setText(it) }
		parts.hwid?.let {
			if (!inputHwid.isEnabled) handleToggleHwidEdit(true)
			inputHwid.setText(it)
		}
		parts.userAgent?.let { inputUserAgent.setText(it) }
	}

	// The HWID field has no filter of its own, so line breaks are taken out here.
	private fun handlePasteHwid() {
		clipboardTextOrSaySo()?.let { inputHwid.setText(it.replace("\n", "").replace("\r", "")) }
	}

	// Toggle manual HWID entry; gracefully dismiss the keyboard and the hint animation
	private fun handleToggleHwidEdit(enabled: Boolean) {
		val prefs = PrefsManager.getSafePrefs(this)

		val hadFocus = inputHwid.hasFocus()
		val isImeVisible = try {
			ViewCompat.getRootWindowInsets(window.decorView)
				?.isVisible(WindowInsetsCompat.Type.ime()) ?: false
		} catch (_: Throwable) { false }

		val stableHintHeight = if (hadFocus && hwidHint.isVisible) {
			hwidHint.height.coerceAtLeast(0)
		} else -1

		if (hadFocus) {
			inputHwid.hideKeyboard()
			inputHwid.clearFocus()
		}

		inputHwid.isEnabled = enabled
		prefs.edit { putBoolean(PrefsManager.PREF_USE_CUSTOM_HWID_INPUT, enabled) }

		if (!enabled) {
			val captured = prefs.getString(PrefsManager.PREF_CAPTURED_ID, "") ?: ""
			if (hadFocus) {
				// crossfadeText applies the value synchronously, so the suppression window still covers the change;
				// the field just loses focus first.
				hintAnimationSuppressed = true
				inputHwid.crossfadeText(captured)
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
				inputHwid.crossfadeText(captured)
				updateHwidHintVisibility(captured)
			}
		} else {
			val custom = prefs.getString(PrefsManager.PREF_CUSTOM_HWID, "") ?: ""
			if (custom.isNotEmpty()) {
				inputHwid.crossfadeText(custom)
			} else {
				val captured = prefs.getString(PrefsManager.PREF_CAPTURED_ID, "") ?: ""
				inputHwid.crossfadeText(captured)
			}
		}
		refreshFieldStyle(layoutHwid, inputHwid)
		PrefsManager.broadcastSettings(this)
	}

	// On start: reconcile LSPatch, reload history, refresh the UI
	override fun onStart() {
		super.onStart()
		reconcileLspatchApps()
		loadUrlHistory()
		updateUiState()
		if (!historyPrefsListenerRegistered) {
			PrefsManager.getSafePrefs(this).registerOnSharedPreferenceChangeListener(historyPrefsListener)
			historyPrefsListenerRegistered = true
		}
	}

	override fun onStop() {
		if (historyPrefsListenerRegistered) {
			PrefsManager.getSafePrefs(this).unregisterOnSharedPreferenceChangeListener(historyPrefsListener)
			historyPrefsListenerRegistered = false
		}
		super.onStop()
	}

	// Reconcile LSPatch apps (signatures / installed state) and toggle lspatch_mode
	private fun reconcileLspatchApps() {
		val prefs = PrefsManager.getSafePrefs(this)
		// Reconciliation runs whatever the Xposed state, only the mode flag is Xposed's business:
		// skipping it would keep uninstalled apps in the list and the combined status label up.
		val xposedActive = ModuleStatus.isModuleActive()

		val lspatchApps = PrefsManager.lspatchApps(prefs)
		val sigMapJson = prefs.getString(PrefsManager.PREF_LSPATCH_SIGNATURES, "{}") ?: "{}"
		val sigMap = try { JSONObject(sigMapJson) } catch (_: Throwable) { JSONObject() }

		Log.d(ModuleIds.LOG_LSP, "Checking status. Apps in list: ${lspatchApps.size}")

		val iterator = lspatchApps.iterator()
		var changed = false

		while (iterator.hasNext()) {
			val pkgName = iterator.next()
			val savedCrc = sigMap.optLong(pkgName, -1L)
			val currentCrc = PrefsManager.getSignatureCrc32(this, pkgName)

			Log.d(ModuleIds.LOG_LSP, "Validating $pkgName: SavedCRC=$savedCrc, CurrentCRC=$currentCrc")

			val isInstalled = PrefsManager.isPackageInstalled(this, pkgName)

			if (!isInstalled) {
				Log.i(ModuleIds.LOG_LSP, "Removing $pkgName: App not installed")
				iterator.remove()
				sigMap.remove(pkgName)
				changed = true
			} else if (currentCrc == null) {
				Log.w(ModuleIds.LOG_LSP,
					"Keeping $pkgName: CRC failed but app installed (signature query unavailable)")
			} else if (savedCrc != -1L && currentCrc != savedCrc) {
				Log.i(ModuleIds.LOG_LSP, "Removing $pkgName: Signature mismatch (reinstalled?)")
				iterator.remove()
				sigMap.remove(pkgName)
				changed = true
			}
		}

		if (changed) {
			Log.d(ModuleIds.LOG_LSP, "Saving updated app list. New count: ${lspatchApps.size}")
			prefs.edit {
				putStringSet(PrefsManager.PREF_LSPATCH_APPS, lspatchApps)
				putString(PrefsManager.PREF_LSPATCH_SIGNATURES, sigMap.toString())
			}
		}

		if (xposedActive) {
			// Xposed owns the mode; the list stays (it now holds only genuinely patched apps)
			// but must not switch the app into LSPatch mode.
			if (prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)) {
				Log.i(ModuleIds.LOG_LSP, "Xposed active, clearing lspatch_mode flag")
				prefs.edit { putBoolean(PrefsManager.PREF_LSPATCH_MODE, false) }
			}
			return
		}

		val hasValidApp = lspatchApps.isNotEmpty()
		val currentMode = prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)

		if (currentMode != hasValidApp) {
			Log.i(ModuleIds.LOG_LSP, "Toggling lspatch_mode: $currentMode -> $hasValidApp")
			prefs.edit { putBoolean(PrefsManager.PREF_LSPATCH_MODE, hasValidApp) }
		}
	}

	// Redraw the UI for the current mode (Xposed / LSPatch / plain)
	private fun updateUiState() {
		val prefs = PrefsManager.getSafePrefs(this)
		val lspatchMode = prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)
		val moduleActive = ModuleStatus.isModuleActive()
		val isFullActive = moduleActive || lspatchMode

		mainContainer.beginDelayedTransitionIfEnabled(fastTransition)

		val isInterceptEnabled = PrefsManager.isInterceptEnabled(this)
		islandIntercept.visibility = if (isInterceptEnabled && isFullActive) View.VISIBLE else View.GONE

		// Interception is independent of HWID spoofing, so the island above still follows
		// isFullActive - only the HWID field itself drops back to unhooked behaviour.
		val hwidHooked = isHwidFieldHooked()

		findViewById<ImageButton>(R.id.btnEditHwidManual).apply {
			setImageResource(if (hwidHooked) R.drawable.ic_edit else R.drawable.ic_paste)
			contentDescription = getString(if (hwidHooked) R.string.cd_edit_hwid else R.string.cd_paste_hwid)
		}

		val isInputEnabled = prefs.getBoolean(PrefsManager.PREF_USE_CUSTOM_HWID_INPUT, false)
		inputHwid.isEnabled = if (hwidHooked) isInputEnabled else true

		val captured = prefs.getString(PrefsManager.PREF_CAPTURED_ID, "") ?: ""
		val custom = prefs.getString(PrefsManager.PREF_CUSTOM_HWID, "") ?: ""
		val displayId = when {
			hwidHooked && !isInputEnabled -> captured
			// Still hooked, just manually overridden: the captured id is a reasonable starting
			// point until the person types their own.
			hwidHooked -> custom.ifEmpty { captured }
			// Spoofing itself is off: the field behaves as if unhooked, so nothing here ever
			// falls back to what was captured - an unhooked field wouldn't have that anyway.
			else -> custom
		}

		if (inputHwid.text?.toString() != displayId && displayId.isNotEmpty()) {
			inputHwid.setText(displayId)
		}
		updateHwidHintVisibility(inputHwid.text?.toString())

		val targetUa = getCurrentUa()
		if (inputUserAgent.text.toString() != targetUa) {
			inputUserAgent.setText(targetUa)
		}

		refreshAllFieldsStyle()
	}

	// The field behaves the hooked way only while a hook will substitute something. With spoofing off the hook
	// leaves the value alone, so it falls back to the plain paste-it-yourself behaviour.
	private fun isHwidFieldHooked(): Boolean {
		val prefs = PrefsManager.getSafePrefs(this)
		val fullActive = ModuleStatus.isModuleActive() ||
			prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)
		return fullActive && PrefsManager.isHwidSpoofEnabled(this)
	}

	// "HWID unknown" hint animation (manual height calc to avoid jitter under the IME)
	private fun updateHwidHintVisibility(id: String?) {
		if (hintAnimationSuppressed) return
		// An empty field with an id already captured is someone typing their own, not an unknown one.
		val captured = PrefsManager.getSafePrefs(this).getString(PrefsManager.PREF_CAPTURED_ID, "").orEmpty()
		val shouldShow = id.isNullOrEmpty() && captured.isEmpty() && isHwidFieldHooked()
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
			abs(hwidHint.alpha - 1f) < 0.01f &&
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

		val duration = stateChangeDuration(R.integer.duration_fast_transition)

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
			val hintHeight = hwidHint.measuredHeight
			hwidHint.layoutParams.height = savedHeight
			hwidHint.layoutParams = hwidHint.layoutParams
			hintHeight
		} else 0

		val startRowMargin = rowLp.bottomMargin
		val startAlpha = hwidHint.alpha
		val startHeight = if (pendingStartHeight > 0) {
			val startHeight = pendingStartHeight
			pendingStartHeight = -1
			startHeight
		} else {
			hwidHint.height.coerceAtLeast(0)
		}
		val startHintMargin = hintLp?.bottomMargin ?: 0

		// Animate row margin, alpha and height together
		val anim = ValueAnimator.ofFloat(0f, 1f).apply {
			this.duration = duration
			addUpdateListener { animator ->
				val fraction = animator.animatedFraction
				rowLp.bottomMargin = (startRowMargin + (targetRowMargin - startRowMargin) * fraction).toInt()
				rowHwid.layoutParams = rowLp
				hwidHint.alpha = startAlpha + (targetAlpha - startAlpha) * fraction
				val hLp = hwidHint.layoutParams
				hLp.height = (startHeight + (measuredTargetHeight - startHeight) * fraction).toInt()
				if (hLp is ViewGroup.MarginLayoutParams) {
					hLp.bottomMargin = (startHintMargin +
						(targetHintMargin - startHintMargin) * fraction).toInt()
				}
				hwidHint.layoutParams = hLp
			}
			addListener(object : AnimatorListenerAdapter() {
				var ended = false
				override fun onAnimationEnd(animation: Animator) {
					if (ended) return
					ended = true
					applyFinalState()
					if (hwidHintAnim === animation) hwidHintAnim = null
				}
				override fun onAnimationCancel(animation: Animator) {
					ended = true
				}
			})
		}
		hwidHintAnim = anim
		anim.start()
	}

	// Clears the rows on screen and everything that describes them.
	private fun resetHistoryView() {
		capturedUrlsContainer.removeAllViews()
		shownHistoryUrls = HashSet()
		historyNextOffset = -1L
		historyReachedEnd = false
		historyLoadingPage = false
		historyPrepends = 0
		historyShowDuplicates =
			PrefsManager.getSafePrefs(this).getBoolean(PrefsManager.PREF_SHOW_DUPLICATES, false)
	}

	// Load the first (newest) page of history from scratch.
	private fun loadUrlHistory() {
		resetHistoryView()

		appendHistoryPage()

		updateEmptyHistoryVisibility()
		updateUiState()
	}

	// Renders the next older page of the history and moves the paging position past it.
	private fun appendHistoryPage() {
		val page = UrlHistory.readPage(this, HISTORY_PAGE, historyNextOffset)
		renderHistoryRows(page.entries)
		historyNextOffset = page.nextOffset
		historyReachedEnd = !page.hasMore
	}

	// Pull the next older page in when the scroll nears the bottom. Called from
	// NoAutoScrollView.onScrollChanged, so it must stay cheap and re-entrant.
	fun maybeLoadMoreHistory() {
		if (historyLoadingPage || historyReachedEnd) return
		historyLoadingPage = true
		try {
			appendHistoryPage()
		} finally {
			historyLoadingPage = false
		}
	}

	// De-duplication is a view concern, since storage keeps everything: skip a URL already on
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
		// Any app can report a capture, and a flood would grow the list without end: after a page
		// of them it is drawn afresh from the file, which keeps only the newest anyway.
		if (historyPrepends >= HISTORY_PAGE) {
			loadUrlHistory()
			return
		}
		// add() first and unconditionally: as !historyShowDuplicates && !add(url), the add would be
		// skipped whenever duplicates are shown, and the set would stop tracking what is on screen.
		val firstTime = shownHistoryUrls.add(url)
		if (!firstTime && !historyShowDuplicates) return
		capturedUrlsContainer.beginDelayedTransitionIfEnabled(fastTransition)
		addUrlToUi(url, atTop = true)
		historyPrepends++
		updateEmptyHistoryVisibility()
	}

	// One tappable history row that refills the URL field.
	private fun addUrlToUi(url: String, atTop: Boolean = false) {
		val row = TextView(this).apply {
			text = url
			val verticalPadding = resources.getDimensionPixelSize(R.dimen.padding_history_vertical)
			setPadding(0, verticalPadding, 0, verticalPadding)
			setTextColor(MaterialColors.getColor(
				this, R.attr.happAccent,
				ContextCompat.getColor(context, R.color.brand_purple_secondary)
			))
			textSize = 14f

			// The ripple comes from the drawable; resolving selectableItemBackground from the theme as
			// well would be one attribute lookup per row, three hundred to a page, for a value nothing reads.
			setBackgroundResource(R.drawable.bg_row_ripple)
			isClickable = true
			isFocusable = true

			setOnClickListener { putLink(url) }
		}
		if (atTop) capturedUrlsContainer.addView(row, 0) else capturedUrlsContainer.addView(row)
		updateEmptyHistoryVisibility()
	}

	private fun updateEmptyHistoryVisibility() {
		// childCount, not the store: with duplicates hidden the store may hold entries that are all
		// collapsed away, and the label should reflect what is actually on screen.
		val isEmpty = capturedUrlsContainer.isEmpty()
		if (isEmpty) {
			emptyHistoryText.visibility = View.VISIBLE
			val msg = getString(R.string.label_history_empty)
			emptyHistoryText.text = fromHtml(msg)
		} else {
			emptyHistoryText.visibility = View.GONE
		}
		// Nothing on screen, nothing to clear. Same fade the Result-area buttons use, so a tap's
		// ripple finishes spreading while the button goes away.
		fadeIconButton(btnClearHistory, !isEmpty)
	}

	// Compare version names numerically so 3.22.1 > 3.9.0; pulls digit groups, ignores the rest
	private fun compareVersionNames(first: String, second: String): Int {
		val digits = Regex("\\d+")
		val firstParts = digits.findAll(first).map { it.value.toLongOrNull() ?: 0L }.toList()
		val secondParts = digits.findAll(second).map { it.value.toLongOrNull() ?: 0L }.toList()
		for (i in 0 until maxOf(firstParts.size, secondParts.size)) {
			val firstPart = firstParts.getOrElse(i) { 0L }
			val secondPart = secondParts.getOrElse(i) { 0L }
			if (firstPart != secondPart) return firstPart.compareTo(secondPart)
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
				val installedVersion = packageManager.getPackageInfo(pkg, 0).versionName
				if (!installedVersion.isNullOrEmpty() && (best == null ||
					compareVersionNames(installedVersion, best) > 0)) {
					best = installedVersion
				}
			} catch (_: PackageManager.NameNotFoundException) {
			} catch (_: Throwable) {}
		}
		return if (best != null) default.substringBefore("/") + "/" + best else default
	}

	// The UA string for a given preset (version filled from the installed app when present)
	private fun uaForPreset(preset: String): String = when (preset) {
		"v2raytun" -> getString(R.string.ua_default_v2raytun)
		"incy" -> buildPresetUa(R.string.ua_default_incy, arrayOf(PrefsManager.INCY_PKG))
		else -> buildPresetUa(R.string.ua_default_happ, arrayOf(PrefsManager.HAPP_PKG_PRIMARY,
			PrefsManager.HAPP_PKG_SECONDARY))
	}

	// UA to show on startup: whatever the user last had; empty by default (then UA is omitted)
	private fun getCurrentUa(): String {
		return PrefsManager.getSafePrefs(this).getString(PrefsManager.PREF_CUSTOM_USER_AGENT, "") ?: ""
	}

	// Picks one of 3 preset User-Agents; the field stays editable. Below the presets: whether a subscription that
	// names its own User-Agent may override whatever the field holds.
	private fun showUaSelectDialog(page: String? = null) {
		if (alreadyShowing(DIALOG_UA_SELECT)) return
		val current = inputUserAgent.text.toString().trim()
		// The note opens in place of the presets, in the same window; the picker has no buttons of
		// its own, so OK shows only while the note does.
		val title = getString(R.string.ua_select_title)
		uaPage = page
		val pages = DialogPages(this, title, homeButtons = false, onPage = { uaPage = it }) {
			layoutInflater.inflate(R.layout.dialog_ua_select, it, false)
		}
		val dialogView = pages.home
		val radioGroup = dialogView.findViewById<RadioGroup>(R.id.dialogRadioGroup)
		val firstRadio = dialogView.findViewById<MaterialRadioButton>(R.id.radioOption1)
		val secondRadio = dialogView.findViewById<MaterialRadioButton>(R.id.radioOption2)
		val thirdRadio = dialogView.findViewById<MaterialRadioButton>(R.id.radioOption3)
		val checkPreferSubscriptionUa =
			dialogView.findViewById<MaterialCheckBox>(R.id.checkPreferSubscriptionUa)
		val happUa = uaForPreset("happ")
		val v2rayUa = uaForPreset("v2raytun")
		val incyUa = uaForPreset("incy")
		firstRadio.text = happUa
		secondRadio.text = v2rayUa
		thirdRadio.text = incyUa
		when (current) {
			v2rayUa -> secondRadio.isChecked = true
			incyUa -> thirdRadio.isChecked = true
			happUa -> firstRadio.isChecked = true
		}

		// Written the moment it is flipped rather than on dismiss: picking a preset closes this
		// dialog, and a tick made just before that must not be lost with it.
		checkPreferSubscriptionUa.isChecked = PrefsManager.preferSubscriptionUa(prefs)
		checkPreferSubscriptionUa.setOnCheckedChangeListener { _, isChecked ->
			prefs.edit { putBoolean(PrefsManager.PREF_PREFER_SUBSCRIPTION_UA, isChecked) }
		}

		val dialog = AnimatedDialogBuilder(this)
			.setTitle(title)
			.setView(pages.view)
			.setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
			.showAnimated()
		track(dialog, DIALOG_UA_SELECT)
		pages.attach(dialog)
		val noteTitle = fromHtml(getString(R.string.ua_prefer_subscription_info_title))
		val note = DialogPages.Page(noteTitle, PAGE_UA_NOTE) {
			layoutInflater.infoView(getString(R.string.ua_prefer_subscription_info_msg), it)
		}
		dialogView.findViewById<ImageView>(R.id.btnPreferSubscriptionUaInfo).setOnClickListener {
			pages.open(note)
		}
		radioGroup.setOnCheckedChangeListener { _, checkedId ->
			val picked = when (checkedId) {
				R.id.radioOption2 -> v2rayUa
				R.id.radioOption3 -> incyUa
				else -> happUa
			}
			inputUserAgent.crossfadeText(picked) { refreshFieldStyle(layoutUserAgent, inputUserAgent) }
			dialog.dismissAnimated()
		}
		if (page == PAGE_UA_NOTE) pages.open(note, animated = false)
	}

	// Tracks an open dialog under its tag; one dismissed from outside is forgotten, along with
	// whatever forget clears.
	private fun track(dlg: AlertDialog, tag: String, forget: () -> Unit = {}) {
		currentDialog = dlg
		currentDialogTag = tag
		dlg.setOnExternalDismissListener {
			if (currentDialog === dlg) {
				currentDialog = null
				currentDialogTag = null
				forget()
			}
		}
	}

	// Generic info dialog (tracked so it survives a recreate)
	private fun showInfoDialog(title: String, htmlMessage: String) {
		if (alreadyShowing(DIALOG_INFO) && currentDialogInfoTitle == title) return
		val dialogView = layoutInflater.infoView(htmlMessage)

		val dlg = AnimatedDialogBuilder(this)
			.setTitle(fromHtml(title))
			.setView(dialogView)
			.setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
			.showAnimated()

		currentDialogInfoTitle = title
		currentDialogInfoMessage = htmlMessage
		track(dlg, DIALOG_INFO) {
			currentDialogInfoTitle = null
			currentDialogInfoMessage = null
		}
	}

	// First-time bridge explainer; on OK mark it shown and re-tap Get
	private fun showBridgeHintDialog() {
		if (alreadyShowing(DIALOG_BRIDGE_HINT)) return
		val msg = getString(R.string.msg_bridge_service_enable)
		val dialogView = layoutInflater.infoView(msg)

		val dlg = AnimatedDialogBuilder(this)
			.setTitle(fromHtml(getString(R.string.setting_bridge_header)))
			.setView(dialogView)
			.setPositiveButton(fromHtml(getString(R.string.btn_ok))) { _, _ ->
				prefs.edit { putBoolean(PrefsManager.PREF_BRIDGE_HINT_SHOWN, true) }
				copySubscriptionLink()
			}
			.showAnimated()

		track(dlg, DIALOG_BRIDGE_HINT)
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

	private fun isSettingsVisible(): Boolean {
		val fragment = supportFragmentManager.findFragmentByTag(SETTINGS_FRAGMENT_TAG) ?: return false
		return !fragment.isHidden
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
				focused.hideKeyboard()
				focused.clearFocus()
			}
		} catch (_: Throwable) {}

		val host = findViewById<View>(R.id.rootLayout) ?: return
		val container = findViewById<View>(R.id.settingsFragmentContainer) ?: return
		val mode = animMode()

		if (mode == ANIM_MODE_SYSTEM) {
			// A separate activity, which the check above cannot see: a double tap would open two.
			if (!settingsTap.accept()) return
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
		val callback = object : OnBackPressedCallback(false) {
			override fun handleOnBackPressed() {
				closeSettings()
			}
		}
		onBackPressedDispatcher.addCallback(this, callback)
		settingsBackCallback = callback
		return callback
	}

	// After a recreate, snap settings back to the open state
	private fun restoreSettingsStateIfNeeded() {
		if (!isSettingsVisible()) return
		val host = findViewById<View>(R.id.rootLayout) ?: return
		val container = findViewById<View>(R.id.settingsFragmentContainer) ?: return
		applySettingsOpenStateInstantly(host, container)
		ensureSettingsBackCallback().isEnabled = true
	}

	companion object {
		// Theme/Monet change: longer than dialog fades, the whole screen cross-fades on recreate.
		private const val THEME_RECREATE_MS = 430L

		// Longest link taken from outside. Each kind carries one address, and none kept is over
		// 8 KiB; an unbounded one, saved with its open dialog, could crash the app on stop.
		private const val MAX_IMPORT_LINK_CHARS = 64 * 1024

		// Padding after a container transition, so the relayout lands on settled bounds.
		private const val SCROLL_UNLOCK_GRACE_MS = 100L

		// Windowed history: rows are drawn newest-first in pages, so a history of any size only ever
		// inflates the first page's TextViews plus whatever the person has scrolled to.
		private const val HISTORY_PAGE = 300

		private const val LOG_CONVERT = "Happwner:Convert"
		private const val LOG_SAVE = "Happwner:Save"

		// Fragment and dialog tags, and saved-state keys
		private const val SETTINGS_FRAGMENT_TAG = "settings_fragment"
		private const val STATE_OPEN_DIALOG_TAG = "main_open_dialog_tag"
		private const val STATE_OPEN_DIALOG_TITLE = "main_open_dialog_title"
		private const val STATE_OPEN_DIALOG_MESSAGE = "main_open_dialog_message"
		private const val STATE_UA_PAGE = "main_ua_page"
		private const val STATE_IMPORT_LINK = "main_import_link"
		private const val DIALOG_INFO = "info"
		private const val DIALOG_BRIDGE_HINT = "bridge_hint"
		private const val DIALOG_IMPORT_CONFIRM = "import_confirm"
		private const val DIALOG_UA_SELECT = "ua_select"
		private const val PAGE_UA_NOTE = "ua_note"
	}

	override fun onDestroy() {
		super.onDestroy()
		try { unregisterReceiver(receiver) } catch (_: Exception) {}
	}

	// How the URL field reads, which its colour and its error line both follow: a crypt link
	// waiting to be decrypted, and text that is none of the links the field takes.
	private data class UrlLook(val encrypted: Boolean, val invalid: Boolean)

	private fun urlLook(text: String): UrlLook {
		val encrypted = isCryptLinkWithPayload(text)
		val wrapper = text.startsWith("happ://add/") || V2RayTunLinks.isImportLink(text) ||
			IncyLinks.isIncyLink(text)
		val invalid = text.isNotEmpty() && !encrypted && !wrapper &&
			!text.startsWith("http://") && !text.startsWith("https://")
		return UrlLook(encrypted, invalid)
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
		if (!text.startsWith(prefix, ignoreCase = true)) return false
		var position = prefix.length
		while (position < text.length && text[position].isDigit()) position++
		return position < text.length && text[position] == '/'
	}

	// Pick the URL field colour by state (error / encrypted / normal)
	private fun getUrlCurrentColor(): Int {
		val (isCrypt, hasError) = urlLook(inputUrl.text.toString().trim())

		return when {
			hasError -> ContextCompat.getColor(this, R.color.error_red)
			isCrypt -> {
				if (isNightMode()) Color.WHITE else Color.BLACK
			}
			else -> MaterialColors.getColor(
				this, R.attr.happAccent,
				ContextCompat.getColor(this, R.color.brand_purple_secondary)
			)
		}
	}

	// Every field's colours set at once, without the crossfade.
	private fun refreshAllFieldsStyle() {
		refreshFieldStyle(layoutUrl, inputUrl, animate = false)
		refreshFieldStyle(layoutHwid, inputHwid, animate = false)
		refreshFieldStyle(layoutUserAgent, inputUserAgent, animate = false)
	}

	// Field border/cursor/text colour for its state (focused / error / disabled)
	private fun refreshFieldStyle(layout: TextInputLayout, editText: EditText, animate: Boolean = true) {
		val isEnabled = editText.isEnabled
		val accent = MaterialColors.getColor(
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
			unfocusedColor = if (focusedColor == accent) gray else focusedColor
		} else {
			focusedColor = accent
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

	// Apply the field colours immediately, no animation
	private fun syncFieldColorDirect(layout: TextInputLayout, editText: EditText, color: Int,
		unfocusedColor: Int) {
		paintField(layout, editText, color, unfocusedColor)
		editText.setTextColor(targetEditTextColor(editText))

		fieldColorMap[layout.id] = color
		fieldUnfocusedColorMap[layout.id] = unfocusedColor
	}

	// Paints the box stroke, hint, cursor and handles of one field in its focused, unfocused and
	// disabled colours.
	private fun paintField(layout: TextInputLayout, editText: EditText, color: Int, unfocusedColor: Int) {
		val disabledColor = ContextCompat.getColor(this, R.color.text_disabled)
		val colorList = ColorStateList(
			arrayOf(
				intArrayOf(-AndroidR.attr.state_enabled),
				intArrayOf(AndroidR.attr.state_focused),
				intArrayOf()
			),
			intArrayOf(disabledColor, color, unfocusedColor)
		)
		layout.setBoxStrokeColorStateList(colorList)
		layout.hintTextColor = colorList
		layout.defaultHintTextColor = colorList
		if (Build.VERSION.SDK_INT >= 29) {
			layout.setCursorColor(ColorStateList.valueOf(color))
		}
		updateTextViewHandlesColor(editText, if (editText.isEnabled) color else disabledColor)
	}

	private fun targetEditTextColor(editText: EditText): Int {
		val colorRes = if (editText.isEnabled) R.color.text_primary else R.color.text_disabled
		return ContextCompat.getColor(this, colorRes)
	}

	// Crossfade the field colours (stroke / hint / cursor / text)
	private fun animateFieldColor(layout: TextInputLayout, editText: EditText, targetColor: Int,
		targetUnfocusedColor: Int) {
		val layoutId = layout.id
		val startColor = fieldColorMap[layoutId] ?: layout.boxStrokeColor
		val startUnfocusedColor = fieldUnfocusedColorMap[layoutId] ?: ContextCompat.getColor(this,
			R.color.text_secondary)
		val startTextColor = editText.currentTextColor
		val targetTextColor = targetEditTextColor(editText)

		if (startColor == targetColor &&
			startUnfocusedColor == targetUnfocusedColor &&
			startTextColor == targetTextColor) {
			if (!editText.isEnabled) layout.isEnabled = false
			updateTextViewHandlesColor(editText,
				if (editText.isEnabled) targetColor else ContextCompat.getColor(this, R.color.text_disabled))
			return
		}

		val mode = animMode()
		if (mode == ANIM_MODE_OFF) {
			fieldAnimatorMap[layoutId]?.cancel()
			syncFieldColorDirect(layout, editText, targetColor, targetUnfocusedColor)
			if (!editText.isEnabled) layout.isEnabled = false
			return
		}

		val animDuration = stateChangeDuration(R.integer.duration_standard_transition)

		fieldAnimatorMap[layoutId]?.cancel()
		val argb = ArgbEvaluator()
		val animator = ValueAnimator.ofFloat(0f, 1f).apply {
			duration = animDuration
			addUpdateListener { anim ->
				val fraction = anim.animatedFraction
				val color = argb.evaluate(fraction, startColor, targetColor) as Int
				val unfocused = argb.evaluate(fraction, startUnfocusedColor, targetUnfocusedColor) as Int
				val textColor = argb.evaluate(fraction, startTextColor, targetTextColor) as Int

				paintField(layout, editText, color, unfocused)
				editText.setTextColor(textColor)
				fieldColorMap[layoutId] = color
				fieldUnfocusedColorMap[layoutId] = unfocused
			}
			addListener(object : AnimatorListenerAdapter() {
				private var cancelled = false

				override fun onAnimationCancel(animation: Animator) {
					cancelled = true
				}

				// onAnimationEnd fires after a cancel too, and flipping to the disabled state there repaints the hint
				// instantly: only a completed run has reached the disabled colour, so only it may flip.
				override fun onAnimationEnd(animation: Animator) {
					if (cancelled) return
					if (!editText.isEnabled) layout.isEnabled = false
				}
			})
		}
		fieldAnimatorMap[layoutId] = animator
		animator.start()
	}
}
