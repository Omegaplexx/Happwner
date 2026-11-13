package com.happwner.ui

import android.R as AndroidR
import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ArgbEvaluator
import android.animation.ValueAnimator
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.SharedPreferences
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Rect
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.method.LinkMovementMethod
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.Button
import android.widget.ImageView
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import androidx.core.view.updateLayoutParams
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.card.MaterialCardView
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.color.MaterialColors
import com.google.android.material.radiobutton.MaterialRadioButton
import com.google.android.material.switchmaterial.SwitchMaterial
import com.happwner.R
import com.happwner.bridge.BridgeController
import com.happwner.bridge.BridgeLink
import com.happwner.client.HappanionBridge
import com.happwner.data.ModuleStatus
import com.happwner.data.PrefsManager
import com.happwner.patcher.AppIcons
import com.happwner.patcher.InstalledApps
import com.happwner.patcher.LSPortableRunner
import com.happwner.patcher.PatchSession
import com.happwner.patcher.PatchSource
import com.happwner.patcher.PatchTarget
import com.happwner.patcher.ReleaseDownloader
import java.io.File
import java.util.Locale
import kotlin.math.max
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private fun View.radioButton(id: Int): MaterialRadioButton = findViewById(id)

class SettingsFragment : Fragment() {

	companion object {
		private const val TAG = "Happwner:Settings"

		// The app languages in the order of language_options.
		private val LANGUAGES = listOf("system", "ru", "en")

		private const val STATE_OPEN_DIALOG = "settings_open_dialog"
		private const val STATE_SCOPE_PAGE = "settings_scope_page"
		private const val STATE_PATCHER_PAGE = "settings_patcher_page"

		private const val DIALOG_LANGUAGE = "language"
		private const val DIALOG_THEME = "theme"
		private const val DIALOG_ANIMATIONS = "animations"
		private const val DIALOG_PROCESS_SCOPE_MANUAL = "process_scope_manual"
		private const val DIALOG_PROCESS_SCOPE_SERVER = "process_scope_server"
		private const val PAGE_URI_OPTIONS = "process_uri_options"

		private const val DIALOG_RESPONSE_HEADER_INFO = "response_header_info"
		private const val DIALOG_DECRYPTION_HEADER_INFO = "decryption_header_info"
		private const val DIALOG_BRIDGE_INFO = "bridge_info"
		private const val DIALOG_INFO = "info"
		private const val DIALOG_XPOSED = "xposed"
		private const val DIALOG_HAPPANION = "happanion"
		private const val DIALOG_PATCHER = "patcher"
		private const val DIALOG_PATCHED = "patched"
		private const val DIALOG_PATCH_ERROR = "patch_error"

		private const val PAGE_INSTALLED_APPS = "patcher_installed_apps"
		// Icons loaded ahead for the first rows, so the list page opens with them on screen.
		private const val WARMUP_ICONS = 12
	}

	private var prefsListenerRegistered = false
	private var currentDialog: AlertDialog? = null
	private var currentDialogTag: String? = null

	// The page the scope dialog shows, null for its own - a recreate reopens it there.
	private var scopePage: String? = null

	// The same for the patcher dialog.
	private var patcherPage: String? = null

	// Runs the tick's colour across, and is kept so a second tick cancels the first.
	private var checkboxTintAnimator: ValueAnimator? = null

	// Tracks the open Xposed dialog so prefsListener can refresh it live.
	private var xposedDialogRoot: View? = null

	// Same for the Happanion dialog, refreshed from onResume instead - installs/uninstalls don't touch prefs.
	private var happanionDialogRoot: View? = null

	private val prefsListener = SharedPreferences.OnSharedPreferenceChangeListener { sharedPrefs, key ->
		if (key == PrefsManager.PREF_BRIDGE_ENABLED) {
			val isEnabled = sharedPrefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)
			val root = view ?: return@OnSharedPreferenceChangeListener
			root.post {
				root.findViewById<SwitchMaterial>(R.id.switchEnableBridge).isChecked = isEnabled
				updateBridgeCard(root)
			}
		} else if (key == PrefsManager.PREF_LSPATCH_MODE || key == PrefsManager.PREF_LSPATCH_APPS) {
			whileXposedDialogShows { dialogView -> populateXposedDialogContent(dialogView) }
		} else if (key == PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION ||
			key == PrefsManager.PREF_USE_CUSTOM_HWID_INPUT ||
				key == PrefsManager.PREF_CUSTOM_HWID || key == PrefsManager.PREF_CAPTURED_ID) {
			whileXposedDialogShows { dialogView ->
				dialogView.findViewById<SwitchMaterial>(R.id.switchHwidSpoof)?.isChecked =
					PrefsManager.isHwidSpoofEnabled(dialogView.context)
				updateHwidSpoofStatus(dialogView)
			}
		}
	}

	// Updates the Xposed dialog next frame, only if it's still the one showing - it can be
	// closing when a preference changes.
	private fun whileXposedDialogShows(update: (View) -> Unit) {
		val dialogView = xposedDialogRoot ?: return
		dialogView.post {
			try {
				if (isAdded && !isHidden && currentDialogTag == DIALOG_XPOSED &&
					currentDialog?.isShowing == true
				) {
					update(dialogView)
				}
			} catch (_: Throwable) {}
		}
	}

	override fun onCreateView(
		inflater: LayoutInflater,
		container: ViewGroup?,
		savedInstanceState: Bundle?
	): View {
		return inflater.inflate(R.layout.fragment_settings, container, false)
	}

	override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
		super.onViewCreated(view, savedInstanceState)

		(view as? ViewGroup)?.hostHeightGlides()
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
		bindLanModeItem(view)
		bindBridgeInstructionIcon(view)
		bindWatchdogItem(view)
		bindXposedCardItem(view)
		followPatchSession()
		PatchSession.sweep(view.context)

		// Before restoreDialog() below, which reopens the scope dialog on the page it showed.
		scopePage = savedInstanceState?.getString(STATE_SCOPE_PAGE)
		patcherPage = savedInstanceState?.getString(STATE_PATCHER_PAGE)

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
		outState.putString(STATE_SCOPE_PAGE, scopePage)
		outState.putString(STATE_PATCHER_PAGE, patcherPage)
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

	override fun onConfigurationChanged(newConfig: Configuration) {
		super.onConfigurationChanged(newConfig)
		if (isHidden) return
		if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
		if (context == null) return
		(view as? ViewGroup)?.beginResizeTransition()
		// After the glide is begun: a dialog put back waits for that glide to end.
		replaceOpenDialog()
	}

	override fun onDestroyView() {
		dismissCurrentDialog()
		// The run goes on without this screen: its dialog is shown again by the one that replaces it.
		val progress = patchProgressDialog
		patchProgressDialog = null
		try { progress?.dismiss() } catch (_: Throwable) {}
		super.onDestroyView()
	}

	private fun dismissCurrentDialog() {
		// The checkbox this animates lives inside the dialog view: the animator must not
		// outlive it, or onAnimationEnd touches a detached view.
		checkboxTintAnimator?.cancel()
		checkboxTintAnimator = null

		// Cleared here too, since a dialog already gone doesn't run its own dismiss listener.
		xposedDialogRoot = null
		happanionDialogRoot = null

		val dialog = currentDialog
		currentDialog = null
		currentDialogTag = null
		if (dialog != null && dialog.isShowing) {
			try { dialog.dismiss() } catch (_: Throwable) {}
		}
	}

	// A second tap can land before the first dialog covers the screen - don't open it twice.
	private fun alreadyShowing(tag: String): Boolean =
		currentDialogTag == tag && currentDialog?.isShowing == true

	// The open dialog is laid out for the old screen: it is put back for the new one, to take exactly the
	// size a fresh one gets, and morphs into it once the screen has glided.
	private fun replaceOpenDialog() {
		val tag = currentDialogTag ?: return
		val open = currentDialog ?: return
		open.putBackForNewScreen {
			// Settings gone in the meantime put nothing back: the open one stays, as it is.
			if (!isAdded || isHidden) return@putBackForNewScreen null
			checkboxTintAnimator?.cancel()
			checkboxTintAnimator = null
			currentDialog = null
			currentDialogTag = null
			showInPlace { restoreDialog(tag) }
			val next = currentDialog
			// Nothing put back after all: the open one stays, tracked as it was.
			if (next == null) {
				currentDialog = open
				currentDialogTag = tag
			}
			next
		}
	}

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

	private fun restoreDialog(tag: String) {
		when (tag) {
			DIALOG_LANGUAGE -> showLanguageDialog()
			DIALOG_THEME -> showThemeDialog()
			DIALOG_ANIMATIONS -> showAnimationsDialog()
			in infoTexts -> showInfo(tag)
			DIALOG_PROCESS_SCOPE_MANUAL ->
				showProcessScopeDialog(PrefsManager.SCOPE_MANUAL, scopePage)
			DIALOG_PROCESS_SCOPE_SERVER ->
				showProcessScopeDialog(PrefsManager.SCOPE_SERVER, scopePage)
			DIALOG_INFO -> showInfoDialog()
			DIALOG_XPOSED -> showXposedDialog()
			DIALOG_HAPPANION -> showHappanionDialog()
			DIALOG_PATCHER -> showPatcherDialog(patcherPage)
			DIALOG_PATCHED, DIALOG_PATCH_ERROR -> showPatchResult()
			// Every tag passed to trackDialog needs a branch above.
			else -> Log.w(
				TAG,
				"no restore path for dialog tag \"$tag\" - it will not survive a rotation"
			)
		}
	}

	private fun registerPrefsListener() {
		if (prefsListenerRegistered) return
		val ctx = context ?: return
		PrefsManager.getSafePrefs(ctx).registerOnSharedPreferenceChangeListener(prefsListener)
		prefsListenerRegistered = true
	}

	private fun unregisterPrefsListener() {
		if (!prefsListenerRegistered) return
		val ctx = context ?: return
		PrefsManager.getSafePrefs(ctx).unregisterOnSharedPreferenceChangeListener(prefsListener)
		prefsListenerRegistered = false
	}

	// Called from onResume - installs/uninstalls don't touch prefs, so nothing else catches this.
	private fun refreshHappanionDialogIfShowing() {
		val dialogView = happanionDialogRoot ?: return
		val dialog = currentDialog ?: return
		if (currentDialogTag != DIALOG_HAPPANION || !dialog.isShowing) return
		populateHappanionDialogContent(dialogView)
		applyHappanionInstallButton(dialog)
	}

	private fun refreshDynamicState() {
		val root = view ?: return
		val ctx = context ?: return
		val prefs = PrefsManager.getSafePrefs(ctx)

		// ensureServing, not the raw preference: "on" over a dead service would be a lie.
		root.findViewById<SwitchMaterial>(R.id.switchEnableBridge)?.isChecked =
			BridgeController.ensureServing(ctx)
		root.findViewById<SwitchMaterial>(R.id.switchWatchdog)?.isChecked =
			prefs.getBoolean(PrefsManager.PREF_BRIDGE_WATCHDOG, false)

		val animationOptions = resources.getStringArray(R.array.animation_options)
		root.findViewById<TextView>(R.id.textAnimationsStatus)?.text =
			fromHtml(animationOptions.getOrElse(ctx.animMode()) { animationOptions[0] })

		updateBridgeCard(root)
	}

	// Insets for the system bars, plus auto-scroll to the field when the keyboard appears
	private fun bindInsets(view: View) {
		val statusBarBackground = view.findViewById<View>(R.id.settingsStatusBarBackground)
		val settingsScrollView = view.findViewById<ScrollView>(R.id.settingsScrollView)
		val toolbar = view.findViewById<View>(R.id.settingsToolbar)
		ViewCompat.setOnApplyWindowInsetsListener(view) { _, insets ->
			val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
			val imeInsets = insets.getInsets(WindowInsetsCompat.Type.ime())
			val imeVisible = insets.isVisible(WindowInsetsCompat.Type.ime())
			val bottomPadding = max(systemBars.bottom, imeInsets.bottom)

			statusBarBackground.layoutParams.height = systemBars.top
			statusBarBackground.requestLayout()
			settingsScrollView.setPadding(systemBars.left, 0, systemBars.right, bottomPadding)
			toolbar?.setPadding(systemBars.left, toolbar.paddingTop, systemBars.right, toolbar.paddingBottom)

			if (imeVisible) {
				activity?.currentFocus?.let { focused ->
					if (!focused.isDescendantOfView(settingsScrollView)) return@let
					// Read while the view is attached: the scroll runs a frame later, when the
					// settings may already be gone.
					val density = resources.displayMetrics.density
					val offset =
						(resources.getInteger(R.integer.scroll_offset_ime_dp) * density).toInt()
					settingsScrollView.post {
						val rect = Rect()
						focused.getDrawingRect(rect)
						settingsScrollView.offsetDescendantRectToMyCoords(focused, rect)
						val targetScrollY = rect.bottom - (settingsScrollView.height - bottomPadding) + offset
						if (targetScrollY > settingsScrollView.scrollY) {
							settingsScrollView.smoothScrollToIfEnabled(targetScrollY)
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
				else -> act?.finish()
			}
		}
		view.findViewById<View>(R.id.action_info).setOnClickListener {
			showInfoDialog()
		}
	}

	private fun bindLanguageItem(view: View) {
		val textLanguageStatus = view.findViewById<TextView>(R.id.textLanguageStatus)
		val langOptionsRaw = resources.getStringArray(R.array.language_options)
		val ctx = requireContext()
		val currentLang = PrefsManager.getSafePrefs(ctx)
			.getString(PrefsManager.PREF_APP_LANG, "system") ?: "system"
		val currentLangIndex = LANGUAGES.indexOf(currentLang).coerceAtLeast(0)
		textLanguageStatus.text = fromHtml(langOptionsRaw[currentLangIndex])

		view.findViewById<MaterialCardView>(R.id.itemLanguage).setOnClickListener {
			showLanguageDialog()
		}
	}

	// Language picker; on choice rename the bridge notification and recreate for the new locale
	private fun showLanguageDialog() {
		if (alreadyShowing(DIALOG_LANGUAGE)) return
		val act = activity ?: return
		val ctx = context ?: return
		val prefs = PrefsManager.getSafePrefs(ctx)
		val langOptions = resources.getStringArray(R.array.language_options).map { fromHtml(it) }
		val currentLang = prefs.getString(PrefsManager.PREF_APP_LANG, "system") ?: "system"
		val currentLangIndex = LANGUAGES.indexOf(currentLang).coerceAtLeast(0)

		showChoiceDialog(act, DIALOG_LANGUAGE, R.string.label_language, langOptions,
			currentLangIndex) { dialog, picked ->
			val newLang = LANGUAGES[picked]
			prefs.edit { putString(PrefsManager.PREF_APP_LANG, newLang) }
			// Renames the notification/channel in the new language; stopping to restart would
			// risk the stop-while-starting crash.
			if (prefs.getBoolean(PrefsManager.PREF_BRIDGE_ENABLED, false)) {
				BridgeController.startService(act, tellPerson = true)
			}
			ThemeTransition.captureAndRecreate(act, LANGUAGE_CHANGE_MS)
			closeDialog(dialog)
		}
	}

	// One of three choices, the current one checked. onPick gets the dialog and the index picked,
	// 0 to 2: the layout's fourth option stays hidden here.
	private fun showChoiceDialog(
		act: Context,
		tag: String,
		titleRes: Int,
		options: List<CharSequence>,
		checked: Int,
		onPick: (dialog: AlertDialog, picked: Int) -> Unit
	) {
		val dialogView = layoutInflater.inflate(R.layout.dialog_select_option, null)
		val radioGroup = dialogView.findViewById<RadioGroup>(R.id.dialogRadioGroup)
		val ids = listOf(R.id.radioOption1, R.id.radioOption2, R.id.radioOption3)
		ids.forEachIndexed { index, id -> dialogView.radioButton(id).text = options[index] }
		ids.getOrNull(checked)?.let { dialogView.radioButton(it).isChecked = true }

		val dialog = AnimatedDialogBuilder(act)
			.setTitle(fromHtml(getString(titleRes)))
			.setView(dialogView)
			.showAnimated()
		trackDialog(tag, dialog)

		radioGroup.setOnCheckedChangeListener { _, checkedId ->
			onPick(dialog, ids.indexOf(checkedId))
		}
	}

	private fun bindThemeItem(view: View) {
		val textThemeStatus = view.findViewById<TextView>(R.id.textThemeStatus)
		val ctx = requireContext()
		val themeOptionsRaw = resources.getStringArray(R.array.theme_options)
		val currentTheme = PrefsManager.getSafePrefs(ctx).getInt(PrefsManager.PREF_THEME_MODE, 0)
		textThemeStatus.text = fromHtml(themeStatusText(ctx, currentTheme, themeOptionsRaw))

		view.findViewById<MaterialCardView>(R.id.itemTheme).setOnClickListener {
			showThemeDialog()
		}
	}

	private fun themeStatusText(ctx: Context, themeIdx: Int, themeOptionsRaw: Array<String>): String {
		val base = themeOptionsRaw.getOrElse(themeIdx) { themeOptionsRaw[0] }
		return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
			PrefsManager.getSafePrefs(ctx).getBoolean(PrefsManager.PREF_MONET_ACCENT, false)
		) {
			"$base, ${getString(R.string.setting_monet_accent)}"
		} else {
			base
		}
	}

	// Theme picker (+ Monet switch on Android 12+); recreate on change
	private fun showThemeDialog() {
		if (alreadyShowing(DIALOG_THEME)) return
		val act = activity ?: return
		val ctx = context ?: return
		val prefs = PrefsManager.getSafePrefs(ctx)
		val themeOptionsRaw = resources.getStringArray(R.array.theme_options)
		val themeOptions = themeOptionsRaw.map { fromHtml(it) }.toTypedArray()
		var currentTheme = prefs.getInt(PrefsManager.PREF_THEME_MODE, 0)
		val textThemeStatus = view?.findViewById<TextView>(R.id.textThemeStatus)

		val dialogView = layoutInflater.inflate(R.layout.dialog_theme_select, null)
		val radioGroup = dialogView.findViewById<RadioGroup>(R.id.dialogRadioGroup)
		val firstRadio = dialogView.radioButton(R.id.radioOption1)
		val secondRadio = dialogView.radioButton(R.id.radioOption2)
		val thirdRadio = dialogView.radioButton(R.id.radioOption3)
		val fourthRadio = dialogView.radioButton(R.id.radioOption4)
		val monetContainer = dialogView.findViewById<View>(R.id.monetContainer)
		val monetDivider = dialogView.findViewById<View>(R.id.monetDivider)
		val switchMonet = dialogView.findViewById<SwitchMaterial>(R.id.switchMonetAccent)

		firstRadio.text = themeOptions[0]
		secondRadio.text = themeOptions[1]
		thirdRadio.text = themeOptions[2]
		fourthRadio.text = themeOptions[3]
		when (currentTheme) {
			0 -> firstRadio.isChecked = true
			1 -> secondRadio.isChecked = true
			2 -> thirdRadio.isChecked = true
			3 -> fourthRadio.isChecked = true
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
				if (prefs.getBoolean(PrefsManager.PREF_MONET_ACCENT,
					false) == isChecked) return@setOnCheckedChangeListener
				prefs.edit { putBoolean(PrefsManager.PREF_MONET_ACCENT, isChecked) }
				ThemeTransition.captureAndRecreate(act, THEME_CHANGE_MS)
				closeDialog(dialog)
			}
		}

		radioGroup.setOnCheckedChangeListener { _, checkedId ->
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
			prefs.edit { putInt(PrefsManager.PREF_THEME_MODE, which) }
			// No crossfade: captureAndRecreate below recreates the activity, cutting it off mid-way.
			textThemeStatus?.text = fromHtml(themeStatusText(ctx, which, themeOptionsRaw))
			ThemeTransition.captureAndRecreate(act, THEME_CHANGE_MS)
			closeDialog(dialog)
		}
	}

	// Forgets the tracked dialog and closes it.
	private fun closeDialog(dialog: AlertDialog) {
		currentDialog = null
		currentDialogTag = null
		try { dialog.dismiss() } catch (_: Throwable) {}
	}

	private fun bindAnimationsItem(view: View) {
		val textAnimationsStatus = view.findViewById<TextView>(R.id.textAnimationsStatus)
		val ctx = requireContext()
		val animationOptionsRaw = resources.getStringArray(R.array.animation_options)
		textAnimationsStatus.text = fromHtml(animationOptionsRaw.getOrElse(
			ctx.animMode()) { animationOptionsRaw[0] })

		view.findViewById<MaterialCardView>(R.id.itemAnimations).setOnClickListener {
			showAnimationsDialog()
		}
	}

	private fun showAnimationsDialog() {
		if (alreadyShowing(DIALOG_ANIMATIONS)) return
		val act = activity ?: return
		val ctx = context ?: return
		val prefs = PrefsManager.getSafePrefs(ctx)
		val animationOptionsRaw = resources.getStringArray(R.array.animation_options)
		val textAnimationsStatus = view?.findViewById<TextView>(R.id.textAnimationsStatus)

		// The options are listed in mode order: ANIM_MODE_OFF, _SYSTEM and _SOFTWARE are 0, 1, 2.
		showChoiceDialog(act, DIALOG_ANIMATIONS, R.string.label_animations,
			animationOptionsRaw.map { fromHtml(it) }, ctx.animMode()) { dialog, mode ->
			prefs.edit { putInt(PrefsManager.PREF_ANIM_MODE, mode) }
			textAnimationsStatus?.crossfadeText(fromHtml(animationOptionsRaw[mode]))
			dialog.dismissAnimated {
				resetAnimatorScale(ctx)
			}
		}
	}

	// Opens straight to the "not found" explanation or the four Xposed options.
	private fun bindXposedCardItem(view: View) {
		view.findViewById<MaterialCardView>(R.id.itemXposed).setOnClickListener {
			showXposedDialog()
		}
	}

	private fun showXposedDialog() {
		if (alreadyShowing(DIALOG_XPOSED)) return
		val act = activity ?: return
		val dialogView = layoutInflater.inflate(R.layout.dialog_xposed, null)
		populateXposedDialogContent(dialogView)

		val builder = AnimatedDialogBuilder(act)
			.setTitle(fromHtml(getString(R.string.setting_header_xposed)))
			.setView(dialogView)
			.setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
			.setNegativeButton(fromHtml(getString(R.string.btn_patcher))) { _, _ -> showPatcherDialog() }
		// The window's wide margin above and below the card would hold it under the share it is given.
		val margin = resources.getDimensionPixelSize(R.dimen.dialog_tall_margin)
		builder.setBackgroundInsetTop(margin)
		builder.setBackgroundInsetBottom(margin)
		val dialog = builder.showAnimated()
		dialog.hostHeightGlides()
		// Through the dialog's own dispatch, not in its place, and only for this view: after a rotation
		// the dialog put back is already up when this one goes.
		dialog.setOnExternalDismissListener {
			if (xposedDialogRoot === dialogView) xposedDialogRoot = null
		}
		xposedDialogRoot = dialogView
		trackDialog(DIALOG_XPOSED, dialog)
	}

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
			textNotFound?.movementMethod = LinkMovementMethod.getInstance()
			dialogView.findViewById<TextView>(R.id.textXposedFeatures)?.text =
				fromHtml(getString(R.string.setting_xposed_not_found_features))
			return
		}

		// Show-duplicates first: its click listener makes the row clickable again, and
		// bindInterceptLinksItem ends by applying the lock, which has to come last.
		bindShowDuplicatesItem(dialogView)
		bindInterceptLinksItem(dialogView)
		bindHwidSpoofItem(dialogView)
		bindUnlockItem(dialogView)
		bindRedirectItem(dialogView)

		val unlockTargetActive = PrefsManager.isUnlockTargetActiveForModule(ctx)
		dialogView.findViewById<View>(R.id.itemUnlock)?.visibility =
			if (unlockTargetActive) View.VISIBLE else View.GONE

		// Apps a patcher listed, not PREF_LSPATCH_MODE, which Xposed force-clears - and they say
		// nothing of Xposed itself: only ModuleStatus.isModuleActive() tells if it is live too.
		val moduleActive = ModuleStatus.isModuleActive()
		val hasPatchedApps = PrefsManager.lspatchApps(PrefsManager.getSafePrefs(ctx)).isNotEmpty()
		val modeLabel = when {
			moduleActive && hasPatchedApps -> getString(R.string.label_xposed_lspatch_active)
			moduleActive -> getString(R.string.label_xposed_active)
			else -> getString(R.string.label_lspatch_active)
		}
		// Resolved at runtime, not baked in - happAccent follows Material You's system accent.
		val accent = MaterialColors.getColor(
			dialogView,
			R.attr.happAccent,
			ContextCompat.getColor(ctx, R.color.brand_purple_secondary)
		)
		// Fixed locale: some locales render formatted digits in their own numbering system, and
		// this colour is markup for a parser, not text for a person.
		val accentHex = String.format(Locale.US, "#%06X", 0xFFFFFF and accent)
		dialogView.findViewById<TextView>(R.id.textXposedStatus)?.text =
			fromHtml(getString(R.string.label_xposed_status, "<font color=\"$accentHex\">$modeLabel</font>"))
	}

	// The run itself lives in PatchSession, which a rebuilt screen reads again; this screen holds the
	// dialog it shows for it.
	private var patchProgressDialog: AlertDialog? = null
	// Version fetch for the selected app; restarted on each selection change
	private var patcherVersionFetchJob: Job? = null
	// Reads the installed apps and their first icons while the dialog is still on its first page
	private var patcherWarmupJob: Job? = null

	// What the dialog has chosen. Fields, not locals, so a dialog put back for a new screen keeps it.
	private var patchSource: PatchSource = PatchSource.Release(PatchTarget.HAPP)
	private var sigBypassLevel = LSPortableRunner.DEFAULT_SIG_BYPASS_LEVEL

	// Proceeds even if the uninstall was cancelled; the installer then refuses on its own
	private val patchUninstallLauncher = registerForActivityResult(
		ActivityResultContracts.StartActivityForResult()
	) { PatchSession.install() }

	private fun showPatcherDialog(page: String? = null) {
		if (alreadyShowing(DIALOG_PATCHER)) return
		val act = activity ?: return
		val title = fromHtml(getString(R.string.dialog_title_lsportable))
		patcherPage = page
		val pages = DialogPages(act, title, onPage = { patcherPage = it }) {
			layoutInflater.inflate(R.layout.dialog_patcher, it, false)
		}
		val home = pages.home
		val inputTarget = home.findViewById<AutoCompleteTextView>(R.id.inputPatcherTarget)
		val textPackageName = home.findViewById<TextView>(R.id.textPatcherPackageName)
		val textVersionName = home.findViewById<TextView>(R.id.textPatcherVersionName)
		home.findViewById<TextView>(R.id.textPatcherInfo).apply {
			setHtmlText(R.string.msg_patch_confirm)
			movementMethod = LinkMovementMethod.getInstance()
		}

		// The files of an app that was patched and reinstalled since are gone.
		val chosen = patchSource
		if (chosen is PatchSource.Installed && !chosen.app.apks.all { it.exists() }) {
			patchSource = PatchSource.Release(PatchTarget.HAPP)
		}
		fun showInfo() = showPatchInfo(patchSource, textPackageName, textVersionName)
		showInfo()

		fun installedAppsPage() = DialogPages.Page(
			fromHtml(getString(R.string.dialog_title_installed_apps)),
			PAGE_INSTALLED_APPS,
			buttons = false,
			textInput = true,
			tall = true
		) { parent ->
			InstalledAppsPicker { app ->
				patchSource = PatchSource.Installed(app)
				inputTarget.setText(app.label, false)
				showInfo()
				pages.close()
			}.create(parent)
		}

		val releases = PatchTarget.entries
		val targetOptions = releases.map { fieldLabel(PatchSource.Release(it)) } +
			getString(R.string.label_patcher_installed)
		inputTarget.setOptions(targetOptions, fieldLabel(patchSource)) { position ->
			if (position < releases.size) {
				patchSource = PatchSource.Release(releases[position])
				showInfo()
			} else {
				// The field keeps the current choice until an app is picked.
				inputTarget.setText(fieldLabel(patchSource), false)
				pages.open(installedAppsPage())
			}
		}

		// The option's position in the list is its bypass level
		val sigBypassLabels = listOf(
			R.string.label_sig_bypass_0, R.string.label_sig_bypass_1,
			R.string.label_sig_bypass_2, R.string.label_sig_bypass_3
		).map { getString(it) }
		home.findViewById<AutoCompleteTextView>(R.id.inputSigBypass)
			.setOptions(sigBypassLabels, sigBypassLabels[sigBypassLevel]) { sigBypassLevel = it }

		val dialog = AnimatedDialogBuilder(act)
			.setTitle(title)
			.setView(pages.view)
			.setNegativeButton(fromHtml(getString(R.string.btn_no)), null)
			.setPositiveButton(fromHtml(getString(R.string.btn_patcher_start))) { _, _ ->
				PatchSession.start(act, patchSource, sigBypassLevel)
			}
			.showAnimated()
		dialog.setOnExternalDismissListener {
			patcherVersionFetchJob?.cancel()
			patcherWarmupJob?.cancel()
		}
		trackDialog(DIALOG_PATCHER, dialog)
		pages.attach(dialog)
		if (page == PAGE_INSTALLED_APPS) pages.open(installedAppsPage(), animated = false)
		warmUpInstalledApps(act.applicationContext)
	}

	private fun AutoCompleteTextView.setOptions(
		options: List<String>,
		current: String,
		onPick: (Int) -> Unit
	) {
		setAdapter(ArrayAdapter(context, AndroidR.layout.simple_list_item_1, options))
		setText(current, false)
		setOnItemClickListener { _, _, position, _ -> onPick(position) }
	}

	// A release is marked as coming from GitHub.
	private fun fieldLabel(source: PatchSource) = when (source) {
		is PatchSource.Release -> getString(R.string.label_patcher_release, source.label)
		is PatchSource.Installed -> source.label
	}

	// A release shows the latest version GitHub has; an installed app, the one it is.
	private fun showPatchInfo(source: PatchSource, packageName: TextView, versionName: TextView) {
		packageName.text = getString(R.string.label_patcher_package, source.packageName)
		patcherVersionFetchJob?.cancel()
		if (source is PatchSource.Installed) {
			versionName.text = getString(R.string.label_patcher_version_name, source.app.versionName)
			return
		}
		val release = (source as PatchSource.Release).target.source
		versionName.text = getString(R.string.label_patcher_version_name, "…")
		patcherVersionFetchJob = viewLifecycleOwner.lifecycleScope.launch {
			val latest = withContext(Dispatchers.IO) { ReleaseDownloader.fetchLatest(release) }
			versionName.text = getString(R.string.label_patcher_version_name, latest?.versionName ?: "?")
		}
	}

	private fun warmUpInstalledApps(ctx: Context) {
		InstalledApps.refresh(ctx)
		patcherWarmupJob?.cancel()
		patcherWarmupJob = viewLifecycleOwner.lifecycleScope.launch {
			AppIcons.prefetch(ctx, InstalledApps.list(ctx).take(WARMUP_ICONS))
		}
	}

	// Follows the run: its dialog while it works, then how it ended. Begun with the view, so a screen
	// rebuilt in the middle of a run takes it up where it is.
	private fun followPatchSession() {
		viewLifecycleOwner.lifecycleScope.launch {
			viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
				launch { PatchSession.progress.collect(::showPatchProgress) }
				launch { PatchSession.result.collect { showPatchResult() } }
				launch { PatchSession.requests.collect(::openSystemScreen) }
			}
		}
	}

	private fun showPatchProgress(progress: PatchSession.Progress?) {
		val text = when (progress) {
			null -> return dismissPatchProgressDialog()
			is PatchSession.Progress.Downloading -> downloadText(progress)
			PatchSession.Progress.Patching -> getString(R.string.status_patch_patching)
		}
		patchProgressDialog?.let {
			it.findViewById<TextView>(AndroidR.id.message)?.text = text
			return
		}
		val act = activity ?: return
		val dialog = AnimatedDialogBuilder(act)
			.setTitle(fromHtml(getString(R.string.dialog_title_patching)))
			.setMessage(text)
			.showAnimated()
		dialog.blockOutsideTapDismiss()
		// Only Back reaches this while it is still the current dialog; our own dismiss clears it first
		dialog.setOnExternalDismissListener {
			if (patchProgressDialog === dialog) {
				patchProgressDialog = null
				PatchSession.cancel()
			}
		}
		patchProgressDialog = dialog
	}

	private fun downloadText(download: PatchSession.Progress.Downloading): String {
		if (download.total <= 0) return getString(R.string.status_patch_downloading, download.name)
		return getString(
			R.string.status_patch_downloading_progress,
			download.name,
			megabytes(download.downloaded),
			megabytes(download.total),
			(download.downloaded * 100 / download.total).toInt()
		)
	}

	private fun megabytes(bytes: Long): String = String.format(Locale.US, "%.1f", bytes / (1024.0 * 1024.0))

	private fun dismissPatchProgressDialog() {
		val dialog = patchProgressDialog ?: return
		patchProgressDialog = null
		dialog.dismissAnimated()
	}

	// How the run ended, shown until the person has seen it: also on a screen that was not there when
	// it ended, or that was rebuilt while the dialog was up.
	private fun showPatchResult() {
		val act = activity ?: return
		val result = PatchSession.result.value ?: return
		val installed = result is PatchSession.Result.Installed
		val tag = if (installed) DIALOG_PATCHED else DIALOG_PATCH_ERROR
		if (alreadyShowing(tag)) return
		val builder = AnimatedDialogBuilder(act)
		when (result) {
			is PatchSession.Result.Installed -> describeInstalled(builder, result.source)
			is PatchSession.Result.DownloadFailed ->
				describeError(builder, getString(R.string.msg_patch_download_failed, result.name))
			is PatchSession.Result.InstallFailed ->
				describeError(builder, getString(R.string.msg_patch_install_failed, result.message ?: "?"))
			is PatchSession.Result.PatchFailed -> describeError(builder, result.text)
		}
		val dialog = builder.showAnimated()
		if (result is PatchSession.Result.Installed) wireDetailsButton(dialog, result.source.packageName)
		if (!installed) dialog.findViewById<TextView>(AndroidR.id.message)?.setTextIsSelectable(true)
		// Before trackDialog, whose own listener clears the dialog this one is told apart by: a dialog
		// put back for a new screen is not one the person has seen.
		dialog.setOnExternalDismissListener {
			if (currentDialog === dialog) PatchSession.acknowledge(result)
		}
		trackDialog(tag, dialog)
	}

	// Details opens the app's system screen. Its own listener, so the dialog stays for the person
	// to come back to.
	private fun wireDetailsButton(dialog: AlertDialog, packageName: String) {
		dialog.getButton(DialogInterface.BUTTON_NEUTRAL)?.setOnClickListener {
			val details = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, "package:$packageName".toUri())
			try { startActivity(details) } catch (_: ActivityNotFoundException) {}
		}
	}

	// Launch is offered only for an app that has a screen to open.
	private fun describeInstalled(builder: AnimatedDialogBuilder, source: PatchSource) {
		val pm = requireContext().packageManager
		// The version that is installed now, which for a release is the one just downloaded.
		val version = runCatching { pm.getPackageInfo(source.packageName, 0).versionName }.getOrNull()
		builder
			.setTitle(fromHtml(getString(R.string.dialog_title_patch_installed)))
			.setMessage("${source.label} ${version ?: "?"}\n${source.packageName}")
			.setNeutralButton(fromHtml(getString(R.string.btn_details)), null)
			.setNegativeButton(fromHtml(getString(R.string.btn_ok)), null)
		pm.getLaunchIntentForPackage(source.packageName)?.let { launch ->
			builder.setPositiveButton(fromHtml(getString(R.string.btn_launch))) { _, _ -> startActivity(launch) }
		}
	}

	// The error and nothing else: it is on the screen, to be read or selected and copied by hand.
	private fun describeError(builder: AnimatedDialogBuilder, text: String) {
		builder
			.setTitle(fromHtml(getString(R.string.dialog_title_error)))
			.setMessage(text)
			.setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
	}

	private fun openSystemScreen(request: PatchSession.Request) {
		when (request) {
			is PatchSession.Request.Uninstall ->
				patchUninstallLauncher.launch(LSPortableRunner.uninstallIntent(request.packageName))
			is PatchSession.Request.Confirm -> activity?.startActivity(request.intent)
		}
	}

	// Opens straight to the "not compatible" explanation or the Force-Happanion test toggle.
	private fun bindHappanionCardItem(view: View) {
		view.findViewById<MaterialCardView>(R.id.itemHappanion).setOnClickListener {
			showHappanionDialog()
		}
	}

	private fun showHappanionDialog() {
		if (alreadyShowing(DIALOG_HAPPANION)) return
		val act = activity ?: return
		val ctx = context ?: return
		val dialogView = layoutInflater.inflate(R.layout.dialog_happanion, null)
		populateHappanionDialogContent(dialogView)

		// The label and listener are set again in applyHappanionInstallButton once the dialog
		// exists, so returning from the installer swaps "Install" for "Uninstall" in place.
		val dialog = AnimatedDialogBuilder(act)
			.setTitle(fromHtml(getString(R.string.setting_header_happanion)))
			.setView(dialogView)
			.setNeutralButton(fromHtml(getString(R.string.btn_info)), null)
			.setNegativeButton(
				fromHtml(getString(
					if (HappanionBridge.isCompatibleVersionInstalled(ctx)) R.string.btn_uninstall
					else R.string.btn_install
				)),
				null
			)
			.setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
			.showAnimated()

		// Own listener, not the deferred one, so it doesn't close the dialog either - same
		// reason as the Install/Uninstall button below.
		dialog.getButton(DialogInterface.BUTTON_NEUTRAL)?.setOnClickListener {
			try { startActivity(HappanionBridge.projectPageIntent()) } catch (_: Throwable) {}
		}
		applyHappanionInstallButton(dialog)
		// As for the Xposed dialog: through the dispatch, and only for this view.
		dialog.setOnExternalDismissListener {
			if (happanionDialogRoot === dialogView) happanionDialogRoot = null
		}
		happanionDialogRoot = dialogView
		trackDialog(DIALOG_HAPPANION, dialog)
	}

	// Holds the just-downloaded APK between "remove what's there" and "install this" when the
	// package is occupied by the original Happ rather than Happanion.
	private var pendingHappanionApk: File? = null

	// The download in flight: a dialog refreshed on resume must not offer a second one writing the
	// same file under it.
	private var happanionDownload: Job? = null

	// A second tap before the prompt shows would ask again, and Android answers that one at once
	// with a refusal.
	private var askingLocalNetwork = false

	// LAN mode switches on only with leave to reach the local network, where the system asks for it.
	private val localNetworkPermission =
		registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
			askingLocalNetwork = false
			val root = view ?: return@registerForActivityResult
			if (granted) {
				applyLanMode(root, true)
			} else {
				Toast.makeText(root.context, R.string.toast_lan_permission_denied, Toast.LENGTH_SHORT).show()
			}
		}

	private val happOriginalUninstallLauncher = registerForActivityResult(
		ActivityResultContracts.StartActivityForResult()
	) { result ->
		val ctx = context ?: return@registerForActivityResult
		val apk = pendingHappanionApk ?: return@registerForActivityResult
		pendingHappanionApk = null
		// EXTRA_RETURN_RESULT makes this RESULT_OK only once the original Happ is actually gone -
		// installing over it otherwise would just fail on the signature mismatch.
		if (result.resultCode != Activity.RESULT_OK) return@registerForActivityResult
		try {
			startActivity(HappanionBridge.installApkIntent(ctx, apk))
		} catch (_: Throwable) {
			Toast.makeText(ctx, getString(R.string.toast_happanion_install_failed),
				Toast.LENGTH_LONG).show()
		}
	}

	// Whichever action fits what's installed; listener on the button so it won't close the dialog.
	private fun applyHappanionInstallButton(dialog: AlertDialog) {
		val ctx = context ?: return
		val button = dialog.getButton(DialogInterface.BUTTON_NEGATIVE) ?: return
		val compatible = HappanionBridge.isCompatibleVersionInstalled(ctx)

		button.text = fromHtml(getString(if (compatible) R.string.btn_uninstall else R.string.btn_install))
		button.isEnabled = happanionDownload?.isActive != true
		button.setOnClickListener {
			if (compatible) {
				if (!HappanionBridge.isInstalled(ctx)) return@setOnClickListener
				// Off until onResume enables it again, so a double tap opens the uninstaller once.
				button.isEnabled = false
				try {
					startActivity(HappanionBridge.uninstallIntent())
				} catch (_: Throwable) {
					button.isEnabled = true
				}
			} else {
				downloadAndInstallHappanion(button)
			}
		}
	}

	// Fetches the latest release and, if the package is free, installs it directly; if the
	// original Happ occupies it, offers to remove that first and installs right after.
	private fun downloadAndInstallHappanion(button: Button) {
		if (happanionDownload?.isActive == true) return
		button.isEnabled = false
		happanionDownload = viewLifecycleOwner.lifecycleScope.launch {
			val ctx = context
			val apk = if (ctx != null) HappanionBridge.downloadLatestRelease(ctx) else null
			val stillCtx = context ?: return@launch
			if (apk == null) {
				Toast.makeText(stillCtx, getString(R.string.toast_happanion_download_failed),
					Toast.LENGTH_LONG).show()
				button.isEnabled = true
				return@launch
			}
			if (HappanionBridge.originalHappInstalled(stillCtx)) {
				pendingHappanionApk = apk
				try {
					happOriginalUninstallLauncher.launch(HappanionBridge.uninstallIntent())
				} catch (_: Throwable) {
					pendingHappanionApk = null
					button.isEnabled = true
				}
			} else {
				try {
					startActivity(HappanionBridge.installApkIntent(stillCtx, apk))
				} catch (_: Throwable) {
					Toast.makeText(stillCtx, getString(R.string.toast_happanion_install_failed),
						Toast.LENGTH_LONG).show()
				}
				button.isEnabled = true
			}
		}
	}

	// "Send every link" shows only for a build that speaks this protocol - no other could answer it.
	private fun populateHappanionDialogContent(dialogView: View) {
		val ctx = context ?: return
		val compatible = HappanionBridge.isCompatibleVersionInstalled(ctx)

		dialogView.findViewById<View>(R.id.happanionNotFoundBlock)?.visibility =
			if (compatible) View.GONE else View.VISIBLE
		dialogView.findViewById<View>(R.id.itemForceHappanion)?.visibility =
			if (compatible) View.VISIBLE else View.GONE

		if (!compatible) {
			dialogView.findViewById<TextView>(R.id.textHappanionNotFound)?.text =
				fromHtml(getString(R.string.setting_happanion_not_found))
			return
		}

		bindForceHappanionItem(dialogView)
	}

	private fun bindHwidSpoofItem(view: View) {
		val row = view.findViewById<View>(R.id.rowHwidSpoofToggle)
		val switch = view.findViewById<SwitchMaterial>(R.id.switchHwidSpoof)
		val ctx = requireContext()
		switch.isChecked = PrefsManager.isHwidSpoofEnabled(ctx)
		updateHwidSpoofStatus(view, animate = false)
		row.setOnClickListener {
			val newState = !switch.isChecked
			PrefsManager.getSafePrefs(ctx).edit {
				putBoolean(PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION, newState)
			}
			switch.isChecked = newState
			updateHwidSpoofStatus(view)
			PrefsManager.broadcastSettings(ctx)
		}
	}

	// animate = false for the first state of a dialog that is opening: it is there from the start.
	private fun updateHwidSpoofStatus(view: View, animate: Boolean = true) {
		val status = view.findViewById<TextView>(R.id.textHwidSpoofStatus) ?: return
		val ctx = context ?: return
		val prefs = PrefsManager.getSafePrefs(ctx)
		val toggleOn = PrefsManager.isHwidSpoofEnabled(ctx)
		val fieldActive = prefs.getBoolean(PrefsManager.PREF_USE_CUSTOM_HWID_INPUT, false)
		val custom = prefs.getString(PrefsManager.PREF_CUSTOM_HWID, "")?.trim().orEmpty()

		val newStatus = when {
			toggleOn && !fieldActive -> getString(R.string.label_hwid_spoof_enable_field)
			toggleOn && fieldActive && custom.isNotEmpty() ->
				getString(R.string.label_hwid_spoof_current, custom)
			else -> null
		}
		val visibility = if (newStatus != null) View.VISIBLE else View.GONE
		if (!animate || ctx.skipProgrammaticAnimations() ||
			(status.isVisible && status.height == 0)) {
			status.animate().cancel()
			status.alpha = 1f
			status.updateLayoutParams<ViewGroup.MarginLayoutParams> { bottomMargin = 0 }
			newStatus?.let { status.text = it }
			status.visibility = visibility
			return
		}

		// A fading line keeps its place but gives up its space (negative bottom margin): the description
		// slides over it, and it is never drawn over the description.
		val givesUpSpace = (status.layoutParams as ViewGroup.MarginLayoutParams).bottomMargin < 0
		val takeSpace = { status.updateLayoutParams<ViewGroup.MarginLayoutParams> { bottomMargin = 0 } }

		// A line still hidden just takes the text; crossfadeText no-ops on unchanged text.
		if (newStatus != null) {
			if (status.isVisible) status.crossfadeText(newStatus) else status.text = newStatus
		}
		// Already there, or already on its way: a second refresh must not restart or cut the fade short.
		val settled = if (visibility == View.VISIBLE) status.isVisible && !givesUpSpace
			else !status.isVisible || givesUpSpace
		if (settled) return

		val duration = ctx.stateChangeDuration(R.integer.duration_standard_transition)
		status.animate().cancel()
		if (visibility == View.VISIBLE) {
			status.glideHeights {
				takeSpace()
				// Back from a fade that was under way: up from where it got to.
				if (status.isVisible) status.animate().alpha(1f).setDuration(duration).withLayer().start()
				else status.fadeIn(duration)
			}
		} else {
			status.glideHeights {
				status.updateLayoutParams<ViewGroup.MarginLayoutParams> { bottomMargin = -(status.height + topMargin) }
			}
			status.animate().alpha(0f).setDuration(duration).withLayer().withEndAction {
				// A cancelled fade ends here too; only a finished one has gone clear.
				if (status.alpha != 0f) return@withEndAction
				status.visibility = View.GONE
				status.alpha = 1f
				takeSpace()
			}.start()
		}
	}

	private fun bindUnlockItem(view: View) {
		val item = view.findViewById<View>(R.id.itemUnlock)
		val switch = view.findViewById<SwitchMaterial>(R.id.switchUnlock)
		val ctx = requireContext()
		switch.isChecked = PrefsManager.isUnlockHookEnabled(ctx)
		val update: (Boolean) -> Unit = { checked ->
			PrefsManager.getSafePrefs(ctx).edit {
				putBoolean(PrefsManager.PREF_HOOK_HAPP_UNLOCK_SETTINGS, checked)
			}
			switch.isChecked = checked
			PrefsManager.broadcastSettings(ctx)
		}
		item.setOnClickListener { update(!switch.isChecked) }
	}

	private fun bindRedirectItem(view: View) {
		val item = view.findViewById<View>(R.id.itemRedirect)
		val switch = view.findViewById<SwitchMaterial>(R.id.switchRedirect)
		val ctx = requireContext()
		switch.isChecked = PrefsManager.isRedirectIntentsEnabled(ctx)
		val update: (Boolean) -> Unit = { checked ->
			PrefsManager.getSafePrefs(ctx).edit { putBoolean(PrefsManager.PREF_REDIRECT_INTENTS, checked) }
			switch.isChecked = checked
			PrefsManager.broadcastSettings(ctx)
		}
		item.setOnClickListener { update(!switch.isChecked) }
	}

	// Locked while link interception (below) is off.
	private fun bindShowDuplicatesItem(view: View) {
		val item = view.findViewById<View>(R.id.itemShowDuplicates)
		val switch = view.findViewById<SwitchMaterial>(R.id.switchShowDuplicates)
		val ctx = requireContext()
		switch.isChecked = PrefsManager.getSafePrefs(ctx).getBoolean(PrefsManager.PREF_SHOW_DUPLICATES, false)
		val update: (Boolean) -> Unit = { checked ->
			PrefsManager.getSafePrefs(ctx).edit { putBoolean(PrefsManager.PREF_SHOW_DUPLICATES, checked) }
			switch.isChecked = checked
			PrefsManager.broadcastSettings(ctx)
		}
		item.setOnClickListener { update(!switch.isChecked) }
	}

	// Locked, not just greyed: a tap while off would flip a setting that means nothing yet.
	private fun applyShowDuplicatesLock(dialogView: View, interceptEnabled: Boolean,
		animate: Boolean = true) {
		val item = dialogView.findViewById<View>(R.id.itemShowDuplicates) ?: return
		val switch = dialogView.findViewById<SwitchMaterial>(R.id.switchShowDuplicates)
		val title = dialogView.findViewById<TextView>(R.id.textShowDuplicatesTitle)
		val desc = dialogView.findViewById<TextView>(R.id.textShowDuplicatesDesc)

		// Capture the on-screen colours before flipping isEnabled, then fade old to new.
		val titleFrom = title?.currentTextColor
		val descFrom = desc?.currentTextColor

		// Clickability goes first so a locked row stops responding immediately.
		item.isEnabled = interceptEnabled
		item.isClickable = interceptEnabled
		title?.isEnabled = interceptEnabled
		desc?.isEnabled = interceptEnabled

		val instant = !animate || context?.skipProgrammaticAnimations() != false
		if (instant) {
			switch?.isEnabled = interceptEnabled
			return
		}
		if (title != null && titleFrom != null) fadeTextColorFrom(title, titleFrom)
		if (desc != null && descFrom != null) fadeTextColorFrom(desc, descFrom)
		if (switch != null) fadeSwitchState(switch, interceptEnabled)
	}

	// Flips the enabled state and interpolates thumb/track tints, which Material 2 would snap.
	private fun fadeSwitchState(switch: SwitchMaterial, enabled: Boolean) {
		if (switch.isEnabled == enabled) return

		val checked = switch.isChecked
		val fromState = controlState(switch.isEnabled, checked)

		// Before cancelling: mid-animation the switch carries a flat colour, which is the
		// current one, so a restart stays seamless.
		val thumbFrom = switch.thumbTintList?.getColorForState(fromState, 0)
		val trackFrom = switch.trackTintList?.getColorForState(fromState, 0)

		// Cancel only now, restoring the real tint lists - reading them earlier would have
		// captured a flat midpoint as "the original".
		(switch.getTag(R.id.tag_label_color_fade) as? ValueAnimator)?.cancel()

		val thumbList = switch.thumbTintList
		val trackList = switch.trackTintList
		if (thumbList == null || trackList == null || thumbFrom == null || trackFrom == null) {
			switch.isEnabled = enabled
			return
		}

		val toState = controlState(enabled, checked)
		val thumbTo = thumbList.getColorForState(toState, thumbList.defaultColor)
		val trackTo = trackList.getColorForState(toState, trackList.defaultColor)

		switch.isEnabled = enabled
		if (thumbFrom == thumbTo && trackFrom == trackTo) return

		val argb = ArgbEvaluator()
		val restore = {
			switch.thumbTintList = thumbList
			switch.trackTintList = trackList
			switch.setTag(R.id.tag_label_color_fade, null)
		}
		val animator = ValueAnimator.ofFloat(0f, 1f).apply {
			duration = switch.context.stateChangeDuration(R.integer.duration_standard_transition)
			addUpdateListener {
				val fraction = it.animatedFraction
				switch.thumbTintList = ColorStateList.valueOf(
					argb.evaluate(fraction, thumbFrom, thumbTo) as Int
				)
				switch.trackTintList = ColorStateList.valueOf(
					argb.evaluate(fraction, trackFrom, trackTo) as Int
				)
			}
			addListener(object : AnimatorListenerAdapter() {
				override fun onAnimationEnd(animation: Animator) = restore()
				override fun onAnimationCancel(animation: Animator) = restore()
			})
		}
		switch.setTag(R.id.tag_label_color_fade, animator)
		animator.start()
	}

	private fun fadeTextColorFrom(view: TextView, fromColor: Int) {
		// Cancel first, or reading the target colour picks up a running animation's flat midpoint.
		(view.getTag(R.id.tag_label_color_fade) as? ValueAnimator)?.cancel()
		val toColor = view.currentTextColor
		if (fromColor == toColor) return
		// setTextColor(Int) replaces the whole state list - keep the original to restore later.
		val originalColors = view.textColors
		val argb = ArgbEvaluator()
		val restore = {
			view.setTextColor(originalColors)
			view.setTag(R.id.tag_label_color_fade, null)
		}
		val animator = ValueAnimator.ofFloat(0f, 1f).apply {
			duration = view.context.stateChangeDuration(R.integer.duration_standard_transition)
			addUpdateListener {
				view.setTextColor(argb.evaluate(it.animatedFraction, fromColor, toColor) as Int)
			}
			addListener(object : AnimatorListenerAdapter() {
				override fun onAnimationEnd(animation: Animator) = restore()
				override fun onAnimationCancel(animation: Animator) = restore()
			})
		}
		view.setTag(R.id.tag_label_color_fade, animator)
		animator.start()
	}

	// Sends every happ:// link through Happanion. Testing only - read in-process by MainActivity,
	// so no need to broadcast to a hooked process.
	private fun bindForceHappanionItem(view: View) {
		val item = view.findViewById<View>(R.id.itemForceHappanion)
		val switch = view.findViewById<SwitchMaterial>(R.id.switchForceHappanion)
		val prefs = PrefsManager.getSafePrefs(requireContext())
		switch.isChecked = prefs.getBoolean(PrefsManager.PREF_FORCE_HAPPANION, false)
		val update: (Boolean) -> Unit = { checked ->
			prefs.edit { putBoolean(PrefsManager.PREF_FORCE_HAPPANION, checked) }
			switch.isChecked = checked
		}
		item.setOnClickListener { update(!switch.isChecked) }
	}

	private fun bindInterceptLinksItem(view: View) {
		val item = view.findViewById<View>(R.id.itemInterceptLinks)
		val switch = view.findViewById<SwitchMaterial>(R.id.switchInterceptLinks)
		val ctx = requireContext()
		switch.isChecked = PrefsManager.isInterceptEnabled(ctx)
		applyShowDuplicatesLock(view, switch.isChecked, animate = false)
		val update: (Boolean) -> Unit = { checked ->
			PrefsManager.getSafePrefs(ctx).edit { putBoolean(PrefsManager.PREF_INTERCEPT_ENABLED, checked) }
			switch.isChecked = checked
			PrefsManager.broadcastSettings(ctx)
			applyShowDuplicatesLock(view, checked)
		}
		item.setOnClickListener { update(!switch.isChecked) }
	}

	// Conversion for manually pasted or fetched profiles, shown to the person as "Profiles".
	private fun bindProcessManualScopeItem(view: View) {
		view.findViewById<TextView>(R.id.textProcessManualScopeDesc)
			.setHtmlText(R.string.setting_process_scope_manual_desc)
		view.findViewById<MaterialCardView>(R.id.itemProcessManualScope).setOnClickListener {
			showProcessScopeDialog(PrefsManager.SCOPE_MANUAL)
		}
	}

	// Conversion for the background Bridge subscription, shown to the person as "Subscription".
	private fun bindProcessServerScopeItem(view: View) {
		view.findViewById<TextView>(R.id.textProcessServerScopeDesc)
			.setHtmlText(R.string.setting_process_scope_server_desc)
		view.findViewById<MaterialCardView>(R.id.itemProcessServerScope).setOnClickListener {
			showProcessScopeDialog(PrefsManager.SCOPE_SERVER)
		}
	}

	// The state a ColorStateList is queried with: target colours come from the XML selectors the
	// layout uses (dialog_control_selector / dialog_label_selector).
	private fun controlState(enabled: Boolean, checked: Boolean): IntArray = intArrayOf(
		if (enabled) AndroidR.attr.state_enabled else -AndroidR.attr.state_enabled,
		if (checked) AndroidR.attr.state_checked else -AndroidR.attr.state_checked
	)

	private fun animateCheckboxTint(
		check: MaterialCheckBox,
		fromChecked: Boolean,
		toChecked: Boolean,
		animate: Boolean
	) {
		val ctx = context ?: return
		checkboxTintAnimator?.cancel()
		checkboxTintAnimator = null

		val tintCsl = ContextCompat.getColorStateList(ctx,
			R.color.dialog_control_selector)
		val labelCsl = ContextCompat.getColorStateList(ctx,
			R.color.dialog_label_selector)

		fun restoreStateLists() {
			check.buttonTintList = tintCsl
			check.buttonIconTintList = tintCsl
			if (labelCsl != null) check.setTextColor(labelCsl)
		}

		if (tintCsl == null || labelCsl == null) return

		val fromState = controlState(enabled = true, checked = fromChecked)
		val toState = controlState(enabled = true, checked = toChecked)
		val tintFrom = tintCsl.getColorForState(fromState, tintCsl.defaultColor)
		val tintTo = tintCsl.getColorForState(toState, tintCsl.defaultColor)
		val labelFrom = labelCsl.getColorForState(fromState, labelCsl.defaultColor)
		val labelTo = labelCsl.getColorForState(toState, labelCsl.defaultColor)

		val nothingToDo = tintFrom == tintTo && labelFrom == labelTo
		if (!animate || nothingToDo || ctx.skipProgrammaticAnimations()) {
			restoreStateLists()
			return
		}

		val duration = ctx.stateChangeDuration(R.integer.duration_standard_transition)

		val argb = ArgbEvaluator()
		checkboxTintAnimator = ValueAnimator.ofFloat(0f, 1f).apply {
			this.duration = duration
			addUpdateListener { anim ->
				val fraction = anim.animatedFraction
				val tint = argb.evaluate(fraction, tintFrom, tintTo) as Int
				val label = argb.evaluate(fraction, labelFrom, labelTo) as Int
				check.buttonTintList = ColorStateList.valueOf(tint)
				check.buttonIconTintList = ColorStateList.valueOf(tint)
				check.setTextColor(label)
			}
			addListener(object : AnimatorListenerAdapter() {
				override fun onAnimationEnd(animation: Animator) {
					// Back to the XML selectors: the re-enabled checkbox recolours on later taps.
					restoreStateLists()
					checkboxTintAnimator = null
				}
			})
			start()
		}
	}

	// Base64 output + Xray conversion mode for one scope, via process_b64_/process_mode_<scope>,
	// with the URI mode's options as a page of the same dialog.
	private fun showProcessScopeDialog(scope: String, page: String? = null) {
		val dialogTag = if (scope == PrefsManager.SCOPE_MANUAL) DIALOG_PROCESS_SCOPE_MANUAL
			else DIALOG_PROCESS_SCOPE_SERVER
		if (alreadyShowing(dialogTag)) return
		val act = activity ?: return
		val ctx = context ?: return
		val prefs = PrefsManager.getSafePrefs(ctx)

		val titleRes = if (scope == PrefsManager.SCOPE_MANUAL) R.string.setting_process_scope_manual
			else R.string.setting_process_scope_server
		val title = fromHtml(getString(titleRes))
		scopePage = page
		val pages = DialogPages(ctx, title, onPage = { scopePage = it }) {
			layoutInflater.inflate(R.layout.dialog_process_scope, it, false)
		}
		val dialogView = pages.home
		dialogView.findViewById<TextView>(R.id.textProcessLimits).apply {
			text = fromHtml(getString(R.string.setting_process_limits))
			movementMethod = LinkMovementMethod.getInstance()
		}
		val checkB64 = dialogView.findViewById<MaterialCheckBox>(R.id.checkDecodeBase64)
		val radioOff = dialogView.radioButton(R.id.radioModeOff)
		val radioSingBox = dialogView.radioButton(R.id.radioModeSingBox)
		val radioMihomo = dialogView.radioButton(R.id.radioModeMihomo)
		val radioUri = dialogView.radioButton(R.id.radioModeUri)
		val modeRadios = listOf(radioOff, radioSingBox, radioMihomo, radioUri)

		var userB64Choice = PrefsManager.userBase64Choice(prefs, scope)

		// Belongs to the person in every mode: the converter reads a base64 subscription anyway,
		// so the checkbox says what the answer should look like, not what the input may be.
		fun applyMode(
			selected: MaterialRadioButton,
			animate: Boolean = true
		) {
			val wasChecked = checkB64.isChecked

			modeRadios.forEach { it.isChecked = (it === selected) }
			checkB64.isChecked = userB64Choice

			animateCheckboxTint(
				checkB64,
				fromChecked = wasChecked,
				toChecked = checkB64.isChecked,
				animate = animate
			)
		}

		val initialRadio = when (PrefsManager.resolveConversionMode(prefs, scope)) {
			PrefsManager.MODE_SINGBOX -> radioSingBox
			PrefsManager.MODE_MIHOMO -> radioMihomo
			PrefsManager.MODE_URI -> radioUri
			else -> radioOff
		}
		applyMode(initialRadio, animate = false)

		checkB64.setOnCheckedChangeListener { _, isChecked ->
			userB64Choice = isChecked
		}

		// Not a RadioGroup: the radios sit in rows, which its direct-child-only auto-exclusion
		// wouldn't see.
		modeRadios.forEach { radio ->
			radio.setOnClickListener { applyMode(radio) }
		}

		val dialog = AnimatedDialogBuilder(act)
			.setTitle(title)
			.setView(pages.view)
			.setPositiveButton(fromHtml(getString(R.string.btn_ok))) { _, _ ->
				val mode = when {
					radioSingBox.isChecked -> PrefsManager.MODE_SINGBOX
					radioMihomo.isChecked -> PrefsManager.MODE_MIHOMO
					radioUri.isChecked -> PrefsManager.MODE_URI
					else -> PrefsManager.MODE_OFF
				}
				prefs.edit {
					putBoolean(PrefsManager.base64ChoiceKey(scope), userB64Choice)
					putString(PrefsManager.conversionModeKey(scope), mode)
				}
				PrefsManager.broadcastSettings(ctx)
			}
			.showAnimated()
		trackDialog(dialogTag, dialog)
		pages.attach(dialog)

		// Built once resolveConversionMode above has settled this scope's conversion settings.
		dialogView.findViewById<ImageView>(R.id.btnModeUriSettings).setOnClickListener {
			pages.open(uriOptionsPage(scope, prefs))
		}
		if (page == PAGE_URI_OPTIONS) pages.open(uriOptionsPage(scope, prefs), animated = false)
	}

	// The URI mode's options: the two boxes as saved, written back when OK takes the page.
	private fun uriOptionsPage(scope: String, prefs: SharedPreferences): DialogPages.Page {
		val singBoxKey = PrefsManager.uriDropIncompatibleKey(scope)
		val mihomoKey = PrefsManager.uriDropMihomoKey(scope)
		fun View.checkBox(id: Int) = findViewById<MaterialCheckBox>(id)
		return DialogPages.Page(
			fromHtml(getString(R.string.setting_process_mode_uri)),
			PAGE_URI_OPTIONS,
			onOk = {
				prefs.edit {
					putBoolean(singBoxKey, it.checkBox(R.id.checkDropIncompatible).isChecked)
					putBoolean(mihomoKey, it.checkBox(R.id.checkDropIncompatibleMihomo).isChecked)
				}
				PrefsManager.broadcastSettings(it.context)
			}
		) { parent ->
			layoutInflater.inflate(R.layout.dialog_uri_options, parent, false).apply {
				checkBox(R.id.checkDropIncompatible).isChecked = prefs.getBoolean(singBoxKey, false)
				checkBox(R.id.checkDropIncompatibleMihomo).isChecked =
					prefs.getBoolean(mihomoKey, false)
			}
		}
	}

	private class InfoText(val titleRes: Int, val messageRes: Int)

	private val infoTexts = mapOf(
		DIALOG_DECRYPTION_HEADER_INFO to InfoText(
			R.string.setting_header_decryption, R.string.setting_header_decryption_info),
		DIALOG_RESPONSE_HEADER_INFO to InfoText(
			R.string.setting_header_response, R.string.setting_header_response_info),
		DIALOG_BRIDGE_INFO to InfoText(
			R.string.setting_bridge_header, R.string.msg_bridge_service_info),
	)

	private fun showInfo(tag: String) {
		val text = infoTexts.getValue(tag)
		showInfo(tag, text.titleRes) { getString(text.messageRes) }
	}

	// An information dialog - an HTML message under a title - tracked under its tag. The message
	// is a lambda, built only once the fragment is known to be attached.
	private fun showInfo(
		tag: String,
		titleRes: Int,
		withLinks: Boolean = false,
		message: () -> String
	) {
		if (alreadyShowing(tag)) return
		val act = activity ?: return
		val dialogView = layoutInflater.infoView(message(), withLinks = withLinks)

		val dialog = AnimatedDialogBuilder(act)
			.setTitle(fromHtml(getString(titleRes)))
			.setView(dialogView)
			.setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
			.showAnimated()
		trackDialog(tag, dialog)
	}

	private fun bindEnableBridgeItem(view: View) {
		val item = view.findViewById<MaterialCardView>(R.id.itemEnableBridge)
		val switch = view.findViewById<SwitchMaterial>(R.id.switchEnableBridge)
		val ctx = requireContext()
		// What runs now - bringing it back is refreshDynamicState's job on resume, so a refusal
		// there is only told once.
		switch.isChecked = BridgeController.isOn(ctx)

		item.setOnClickListener {
			if (switch.isChecked) {
				BridgeController.disable(ctx)
				switch.isChecked = false
				updateBridgeCard(view)
				return@setOnClickListener
			}
			bridgePermissions.enableBridge()
		}
	}

	private fun bindBridgeInstructionIcon(view: View) {
		view.findViewById<ImageView>(R.id.iconBridgeInstruction).setOnClickListener {
			showInfo(DIALOG_BRIDGE_INFO)
		}
	}

	private fun bindResponseHeaderInfoIcon(view: View) {
		view.findViewById<ImageView>(R.id.iconResponseInfo).setOnClickListener {
			showInfo(DIALOG_RESPONSE_HEADER_INFO)
		}
	}

	private fun bindDecryptionHeaderInfoIcon(view: View) {
		view.findViewById<ImageView>(R.id.iconDecryptionInfo).setOnClickListener {
			showInfo(DIALOG_DECRYPTION_HEADER_INFO)
		}
	}

	private fun bindWatchdogItem(view: View) {
		val item = view.findViewById<MaterialCardView>(R.id.itemWatchdog)
		val switch = view.findViewById<SwitchMaterial>(R.id.switchWatchdog)
		val enableSwitch = view.findViewById<SwitchMaterial>(R.id.switchEnableBridge)
		val ctx = requireContext()
		val act = requireActivity()
		switch.isChecked = PrefsManager.getSafePrefs(ctx).getBoolean(PrefsManager.PREF_BRIDGE_WATCHDOG, false)
		val update: (Boolean) -> Unit = { checked ->
			PrefsManager.getSafePrefs(ctx).edit { putBoolean(PrefsManager.PREF_BRIDGE_WATCHDOG, checked) }
			switch.isChecked = checked
			if (enableSwitch.isChecked) {
				BridgeController.startService(act, tellPerson = true)
			}
		}
		item.setOnClickListener { update(!switch.isChecked) }
	}

	// Setting: LAN mode, which opens the bridge from this phone alone to the local network too.
	// The row lives in the bridge card, which grows to show it while the bridge is on.
	private fun bindLanModeItem(view: View) {
		val item = view.findViewById<View>(R.id.itemLanMode)
		val check = view.findViewById<MaterialCheckBox>(R.id.checkLanMode)
		val ctx = requireContext()
		check.isChecked = BridgeController.isLanModeOn(ctx)
		item.setOnClickListener {
			val turnOn = !check.isChecked
			val needed = if (turnOn) BridgeController.lanModePermissionNeeded(ctx) else null
			when {
				needed == null -> applyLanMode(view, turnOn)
				!askingLocalNetwork -> {
					askingLocalNetwork = true
					localNetworkPermission.launch(needed)
				}
			}
		}
		updateBridgeCard(view)
	}

	private fun applyLanMode(root: View, on: Boolean) {
		val ctx = root.context
		PrefsManager.getSafePrefs(ctx).edit { putBoolean(PrefsManager.PREF_BRIDGE_LAN_MODE, on) }
		root.findViewById<MaterialCheckBox>(R.id.checkLanMode).isChecked = on
		BridgeController.rebind(ctx)
		updateBridgeCard(root)
	}

	// Follows the switch, not the raw preference - a preference can outlive a start that was
	// refused. Grows to show the address and LAN row only while the bridge shows as on.
	private fun updateBridgeCard(root: View) {
		// Null when a change posted from prefsListener lands after the fragment has left.
		val ctx = context ?: return
		val text = root.findViewById<TextView>(R.id.textBridgeAddress)
		val divider = root.findViewById<View>(R.id.bridgeLanDivider)
		val row = root.findViewById<View>(R.id.itemLanMode)
		val enabled = root.findViewById<SwitchMaterial>(R.id.switchEnableBridge).isChecked
		val lanMode = BridgeController.isLanModeOn(ctx)
		val duration = root.context.stateChangeDuration(R.integer.duration_standard_transition)

		if (enabled) {
			// Host only - scheme and port aren't ours to change. LAN mode with no network falls
			// back to loopback, and then the line says why instead of showing what was asked for.
			val host = BridgeLink.hostFor(lanMode)
			val newText = if (lanMode && host == BridgeLink.LOOPBACK) {
				getString(R.string.setting_bridge_no_network, host)
			} else {
				getString(R.string.setting_bridge_address, host)
			}
			// A line still hidden just takes the text.
			if (row.isVisible) text.crossfadeText(newText) else text.text = newText
			root.findViewById<MaterialCheckBox>(R.id.checkLanMode).isChecked = lanMode
		}

		val visibility = if (enabled) View.VISIBLE else View.GONE
		if (row.visibility == visibility) return
		val views = listOf(text, divider, row)
		views.forEach { it.animate().cancel() }

		if (ctx.skipProgrammaticAnimations()) {
			views.forEach { it.visibility = visibility }
			return
		}

		root.glideHeights {
			if (visibility == View.VISIBLE) {
				views.forEach { it.fadeIn(duration) }
			} else {
				// The snapshot dissolves while the view goes at once, so fade and collapse run together.
				views.forEach { view -> view.crossfadeSnapshot { view.visibility = View.GONE } }
			}
		}
	}

	private fun finishEnablingBridge() {
		val root = view ?: return
		val ctx = context ?: return
		val started = BridgeController.enable(ctx)
		root.findViewById<SwitchMaterial>(R.id.switchEnableBridge)?.isChecked = started
		updateBridgeCard(root)
	}

	// Built with the fragment: result launchers have to be registered before it is created.
	private val bridgePermissions =
		BridgeController.Permissions(this, { context }) { finishEnablingBridge() }

	// About dialog, with the installed version filled in
	private fun showInfoDialog() = showInfo(DIALOG_INFO, R.string.about_app, withLinks = true) {
		val ctx = requireContext()
		val versionName = try {
			ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName
		} catch (_: Exception) {
			"Unknown"
		}
		getString(R.string.about_app_text, versionName)
	}
}
