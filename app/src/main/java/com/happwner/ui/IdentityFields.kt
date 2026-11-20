package com.happwner.ui

import android.content.Context
import android.content.SharedPreferences
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.Filter
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.edit
import androidx.core.view.isVisible
import androidx.core.view.updateLayoutParams
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.textfield.TextInputLayout
import com.happwner.R
import com.happwner.data.DeviceCatalog
import com.happwner.data.DeviceCatalog.Platform
import com.happwner.data.PrefsManager

// The advanced mode's part of the form: model, OS and version, headers, and the line naming the identity.
// The HWID and User-Agent fields stay with the screen.
internal class IdentityFields(
	root: View,
	private val devices: DeviceCatalog,
	private val prefs: SharedPreferences,
	private val onChanged: () -> Unit,
	private val beginTransition: () -> Unit,
	private val beginToggle: (View) -> Unit,
	private val restyle: (TextInputLayout, EditText, Boolean) -> Unit
) {
	private val context: Context = root.context
	private val header: View = root.findViewById(R.id.identityHeader)
	private val fields: View = root.findViewById(R.id.identityFields)
	private val summary: TextView = root.findViewById(R.id.identitySummary)
	private val arrow: ImageView = root.findViewById(R.id.identityExpand)
	val saveButton: ImageButton = root.findViewById(R.id.identitySave)
	val personButton: ImageButton = root.findViewById(R.id.identityPerson)
	private val rowDevice: View = root.findViewById(R.id.rowDevice)
	private val rowUserAgent: View = root.findViewById(R.id.rowUserAgent)
	private val layoutModel: TextInputLayout = root.findViewById(R.id.layoutModel)
	private val layoutOs: TextInputLayout = root.findViewById(R.id.layoutOs)
	private val layoutVersion: TextInputLayout = root.findViewById(R.id.layoutOsVersion)
	private val inputModel: EditText = root.findViewById(R.id.inputModel)
	private val inputOs: DropdownField = root.findViewById(R.id.inputOs)
	private val inputVersion: DropdownField = root.findViewById(R.id.inputOsVersion)
	private val headerFields = HeaderFields(root, prefs, ::changed, beginTransition, restyle)

	private val notSet = context.getString(R.string.option_not_set)
	private val enter = context.getString(R.string.option_enter)
	private var expanded = prefs.getBoolean(PrefsManager.PREF_IDENTITY_EXPANDED, true)
	private var shownPlatform: Platform? = null
	private var applying = false

	val model get() = inputModel.text.toString().trim()
	val os get() = inputOs.text.toString().trim()
	val platform get() = devices.platformOf(os)

	// A platform with no versions takes none; with no platform named, one can still be typed.
	private val takesVersion get() = platform?.versions?.isNotEmpty() != false
	val osVersion get() = if (takesVersion) inputVersion.text.toString().trim() else ""

	val headers get() = headerFields.headers

	val styled get() = listOf(layoutModel to inputModel, layoutOs to inputOs, layoutVersion to inputVersion) +
		headerFields.styled

	init {
		inputOs.setAdapter(FullListAdapter(context, devices.platforms.map { it.header } + notSet))
		inputModel.setText(prefs.getString(PrefsManager.PREF_IDENTITY_MODEL, ""))
		inputOs.setText(prefs.getString(PrefsManager.PREF_IDENTITY_OS, ""), false)
		inputVersion.setText(prefs.getString(PrefsManager.PREF_IDENTITY_OS_VERSION, ""), false)
		shownPlatform = platform
		updateVersions(animate = false)

		inputModel.doAfterTextChanged {
			prefs.edit { putString(PrefsManager.PREF_IDENTITY_MODEL, model) }
			changed()
		}
		inputOs.doAfterTextChanged { onOsChanged() }
		inputOs.commands = listOf(notSet)
		inputOs.setOnItemClickListener { _, _, position, _ ->
			if (position == devices.platforms.size) inputOs.crossfadeTo("")
		}
		inputVersion.doAfterTextChanged {
			prefs.edit { putString(PrefsManager.PREF_IDENTITY_OS_VERSION, inputVersion.text.toString().trim()) }
			changed()
		}
		inputVersion.commands = listOf(notSet, enter)
		inputVersion.setOnItemClickListener { _, _, position, _ ->
			when (inputVersion.adapter.getItem(position)) {
				notSet -> inputVersion.crossfadeTo("")
				enter -> inputVersion.startTyping()
			}
		}
		listOf(inputModel, inputVersion).forEach { input ->
			input.setOnEditorActionListener { view, _, _ ->
				view.hideKeyboard()
				view.clearFocus()
				true
			}
		}
		inputModel.setOnTouchListener { _, _ ->
			restyle(layoutModel, inputModel, false)
			false
		}
		inputModel.setOnFocusChangeListener { _, _ -> restyle(layoutModel, inputModel, true) }

		header.setOnClickListener { toggle() }
	}

	// Shows or hides everything this mode adds; the caller begins the transition.
	fun setAdvanced(on: Boolean) {
		header.isVisible = on
		rowDevice.isVisible = on
		headerFields.setAdvanced(on)
		rowUserAgent.updateLayoutParams<ViewGroup.MarginLayoutParams> {
			bottomMargin = context.resources.getDimensionPixelSize(if (on) R.dimen.island_margin_bottom else R.dimen.spacing_normal)
		}
		fields.isVisible = !on || expanded
		arrow.setImageResource(if (expanded) R.drawable.ic_expand_less else R.drawable.ic_expand_more)
	}

	// Sets the fields a device or a link names, the ones left null staying as they are; the change is told once.
	fun apply(
		model: String? = null, os: String? = null, osVersion: String? = null,
		headers: List<Pair<String, String>>? = null
	) {
		applying = true
		model?.let { inputModel.crossfadeText(it) }
		os?.let { inputOs.crossfadeTo(devices.platformOf(it)?.header ?: it) }
		osVersion?.let { inputVersion.crossfadeTo(it) }
		headers?.let { headerFields.replace(it) }
		applying = false
		onChanged()
	}

	// The name above the fields, and the button that saves what they hold, shown when there is something unsaved.
	// The button keeps its room while it is out, so the name does not shift with it.
	fun show(label: String, canSave: Boolean) {
		summary.crossfadeText(label)
		saveButton.fadeTo(canSave, View.INVISIBLE)
	}

	private fun toggle() {
		header.rootView.findFocus()?.clearFocus()
		beginToggle(fields)
		expanded = !expanded
		prefs.edit { putBoolean(PrefsManager.PREF_IDENTITY_EXPANDED, expanded) }
		fields.isVisible = expanded
		arrow.setImageResource(if (expanded) R.drawable.ic_expand_less else R.drawable.ic_expand_more)
	}

	private fun changed() {
		if (!applying) onChanged()
	}

	// A version belongs to its platform, so another platform starts without one.
	private fun onOsChanged() {
		prefs.edit { putString(PrefsManager.PREF_IDENTITY_OS, os) }
		if (platform != shownPlatform) {
			shownPlatform = platform
			inputVersion.crossfadeTo("")
			updateVersions(animate = true)
		}
		changed()
	}

	private fun updateVersions(animate: Boolean) {
		if (animate && layoutVersion.isVisible != takesVersion) beginTransition()
		layoutVersion.isVisible = takesVersion
		inputVersion.setAdapter(FullListAdapter(context, platform?.versions.orEmpty() + enter + notSet))
	}
}

// A list that shows every item whatever the field holds: the text a recreated screen gives back would
// narrow a plain one to the item it names, and a version typed after Enter names none.
private class FullListAdapter(context: Context, private val items: List<String>) :
	ArrayAdapter<String>(context, android.R.layout.simple_list_item_1, items) {

	override fun getFilter() = object : Filter() {
		override fun performFiltering(constraint: CharSequence?) =
			FilterResults().apply { values = items; count = items.size }

		override fun publishResults(constraint: CharSequence?, results: FilterResults) = notifyDataSetChanged()
	}
}
