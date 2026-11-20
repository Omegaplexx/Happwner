package com.happwner.ui

import android.content.Context
import android.content.SharedPreferences
import android.text.InputFilter
import android.view.LayoutInflater
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.LinearLayout
import androidx.core.content.edit
import androidx.core.view.doOnNextLayout
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.textfield.TextInputLayout
import com.happwner.R
import com.happwner.bridge.CustomHeaders
import com.happwner.data.PrefsManager
import org.json.JSONArray
import org.json.JSONException

// The headers a person adds to the request: a row for each, and below them a line that asks for a name.
// The name field takes the line's place; once the name is accepted it becomes the hint of the row that takes the value.
internal class HeaderFields(
	root: View,
	private val prefs: SharedPreferences,
	private val onChanged: () -> Unit,
	private val beginTransition: () -> Unit,
	private val restyle: (TextInputLayout, EditText, Boolean) -> Unit
) {
	private class Row(val name: String, val view: View, val layout: TextInputLayout, val input: EditText)

	private val context: Context = root.context
	private val inflater = LayoutInflater.from(context)
	private val block: View = root.findViewById(R.id.headersBlock)
	private val list: LinearLayout = root.findViewById(R.id.headerRows)
	private val addRow: View = root.findViewById(R.id.rowHeaderAdd)
	private val entry: View = root.findViewById(R.id.headerEntry)
	private val nameLayout: TextInputLayout = root.findViewById(R.id.layoutHeaderName)
	private val nameInput: EditText = root.findViewById(R.id.inputHeaderName)
	private val cancel: View = root.findViewById(R.id.headerCancel)
	private val add: View = root.findViewById(R.id.headerAdd)
	private val confirm: View = root.findViewById(R.id.headerConfirm)
	private val rows = mutableListOf<Row>()

	// The rows that carry a value; a row still waiting for one sends nothing.
	val headers: List<Pair<String, String>>
		get() = rows.mapNotNull { row ->
			val value = row.input.text.toString().trim()
			if (value.isNotEmpty() && CustomHeaders.isAllowedValue(value)) row.name to value else null
		}

	val styled get() = listOf(nameLayout to nameInput) + rows.map { it.layout to it.input }

	init {
		nameInput.filters = arrayOf(keeping(CustomHeaders::isNameChar), InputFilter.LengthFilter(CustomHeaders.MAX_NAME_LENGTH))
		nameInput.doAfterTextChanged { clearError() }
		nameInput.setOnEditorActionListener { _, actionId, _ ->
			if (actionId != EditorInfo.IME_ACTION_DONE) return@setOnEditorActionListener false
			accept()
			true
		}
		watchStyle(nameLayout, nameInput)
		add.setOnClickListener { openEntry() }
		cancel.setOnClickListener { closeEntry() }
		confirm.setOnClickListener { accept() }
		readSaved().forEach { (name, value) -> addRow(name, value) }
		updateAddRow()
	}

	fun setAdvanced(on: Boolean) {
		block.isVisible = on
	}

	// Replaces the list on screen; the caller tells of the change.
	fun replace(headers: List<Pair<String, String>>) {
		val wanted = headers.take(CustomHeaders.MAX_FROM_LINK)
		if (wanted == rows.map { it.name to it.input.text.toString() }) return
		dropFocusIn(list)
		beginTransition()
		rows.clear()
		list.removeAllViews()
		wanted.forEach { (name, value) -> addRow(name, value) }
		updateAddRow()
		save()
	}

	private fun addRow(name: String, value: String): Row {
		val view = inflater.inflate(R.layout.item_header, list, false)
		val layout = view.findViewById<TextInputLayout>(R.id.layoutHeaderValue)
		val input = view.findViewById<EditText>(R.id.inputHeaderValue)
		// Each field is styled by its id, so the rows cannot share the one the layout gives them.
		layout.id = View.generateViewId()
		layout.hint = name
		input.filters = arrayOf(keeping { it in ' '..'~' }, InputFilter.LengthFilter(MAX_VALUE_LENGTH))
		input.setText(value)
		val row = Row(name, view, layout, input)
		input.doAfterTextChanged {
			save()
			onChanged()
		}
		input.setOnEditorActionListener { field, _, _ ->
			field.hideKeyboard()
			field.clearFocus()
			true
		}
		view.findViewById<View>(R.id.headerDelete).setOnClickListener { remove(row) }
		watchStyle(layout, input)
		rows.add(row)
		list.addView(view)
		return row
	}

	// A field that goes away with the focus in it would pass the focus on to the topmost field in sight: the keyboard
	// goes and the focus is put down first.
	private fun dropFocusIn(view: View) {
		val focused = view.findFocus() ?: return
		focused.hideKeyboard()
		focused.clearFocus()
	}

	private fun remove(row: Row) {
		dropFocusIn(row.view)
		beginTransition()
		rows.remove(row)
		list.removeView(row.view)
		updateAddRow()
		save()
		onChanged()
	}

	private fun watchStyle(layout: TextInputLayout, input: EditText) {
		restyle(layout, input, false)
		input.setOnTouchListener { _, _ ->
			restyle(layout, input, false)
			false
		}
		input.setOnFocusChangeListener { _, _ -> restyle(layout, input, true) }
	}

	private fun updateAddRow() {
		addRow.isVisible = rows.size < CustomHeaders.MAX_ON_SCREEN
	}

	// The field is made empty while it is out of sight, so what was typed fades out with it.
	private fun openEntry() {
		nameInput.setText("")
		beginTransition()
		setEntry(true)
		focusAndType(nameInput)
	}

	// Once the field is laid out in its place.
	private fun focusAndType(input: EditText) {
		input.doOnNextLayout { input.showKeyboard() }
	}

	private fun closeEntry() {
		nameInput.hideKeyboard()
		nameInput.clearFocus()
		beginTransition()
		setEntry(false)
	}

	private fun setEntry(open: Boolean) {
		entry.isVisible = open
		add.isVisible = !open
	}

	// An empty name is the same as giving up.
	private fun accept() {
		val name = nameInput.text.toString().trim()
		if (name.isEmpty()) return closeEntry()
		val problem = when {
			!CustomHeaders.isAllowedName(name) -> R.string.error_header_reserved
			rows.any { it.name.equals(name, ignoreCase = true) } -> R.string.error_header_exists
			else -> null
		}
		if (problem != null) {
			beginTransition()
			nameLayout.error = context.getString(problem)
			restyle(nameLayout, nameInput, true)
			return
		}
		nameInput.clearFocus()
		beginTransition()
		val row = addRow(name, "")
		setEntry(false)
		updateAddRow()
		save()
		onChanged()
		focusAndType(row.input)
	}

	private fun clearError() {
		if (nameLayout.error == null) return
		beginTransition()
		nameLayout.error = null
		nameLayout.isErrorEnabled = false
		restyle(nameLayout, nameInput, true)
	}

	private fun save() {
		val array = JSONArray()
		rows.forEach { array.put(JSONArray().put(it.name).put(it.input.text.toString())) }
		prefs.edit { putString(PrefsManager.PREF_IDENTITY_HEADERS, array.toString()) }
	}

	private fun readSaved(): List<Pair<String, String>> {
		val text = prefs.getString(PrefsManager.PREF_IDENTITY_HEADERS, null) ?: return emptyList()
		return try {
			val array = JSONArray(text)
			(0 until array.length()).mapNotNull { index ->
				val pair = array.optJSONArray(index)
				val name = pair?.optString(0).orEmpty()
				if (pair != null && pair.length() == 2 && CustomHeaders.isAllowedName(name)) name to pair.optString(1) else null
			}.take(CustomHeaders.MAX_FROM_LINK)
		} catch (_: JSONException) {
			emptyList()
		}
	}

	private companion object {
		const val MAX_VALUE_LENGTH = 1024
	}
}

private fun keeping(allowed: (Char) -> Boolean) = InputFilter { source, start, end, _, _, _ ->
	val kept = source.subSequence(start, end).filter(allowed)
	if (kept.length == end - start) null else kept
}
