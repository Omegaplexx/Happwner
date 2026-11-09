package com.happwner.ui

import android.content.Context
import android.content.res.ColorStateList
import android.os.Build
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.doOnAttach
import androidx.core.view.isVisible
import androidx.core.view.updatePadding
import androidx.core.widget.doAfterTextChanged
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.happwner.R
import com.happwner.patcher.AppIcons
import com.happwner.patcher.InstalledApp
import com.happwner.patcher.InstalledApps
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

// The page that lists the person's apps with a search box. The icons come in as the rows are shown,
// from a cache the warm-up has already started to fill.
class InstalledAppsPicker(private val onPick: (InstalledApp) -> Unit) {

	// Lives as long as the page does, which is as long as its view stays in a window.
	private val job = SupervisorJob()
	private val scope = CoroutineScope(Dispatchers.Main.immediate + job)

	// The cursor, selection handles and highlight take the accent colour, as in the main fields.
	private fun tintSearchField(layout: TextInputLayout, search: TextInputEditText) {
		val accent = MaterialColors.getColor(
			search, R.attr.happAccent,
			ContextCompat.getColor(search.context, R.color.brand_purple_secondary)
		)
		if (Build.VERSION.SDK_INT >= 29) layout.setCursorColor(ColorStateList.valueOf(accent))
		updateTextViewHandlesColor(search, accent)
	}

	fun create(parent: ViewGroup): View {
		val context = parent.context
		val root = LayoutInflater.from(context).inflate(R.layout.page_installed_apps, parent, false)
		root.addOnAttachStateChangeListener(object : View.OnAttachStateChangeListener {
			override fun onViewAttachedToWindow(v: View) = Unit
			override fun onViewDetachedFromWindow(v: View) = job.cancel()
		})

		val search = root.findViewById<TextInputEditText>(R.id.inputInstalledSearch)
		tintSearchField(root.findViewById(R.id.layoutInstalledSearch), search)
		val status = root.findViewById<TextView>(R.id.textInstalledStatus)
		val list = root.findViewById<RecyclerView>(R.id.listInstalledApps)
		val adapter = AppAdapter(context, scope, onPick)
		list.layoutManager = LinearLayoutManager(context)
		list.adapter = adapter
		list.setHasFixedSize(true)
		// Rows that slide or fade as the filter changes would read as the list jumping.
		list.itemAnimator = null
		keepClearOfKeyboard(root, list)

		var all: List<InstalledApp>? = null
		// Until the list is read the status keeps saying so, whatever is typed meanwhile.
		fun filter() {
			val apps = all ?: return
			val query = search.text?.toString().orEmpty().trim().lowercase()
			val shown = if (query.isEmpty()) apps else apps.filter { query in it.searchKey }
			status.setText(R.string.msg_installed_apps_empty)
			status.isVisible = shown.isEmpty()
			adapter.submitList(shown) { list.scrollToPosition(0) }
		}
		search.doAfterTextChanged { filter() }
		search.setOnEditorActionListener { view, actionId, _ ->
			if (actionId != EditorInfo.IME_ACTION_SEARCH) return@setOnEditorActionListener false
			view.hideKeyboard()
			// Focus has to go somewhere: to the page itself, so the field keeps no cursor.
			(root as ViewGroup).descendantFocusability = ViewGroup.FOCUS_BEFORE_DESCENDANTS
			root.isFocusableInTouchMode = true
			root.requestFocus()
			true
		}

		// A list the warm-up has read is there at once, before the page's first layout.
		scope.launch {
			val apps = InstalledApps.list(context)
			all = apps
			filter()
			AppIcons.prefetch(context, apps)
		}
		return root
	}

	// The keyboard covers the window's lower part without moving or resizing it, so the list only
	// gets room to scroll its last rows above it: nothing on screen shifts.
	private fun keepClearOfKeyboard(root: View, list: RecyclerView) {
		ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
			val keyboardTop = view.rootView.height - insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
			val at = IntArray(2)
			list.getLocationInWindow(at)
			list.updatePadding(bottom = (at[1] + list.height - keyboardTop).coerceAtLeast(0))
			insets
		}
		root.doOnAttach { it.requestApplyInsets() }
	}

	private class AppAdapter(
		context: Context,
		private val scope: CoroutineScope,
		private val onPick: (InstalledApp) -> Unit
	) : ListAdapter<InstalledApp, AppAdapter.Holder>(object : DiffUtil.ItemCallback<InstalledApp>() {
		override fun areItemsTheSame(a: InstalledApp, b: InstalledApp) = a.packageName == b.packageName
		override fun areContentsTheSame(a: InstalledApp, b: InstalledApp) = a == b
	}) {
		private val appContext = context.applicationContext

		class Holder(view: View) : RecyclerView.ViewHolder(view) {
			val icon: ImageView = view.findViewById(R.id.imageAppIcon)
			val label: TextView = view.findViewById(R.id.textAppLabel)
			val details: TextView = view.findViewById(R.id.textAppDetails)
			var iconJob: Job? = null
		}

		override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
			val view = LayoutInflater.from(parent.context).inflate(R.layout.item_installed_app, parent, false)
			return Holder(view).also { holder ->
				view.setOnClickListener {
					val position = holder.bindingAdapterPosition
					if (position != RecyclerView.NO_POSITION) onPick(getItem(position))
				}
			}
		}

		override fun onBindViewHolder(holder: Holder, position: Int) {
			val app = getItem(position)
			holder.label.text = app.label
			holder.details.text = holder.itemView.context
				.getString(R.string.label_installed_app_details, app.versionName, app.packageName)
			holder.iconJob?.cancel()
			holder.iconJob = null
			val ready = AppIcons.cached(app)
			if (ready != null) {
				holder.icon.setImageBitmap(ready)
			} else {
				holder.icon.setImageResource(R.drawable.app_icon_placeholder)
				holder.iconJob = scope.launch {
					holder.icon.setImageBitmap(AppIcons.load(appContext, app))
				}
			}
		}

		// A row scrolled away no longer waits for its icon.
		override fun onViewRecycled(holder: Holder) {
			holder.iconJob?.cancel()
			holder.iconJob = null
		}
	}
}
