package com.happwner.ui

import android.annotation.SuppressLint
import android.app.Activity
import android.graphics.Canvas
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.ImageButton
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.view.doOnNextLayout
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.radiobutton.MaterialRadioButton
import com.happwner.R
import com.happwner.bridge.RequestIdentity
import com.happwner.data.IdentityStore
import com.happwner.data.SavedIdentity
import kotlin.math.abs

// Saved identities, picked and managed in one dialog: a tap picks, holding a row switches the list to managing.
// Holding again, Back and a tap outside end the typing first, then the managing; OK is for a new identity only.
internal class IdentitiesDialog(
	private val activity: Activity,
	private val store: IdentityStore,
	private val current: () -> RequestIdentity,
	private val standing: () -> IdentityStore.Standing,
	private val defaultName: () -> String,
	private val onPick: (SavedIdentity) -> Unit,
	private val onChanged: () -> Unit
) {
	// A name being typed: that of a new identity (no id) or the one of the identity with the id.
	private class Edit(val id: String?, var text: String)

	private val inflater = LayoutInflater.from(activity)
	private lateinit var pages: DialogPages
	private lateinit var dialog: AlertDialog
	private lateinit var list: RecyclerView
	private lateinit var add: View
	private lateinit var delete: ImageButton
	private lateinit var lift: DialogKeyboard
	private val adapter = Adapter()
	private var managing = false
	private var editing: Edit? = null
	private var closesAfterAdd = false
	private val chosen = mutableSetOf<String>()
	// How far the list was scrolled to keep the typed line in view, to be scrolled back.
	private var scrolledForEdit = 0
	// The change a refresh carries for a row bound later, with its tools to fade.
	private val fading = Any()

	private val mover = ItemTouchHelper(object : ItemTouchHelper.SimpleCallback(ItemTouchHelper.UP or ItemTouchHelper.DOWN, 0) {
		override fun isLongPressDragEnabled() = false

		override fun onMove(view: RecyclerView, from: RecyclerView.ViewHolder, to: RecyclerView.ViewHolder): Boolean {
			val a = from.bindingAdapterPosition
			val b = to.bindingAdapterPosition
			if (a == RecyclerView.NO_POSITION || b == RecyclerView.NO_POSITION) return false
			adapter.move(a, b)
			return true
		}

		override fun onSwiped(holder: RecyclerView.ViewHolder, direction: Int) = Unit

		// A row gives way once the held one has covered half of it, the farthest such row when there are several.
		override fun chooseDropTarget(
			selected: RecyclerView.ViewHolder, targets: MutableList<RecyclerView.ViewHolder>, curX: Int, curY: Int
		): RecyclerView.ViewHolder? {
			val row = selected.itemView
			val down = curY > row.top
			val edge = if (down) curY + row.height else curY
			return targets.filter {
				val other = it.itemView
				val middle = (other.top + other.bottom) / 2
				if (down) other.top > row.top && middle < edge else other.top < row.top && middle > edge
			}.maxByOrNull { abs(it.itemView.top - row.top) }
		}

		// The row stops at the list's ends.
		override fun onChildDraw(
			canvas: Canvas, view: RecyclerView, holder: RecyclerView.ViewHolder,
			dX: Float, dY: Float, actionState: Int, isCurrentlyActive: Boolean
		) {
			val row = holder.itemView
			val limited = dY.coerceIn(
				(view.paddingTop - row.top).toFloat(), (view.height - view.paddingBottom - row.bottom).toFloat()
			)
			super.onChildDraw(canvas, view, holder, dX, limited, actionState, isCurrentlyActive)
		}

		override fun clearView(view: RecyclerView, holder: RecyclerView.ViewHolder) {
			super.clearView(view, holder)
			holder.itemView.isPressed = false
			store.reorder(adapter.items.map { it.id })
		}
	})

	// With saveNew the dialog opens with the line that asks for a name, and closes once the identity is saved.
	fun show(saveNew: Boolean = false): AlertDialog {
		val title = activity.getString(R.string.identities_title)
		pages = DialogPages(activity, title, homeButtons = false, onHomeClose = ::onClose, homeActions = ::createActions) {
			inflater.inflate(R.layout.dialog_identities, it, false)
		}
		dialog = AnimatedDialogBuilder(activity)
			.setTitle(title)
			.setView(pages.view)
			.setPositiveButton(fromHtml(activity.getString(R.string.btn_ok)), null)
			.showAnimated()
		pages.attach(dialog)
		dialog.hostHeightGlides(fades = true)
		lift = DialogKeyboard(dialog).also { it.attach() }
		list = pages.home.findViewById<RecyclerView>(R.id.identityList).also {
			it.layoutManager = LinearLayoutManager(activity)
			it.adapter = adapter
			// A list the keyboard shortens keeps the line being typed in in view.
			it.addOnLayoutChangeListener { _, _, top, _, bottom, _, oldTop, _, oldBottom ->
				if (editing != null && bottom - top < oldBottom - oldTop) it.post(::showEdited)
			}
		}
		mover.attachToRecyclerView(list)
		render()
		if (saveNew) {
			closesAfterAdd = true
			editing = Edit(null, defaultName())
			pages.takeKeyboard(true)
			pages.morphHome(buttons = true, animated = false, change = ::render)
		}
		return dialog
	}

	private fun createActions(parent: ViewGroup): View {
		val actions = inflater.inflate(R.layout.dialog_identities_actions, parent, false)
		add = actions.findViewById<View>(R.id.identityAdd).also {
			it.setOnClickListener { if (!busy()) startAdding() }
		}
		delete = actions.findViewById<ImageButton>(R.id.identityDelete).also {
			it.setOnClickListener { if (!busy()) deleteChosen() }
		}
		return actions
	}

	// What the lists hold as things stand now; the identity the fields equal is the one marked.
	private fun syncItems() {
		val fields = standing()
		adapter.items = store.all().toMutableList()
		adapter.marked = if (fields.modified) null else fields.saved?.id
	}

	private fun renderChrome() {
		val home = pages.home
		home.findViewById<View>(R.id.identitiesEmpty).isVisible = adapter.items.isEmpty() && editing == null
		home.findViewById<View>(R.id.identitiesHint).isVisible = adapter.items.isNotEmpty() && !store.hintDone
		add.isVisible = !managing && editing == null
		delete.isVisible = managing
		delete.isEnabled = chosen.isNotEmpty()
	}

	// The list laid out anew, and the rest; for a change in what the list holds.
	private fun render() {
		syncItems()
		adapter.notifyDataSetChanged()
		renderChrome()
	}

	private fun refreshRows(fadeTools: Boolean = false) {
		for (index in 0 until list.childCount) (list.getChildViewHolder(list.getChildAt(index)) as? Holder)?.bind(fadeTools)
		adapter.notifyItemRangeChanged(0, adapter.itemCount, if (fadeTools) fading else Unit)
	}

	// The bar is shown while a new identity is named.
	private fun wantsButtons() = editing != null && !managing

	// A change in what the list holds is dissolved into place, one in how it shows glides in place.
	private fun morph() = pages.morphHome(wantsButtons(), change = ::render)

	private fun reshape() = pages.reshapeHome {
		syncItems()
		renderChrome()
		refreshRows()
	}

	// The same with no glide, for what is done as the keyboard leaves.
	private fun refreshNow() {
		syncItems()
		renderChrome()
		refreshRows(fadeTools = true)
	}

	private fun morphWhenDown() = lift.afterDown { if (dialog.isShowing) morph() }

	// The line being typed in lies wholly in the list.
	private fun showEdited() {
		val edit = editing ?: return
		val position = if (edit.id == null) 0 else adapter.items.indexOfFirst { it.id == edit.id }
		val row = list.findViewHolderForAdapterPosition(position)?.itemView ?: return list.scrollToPosition(position)
		val over = row.bottom - (list.height - list.paddingBottom)
		val by = if (over > 0) over else minOf(0, row.top - list.paddingTop)
		if (by == 0) return
		list.scrollBy(0, by)
		scrolledForEdit += by
	}

	// What the typing scrolled is scrolled back as the dialog comes down: a list scrolled past a row is no taller
	// than what it holds from there, and would jump to its height once it is back at the top.
	private fun scrollBack() {
		val back = scrolledForEdit.coerceIn(0, maxOf(0, list.computeVerticalScrollOffset()))
		scrolledForEdit = 0
		if (back == 0) return
		if (activity.skipProgrammaticAnimations()) return list.scrollBy(0, -back)
		val mode = activity.animMode()
		list.smoothScrollBy(
			0, -back, curveFor(mode, materialStandard),
			activity.stateChangeDuration(R.integer.duration_standard_transition).toInt()
		)
	}

	// Anything but the typing ends it first, and is otherwise left undone.
	private fun busy(): Boolean {
		if (editing == null) return false
		commit()
		return true
	}

	private fun startAdding() {
		editing = Edit(null, defaultName())
		pages.takeKeyboard(true)
		pages.morphHome(buttons = true, after = ::focusEdit, change = ::render)
	}

	private fun startRename(item: SavedIdentity) {
		editing = Edit(item.id, item.name)
		pages.takeKeyboard(true)
		val holder = list.findViewHolderForAdapterPosition(adapter.items.indexOf(item)) as? Holder
		renderChrome()
		holder?.bind(fadeTools = true)
		holder?.focusName()
	}

	private fun focusEdit() {
		if (!dialog.isShowing) return
		(list.findViewHolderForAdapterPosition(0) as? Holder)?.focusName()
	}

	private fun commit() {
		val edit = editing ?: return
		val typed = edit.text.trim()
		val saved = edit.id?.let(store::find)
		if (edit.id == null) {
			store.add(typed.ifEmpty { defaultName() }, current())
		} else {
			store.rename(edit.id, typed.ifEmpty { saved?.name ?: defaultName() })
		}
		onChanged()
		finishEdit()
		when {
			edit.id != null -> refreshNow()
			closesAfterAdd -> dialog.dismissAnimated()
			else -> morphWhenDown()
		}
	}

	private fun cancelEdit() {
		val wasNew = editing?.id == null
		finishEdit()
		if (wasNew) morphWhenDown() else refreshNow()
	}

	private fun finishEdit() {
		editing = null
		list.findFocus()?.clearFocus()
		list.hideKeyboard()
		pages.takeKeyboard(false)
		scrollBack()
	}

	private fun startManaging() {
		store.hintDone = true
		chosen.clear()
		managing = true
		reshape()
	}

	// Ends the managing, if it is on, and says whether it was.
	private fun stopManaging(): Boolean {
		if (!managing) return false
		managing = false
		chosen.clear()
		reshape()
		return true
	}

	// OK, and Back or a tap outside; true keeps the dialog open.
	private fun onClose(confirmed: Boolean): Boolean {
		if (editing == null) return stopManaging()
		when {
			confirmed -> commit()
			closesAfterAdd -> {
				finishEdit()
				return false
			}
			else -> cancelEdit()
		}
		return true
	}

	private fun deleteChosen() {
		if (chosen.isEmpty()) return
		store.remove(chosen.toSet())
		chosen.clear()
		onChanged()
		if (store.all().isEmpty()) managing = false
		morph()
	}

	private fun toggle(item: SavedIdentity, check: MaterialCheckBox) {
		if (!chosen.add(item.id)) chosen.remove(item.id)
		check.isChecked = item.id in chosen
		delete.isEnabled = chosen.isNotEmpty()
	}

	private inner class Adapter : RecyclerView.Adapter<Holder>() {
		var items = mutableListOf<SavedIdentity>()
		var marked: String? = null

		// A new identity's line comes first, ahead of the saved ones.
		private val offset get() = if (editing?.id == null && editing != null) 1 else 0

		override fun getItemCount() = items.size + offset

		fun itemAt(position: Int) = items.getOrNull(position - offset)

		override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
			Holder(inflater.inflate(R.layout.item_identity, parent, false))

		override fun onBindViewHolder(holder: Holder, position: Int) = holder.bind()

		// A rebind must not cut short the fade of the tools the refresh began.
		override fun onBindViewHolder(holder: Holder, position: Int, payloads: MutableList<Any>) =
			holder.bind(fading in payloads)

		fun move(from: Int, to: Int) {
			items.add(to, items.removeAt(from))
			notifyItemMoved(from, to)
		}
	}

	private inner class Holder(view: View) : RecyclerView.ViewHolder(view) {
		private val radio: MaterialRadioButton = view.findViewById(R.id.identityRadio)
		private val check: MaterialCheckBox = view.findViewById(R.id.identityCheck)
		private val name: TextView = view.findViewById(R.id.identityName)
		private val field: EditText = view.findViewById(R.id.identityNameEdit)
		private val tools: View = view.findViewById(R.id.identityTools)

		init {
			tintAccent(field)
			view.setOnClickListener {
				if (busy()) return@setOnClickListener
				val item = item() ?: return@setOnClickListener
				if (managing) {
					toggle(item, check)
				} else {
					onPick(item)
					dialog.dismissAnimated()
				}
			}
			view.setOnLongClickListener {
				if (editing != null || item() == null) return@setOnLongClickListener false
				if (managing) stopManaging() else startManaging()
				true
			}
			view.findViewById<View>(R.id.identityRename).setOnClickListener {
				if (!busy()) item()?.let(::startRename)
			}
			setUpHandle(view.findViewById(R.id.identityMove))
			field.doAfterTextChanged { edit()?.text = it.toString() }
			field.setOnEditorActionListener { _, actionId, _ ->
				if (actionId != EditorInfo.IME_ACTION_DONE) return@setOnEditorActionListener false
				commit()
				true
			}
		}

		private fun item() = adapter.itemAt(bindingAdapterPosition)

		// The typing that is in this line, if any: the new identity's line has no item.
		private fun edit() = editing?.takeIf { it.id == item()?.id }

		// A touch on the handle takes the row: it is held with its ripple lit until it is dropped.
		@SuppressLint("ClickableViewAccessibility")
		private fun setUpHandle(handle: View) {
			handle.setOnTouchListener { _, event ->
				if (event.actionMasked == MotionEvent.ACTION_DOWN && !busy()) {
					mover.startDrag(this)
					itemView.drawableHotspotChanged(tools.left + handle.left + event.x, tools.top + handle.top + event.y)
					itemView.isPressed = true
				}
				true
			}
		}

		// The field takes the keyboard once it is laid out in its place.
		fun focusName() {
			field.setSelection(0, field.length())
			if (field.isLaidOut && !field.isLayoutRequested) field.showKeyboard() else field.doOnNextLayout { field.showKeyboard() }
		}

		fun bind(fadeTools: Boolean = false) {
			val item = item()
			val edit = edit()
			name.text = item?.name.orEmpty()
			name.isVisible = edit == null
			field.isVisible = edit != null
			if (edit != null && field.text.toString() != edit.text) field.setText(edit.text)
			radio.isVisible = !managing
			check.isVisible = managing
			val toolsOn = managing && edit == null
			if (fadeTools && managing) {
				tools.fadeTo(toolsOn, View.INVISIBLE)
			} else {
				tools.animate().cancel()
				tools.alpha = 1f
				tools.isVisible = toolsOn
			}
			radio.isChecked = item != null && item.id == adapter.marked
			check.isChecked = item != null && item.id in chosen
		}
	}
}
