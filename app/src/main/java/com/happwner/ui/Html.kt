package com.happwner.ui

import android.text.method.LinkMovementMethod
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.text.HtmlCompat
import com.happwner.R

// A string resource's markup as a TextView shows it.
internal fun fromHtml(text: String): CharSequence =
	HtmlCompat.fromHtml(text, HtmlCompat.FROM_HTML_MODE_LEGACY)

// A string resource's markup, shown in this view.
internal fun TextView.setHtmlText(resId: Int) {
	text = fromHtml(context.getString(resId))
}

// An HTML message in the information layout - the body of every information dialog and page;
// withLinks makes its links tappable.
internal fun LayoutInflater.infoView(
	html: String,
	parent: ViewGroup? = null,
	withLinks: Boolean = false
): View {
	val view = inflate(R.layout.dialog_info, parent, false)
	val message = view.findViewById<TextView>(R.id.dialogMessage)
	message.text = fromHtml(html)
	if (withLinks) message.movementMethod = LinkMovementMethod.getInstance()
	return view
}
