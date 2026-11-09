package com.happwner.bridge

import android.app.Activity
import android.os.Bundle
import androidx.core.content.pm.ShortcutManagerCompat

// The launcher shortcut's target, and the tile's when a start from the tile itself is refused:
// switches the bridge to the other state and closes - no window, nothing asked. The shortcut's
// icon shows the state, and a refused start is told by enable() itself.
class BridgeToggleActivity : Activity() {

	override fun onCreate(savedInstanceState: Bundle?) {
		super.onCreate(savedInstanceState)
		// Done however it was reached: the launcher ranks shortcuts by their actions taking place.
		// Android refuses the report while the user is locked - never a reason to skip the toggle.
		try {
			ShortcutManagerCompat.reportShortcutUsed(this, BridgeController.SHORTCUT_ID_TOGGLE)
		} catch (_: Throwable) {}
		if (BridgeController.isOn(this)) {
			BridgeController.disable(this)
		} else {
			BridgeController.enable(this)
		}
		finish()
	}
}
