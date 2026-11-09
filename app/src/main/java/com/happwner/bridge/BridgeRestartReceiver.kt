package com.happwner.bridge

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

// A boot and an update of this app both kill the bridge, and both broadcasts open a window in which
// a foreground service may be started from the background: the start is made here, in that window.
class BridgeRestartReceiver : BroadcastReceiver() {
	override fun onReceive(context: Context, intent: Intent) {
		val action = intent.action ?: return
		if (action != Intent.ACTION_MY_PACKAGE_REPLACED &&
			action != Intent.ACTION_BOOT_COMPLETED) return
		if (!BridgeController.isEnabled(context)) return
		BridgeRecovery.begin(context, action.substringAfterLast('.'))
	}
}
