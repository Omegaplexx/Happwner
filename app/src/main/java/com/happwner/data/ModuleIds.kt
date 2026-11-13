package com.happwner.data

import com.happwner.BuildConfig

// Names derived from the application id.
internal object ModuleIds {

	// The application id this build actually carries.
	const val PACKAGE = BuildConfig.APPLICATION_ID

	// The settings provider's authority, matching `${applicationId}.settings`.
	const val AUTHORITY = "$PACKAGE.settings"

	// The provider's address, as the hook and the app both address it.
	const val SETTINGS_URI = "content://$AUTHORITY/settings"

	// Broadcasts the app sends itself; the suffixes match the manifest.
	const val ACTION_ID_CAPTURED = "$PACKAGE.ID_CAPTURED"
	const val ACTION_URL_CAPTURED = "$PACKAGE.URL_CAPTURED"
	const val ACTION_REFRESH_UI = "$PACKAGE.REFRESH_UI"
	const val ACTION_MODULE_LOADED = "$PACKAGE.MODULE_LOADED"
	const val ACTION_SETTINGS_REQUEST = "$PACKAGE.SETTINGS_REQUEST"
	const val ACTION_SETTINGS_UPDATE = "$PACKAGE.SETTINGS_UPDATE"
	const val ACTION_TOGGLE_BRIDGE = "$PACKAGE.action.TOGGLE_BRIDGE"
	const val ACTION_BRIDGE_RECOVERY = "$PACKAGE.action.BRIDGE_RECOVERY"

	// Sent by the hook's three-finger gesture; carries the app it came from in EXTRA_PACKAGE.
	const val ACTION_SWITCH_FROM_APP = "$PACKAGE.action.SWITCH_FROM_APP"

	// The screen that takes a link opened in Happwner; named as a string to keep UI classes out of
	// the hooked apps.
	const val MAIN_ACTIVITY = "$PACKAGE.ui.MainActivity"

	// The prefix form, for the lists of packages the hook passes over.
	const val PACKAGE_PREFIX = "$PACKAGE."

	// Every Xposed/LSPatch log line uses this, defined once here rather than copied per file.
	const val LOG_LSP = "Happwner:LSP"
}
