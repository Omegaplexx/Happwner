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
    const val ACTION_HAPPANION_INSTALL_STATUS = "$PACKAGE.HAPPANION_INSTALL_STATUS"

    // The prefix form, for the lists of packages the hook passes over.
    const val PACKAGE_PREFIX = "$PACKAGE."
}
