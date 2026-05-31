package com.happwner

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ShortcutInfo
import android.content.pm.ShortcutManager
import android.content.res.Configuration
import android.content.res.Resources
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.TileService
import java.util.Locale

object BridgeController {

    const val PREF_BRIDGE_ENABLED = "bridge_enabled"
    const val ACTION_TOGGLE = "com.happwner.action.TOGGLE_BRIDGE"
    const val SHORTCUT_ID_TOGGLE = "bridge_toggle"

    fun isEnabled(context: Context): Boolean =
        PrefsManager.getSafePrefs(context).getBoolean(PREF_BRIDGE_ENABLED, false)

    // Enable the bridge: set the flag and start the service; roll the flag back on failure
    fun enable(context: Context): Boolean {
        val app = context.applicationContext
        val prefs = PrefsManager.getSafePrefs(app)
        prefs.edit().putBoolean(PREF_BRIDGE_ENABLED, true).apply()
        val intent = Intent(app, SubscriptionService::class.java)
        val started = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                app.startForegroundService(intent)
            } else {
                app.startService(intent)
            }
            true
        } catch (_: Throwable) {
            prefs.edit().putBoolean(PREF_BRIDGE_ENABLED, false).apply()
            false
        }
        notifyChanged(app)
        return started
    }

    // Disable the bridge: clear the flag and stop the service
    fun disable(context: Context) {
        val app = context.applicationContext
        PrefsManager.getSafePrefs(app).edit().putBoolean(PREF_BRIDGE_ENABLED, false).apply()
        try {
            app.stopService(Intent(app, SubscriptionService::class.java))
        } catch (_: Throwable) {
        }
        notifyChanged(app)
    }

    // Broadcast a UI refresh, then resync the tile and shortcut
    fun notifyChanged(context: Context) {
        val app = context.applicationContext
        try {
            app.sendBroadcast(Intent("${app.packageName}.REFRESH_UI"))
        } catch (_: Throwable) {
        }
        refreshSurfaces(app)
    }

    // Sync the QS tile and launcher shortcut to the current state
    fun refreshSurfaces(context: Context) {
        val app = context.applicationContext
        refreshTile(app)
        refreshShortcut(app)
    }

    // Nudge the system to re-poll the QS tile (it re-reads state on listening)
    fun refreshTile(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return
        try {
            TileService.requestListeningState(
                context.applicationContext,
                ComponentName(context.applicationContext, BridgeTileService::class.java)
            )
        } catch (_: Throwable) {
        }
    }

    // (Re)publish the dynamic launcher shortcut with the on/off icon and toggle intent
    fun refreshShortcut(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N_MR1) return
        val app = context.applicationContext
        val manager = app.getSystemService(ShortcutManager::class.java) ?: return
        val enabled = isEnabled(app)
        val local = localizedContext(app)
        val label = local.getString(R.string.tile_bridge_label)
        val intent = Intent(app, BridgeToggleActivity::class.java).apply {
            action = ACTION_TOGGLE
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        }
        val shortcut = ShortcutInfo.Builder(app, SHORTCUT_ID_TOGGLE)
            .setShortLabel(label)
            .setLongLabel(label)
            .setIcon(
                Icon.createWithResource(
                    app,
                    if (enabled) R.drawable.ic_shortcut_bridge_on else R.drawable.ic_shortcut_bridge_off
                )
            )
            .setIntent(intent)
            .build()
        try {
            manager.setDynamicShortcuts(listOf(shortcut))
        } catch (_: Throwable) {
        }
    }

    // Context using the app's language, so the tile/shortcut are localized
    fun localizedContext(context: Context): Context {
        val lang = PrefsManager.getSafePrefs(context).getString("app_lang", "system") ?: "system"
        val locale = if (lang == "system") {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                Resources.getSystem().configuration.locales.get(0)
            } else {
                @Suppress("DEPRECATION")
                Resources.getSystem().configuration.locale
            }
        } else {
            Locale.forLanguageTag(lang)
        }
        val config = Configuration(context.resources.configuration)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            config.setLocale(locale)
        } else {
            @Suppress("DEPRECATION")
            config.locale = locale
        }
        return context.createConfigurationContext(config)
    }
}
