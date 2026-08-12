package com.happwner.data

import android.content.Context
import android.content.res.Configuration
import android.content.res.Resources
import android.os.Build
import java.util.Locale

// The language the app presents itself in. Consolidates the attachBaseContext locale handling
// the two activities, the service and BridgeController each carried, working on a copy of the config.
internal object AppLocale {

    private const val SETTING = "app_lang"
    private const val FOLLOW_SYSTEM = "system"

    // The locale the saved setting asks for, or the system's own.
    fun selected(context: Context): Locale {
        val lang = PrefsManager.getSafePrefs(context)
            .getString(SETTING, FOLLOW_SYSTEM) ?: FOLLOW_SYSTEM
        if (lang != FOLLOW_SYSTEM) return Locale.forLanguageTag(lang)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            Resources.getSystem().configuration.locales.get(0)
        } else {
            @Suppress("DEPRECATION")
            Resources.getSystem().configuration.locale
        }
    }

    // A context whose resources speak that language.
    fun wrap(context: Context, setProcessDefault: Boolean = false): Context {
        val locale = selected(context)
        if (setProcessDefault) Locale.setDefault(locale)
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
