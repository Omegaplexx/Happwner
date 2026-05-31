package com.happwner

import android.content.Context
import android.content.SharedPreferences
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.view.WindowInsetsControllerCompat

// Settings as a standalone activity, a fallback for system-animation mode
class SettingsActivity : AppCompatActivity() {

    private fun getSafePrefs(context: Context): SharedPreferences = PrefsManager.getSafePrefs(context)

    // Apply the selected language before the context is created
    override fun attachBaseContext(newBase: Context) {
        val safePrefs = getSafePrefs(newBase)
        val lang = safePrefs.getString("app_lang", "system") ?: "system"
        val config = newBase.resources.configuration

        val locale = if (lang == "system") {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                android.content.res.Resources.getSystem().configuration.locales.get(0)
            } else {
                @Suppress("DEPRECATION")
                android.content.res.Resources.getSystem().configuration.locale
            }
        } else {
            java.util.Locale.forLanguageTag(lang)
        }

        java.util.Locale.setDefault(locale)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            config.setLocale(locale)
        } else {
            @Suppress("DEPRECATION")
            config.locale = locale
        }
        super.attachBaseContext(newBase.createConfigurationContext(config))
    }

    // Apply theme/AMOLED before super.onCreate so the right style gets inflated
    override fun onCreate(savedInstanceState: Bundle?) {
        val safePrefs = getSafePrefs(this)
        val themeMode = safePrefs.getInt("theme_mode", 0)
        AppCompatDelegate.setDefaultNightMode(when(themeMode) {
            1 -> AppCompatDelegate.MODE_NIGHT_NO
            2, 3 -> AppCompatDelegate.MODE_NIGHT_YES
            else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        })
        if (themeMode == 3) {
            setTheme(R.style.Theme_Happwner_Amoled)
        }
        super.onCreate(savedInstanceState)

        resetAnimatorScale(this)

        // Monet accent (Android 12+): try to apply the system palette
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && safePrefs.getBoolean("monet_accent", false)) {
            try {
                resources.getColor(android.R.color.system_accent1_500, theme)
                theme.applyStyle(R.style.ThemeOverlay_Happwner_Monet, true)
            } catch (_: Throwable) {}
        }

        // Edge-to-edge: transparent system bars, content drawn behind them
        androidx.core.view.WindowCompat.setDecorFitsSystemWindows(window, false)

        window.apply {
            addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS)
            @Suppress("DEPRECATION")
            statusBarColor = Color.TRANSPARENT
            @Suppress("DEPRECATION")
            navigationBarColor = Color.TRANSPARENT
        }
        val isNightMode = (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) == android.content.res.Configuration.UI_MODE_NIGHT_YES
        WindowInsetsControllerCompat(window, window.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = !isNightMode
        }

        // Crossfade on a theme/language change
        ThemeTransition.preApplyBackground(this)
        setContentView(R.layout.activity_settings)
        ThemeTransition.consumeOverlay(this)

        // First launch: attach the settings fragment
        if (savedInstanceState == null) {
            try {
                val fragment = SettingsFragment()
                supportFragmentManager.beginTransaction()
                    .add(R.id.settingsActivityRoot, fragment, "settings_fragment_activity")
                    .commitNow()
            } catch (_: Throwable) {}
        }
    }
}
