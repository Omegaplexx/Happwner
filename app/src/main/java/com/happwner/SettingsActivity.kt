package com.happwner

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.appcompat.widget.Toolbar
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import com.google.android.material.switchmaterial.SwitchMaterial
import com.google.android.material.card.MaterialCardView

class SettingsActivity : AppCompatActivity() {

    private fun getSafePrefs(context: Context): SharedPreferences = PrefsManager.getSafePrefs(context)

    override fun attachBaseContext(newBase: Context) {
        val prefs = getSafePrefs(newBase)
        val lang = prefs.getString("app_lang", "system") ?: "system"
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val safePrefs = getSafePrefs(this)
        val themeMode = safePrefs.getInt("theme_mode", 0)
        AppCompatDelegate.setDefaultNightMode(when(themeMode) {
            1 -> AppCompatDelegate.MODE_NIGHT_NO
            2 -> AppCompatDelegate.MODE_NIGHT_YES
            else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        })

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
        
        setContentView(R.layout.activity_settings)

        val toolbar = findViewById<Toolbar>(R.id.settingsToolbar)
        setSupportActionBar(toolbar)
        // supportActionBar?.setDisplayHomeAsUpEnabled(true) // Remove the system back button

        findViewById<View>(R.id.action_back).setOnClickListener {
            finish()
        }

        findViewById<View>(R.id.action_info).setOnClickListener {
            showInfoDialog()
        }

        val statusBarBackground = findViewById<View>(R.id.statusBarBackground)
        val settingsScrollView = findViewById<android.widget.ScrollView>(R.id.settingsScrollView)
        
        ViewCompat.setOnApplyWindowInsetsListener(window.decorView) { _, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            
            statusBarBackground.layoutParams.height = systemBars.top
            statusBarBackground.requestLayout()
            
            settingsScrollView.setPadding(0, 0, 0, systemBars.bottom)
            insets
        }

        val prefs = getSafePrefs(this)

        // Setting: Language
        val itemLanguage = findViewById<MaterialCardView>(R.id.itemLanguage)
        val textLanguageStatus = findViewById<TextView>(R.id.textLanguageStatus)
        val langOptionsRaw = resources.getStringArray(R.array.language_options)
        val langOptions = langOptionsRaw.map { fromHtml(it) }.toTypedArray()
        val currentLang = prefs.getString("app_lang", "system") ?: "system"
        val currentLangIndex = when(currentLang) {
            "ru" -> 1
            "en" -> 2
            else -> 0
        }
        textLanguageStatus.text = fromHtml(langOptionsRaw[currentLangIndex])

        itemLanguage.setOnClickListener {
            val dialogView = layoutInflater.inflate(R.layout.dialog_select_option, null)
            val rg = dialogView.findViewById<android.widget.RadioGroup>(R.id.dialogRadioGroup)
            val r1 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption1)
            val r2 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption2)
            val r3 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption3)
            
            r1.text = langOptions[0]
            r2.text = langOptions[1]
            r3.text = langOptions[2]
            
            when(currentLangIndex) {
                0 -> r1.isChecked = true
                1 -> r2.isChecked = true
                2 -> r3.isChecked = true
            }

            val dialog = MaterialAlertDialogBuilder(this)
                .setTitle(fromHtml(getString(R.string.label_language)))
                .setView(dialogView)
                .show()

            rg.setOnCheckedChangeListener { _, checkedId ->
                val newLang = when(checkedId) {
                    R.id.radioOption2 -> "ru"
                    R.id.radioOption3 -> "en"
                    else -> "system"
                }
                prefs.edit().putString("app_lang", newLang).apply()
                dialog.dismiss()
                
                // Restart the service to update the notification language
                if (prefs.getBoolean("bridge_enabled", false)) {
                    stopService(Intent(this, SubscriptionService::class.java))
                    val serviceIntent = Intent(this, SubscriptionService::class.java)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        startForegroundService(serviceIntent)
                    } else {
                        startService(serviceIntent)
                    }
                }

                recreate()
            }
        }
        
        // Setting: Theme
        val itemTheme = findViewById<MaterialCardView>(R.id.itemTheme)
        val textThemeStatus = findViewById<TextView>(R.id.textThemeStatus)
        val themeOptionsRaw = resources.getStringArray(R.array.theme_options)
        val themeOptions = themeOptionsRaw.map { fromHtml(it) }.toTypedArray()
        var currentTheme = prefs.getInt("theme_mode", 0)
        textThemeStatus.text = fromHtml(themeOptionsRaw[currentTheme])

        itemTheme.setOnClickListener {
            val dialogView = layoutInflater.inflate(R.layout.dialog_select_option, null)
            val rg = dialogView.findViewById<android.widget.RadioGroup>(R.id.dialogRadioGroup)
            val r1 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption1)
            val r2 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption2)
            val r3 = dialogView.findViewById<com.google.android.material.radiobutton.MaterialRadioButton>(R.id.radioOption3)
            
            r1.text = themeOptions[0]
            r2.text = themeOptions[1]
            r3.text = themeOptions[2]
            
            when(currentTheme) {
                0 -> r1.isChecked = true
                1 -> r2.isChecked = true
                2 -> r3.isChecked = true
            }

            val dialog = MaterialAlertDialogBuilder(this)
                .setTitle(fromHtml(getString(R.string.label_theme)))
                .setView(dialogView)
                .show()

            rg.setOnCheckedChangeListener { _, checkedId ->
                val which = when(checkedId) {
                    R.id.radioOption1 -> 0
                    R.id.radioOption2 -> 1
                    R.id.radioOption3 -> 2
                    else -> 0
                }
                currentTheme = which
                prefs.edit().putInt("theme_mode", which).apply()
                textThemeStatus.text = fromHtml(themeOptionsRaw[which])
                
                AppCompatDelegate.setDefaultNightMode(when(which) {
                    1 -> AppCompatDelegate.MODE_NIGHT_NO
                    2 -> AppCompatDelegate.MODE_NIGHT_YES
                    else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
                })
                dialog.dismiss()
            }
        }

        // Setting: Show duplicates
        val itemShowDuplicates = findViewById<MaterialCardView>(R.id.itemShowDuplicates)
        val switchShowDuplicates = findViewById<SwitchMaterial>(R.id.switchShowDuplicates)
        
        switchShowDuplicates.isChecked = prefs.getBoolean("show_duplicates", false)
        
        val updateDuplicates = { checked: Boolean ->
            prefs.edit().putBoolean("show_duplicates", checked).apply()
            switchShowDuplicates.isChecked = checked
        }
        
        itemShowDuplicates.setOnClickListener { updateDuplicates(!switchShowDuplicates.isChecked) }
        switchShowDuplicates.setOnCheckedChangeListener { _, isChecked -> 
            prefs.edit().putBoolean("show_duplicates", isChecked).apply()
            PrefsManager.fixSharedPrefs(this)
        }

        // Setting: Link interception
        val itemInterceptLinks = findViewById<MaterialCardView>(R.id.itemInterceptLinks)
        val switchInterceptLinks = findViewById<SwitchMaterial>(R.id.switchInterceptLinks)
        switchInterceptLinks.isChecked = prefs.getBoolean("intercept_enabled", false)
        
        val updateInterceptLinks = { checked: Boolean ->
            prefs.edit().putBoolean("intercept_enabled", checked).apply()
            switchInterceptLinks.isChecked = checked
            PrefsManager.fixSharedPrefs(this)
            PrefsManager.broadcastSettings(this)
        }
        itemInterceptLinks.setOnClickListener { updateInterceptLinks(!switchInterceptLinks.isChecked) }
        switchInterceptLinks.setOnClickListener { updateInterceptLinks(switchInterceptLinks.isChecked) }

        // Setting: Parse response
        val itemProcessResponse = findViewById<MaterialCardView>(R.id.itemProcessResponse)
        setHtmlText(findViewById(R.id.textProcessResponseDesc), R.string.setting_process_response_desc)
        itemProcessResponse.setOnClickListener {
            val dialogView = layoutInflater.inflate(R.layout.dialog_process_response, null)
            val checkManual = dialogView.findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.checkProcessManual)
            val checkServer = dialogView.findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.checkProcessServer)

            checkManual.isChecked = prefs.getBoolean("process_manual", true)
            checkServer.isChecked = prefs.getBoolean("process_server", false)

            MaterialAlertDialogBuilder(this)
                .setTitle(fromHtml(getString(R.string.setting_process_response)))
                .setView(dialogView)
                .setPositiveButton(fromHtml(getString(R.string.btn_ok))) { _, _ ->
                    prefs.edit()
                        .putBoolean("process_manual", checkManual.isChecked)
                        .putBoolean("process_server", checkServer.isChecked)
                        .apply()
                    PrefsManager.fixSharedPrefs(this@SettingsActivity)
                }
                .show()
        }

        // Subscription Bridge: Enable
        val itemEnableBridge = findViewById<MaterialCardView>(R.id.itemEnableBridge)
        val switchEnableBridge = findViewById<SwitchMaterial>(R.id.switchEnableBridge)
        switchEnableBridge.isChecked = prefs.getBoolean("bridge_enabled", false)
        
        val updateBridge: (Boolean) -> Unit = { checked ->
            if (checked && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                androidx.core.content.ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), resources.getInteger(R.integer.request_code_notifications))
            } else {
                prefs.edit().putBoolean("bridge_enabled", checked).apply()
                switchEnableBridge.isChecked = checked
                if (checked) {
                    val serviceIntent = Intent(this, SubscriptionService::class.java)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        startForegroundService(serviceIntent)
                    } else {
                        startService(serviceIntent)
                    }
                } else {
                    stopService(Intent(this, SubscriptionService::class.java))
                }
            }
        }
        itemEnableBridge.setOnClickListener { updateBridge(!switchEnableBridge.isChecked) }
        switchEnableBridge.setOnClickListener { updateBridge(switchEnableBridge.isChecked) }

        // Subscription Bridge: Battery optimization
        val itemBatteryOpt = findViewById<MaterialCardView>(R.id.itemBatteryOpt)
        itemBatteryOpt.setOnClickListener {
            try {
                val intent = Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                startActivity(intent)
            } catch (e: Exception) {
                val intent = Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                startActivity(intent)
            }
        }

        // Subscription Bridge: Watchdog
        val itemWatchdog = findViewById<MaterialCardView>(R.id.itemWatchdog)
        val switchWatchdog = findViewById<SwitchMaterial>(R.id.switchWatchdog)
        switchWatchdog.isChecked = prefs.getBoolean("bridge_watchdog", false)
        val updateWatchdog = { checked: Boolean ->
            prefs.edit().putBoolean("bridge_watchdog", checked).apply()
            switchWatchdog.isChecked = checked
            if (switchEnableBridge.isChecked) {
                startService(Intent(this, SubscriptionService::class.java))
            }
        }
        itemWatchdog.setOnClickListener { updateWatchdog(!switchWatchdog.isChecked) }
        
        updateBatteryStatus()
    }

    private val prefsListener = SharedPreferences.OnSharedPreferenceChangeListener { sharedPrefs, key ->
        if (key == "bridge_enabled") {
            val isEnabled = sharedPrefs.getBoolean("bridge_enabled", false)
            runOnUiThread {
                findViewById<SwitchMaterial>(R.id.switchEnableBridge)?.isChecked = isEnabled
            }
        }
    }

    private fun updateBatteryStatus() {
        val textBatteryStatus = findViewById<TextView>(R.id.textBatteryStatus)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val powerManager = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
            val isIgnoring = powerManager.isIgnoringBatteryOptimizations(packageName)

            if (isIgnoring) {
                textBatteryStatus.text = getString(R.string.setting_battery_opt_unrestricted)
                textBatteryStatus.visibility = View.VISIBLE
            } else {
                textBatteryStatus.visibility = View.GONE
            }
        } else {
            textBatteryStatus.visibility = View.GONE
        }
    }

    override fun onResume() {
        super.onResume()
        updateBatteryStatus()
        getSafePrefs(this)
            .registerOnSharedPreferenceChangeListener(prefsListener)
    }

    override fun onPause() {
        super.onPause()
        getSafePrefs(this)
            .unregisterOnSharedPreferenceChangeListener(prefsListener)
    }

    private fun fromHtml(text: String): CharSequence {
        if (text.isEmpty()) return ""
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            android.text.Html.fromHtml(text, android.text.Html.FROM_HTML_MODE_LEGACY)
        } else {
            @Suppress("DEPRECATION")
            android.text.Html.fromHtml(text)
        }
    }

    private fun setHtmlText(textView: TextView, resId: Int) {
        val text = getString(resId)
        textView.text = fromHtml(text)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == resources.getInteger(R.integer.request_code_notifications)) {
            val prefs = getSafePrefs(this)
            val switchEnableBridge = findViewById<SwitchMaterial>(R.id.switchEnableBridge)
            prefs.edit().putBoolean("bridge_enabled", true).apply()
            switchEnableBridge.isChecked = true
            val serviceIntent = Intent(this, SubscriptionService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(serviceIntent)
            } else {
                startService(serviceIntent)
            }
        }
    }

    private fun showInfoDialog() {
        val versionName = try {
            val pInfo = packageManager.getPackageInfo(packageName, 0)
            pInfo.versionName
        } catch (e: Exception) {
            "Unknown"
        }

        val prefs = getSafePrefs(this)
        val lspatchMode = prefs.getBoolean("lspatch_mode", false)
        val moduleActive = ModuleStatus.isModuleActive()
        
        val statusText = when {
            moduleActive -> getString(R.string.label_xposed_active)
            lspatchMode -> getString(R.string.label_lspatch_active)
            else -> getString(R.string.label_xposed_inactive)
        }

        val dialogView = layoutInflater.inflate(R.layout.dialog_info, null)
        val textInfo = dialogView.findViewById<TextView>(R.id.dialogMessage)
        val infoHtml = getString(R.string.about_app_text, versionName, statusText)
        textInfo.text = fromHtml(infoHtml)
        textInfo.movementMethod = android.text.method.LinkMovementMethod.getInstance()

        MaterialAlertDialogBuilder(this)
            .setTitle(fromHtml(getString(R.string.about_app)))
            .setView(dialogView)
            .setPositiveButton(fromHtml(getString(R.string.btn_ok)), null)
            .show()
    }
}
