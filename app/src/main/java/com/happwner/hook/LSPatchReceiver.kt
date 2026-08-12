package com.happwner.hook

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.happwner.data.ModuleIds
import com.happwner.data.PrefsManager
import com.happwner.data.SettingsProvider
import org.json.JSONObject

class LSPatchReceiver : BroadcastReceiver() {
    // Handle MODULE_LOADED: record the patched app and maybe enable LSPatch mode
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        Log.d("Happwner:LSP", "Receiver triggered with action: $action")

        if (action == ModuleIds.ACTION_MODULE_LOADED) {
            val pkg = intent.getStringExtra(SettingsProvider.EXTRA_PACKAGE)
            Log.d("Happwner:LSP", "MODULE_LOADED from package: $pkg")

            if (pkg == null) {
                Log.w("Happwner:LSP", "Package name is null, aborting")
                return
            }
            if (pkg == context.packageName) {
                Log.d("Happwner:LSP", "Self-load detected, ignoring")
                return
            }

            // Load the current patched-apps set and signature map
            val prefs = PrefsManager.getSafePrefs(context)
            val apps = prefs.getStringSet("lspatch_apps", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
            val sigMapJson = prefs.getString(PrefsManager.PREF_LSPATCH_SIGNATURES, "{}") ?: "{}"
            val sigMap = try { JSONObject(sigMapJson) } catch (_: Throwable) { JSONObject() }

            // Important: keep the signature CRC32, otherwise MainActivity drops the app from the list
            val crc = PrefsManager.getSignatureCrc32(context, pkg)
            Log.d("Happwner:LSP", "Signature CRC for $pkg: $crc")

            if (crc != null) {
                sigMap.put(pkg, crc)
            } else {
                Log.w("Happwner:LSP", "Could not get CRC for $pkg - this might cause auto-removal in UI")
            }

            val isNew = apps.add(pkg)
            Log.d("Happwner:LSP", "App in set: $pkg (Is new: $isNew). Current apps count: ${apps.size}")

            val editor = prefs.edit()
                .putStringSet("lspatch_apps", apps)
                .putString(PrefsManager.PREF_LSPATCH_SIGNATURES, sigMap.toString())

            val xposedActive = ModuleStatus.isModuleActive()
            if (!xposedActive) {
                // New app: enable the mode
                if (isNew) {
                    editor.putBoolean(PrefsManager.PREF_LSPATCH_MODE, true)
                    Log.i("Happwner:LSP", "LSPatch mode auto-enabled due to new app: $pkg")
                // App already known but the mode is off: enable it
                } else if (!prefs.getBoolean(PrefsManager.PREF_LSPATCH_MODE, false)) {
                    editor.putBoolean(PrefsManager.PREF_LSPATCH_MODE, true)
                    Log.i("Happwner:LSP", "LSPatch mode restored for existing app: $pkg")
                }
            } else {
                // Xposed is active: record the app in the list, but leave lspatch_mode untouched
                Log.d("Happwner:LSP", "Xposed mode active, accumulating app but not flipping lspatch_mode")
            }

            editor.apply()

            // Tell MainActivity to refresh the UI
            context.sendBroadcast(Intent(ModuleIds.ACTION_REFRESH_UI).setPackage(context.packageName))
            Log.d("Happwner:LSP", "Sent REFRESH_UI broadcast")

            // Send the settings back in the reply
            PrefsManager.broadcastSettings(context)
        }
    }
}
