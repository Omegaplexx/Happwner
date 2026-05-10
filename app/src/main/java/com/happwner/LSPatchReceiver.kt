package com.happwner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import org.json.JSONObject

class LSPatchReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        Log.d("Happwner:LSP", "Receiver triggered with action: $action")

        if (action == "${context.packageName}.MODULE_LOADED") {
            val pkg = intent.getStringExtra("pkg")
            Log.d("Happwner:LSP", "MODULE_LOADED from package: $pkg")
            
            if (pkg == null) {
                Log.w("Happwner:LSP", "Package name is null, aborting")
                return
            }
            if (pkg == context.packageName) {
                Log.d("Happwner:LSP", "Self-load detected, ignoring")
                return
            }
            
            val prefs = PrefsManager.getSafePrefs(context)
            val apps = prefs.getStringSet("lspatch_apps", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
            val sigMapJson = prefs.getString("lspatch_signatures", "{}") ?: "{}"
            val sigMap = JSONObject(sigMapJson)

            // Важно: сохраняем CRC32 подписи, иначе MainActivity удалит приложение из списка
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
                .putString("lspatch_signatures", sigMap.toString())
            
            // Если добавили новое приложение, включаем режим
            if (isNew) {
                editor.putBoolean("lspatch_mode", true)
                Log.i("Happwner:LSP", "LSPatch mode auto-enabled due to new app: $pkg")
            } else if (!prefs.getBoolean("lspatch_mode", false)) {
                // Если приложение уже было, но режим выключен - включаем
                editor.putBoolean("lspatch_mode", true)
                Log.i("Happwner:LSP", "LSPatch mode restored for existing app: $pkg")
            }
            
            editor.apply()
            
            // Уведомляем MainActivity, что нужно обновить UI
            context.sendBroadcast(Intent("${context.packageName}.REFRESH_UI"))
            Log.d("Happwner:LSP", "Sent REFRESH_UI broadcast")
            
            // Отправляем настройки в ответ
            PrefsManager.broadcastSettings(context)
        }
    }
}
