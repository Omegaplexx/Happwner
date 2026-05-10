package com.happwner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class SettingsRequestReceiver : BroadcastReceiver() {
    /**
     * Слушает «крики» целевых приложений (Pull) и тут же отправляет им ответ.
     */
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == "${context.packageName}.SETTINGS_REQUEST") {
            val requester = intent.getStringExtra("requester") ?: "unknown"
            Log.d("Happwner:IPC", "Received PULL request from $requester, sending response...")
            
            // Сразу отправляем актуальные настройки в ответ
            PrefsManager.broadcastSettings(context)
        }
    }
}
