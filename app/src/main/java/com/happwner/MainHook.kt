package com.happwner

import android.app.Activity
import android.content.*
import android.database.Cursor
import android.database.CursorWrapper
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.view.MotionEvent
import de.robv.android.xposed.*
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.net.URL

class MainHook : IXposedHookLoadPackage {

    private val MODULE_PACKAGE = "com.happwner"
    private val SETTINGS_URI = Uri.parse("content://com.happwner.settings/settings")

    companion object {
        private const val TAG = "Happwner:Hook"
        
        @Volatile private var cachedId: String? = null
        @Volatile private var isEnabled: Boolean = false
        @Volatile private var isInterceptEnabled: Boolean = false
        
        private var isInitialized = false
        private val lock = Any()

        fun logTrace(message: String) {
            val stackTrace = Thread.currentThread().stackTrace
                .drop(3)
                .take(8)
                .joinToString("\n") { "  at ${it.className}.${it.methodName}(${it.fileName}:${it.lineNumber})" }
            Log.d(TAG, "$message\n$stackTrace")
        }
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName == MODULE_PACKAGE) {
            XposedHelpers.findAndHookMethod("$MODULE_PACKAGE.ModuleStatus", lpparam.classLoader, "isModuleActive", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) { param.result = true }
            })
            return
        }

        // 1. Early initialization via ContextWrapper
        XposedHelpers.findAndHookMethod("android.content.ContextWrapper", lpparam.classLoader, "attachBaseContext", Context::class.java, object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                val context = param.args[0] as Context
                synchronized(lock) {
                    if (!isInitialized) {
                        registerSignalReceiver(context)
                        initCache(context)
                        
                        // Notify the main app that we are loaded (for auto-enabling the mode)
                        val loadedIntent = Intent("${MODULE_PACKAGE}.MODULE_LOADED").apply {
                            setPackage(MODULE_PACKAGE)
                            putExtra("pkg", context.packageName)
                            addFlags(0x01000000) // FLAG_RECEIVER_INCLUDE_BACKGROUND
                        }
                        context.sendBroadcast(loadedIntent)
                        Log.d(TAG, "Sent MODULE_LOADED for ${context.packageName}")

                        // If initialization via Provider failed (cachedId is still null), 
                        // send a request to get data via Broadcast (Pull)
                        if (cachedId == null) {
                            val requestIntent = Intent("${MODULE_PACKAGE}.SETTINGS_REQUEST").apply {
                                setPackage(MODULE_PACKAGE)
                                addFlags(0x01000000) // FLAG_RECEIVER_INCLUDE_BACKGROUND
                            }
                            context.sendBroadcast(requestIntent)
                        }

                        isInitialized = true
                    }
                }
            }
        })

        // 2. Hooks on Settings.Secure/Global
        val settingsHook = object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                val name = param.args[1] as? String
                if (name == Settings.Secure.ANDROID_ID) {
                    val originalId = param.result as? String
                    if (!originalId.isNullOrEmpty() && originalId != cachedId) {
                        val resolver = param.args[0] as? ContentResolver
                        sendIdCapturedBroadcast(resolver, originalId)
                    }

                    ensureCacheInitialized(param.args[0] as? ContentResolver)
                    if (isEnabled && !cachedId.isNullOrEmpty()) {
                        logTrace("Intercepted Settings.getString: android_id -> $cachedId")
                        param.result = cachedId
                    }
                }
            }
        }

        val settingsClasses = arrayOf("Secure", "System", "Global")
        settingsClasses.forEach { cls ->
            try {
                XposedHelpers.findAndHookMethod("android.provider.Settings.$cls", lpparam.classLoader, "getString", 
                    ContentResolver::class.java, String::class.java, settingsHook)
                
                try {
                    XposedHelpers.findAndHookMethod("android.provider.Settings.$cls", lpparam.classLoader, "getStringForUser", 
                        ContentResolver::class.java, String::class.java, Int::class.java, settingsHook)
                } catch (e: Throwable) {}
            } catch (e: Throwable) {}
        }

        // 3. Hook on NameValueCache (internal Android cache)
        try {
            XposedHelpers.findAndHookMethod("android.provider.Settings\$NameValueCache", lpparam.classLoader, "getStringForUser",
                ContentResolver::class.java, String::class.java, Int::class.java, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val name = param.args[1] as? String
                        if (name == Settings.Secure.ANDROID_ID) {
                            val originalId = param.result as? String
                            if (!originalId.isNullOrEmpty() && originalId != cachedId) {
                                val resolver = param.args[0] as? ContentResolver
                                sendIdCapturedBroadcast(resolver, originalId)
                            }

                            ensureCacheInitialized(param.args[0] as? ContentResolver)
                            if (isEnabled && !cachedId.isNullOrEmpty()) {
                                logTrace("Intercepted NameValueCache.getStringForUser: android_id -> $cachedId")
                                param.result = cachedId
                            }
                        }
                    }
                })
        } catch (e: Throwable) {}

        // 4. Deep interception via IContentProvider.query (lowest level in Java)
        hookIContentProvider(lpparam.classLoader, lpparam.packageName)

        // Intercept URL for history
        XposedHelpers.findAndHookConstructor(URL::class.java, String::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val url = param.args[0] as? String ?: return
                if (url.startsWith("http") && isInterceptEnabled) {
                    saveUrlAsync(url, lpparam.packageName)
                }
            }
        })

        // 5. Three-finger gesture to call Happwner
        try {
            XposedHelpers.findAndHookMethod("android.app.Activity", lpparam.classLoader, "dispatchTouchEvent",
                "android.view.MotionEvent", object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val event = param.args[0] as MotionEvent
                        if (event.pointerCount == 3 && event.actionMasked == MotionEvent.ACTION_POINTER_DOWN) {
                            val activity = param.thisObject as Activity
                            val intent = activity.packageManager.getLaunchIntentForPackage(MODULE_PACKAGE)
                            if (intent != null) {
                                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                activity.startActivity(intent)
                            }
                        }
                    }
                })
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to hook dispatchTouchEvent: ${e.message}")
        }
    }

    private fun hookIContentProvider(classLoader: ClassLoader, currentPackage: String) {
        val queryHook = object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                val uri = findUriInArgs(param.args) ?: return
                val cursor = param.result as? Cursor ?: return

                val uriString = uri.toString()
                if (uriString.contains("settings")) {
                    logTrace("IContentProvider.query: Intercepting settings URI: $uriString")
                    if (isEnabled && !cachedId.isNullOrEmpty()) {
                        param.result = SettingsCursorWrapper(cursor, cachedId!!, currentPackage)
                    } else {
                        param.result = SettingsCursorWrapper(cursor, null, currentPackage)
                    }
                }
            }
        }

        try {
            val proxyClass = XposedHelpers.findClass("android.content.ContentProviderProxy", classLoader)
            
            // API 30+
            try {
                XposedHelpers.findAndHookMethod(proxyClass, "query", 
                    String::class.java, String::class.java, Uri::class.java, Array<String>::class.java, Bundle::class.java, 
                    XposedHelpers.findClass("android.os.ICancellationSignal", classLoader), queryHook)
            } catch (e: Throwable) {}

            // API 26-29
            try {
                XposedHelpers.findAndHookMethod(proxyClass, "query", 
                    String::class.java, Uri::class.java, Array<String>::class.java, Bundle::class.java, 
                    XposedHelpers.findClass("android.os.ICancellationSignal", classLoader), queryHook)
            } catch (e: Throwable) {}

            // API 21-25
            try {
                XposedHelpers.findAndHookMethod(proxyClass, "query", 
                    String::class.java, Uri::class.java, Array<String>::class.java, String::class.java, Array<String>::class.java, String::class.java,
                    XposedHelpers.findClass("android.os.ICancellationSignal", classLoader), queryHook)
            } catch (e: Throwable) {}
            
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to hook IContentProvider: ${e.message}")
        }
    }

    private fun findUriInArgs(args: Array<Any?>): Uri? {
        for (arg in args) {
            if (arg is Uri) return arg
        }
        return null
    }

    private fun sendIdCapturedBroadcast(resolver: ContentResolver?, originalId: String) {
        if (originalId.isEmpty()) return
        try {
            val context = (XposedHelpers.callStaticMethod(XposedHelpers.findClass("android.app.ActivityThread", null), "currentActivityThread") as? Any)
                ?.let { XposedHelpers.callMethod(it, "getApplication") as? Context }
                ?: return

            val intent = Intent("${MODULE_PACKAGE}.ID_CAPTURED").apply {
                setPackage(MODULE_PACKAGE)
                putExtra("original_id", originalId)
                addFlags(0x01000000) // FLAG_RECEIVER_INCLUDE_BACKGROUND
            }
            context.sendBroadcast(intent)
        } catch (e: Exception) {}
    }

    private class SettingsCursorWrapper(cursor: Cursor, private val spoofedId: String?, private val currentPackage: String) : CursorWrapper(cursor) {
        private val nameIdx by lazy { 
            try { cursor.getColumnIndex("name") } catch (e: Exception) { -1 }
        }
        private val valueIdx by lazy { 
            try { cursor.getColumnIndex("value") } catch (e: Exception) { -1 }
        }

        override fun getString(columnIndex: Int): String? {
            val originalValue = super.getString(columnIndex)
            if (columnIndex == valueIdx && nameIdx != -1) {
                try {
                    val name = super.getString(nameIdx)
                    if (name == Settings.Secure.ANDROID_ID) {
                        if (!originalValue.isNullOrEmpty() && originalValue != spoofedId) {
                            sendIdCapturedBroadcast(originalValue)
                        }
                        if (spoofedId != null) {
                            return spoofedId
                        }
                    }
                } catch (e: Exception) {}
            }
            return originalValue
        }

        private fun sendIdCapturedBroadcast(originalId: String) {
            try {
                val context = (XposedHelpers.callStaticMethod(XposedHelpers.findClass("android.app.ActivityThread", null), "currentActivityThread") as? Any)
                    ?.let { XposedHelpers.callMethod(it, "getApplication") as? Context }
                    ?: return

                val intent = Intent("com.happwner.ID_CAPTURED").apply {
                    setPackage("com.happwner")
                    putExtra("original_id", originalId)
                    addFlags(0x01000000)
                }
                context.sendBroadcast(intent)
            } catch (e: Exception) {}
        }

        override fun getType(columnIndex: Int): Int {
            if (columnIndex == valueIdx && nameIdx != -1) {
                try {
                    val name = super.getString(nameIdx)
                    if (name == Settings.Secure.ANDROID_ID && spoofedId != null) {
                        return Cursor.FIELD_TYPE_STRING
                    }
                } catch (e: Exception) {}
            }
            return super.getType(columnIndex)
        }
    }

    private fun initCache(context: Context) {
        initCacheWithResolver(context.contentResolver)
    }

    private fun ensureCacheInitialized(resolver: ContentResolver?) {
        if (cachedId == null && resolver != null) {
            synchronized(lock) {
                if (cachedId == null) {
                    initCacheWithResolver(resolver)
                }
            }
        }
    }

    private fun initCacheWithResolver(resolver: ContentResolver) {
        try {
            val bundle = resolver.call(SETTINGS_URI, "getSettings", null, null)
            if (bundle != null) {
                cachedId = bundle.getString("custom_hwid")
                isEnabled = bundle.getBoolean("use_custom_hwid_substitution", false)
                isInterceptEnabled = bundle.getBoolean("intercept_enabled", false)
                Log.d(TAG, "Cache initialized via Provider: ID=$cachedId, Enabled=$isEnabled")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Provider unreachable (Package Visibility issue?): ${e.message}")
        }
    }

    private fun registerSignalReceiver(context: Context) {
        val filter = IntentFilter("${MODULE_PACKAGE}.SETTINGS_UPDATE")
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                // Пытаемся взять данные напрямую из Intent (самый быстрый и надежный способ для rootless)
                if (intent.hasExtra("custom_hwid")) {
                    cachedId = intent.getStringExtra("custom_hwid")
                    isEnabled = intent.getBooleanExtra("use_custom_hwid_substitution", false)
                    isInterceptEnabled = intent.getBooleanExtra("intercept_enabled", false)
                    Log.d(TAG, "RAM Cache updated via Broadcast: ID=$cachedId, Enabled=$isEnabled")
                } else {
                    // Если данных в Intent нет, пробуем перечитать через Provider
                    initCache(context)
                }
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
    }

    private fun saveUrlAsync(url: String, pkg: String) {
        Thread {
            try {
                val activityThread = XposedHelpers.callStaticMethod(XposedHelpers.findClass("android.app.ActivityThread", null), "currentActivityThread")
                val context = XposedHelpers.callMethod(activityThread, "getApplication") as? Context
                context?.contentResolver?.call(SETTINGS_URI, "saveUrl", url, Bundle().apply { putString("pkg", pkg) })
            } catch (e: Exception) {}
        }.start()
    }
}
