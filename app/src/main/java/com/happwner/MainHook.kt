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
        @Volatile private var isHappUnlockHookEnabled: Boolean = false

        private var isInitialized = false
        private val lock = Any()

        private val unlockStateLock = Any()
        private val unlockStateObservers = java.util.Collections.synchronizedList(mutableListOf<(Boolean) -> Unit>())

        // Set the unlock flag and notify observers if it changed
        private fun applyHappUnlockEnabled(enabled: Boolean) {
            val toFire: List<(Boolean) -> Unit>
            synchronized(unlockStateLock) {
                if (isHappUnlockHookEnabled == enabled) return
                isHappUnlockHookEnabled = enabled
                toFire = synchronized(unlockStateObservers) { unlockStateObservers.toList() }
            }
            for (o in toFire) {
                try { o(enabled) } catch (_: Throwable) {}
            }
        }

        // Debug helper: log a message with a trimmed stack trace
        fun logTrace(message: String) {
            val stackTrace = Thread.currentThread().stackTrace
                .drop(3)
                .take(8)
                .joinToString("\n") { "  at ${it.className}.${it.methodName}(${it.fileName}:${it.lineNumber})" }
            Log.d(TAG, "$message\n$stackTrace")
        }
    }

    // Xposed entry point: runs inside each loaded app's process
    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        // In our own app, just force ModuleStatus.isModuleActive() to true
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

                        // Notify the main app that we are loaded (so it can auto-enable the mode)
                        val loadedIntent = Intent("${MODULE_PACKAGE}.MODULE_LOADED").apply {
                            setPackage(MODULE_PACKAGE)
                            putExtra("pkg", context.packageName)
                            addFlags(0x01000000) // FLAG_RECEIVER_INCLUDE_BACKGROUND
                        }
                        context.sendBroadcast(loadedIntent)
                        Log.d(TAG, "Sent MODULE_LOADED for ${context.packageName}")

                        if (cachedId == null) {
                            // Provider unreachable so far: pull settings via broadcast instead
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

        try {
            // 3. Hook on NameValueCache (Android's internal cache)
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

        // 4. Deep interception via IContentProvider.query (the lowest level in Java)
        hookIContentProvider(lpparam.classLoader, lpparam.packageName)

        // Intercept the URL for history
        XposedHelpers.findAndHookConstructor(URL::class.java, String::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val url = param.args[0] as? String ?: return
                if (url.startsWith("http") && isInterceptEnabled) {
                    saveUrlAsync(url, lpparam.packageName)
                }
            }
        })

        try {
            // 5. Three-finger gesture to summon Happwner
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

        // 6. Optional: unlock the hidden Happ settings
        hookHideSettings(lpparam.classLoader)
    }

    // Clear Happ's _hideSettings via a behavioral probe, without hardcoding method names
    private fun hookHideSettings(classLoader: ClassLoader) {
        val candidateClasses = arrayOf(
            "su.happ.proxyutility.dto.SubscriptionItem",
            "com.happproxy.dto.SubscriptionItem"
        )
        val clazz = candidateClasses.firstNotNullOfOrNull { XposedHelpers.findClassIfExists(it, classLoader) } ?: return

        // Grab the three private flags we'll probe
        val fHide = try { clazz.getDeclaredField("_hideSettings").apply { isAccessible = true } } catch (e: Throwable) { return }
        val fEnc = try { clazz.getDeclaredField("encrypted").apply { isAccessible = true } } catch (e: Throwable) { return }
        val fEncUrl = try { clazz.getDeclaredField("encryptedUrl").apply { isAccessible = true } } catch (e: Throwable) { return }

        val probed = java.util.concurrent.atomic.AtomicBoolean(false)
        val ctorUnhooks = java.util.Collections.synchronizedList(mutableListOf<XC_MethodHook.Unhook>())

        val targetMethods = mutableListOf<java.lang.reflect.Method>()
        val activeUnhooks = mutableListOf<XC_MethodHook.Unhook>()
        val patchLock = Any()

        // Force the discovered getter(s) to return false (settings shown)
        val applyPatches = {
            synchronized(patchLock) {
                if (activeUnhooks.isEmpty()) {
                    for (m in targetMethods) {
                        try {
                            activeUnhooks.add(XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false)))
                        } catch (_: Throwable) {}
                    }
                }
            }
        }

        // Undo those hooks
        val removePatches = {
            synchronized(patchLock) {
                for (uh in activeUnhooks) {
                    try { uh.unhook() } catch (_: Throwable) {}
                }
                activeUnhooks.clear()
            }
        }

        // On the first instance: probe for the getter, then hook it per the toggle
        val ctorHook = object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                if (!isHappUnlockHookEnabled) return
                if (!probed.compareAndSet(false, true)) return
                val probe = param.thisObject ?: run { probed.set(false); return }
                try {
                    val origHide = fHide.getBoolean(probe)
                    val origEnc = fEnc.getBoolean(probe)
                    val origEncUrl = fEncUrl.getBoolean(probe)
                    try {
                        // Probe: find the getter whose truth table depends on _hideSettings/encrypted/encryptedUrl
                        for (m in clazz.declaredMethods) {
                            if (m.parameterTypes.isNotEmpty()) continue
                            if (m.returnType != java.lang.Boolean.TYPE) continue
                            if (!java.lang.reflect.Modifier.isPublic(m.modifiers)) continue
                            try {
                                m.isAccessible = true
                                fHide.setBoolean(probe, false); fEnc.setBoolean(probe, false); fEncUrl.setBoolean(probe, true)
                                val a = m.invoke(probe) as Boolean
                                fEncUrl.setBoolean(probe, false)
                                val b = m.invoke(probe) as Boolean
                                fHide.setBoolean(probe, true)
                                val c = m.invoke(probe) as Boolean
                                if (a && !b && c) {
                                    synchronized(patchLock) { targetMethods.add(m) }
                                }
                            } catch (e: Throwable) {}
                        }
                    } finally {
                        try { fHide.setBoolean(probe, origHide) } catch (e: Throwable) {}
                        try { fEnc.setBoolean(probe, origEnc) } catch (e: Throwable) {}
                        try { fEncUrl.setBoolean(probe, origEncUrl) } catch (e: Throwable) {}
                    }

                    // React to a settings toggle being flipped at runtime
                    val observer: (Boolean) -> Unit = { _ ->
                        if (isHappUnlockHookEnabled) applyPatches() else removePatches()
                    }
                    synchronized(unlockStateLock) {
                        synchronized(unlockStateObservers) { unlockStateObservers.add(observer) }
                        if (isHappUnlockHookEnabled) applyPatches() else removePatches()
                    }
                } catch (e: Throwable) {
                    Log.e(TAG, "hookHideSettings probe: ${e.message}")
                } finally {
                    synchronized(ctorUnhooks) {
                        ctorUnhooks.forEach { try { it.unhook() } catch (e: Throwable) {} }
                        ctorUnhooks.clear()
                    }
                }
            }
        }

        // Hook every constructor so we can probe the first instance
        for (ctor in clazz.declaredConstructors) {
            try { ctorUnhooks.add(XposedBridge.hookMethod(ctor, ctorHook)) } catch (e: Throwable) {}
        }
    }

    private fun hookIContentProvider(classLoader: ClassLoader, currentPackage: String) {
        // Wrap settings-query results so android_id reads return the spoofed value
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
            // Hook each query() overload on ContentProviderProxy
            val proxyClass = XposedHelpers.findClass("android.content.ContentProviderProxy", classLoader)

            try {
                XposedHelpers.findAndHookMethod(proxyClass, "query",
                    String::class.java, String::class.java, Uri::class.java, Array<String>::class.java, Bundle::class.java,
                    XposedHelpers.findClass("android.os.ICancellationSignal", classLoader), queryHook)
            } catch (e: Throwable) {}

            try {
                XposedHelpers.findAndHookMethod(proxyClass, "query",
                    String::class.java, Uri::class.java, Array<String>::class.java, Bundle::class.java,
                    XposedHelpers.findClass("android.os.ICancellationSignal", classLoader), queryHook)
            } catch (e: Throwable) {}

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

    // Tell the app the real android_id we observed (for history/UI)
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

    // Cursor that swaps android_id's value and type for the spoofed id
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
                    addFlags(0x01000000) // FLAG_RECEIVER_INCLUDE_BACKGROUND
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

    // Load HWID/flags from our SettingsProvider
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

    // Pull settings via the provider call() and cache them in RAM
    private fun initCacheWithResolver(resolver: ContentResolver) {
        try {
            val bundle = resolver.call(SETTINGS_URI, "getSettings", null, null)
            if (bundle != null) {
                cachedId = bundle.getString("custom_hwid")
                isEnabled = bundle.getBoolean("use_custom_hwid_substitution", false)
                isInterceptEnabled = bundle.getBoolean("intercept_enabled", false)
                applyHappUnlockEnabled(bundle.getBoolean("hook_happ_unlock_settings", false))
                Log.d(TAG, "Cache initialized via Provider: ID=$cachedId, Spoof=$isEnabled, Unlock=$isHappUnlockHookEnabled")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Provider unreachable (Package Visibility issue?): ${e.message}")
        }
    }

    // Listen for SETTINGS_UPDATE and refresh the RAM cache
    private fun registerSignalReceiver(context: Context) {
        val filter = IntentFilter("${MODULE_PACKAGE}.SETTINGS_UPDATE")
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {

                // Read the data straight from the Intent (the fast, reliable path for rootless)
                if (intent.hasExtra("custom_hwid")) {
                    cachedId = intent.getStringExtra("custom_hwid")
                    isEnabled = intent.getBooleanExtra("use_custom_hwid_substitution", false)
                    isInterceptEnabled = intent.getBooleanExtra("intercept_enabled", false)
                    applyHappUnlockEnabled(intent.getBooleanExtra("hook_happ_unlock_settings", false))
                    Log.d(TAG, "RAM Cache updated via Broadcast: ID=$cachedId, Spoof=$isEnabled, Unlock=$isHappUnlockHookEnabled")
                } else {

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

    // Off-thread: hand a captured URL to the provider for history
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
