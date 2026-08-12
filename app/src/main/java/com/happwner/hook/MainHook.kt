package com.happwner.hook

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
import com.happwner.BuildConfig
import com.happwner.data.ModuleIds
import com.happwner.data.PrefsManager
import com.happwner.data.SettingsProvider
import de.robv.android.xposed.*
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.net.URL

class MainHook : IXposedHookLoadPackage {

    private val MODULE_PACKAGE = ModuleIds.PACKAGE
    // Built from the authority the provider publishes, so the two cannot drift.
    // Both names are const, so this costs no class loading inside the hooked app.
    private val SETTINGS_URI = Uri.parse(ModuleIds.SETTINGS_URI)

    companion object {
        private const val TAG = "Happwner:Hook"

        @Volatile private var cachedId: String? = null
        @Volatile private var isEnabled: Boolean = false
        @Volatile private var isInterceptEnabled: Boolean = false
        @Volatile private var isUnlockHookEnabled: Boolean = false

        // Real (un-spoofed) ANDROID_ID, captured from settings reads, used to recognise HWID labels
        @Volatile private var realAndroidId: String? = null
        // TextViews showing the HWID, kept with a template + case flag so we can refresh them when the spoof changes
        private val hwidViews = java.util.Collections.synchronizedList(mutableListOf<Triple<java.lang.ref.WeakReference<Any>, String, Boolean>>())
        private const val HWID_MARKER = "\u0000HWID\u0000"

        private var isInitialized = false
        private val incyHwidHooked = java.util.concurrent.atomic.AtomicBoolean(false)
        private val incyHwidCaptured = java.util.concurrent.atomic.AtomicBoolean(false)
        private val lock = Any()

        // Single worker with a bounded queue for shipping captured URLs to our provider. Bounded on
        // purpose - see saveUrlAsync.
        private val urlSaveExecutor = java.util.concurrent.ThreadPoolExecutor(
            0, 1, 30L, java.util.concurrent.TimeUnit.SECONDS,
            java.util.concurrent.LinkedBlockingQueue(64)
        ).apply { allowCoreThreadTimeOut(true) }

        private val unlockStateLock = Any()
        private val unlockStateObservers = java.util.Collections.synchronizedList(mutableListOf<(Boolean) -> Unit>())

        // Live v2RayTun RecyclerViews (weak refs) so a runtime toggle can re-bind their rows
        private val v2rayRecyclers = java.util.Collections.synchronizedList(mutableListOf<java.lang.ref.WeakReference<Any>>())

        // Set the unlock flag and notify observers if it changed
        private fun applyUnlockEnabled(enabled: Boolean) {
            val toFire: List<(Boolean) -> Unit>
            synchronized(unlockStateLock) {
                if (isUnlockHookEnabled == enabled) return
                isUnlockHookEnabled = enabled
                toFire = synchronized(unlockStateObservers) { unlockStateObservers.toList() }
            }
            for (o in toFire) {
                try { o(enabled) } catch (_: Throwable) {}
            }
        }

        // Debug helper: log a message with a trimmed stack trace
        fun logTrace(message: String) {
            // Debug builds only: skip building the trace on every settings read
            if (!BuildConfig.DEBUG) return
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
            XposedHelpers.findAndHookMethod(MODULE_STATUS_CLASS, lpparam.classLoader, "isModuleActive", object : XC_MethodHook() {
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
                        val loadedIntent = Intent(ModuleIds.ACTION_MODULE_LOADED).apply {
                            setPackage(MODULE_PACKAGE)
                            putExtra(SettingsProvider.EXTRA_PACKAGE, context.packageName)
                            addFlags(0x01000000) // FLAG_RECEIVER_INCLUDE_BACKGROUND
                        }
                        context.sendBroadcast(loadedIntent)
                        Log.d(TAG, "Sent MODULE_LOADED for ${context.packageName}")

                        if (cachedId == null) {
                            // Provider unreachable so far: pull settings via broadcast instead
                            val requestIntent = Intent(ModuleIds.ACTION_SETTINGS_REQUEST).apply {
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
                    if (!originalId.isNullOrEmpty()) {
                        realAndroidId = originalId
                        if (originalId != cachedId) {
                            sendIdCapturedBroadcast(originalId)
                        }
                    }

                    ensureCacheInitialized(param.args[0] as? ContentResolver)
                    // Snapshot the volatile: testing it and handing it back are two reads, and
                    // another thread rewrites it.
                    val id = cachedId
                    if (isEnabled && !id.isNullOrEmpty()) {
                        logTrace("Intercepted Settings.getString: android_id -> $id")
                        param.result = id
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
                            if (!originalId.isNullOrEmpty()) {
                                realAndroidId = originalId
                                if (originalId != cachedId) {
                                    sendIdCapturedBroadcast(originalId)
                                }
                            }

                            ensureCacheInitialized(param.args[0] as? ContentResolver)
                            // Snapshot, for the same reason as the Settings hook above.
                            val id = cachedId
                            if (isEnabled && !id.isNullOrEmpty()) {
                                logTrace("Intercepted NameValueCache.getStringForUser: android_id -> $id")
                                param.result = id
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

        // 7. Optional: unlock v2RayTun encrypted subscriptions (only fires if its class is present)
        hookV2RayTunUnlock(lpparam.classLoader)

        // 8. Keep the on-screen HWID label in sync with the spoof without a restart (Happ only)
        hookHwidLabels(lpparam.classLoader, lpparam.packageName)

        // 9. INCY: force our HWID, finding the method via its encrypted-cache read (survives obfuscation)
        if (lpparam.packageName == "llc.itdev.incy") hookIncyHwid(lpparam.classLoader)
    }

    // INCY: find the HWID getter from its cached-UUID read (survives obfuscation), mirror that HWID to the field, and force our value
    private fun hookIncyHwid(classLoader: ClassLoader) {
        val hwidShape = Regex("^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$")
        val skip = arrayOf(
            "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.", "dalvik.", "sun.", "libcore.",
            "com.android.", "de.robv.android.xposed.", "org.lsposed.", ModuleIds.PACKAGE_PREFIX
        )
        val probes = mutableListOf<XC_MethodHook.Unhook>()
        val onCacheRead = object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                if (incyHwidHooked.get()) return
                val value = param.result as? String ?: return
                if (!hwidShape.matches(value)) return
                // value is INCY's full HWID (its cached UUID); mirror it into the input field once per launch
                if (incyHwidCaptured.compareAndSet(false, true)) sendIdCapturedBroadcast(value)
                // the no-arg String method that read it is INCY's HWID getter
                val method = Thread.currentThread().stackTrace.asSequence()
                    .filter { fr -> skip.none { fr.className.startsWith(it) } }
                    .mapNotNull { fr ->
                        try {
                            Class.forName(fr.className, false, classLoader).declaredMethods
                                .firstOrNull { it.name == fr.methodName && it.parameterTypes.isEmpty() && it.returnType == String::class.java }
                        } catch (e: Throwable) { null }
                    }
                    .firstOrNull() ?: return
                if (!incyHwidHooked.compareAndSet(false, true)) return
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun afterHookedMethod(p: MethodHookParam) {
                        // Snapshot, for the same reason as the Settings hook above.
                        val id = cachedId
                        if (isEnabled && !id.isNullOrEmpty()) {
                            logTrace("INCY: forced HWID -> $id")
                            p.result = id
                        }
                    }
                })
                probes.forEach { try { it.unhook() } catch (_: Throwable) {} }
                Log.d(TAG, "INCY: HWID hook on ${method.declaringClass.name}.${method.name}")
            }
        }
        val prefImpls = arrayOf("androidx.security.crypto.EncryptedSharedPreferences", "android.app.SharedPreferencesImpl")
        for (cls in prefImpls) {
            try {
                probes.add(XposedHelpers.findAndHookMethod(cls, classLoader, "getString", String::class.java, String::class.java, onCacheRead))
            } catch (e: Throwable) {
                Log.e(TAG, "INCY: cannot hook $cls.getString: ${e.message}")
            }
        }
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
                if (!isUnlockHookEnabled) return
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
                        if (isUnlockHookEnabled) applyPatches() else removePatches()
                    }
                    synchronized(unlockStateLock) {
                        synchronized(unlockStateObservers) { unlockStateObservers.add(observer) }
                        if (isUnlockHookEnabled) applyPatches() else removePatches()
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

    // Unlock v2RayTun: both SubscriptionItem and ConfigItem carry an isEncoded flag that hides share/edit UI
    private fun hookV2RayTunUnlock(classLoader: ClassLoader) {
        hookV2RayTunEncodedFlag(classLoader, "com.v2raytun.android.model.SubscriptionItem")
        hookV2RayTunEncodedFlag(classLoader, "com.v2raytun.android.model.ConfigItem")
        if (XposedHelpers.findClassIfExists("com.v2raytun.android.model.ConfigItem", classLoader) == null) return
        collectV2RayRecyclers(classLoader)
        // One refresh observer (added after both getter hooks) re-binds lists once per toggle, not per class
        val refreshObserver: (Boolean) -> Unit = { _ -> refreshV2RayLists() }
        synchronized(unlockStateObservers) { unlockStateObservers.add(refreshObserver) }
    }

    // Track live RecyclerViews so a runtime toggle can re-bind rows (the getter hook alone won't re-bind cached rows)
    private fun collectV2RayRecyclers(classLoader: ClassLoader) {
        val rvClass = XposedHelpers.findClassIfExists("androidx.recyclerview.widget.RecyclerView", classLoader) ?: return
        try {
            XposedBridge.hookAllMethods(rvClass, "setAdapter", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val rv = param.thisObject ?: return
                    synchronized(v2rayRecyclers) {
                        v2rayRecyclers.removeAll { it.get() == null || it.get() === rv }
                        v2rayRecyclers.add(java.lang.ref.WeakReference(rv))
                    }
                }
            })
        } catch (_: Throwable) {}
    }

    // Re-bind all known RecyclerViews on the UI thread so toggling the hook updates visible rows
    private fun refreshV2RayLists() {
        val handler = android.os.Handler(android.os.Looper.getMainLooper())
        synchronized(v2rayRecyclers) {
            val iter = v2rayRecyclers.iterator()
            while (iter.hasNext()) {
                val rv = iter.next().get()
                if (rv == null) { iter.remove(); continue }
                handler.post {
                    try {
                        val adapter = XposedHelpers.callMethod(rv, "getAdapter")
                        if (adapter != null) XposedHelpers.callMethod(adapter, "notifyDataSetChanged")
                    } catch (_: Throwable) {}
                }
            }
        }
    }

    // Track HWID-showing TextViews so we can refresh them when the spoof changes (apps set them once on screen build)
    private fun hookHwidLabels(classLoader: ClassLoader, currentPackage: String) {
        // The HWID label lives in Happ and v2RayTun; v2RayTun shows it upper-cased, Happ as-is
        if (currentPackage != "com.happproxy" && currentPackage != "su.happ.proxyutility" && currentPackage != "com.v2raytun.android") return
        val tvClass = XposedHelpers.findClassIfExists("android.widget.TextView", classLoader) ?: return
        try {
            XposedBridge.hookAllMethods(tvClass, "setText", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val tv = param.thisObject ?: return
                    val text = try { XposedHelpers.callMethod(tv, "getText")?.toString() } catch (_: Throwable) { null } ?: return
                    val cid = cachedId
                    val rid = realAndroidId
                    // A HWID label contains our spoofed id or the real ANDROID_ID, in lower or upper case
                    val match: Pair<String, Boolean>? = when {
                        !cid.isNullOrEmpty() && text.contains(cid) -> cid to false
                        !cid.isNullOrEmpty() && text.contains(cid.uppercase()) -> cid.uppercase() to true
                        !rid.isNullOrEmpty() && text.contains(rid) -> rid to false
                        !rid.isNullOrEmpty() && text.contains(rid.uppercase()) -> rid.uppercase() to true
                        else -> null
                    }
                    val (matchedId, isUpper) = match ?: return
                    val template = text.replace(matchedId, HWID_MARKER)
                    synchronized(hwidViews) {
                        hwidViews.removeAll { it.first.get() == null || it.first.get() === tv }
                        hwidViews.add(Triple(java.lang.ref.WeakReference<Any>(tv), template, isUpper))
                    }
                }
            })
        } catch (_: Throwable) {}
    }

    // Re-set the HWID text on the UI thread so the label matches the current spoof state without a restart
    private fun refreshHwidViews() {
        val baseId = (if (isEnabled) cachedId else realAndroidId)?.takeIf { it.isNotEmpty() } ?: return
        val handler = android.os.Handler(android.os.Looper.getMainLooper())
        synchronized(hwidViews) {
            val iter = hwidViews.iterator()
            while (iter.hasNext()) {
                val entry = iter.next()
                val tv = entry.first.get()
                if (tv == null) { iter.remove(); continue }
                val newId = if (entry.third) baseId.uppercase() else baseId
                val newText = entry.second.replace(HWID_MARKER, newId)
                handler.post {
                    try { XposedHelpers.callMethod(tv, "setText", newText) } catch (_: Throwable) {}
                }
            }
        }
    }

    // Force a v2RayTun model's isEncoded() getter to return false (UI reads it to hide edit/share)
    private fun hookV2RayTunEncodedFlag(classLoader: ClassLoader, className: String) {
        val clazz = XposedHelpers.findClassIfExists(className, classLoader) ?: return

        // UI reads isEncoded() to hide edit/share; hook the getter directly so it applies at class load
        val getter = try { clazz.getDeclaredMethod("isEncoded") } catch (e: Throwable) { return }
        if (getter.returnType != java.lang.Boolean.TYPE) return

        val patchLock = Any()
        val activeUnhooks = mutableListOf<XC_MethodHook.Unhook>()

        // Force the getter to return false
        val applyPatches = {
            synchronized(patchLock) {
                if (activeUnhooks.isEmpty()) {
                    try {
                        activeUnhooks.add(XposedBridge.hookMethod(getter, XC_MethodReplacement.returnConstant(false)))
                    } catch (_: Throwable) {}
                }
            }
        }

        // Undo the hook
        val removePatches = {
            synchronized(patchLock) {
                for (uh in activeUnhooks) {
                    try { uh.unhook() } catch (_: Throwable) {}
                }
                activeUnhooks.clear()
            }
        }

        // Apply now per the toggle and react to runtime changes
        val observer: (Boolean) -> Unit = { _ ->
            if (isUnlockHookEnabled) applyPatches() else removePatches()
        }
        synchronized(unlockStateLock) {
            synchronized(unlockStateObservers) { unlockStateObservers.add(observer) }
            if (isUnlockHookEnabled) applyPatches() else removePatches()
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
                    // Read the volatile once: checking and dereferencing are two reads and another thread changes the
                    // field, so an NPE in between would land inside the hook and take down the hooked app, not this one.
                    val id = cachedId
                    if (isEnabled && !id.isNullOrEmpty()) {
                        param.result = SettingsCursorWrapper(cursor, id, currentPackage)
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
            val bundle = resolver.call(SETTINGS_URI, SettingsProvider.METHOD_GET_SETTINGS, null, null)
            if (bundle != null) {
                cachedId = bundle.getString(PrefsManager.PREF_CUSTOM_HWID)
                isEnabled = bundle.getBoolean(PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION, false)
                isInterceptEnabled = bundle.getBoolean(PrefsManager.PREF_INTERCEPT_ENABLED, false)
                applyUnlockEnabled(bundle.getBoolean(PrefsManager.PREF_HOOK_HAPP_UNLOCK_SETTINGS, false))
                Log.d(TAG, "Cache initialized via Provider: ID=$cachedId, Spoof=$isEnabled, Unlock=$isUnlockHookEnabled")
                refreshHwidViews()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Provider unreachable (Package Visibility issue?): ${e.message}")
        }
    }

    // Listen for SETTINGS_UPDATE and refresh the RAM cache
    private fun registerSignalReceiver(context: Context) {
        val filter = IntentFilter(ModuleIds.ACTION_SETTINGS_UPDATE)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {

                // Read the data straight from the Intent (the fast, reliable path for rootless)
                if (intent.hasExtra(PrefsManager.PREF_CUSTOM_HWID)) {
                    cachedId = intent.getStringExtra(PrefsManager.PREF_CUSTOM_HWID)
                    isEnabled = intent.getBooleanExtra(PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION, false)
                    isInterceptEnabled = intent.getBooleanExtra(PrefsManager.PREF_INTERCEPT_ENABLED, false)
                    applyUnlockEnabled(intent.getBooleanExtra(PrefsManager.PREF_HOOK_HAPP_UNLOCK_SETTINGS, false))
                    Log.d(TAG, "RAM Cache updated via Broadcast: ID=$cachedId, Spoof=$isEnabled, Unlock=$isUnlockHookEnabled")
                    refreshHwidViews()
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

    // Off-thread: hand a captured URL to the provider for history. This fires on every java.net.URL the
    // host app builds, so one bounded worker does it and a full queue drops the capture.
    private fun saveUrlAsync(url: String, pkg: String) {
        try {
            urlSaveExecutor.execute {
                try {
                    val activityThread = XposedHelpers.callStaticMethod(XposedHelpers.findClass("android.app.ActivityThread", null), "currentActivityThread")
                    val context = XposedHelpers.callMethod(activityThread, "getApplication") as? Context
                    context?.contentResolver?.call(SETTINGS_URI, SettingsProvider.METHOD_SAVE_URL, url, Bundle().apply { putString(SettingsProvider.EXTRA_PACKAGE, pkg) })
                } catch (e: Exception) {}
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            // Queue full: the history is a convenience, not something worth
            // blocking the host app's thread over.
        }
    }
}

// Tell the app the real android_id we observed (for history/UI)
private fun sendIdCapturedBroadcast(originalId: String) {
    if (originalId.isEmpty()) return
    try {
        val context = (XposedHelpers.callStaticMethod(XposedHelpers.findClass("android.app.ActivityThread", null), "currentActivityThread") as? Any)
            ?.let { XposedHelpers.callMethod(it, "getApplication") as? Context }
            ?: return

        // The same constant the rest of this file uses for the module.
        val intent = Intent(ModuleIds.ACTION_ID_CAPTURED).apply {
            // ModuleIds rather than the class constant: this function sits
            // outside the class, where that one is not in scope.
            setPackage(ModuleIds.PACKAGE)
            putExtra(SettingsProvider.EXTRA_ORIGINAL_ID, originalId)
            addFlags(0x01000000) // FLAG_RECEIVER_INCLUDE_BACKGROUND
        }
        context.sendBroadcast(intent)
    } catch (e: Exception) {}
}
