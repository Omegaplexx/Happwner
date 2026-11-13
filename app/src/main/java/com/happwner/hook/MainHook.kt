package com.happwner.hook

import android.app.Activity
import android.app.Instrumentation
import android.content.BroadcastReceiver
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.database.Cursor
import android.database.CursorWrapper
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Log
import android.view.MotionEvent
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import com.happwner.BuildConfig
import com.happwner.data.MODULE_STATUS_CLASS
import com.happwner.data.ModuleIds
import com.happwner.data.PrefsManager
import com.happwner.data.SettingsProvider
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.lang.ref.WeakReference
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.net.URL
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class MainHook : IXposedHookLoadPackage {

	private val MODULE_PACKAGE = ModuleIds.PACKAGE
	// Built from the authority the provider publishes, so the two can't drift; both const, so no
	// extra class loading inside the hooked app.
	private val SETTINGS_URI = ModuleIds.SETTINGS_URI.toUri()

	companion object {
		@Volatile private var cachedId: String? = null

		// isAppPatched() result, cached since the provider call has no Context. Null until
		// attachBaseContext resolves it, so value and readiness never disagree.
		@Volatile private var appIsPatched: Boolean? = null
		@Volatile private var isHwidSpoofActive: Boolean = false
		@Volatile private var isInterceptEnabled: Boolean = false
		@Volatile private var isUnlockHookEnabled: Boolean = false
		// Off until the settings arrive, so an app is never cut off from its links by a guess.
		@Volatile private var isRedirectEnabled: Boolean = false
		private val redirectHooked = AtomicBoolean(false)

		// Real (un-spoofed) ANDROID_ID, captured from settings reads, used to recognise HWID labels.
		@Volatile private var realAndroidId: String? = null
		// TextViews showing the HWID, kept with a template + case flag so they can be refreshed
		// when the spoof changes.
		private val hwidViews = Collections.synchronizedList(
			mutableListOf<Triple<WeakReference<Any>, String, Boolean>>())
		private const val HWID_MARKER = "\u0000HWID\u0000"

		private var isInitialized = false
		private val incyHwidHooked = AtomicBoolean(false)
		private val incyHwidCaptured = AtomicBoolean(false)
		private val lock = Any()

		// Single worker with a bounded queue for shipping captured URLs to our provider - see
		// saveUrlAsync for why it's bounded.
		private val urlSaveExecutor = ThreadPoolExecutor(
			0, 1, 30L, TimeUnit.SECONDS,
			LinkedBlockingQueue(64)
		).apply { allowCoreThreadTimeOut(true) }

		private val unlockStateLock = Any()
		private val unlockStateObservers = Collections.synchronizedList(
			mutableListOf<(Boolean) -> Unit>())

		// Live v2RayTun RecyclerViews (weak refs) so a runtime toggle can re-bind their rows
		private val v2rayRecyclers = Collections.synchronizedList(
			mutableListOf<WeakReference<Any>>())

		// What outgoing messages report. Unresolved counts as patched, so an older hook stays listed.
		private fun patchedFlag(): Boolean = appIsPatched ?: true

		private fun applyUnlockEnabled(enabled: Boolean) {
			val toFire: List<(Boolean) -> Unit>
			synchronized(unlockStateLock) {
				if (isUnlockHookEnabled == enabled) return
				isUnlockHookEnabled = enabled
				toFire = synchronized(unlockStateObservers) { unlockStateObservers.toList() }
			}
			for (observer in toFire) {
				try { observer(enabled) } catch (_: Throwable) {}
			}
		}

		// Uncaught, a hook's exception lands in the hooked app's own stack and takes it down, looking
		// like the app crashing on its own - every callback body runs through this instead.
		private inline fun guardHook(where: String, body: () -> Unit) {
			try {
				body()
			} catch (throwable: Throwable) {
				Log.w(ModuleIds.LOG_LSP,
					"hook $where failed: ${throwable.javaClass.simpleName}: ${throwable.message}")
			}
		}

		fun logTrace(message: String) {
			if (!BuildConfig.DEBUG) return
			val stackTrace = Thread.currentThread().stackTrace
				.drop(3)
				.take(8)
				.joinToString(
					"\n") { "  at ${it.className}.${it.methodName}(${it.fileName}:${it.lineNumber})" }
			Log.d(ModuleIds.LOG_LSP, "$message\n$stackTrace")
		}

		// Applies or removes the patches as the unlock setting stands, now and on every change.
		private fun followUnlockSetting(applyPatches: () -> Unit, removePatches: () -> Unit) {
			val sync = { if (isUnlockHookEnabled) applyPatches() else removePatches() }
			synchronized(unlockStateLock) {
				synchronized(unlockStateObservers) { unlockStateObservers.add { sync() } }
				sync()
			}
		}
	}

	// Remembers the real id and announces it when it changes, then hands back the substitute
	// while spoofing is on. "where" names the hook for the trace only.
	private fun substituteAndroidId(param: XC_MethodHook.MethodHookParam, where: String) {
		val name = param.args[1] as? String
		if (name != Settings.Secure.ANDROID_ID) return
		val originalId = param.result as? String
		if (!originalId.isNullOrEmpty()) {
			realAndroidId = originalId
			if (originalId != cachedId) sendIdCapturedBroadcast(originalId)
		}
		ensureCacheInitialized(param.args[0] as? ContentResolver)
		// Snapshot the volatile - testing and using it are two reads, and another thread rewrites it.
		val id = cachedId
		if (isHwidSpoofActive && !id.isNullOrEmpty()) {
			logTrace("Intercepted $where: android_id -> $id")
			param.result = id
		}
	}

	// Both patchers load the app's code from its data dir; a framework leaves it in /data/app.
	// Unknown -> true, so an older hook predating this check never drops out of the list.
	private fun isAppPatched(context: Context): Boolean {
		return try {
			val info = context.applicationInfo ?: return true
			val src = info.sourceDir ?: return true
			val dataDir = info.dataDir
			val result = (!dataDir.isNullOrEmpty() && src.startsWith(dataDir)) ||
				src.startsWith("/data/data/${context.packageName}") ||
				src.startsWith("/data/user/0/${context.packageName}")
			Log.d(ModuleIds.LOG_LSP,
				"${context.packageName}: ${if (result) "patched" else "framework-hooked"} (sourceDir=$src)")
			result
		} catch (throwable: Throwable) {
			Log.w(ModuleIds.LOG_LSP,
				"Patch detection failed for ${context.packageName}, assuming patched", throwable)
			true
		}
	}

	// Xposed entry point: runs inside each loaded app's process
	override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
		// In our own app, just force ModuleStatus.isModuleActive() to true
		if (lpparam.packageName == MODULE_PACKAGE) {
			XposedHelpers.findAndHookMethod(MODULE_STATUS_CLASS, lpparam.classLoader,
				"isModuleActive", object : XC_MethodHook() {
				override fun beforeHookedMethod(param: MethodHookParam) { param.result = true }
			})
			return
		}

		// 1. Early initialisation via ContextWrapper
		XposedHelpers.findAndHookMethod("android.content.ContextWrapper", lpparam.classLoader,
			"attachBaseContext", Context::class.java, object : XC_MethodHook() {
			override fun afterHookedMethod(param: MethodHookParam) {
				guardHook("handleLoadPackage/after") {
					val context = param.args[0] as Context
					synchronized(lock) {
						if (!isInitialized) {
							appIsPatched = isAppPatched(context)
							registerSignalReceiver(context)
							initCache(context)

							// Notify the main app that we are loaded (so it can auto-enable the mode)
							val loadedIntent = Intent(ModuleIds.ACTION_MODULE_LOADED).apply {
								setPackage(MODULE_PACKAGE)
								putExtra(SettingsProvider.EXTRA_PACKAGE, context.packageName)
								putExtra(SettingsProvider.EXTRA_PATCHED, patchedFlag())
							}
							context.sendBroadcast(loadedIntent)
							Log.d(ModuleIds.LOG_LSP,
								"Sent MODULE_LOADED for ${context.packageName} (patched=${patchedFlag()})")

							if (cachedId == null) {
								// Provider unreachable so far: pull settings via broadcast instead
								val requestIntent = Intent(ModuleIds.ACTION_SETTINGS_REQUEST).apply {
									setPackage(MODULE_PACKAGE)
								}
								context.sendBroadcast(requestIntent)
							}

							isInitialized = true
						}
					}
				}
			}
		})

		// 2. Hooks on Settings.Secure/Global
		val settingsHook = object : XC_MethodHook() {
			override fun afterHookedMethod(param: MethodHookParam) {
				guardHook("handleLoadPackage/after") {
					substituteAndroidId(param, "Settings.getString")
				}
			}
		}

		val settingsClasses = arrayOf("Secure", "System", "Global")
		settingsClasses.forEach { cls ->
			try {
				XposedHelpers.findAndHookMethod("android.provider.Settings.$cls",
					lpparam.classLoader, "getString",
					ContentResolver::class.java, String::class.java, settingsHook)

				try {
					XposedHelpers.findAndHookMethod("android.provider.Settings.$cls",
						lpparam.classLoader, "getStringForUser",
						ContentResolver::class.java, String::class.java, Int::class.java, settingsHook)
				} catch (_: Throwable) {}
			} catch (_: Throwable) {}
		}

		try {
			// 3. Hook on NameValueCache (Android's internal cache)
			XposedHelpers.findAndHookMethod("android.provider.Settings\$NameValueCache",
				lpparam.classLoader, "getStringForUser",
				ContentResolver::class.java, String::class.java, Int::class.java, object : XC_MethodHook() {
					override fun afterHookedMethod(param: MethodHookParam) {
						guardHook("handleLoadPackage/after") {
							substituteAndroidId(param, "NameValueCache.getStringForUser")
						}
					}
				})
		} catch (_: Throwable) {}

		// 4. Deep interception via IContentProvider.query (the lowest level in Java)
		hookIContentProvider(lpparam.classLoader)

		// Capture outgoing http(s) links for history - see installLinkCapture.
		installLinkCapture(lpparam)

		try {
			// 5. Three-finger gesture to summon Happwner
			XposedHelpers.findAndHookMethod("android.app.Activity", lpparam.classLoader, "dispatchTouchEvent",
				"android.view.MotionEvent", object : XC_MethodHook() {
					override fun beforeHookedMethod(param: MethodHookParam) {
						guardHook("handleLoadPackage/before") {
							if (SwitchGesture.isTriggered(param.args[0] as MotionEvent)) {
								val activity = param.thisObject as Activity
								// Explicit, so it reaches the running instance; the package tells Happwner where to return.
								activity.startActivity(Intent(ModuleIds.ACTION_SWITCH_FROM_APP)
									.setClassName(MODULE_PACKAGE, ModuleIds.MAIN_ACTIVITY)
									.putExtra(SettingsProvider.EXTRA_PACKAGE, activity.packageName)
									.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
							}
						}
					}
				})
		} catch (error: Throwable) {
			Log.e(ModuleIds.LOG_LSP, "Failed to hook dispatchTouchEvent: ${error.message}")
		}

		// 5b. Links from outside go to the app chooser first
		hookIntentRedirect()

		// 6. Optional: unlock the hidden Happ settings
		hookHideSettings(lpparam.classLoader)

		// 7. Optional: unlock v2RayTun encrypted subscriptions
		if (lpparam.packageName == "com.v2raytun.android") hookV2RayTunUnlock(lpparam.classLoader)

		// 8. Keep the on-screen HWID label in sync with the spoof without a restart (Happ only)
		hookHwidLabels(lpparam.classLoader, lpparam.packageName)

		// 9. INCY: force our HWID in its formula and in its cache read (found by behaviour, survives obfuscation)
		if (lpparam.packageName == "llc.itdev.incy") hookIncyHwid(lpparam.classLoader)
	}

	// Hooks the framework calls that hand an activity its intent, which run whatever the app does in
	// its own onCreate/onNewIntent. Once per process, however many packages the hook is loaded for.
	private fun hookIntentRedirect() {
		if (!redirectHooked.compareAndSet(false, true)) return
		try {
			val create = object : XC_MethodHook() {
				override fun beforeHookedMethod(param: MethodHookParam) {
					guardHook("intentRedirect/create") {
						// A restored activity is not a new arrival of the link.
						if (!isRedirectEnabled || param.args[1] != null) return@guardHook
						val activity = param.args[0] as Activity
						if (IntentRedirect.redirect(activity, activity.intent)) {
							activity.intent = IntentRedirect.neutral()
							activity.finish()
						}
					}
				}
			}
			XposedBridge.hookAllMethods(Instrumentation::class.java, "callActivityOnCreate", create)

			// The public overload only: the hidden ReferrerIntent one calls it with a copy.
			XposedHelpers.findAndHookMethod(Instrumentation::class.java, "callActivityOnNewIntent",
				Activity::class.java, Intent::class.java, object : XC_MethodHook() {
				override fun beforeHookedMethod(param: MethodHookParam) {
					guardHook("intentRedirect/newIntent") {
						if (!isRedirectEnabled) return@guardHook
						if (IntentRedirect.redirect(param.args[0] as Activity, param.args[1] as Intent?)) {
							param.args[1] = IntentRedirect.neutral()
						}
					}
				}
			})
		} catch (error: Throwable) {
			Log.e(ModuleIds.LOG_LSP, "Failed to hook intent delivery: ${error.message}")
		}
	}

	// INCY renames its classes on every build, so both hooks find their targets by behaviour.
	// The HWID is computed once and cached in an encrypted SharedPreferences, so both are needed.
	private fun hookIncyHwid(classLoader: ClassLoader) {
		hookIncyFormula()
		hookIncyCacheRead(classLoader)
	}

	// hwid = upper(sha256("incy_hwid_" + seed)) cut as 8-4-4-4-12; seed = sha256hex(android_id|MANUFACTURER|
	// MODEL|BRAND|DEVICE|PRODUCT|BOARD|HARDWARE). Only 16 digest bytes are used: ours replace them.
	private fun hookIncyFormula() {
		val salt = "incy_hwid_".toByteArray()
		try {
			XposedHelpers.findAndHookMethod(MessageDigest::class.java, "digest", ByteArray::class.java,
				object : XC_MethodHook() {
				override fun afterHookedMethod(param: MethodHookParam) {
					guardHook("hookIncyFormula/after") {
						val input = param.args[0] as? ByteArray ?: return
						if (input.size < salt.size || !salt.indices.all { input[it] == salt[it] }) return
						val id = cachedId
						if (!isHwidSpoofActive || id.isNullOrEmpty()) return
						val hex = id.replace("-", "")
						if (hex.length != 32 || !hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return
						val digest = ByteArray(32)
						for (i in 0 until 16) digest[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
						logTrace("INCY: formula HWID -> $id")
						param.result = digest
					}
				}
			})
		} catch (error: Throwable) {
			Log.e(ModuleIds.LOG_LSP, "INCY: cannot hook MessageDigest.digest: ${error.message}")
		}
	}

	// The HWID getter reads the cache through SharedPreferences.getString. A UUID-shaped result gives
	// the getter away (the no-arg String method up the stack): its result is replaced from then on.
	private fun hookIncyCacheRead(classLoader: ClassLoader) {
		val hwidShape = Regex("^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$")
		val skip = arrayOf(
			"android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.", "dalvik.", "sun.", "libcore.",
			"com.android.", "de.robv.android.xposed.", "org.lsposed.", ModuleIds.PACKAGE_PREFIX
		)
		val probes = CopyOnWriteArrayList<XC_MethodHook.Unhook>()
		val onCacheRead = object : XC_MethodHook() {
			override fun afterHookedMethod(param: MethodHookParam) {
				guardHook("hookIncyHwid/after") {
					if (incyHwidHooked.get()) return
					val value = param.result as? String ?: return
					if (!hwidShape.matches(value)) return
					// INCY's full HWID (its cached UUID) - mirror it into the input field once per launch.
					if (incyHwidCaptured.compareAndSet(false, true)) sendIdCapturedBroadcast(value)
					val method = Thread.currentThread().stackTrace.asSequence()
						.filter { frame -> skip.none { frame.className.startsWith(it) } }
						.mapNotNull { frame ->
							try {
								Class.forName(frame.className, false, classLoader).declaredMethods
									.firstOrNull { it.name == frame.methodName &&
										it.parameterTypes.isEmpty() && it.returnType == String::class.java }
							} catch (_: Throwable) { null }
						}
						.firstOrNull() ?: return
					if (!incyHwidHooked.compareAndSet(false, true)) return
					XposedBridge.hookMethod(method, object : XC_MethodHook() {
						override fun afterHookedMethod(param: MethodHookParam) {
							guardHook("hookIncyHwid/after") {
								// Snapshot, for the same reason as the Settings hook above.
								val id = cachedId
								if (isHwidSpoofActive && !id.isNullOrEmpty()) {
									logTrace("INCY: forced HWID -> $id")
									param.result = id
								}
							}
						}
					})
					probes.forEach { try { it.unhook() } catch (_: Throwable) {} }
					Log.d(ModuleIds.LOG_LSP,
						"INCY: HWID hook on ${method.declaringClass.name}.${method.name}")
				}
			}
		}

		// The encrypted wrapper reads through SharedPreferencesImpl.getString, so the first app class
		// above it that implements SharedPreferences is the wrapper: its getString gets the hook above.
		val wrapperHooked = AtomicBoolean(false)
		val findWrapper = object : XC_MethodHook() {
			override fun afterHookedMethod(param: MethodHookParam) {
				guardHook("hookIncyHwid/wrapper") {
					if (incyHwidHooked.get() || wrapperHooked.get()) return
					val getString = Thread.currentThread().stackTrace.asSequence()
						.filter { frame -> skip.none { frame.className.startsWith(it) } }
						.mapNotNull { frame ->
							try {
								val cls = Class.forName(frame.className, false, classLoader)
								if (!SharedPreferences::class.java.isAssignableFrom(cls)) null
								else cls.getDeclaredMethod("getString", String::class.java, String::class.java)
							} catch (_: Throwable) { null }
						}
						.firstOrNull() ?: return
					if (!wrapperHooked.compareAndSet(false, true)) return
					probes.add(XposedBridge.hookMethod(getString, onCacheRead))
				}
			}
		}

		// SharedPreferencesImpl also covers INCY's plain fallback file; the named class is older builds.
		try {
			probes.add(XposedHelpers.findAndHookMethod("android.app.SharedPreferencesImpl", classLoader,
				"getString", String::class.java, String::class.java, onCacheRead))
			probes.add(XposedHelpers.findAndHookMethod("android.app.SharedPreferencesImpl", classLoader,
				"getString", String::class.java, String::class.java, findWrapper))
			XposedHelpers.findClassIfExists("androidx.security.crypto.EncryptedSharedPreferences", classLoader)?.let {
				probes.add(XposedHelpers.findAndHookMethod(it, "getString",
					String::class.java, String::class.java, onCacheRead))
			}
		} catch (error: Throwable) {
			Log.e(ModuleIds.LOG_LSP, "INCY: cannot hook getString: ${error.message}")
		}
	}

	// Clears Happ's _hideSettings via a behavioural probe, without hardcoding method names.
	private fun hookHideSettings(classLoader: ClassLoader) {
		val candidateClasses = arrayOf(
			"su.happ.proxyutility.dto.SubscriptionItem",
			"com.happproxy.dto.SubscriptionItem"
		)
		val clazz = candidateClasses.firstNotNullOfOrNull {
			XposedHelpers.findClassIfExists(it, classLoader)
		} ?: return

		// The three private flags the probe below sets and reads back - a build missing one of
		// them isn't the class this hook is for.
		fun privateField(name: String) = try {
			clazz.getDeclaredField(name).apply { isAccessible = true }
		} catch (_: Throwable) {
			null
		}
		val fHide = privateField("_hideSettings") ?: return
		val fEnc = privateField("encrypted") ?: return
		val fEncUrl = privateField("encryptedUrl") ?: return

		val probed = AtomicBoolean(false)
		val ctorUnhooks = Collections.synchronizedList(mutableListOf<XC_MethodHook.Unhook>())

		val targetMethods = mutableListOf<Method>()
		val activeUnhooks = mutableListOf<XC_MethodHook.Unhook>()
		val patchLock = Any()

		// Force the discovered getter(s) to return false (settings shown)
		val applyPatches = {
			synchronized(patchLock) {
				if (activeUnhooks.isEmpty()) {
					for (method in targetMethods) {
						try {
							activeUnhooks.add(XposedBridge.hookMethod(method,
								XC_MethodReplacement.returnConstant(false)))
						} catch (_: Throwable) {}
					}
				}
			}
		}

		val removePatches = { unhookAll(patchLock, activeUnhooks) }

		// On the first instance: probe for the getter, then hook it per the toggle
		val ctorHook = object : XC_MethodHook() {
			override fun afterHookedMethod(param: MethodHookParam) {
				guardHook("hookHideSettings/after") {
					if (!isUnlockHookEnabled) return
					if (!probed.compareAndSet(false, true)) return
					val probe = param.thisObject ?: run { probed.set(false); return }
					try {
						val origHide = fHide.getBoolean(probe)
						val origEnc = fEnc.getBoolean(probe)
						val origEncUrl = fEncUrl.getBoolean(probe)
						try {
							// Probe: find the getter whose truth table depends on the three flags.
							for (method in clazz.declaredMethods) {
								if (method.parameterTypes.isNotEmpty()) continue
								if (method.returnType != Boolean::class.javaPrimitiveType) continue
								if (!Modifier.isPublic(method.modifiers)) continue
								try {
									method.isAccessible = true
									fHide.setBoolean(probe, false)
									fEnc.setBoolean(probe, false)
									fEncUrl.setBoolean(probe, true)
									val firstProbe = method.invoke(probe) as Boolean
									fEncUrl.setBoolean(probe, false)
									val secondProbe = method.invoke(probe) as Boolean
									fHide.setBoolean(probe, true)
									val thirdProbe = method.invoke(probe) as Boolean
									if (firstProbe && !secondProbe && thirdProbe) {
										synchronized(patchLock) { targetMethods.add(method) }
									}
								} catch (_: Throwable) {}
							}
						} finally {
							try { fHide.setBoolean(probe, origHide) } catch (_: Throwable) {}
							try { fEnc.setBoolean(probe, origEnc) } catch (_: Throwable) {}
							try { fEncUrl.setBoolean(probe, origEncUrl) } catch (_: Throwable) {}
						}

						followUnlockSetting(applyPatches, removePatches)
					} catch (error: Throwable) {
						Log.e(ModuleIds.LOG_LSP, "hookHideSettings probe: ${error.message}")
					} finally {
						synchronized(ctorUnhooks) {
							ctorUnhooks.forEach { try { it.unhook() } catch (_: Throwable) {} }
							ctorUnhooks.clear()
						}
					}
				}
			}
		}

		// Hook every constructor so we can probe the first instance
		for (ctor in clazz.declaredConstructors) {
			try { ctorUnhooks.add(XposedBridge.hookMethod(ctor, ctorHook)) } catch (_: Throwable) {}
		}
	}

	// Unlock v2RayTun: its model classes carry an isEncoded field that hides share/edit UI.
	private fun hookV2RayTunUnlock(classLoader: ClassLoader) {
		val models = findV2RayTunModels(classLoader)
		if (models.isEmpty()) {
			Log.w(ModuleIds.LOG_LSP, "v2RayTun: no model class with an isEncoded field found")
			return
		}
		models.forEach { hookV2RayTunEncodedFlag(it) }
		collectV2RayRecyclers(classLoader)
		// Added once, after the getter hook - re-binds lists per toggle, not per class.
		val refreshObserver: (Boolean) -> Unit = { _ -> refreshV2RayLists() }
		synchronized(unlockStateObservers) { unlockStateObservers.add(refreshObserver) }
	}

	// R8 renames the model classes (a, b, ...) but keeps their package and field names, so they are
	// found by asking the package for each short name, not by one fixed name. Older builds kept the
	// real names, which are tried too.
	private fun findV2RayTunModels(classLoader: ClassLoader): List<Class<*>> {
		val names = listOf("ConfigItem", "SubscriptionItem") + ('a'..'z').map { "$it" } + ('A'..'Z').map { "$it" }
		return names.mapNotNull { XposedHelpers.findClassIfExists("com.v2raytun.android.model.$it", classLoader) }
			.filter { clazz ->
				try {
					clazz.declaredFields.any { it.name == "isEncoded" && it.type == Boolean::class.javaPrimitiveType }
				} catch (_: Throwable) { false }
			}
	}

	// Tracks live RecyclerViews so a runtime toggle can re-bind rows - the getter hook alone
	// won't re-bind rows already cached.
	private fun collectV2RayRecyclers(classLoader: ClassLoader) {
		val rvClass = XposedHelpers.findClassIfExists("androidx.recyclerview.widget.RecyclerView",
			classLoader) ?: return
		try {
			XposedBridge.hookAllMethods(rvClass, "setAdapter", object : XC_MethodHook() {
				override fun afterHookedMethod(param: MethodHookParam) {
					guardHook("collectV2RayRecyclers/after") {
						val recycler = param.thisObject ?: return
						synchronized(v2rayRecyclers) {
							v2rayRecyclers.removeAll { it.get() == null || it.get() === recycler }
							v2rayRecyclers.add(WeakReference(recycler))
						}
					}
				}
			})
		} catch (_: Throwable) {}
	}

	// Re-bind all known RecyclerViews on the UI thread so toggling the hook updates visible rows
	private fun refreshV2RayLists() {
		val handler = Handler(Looper.getMainLooper())
		synchronized(v2rayRecyclers) {
			val iter = v2rayRecyclers.iterator()
			while (iter.hasNext()) {
				val recycler = iter.next().get()
				if (recycler == null) { iter.remove(); continue }
				handler.post {
					try {
						val adapter = XposedHelpers.callMethod(recycler, "getAdapter")
						if (adapter != null) XposedHelpers.callMethod(adapter, "notifyDataSetChanged")
					} catch (_: Throwable) {}
				}
			}
		}
	}

	// Tracks HWID-showing TextViews so they can be refreshed when the spoof changes - apps set
	// them once when the screen is built.
	private fun hookHwidLabels(classLoader: ClassLoader, currentPackage: String) {
		// The HWID label lives in Happ and v2RayTun; v2RayTun shows it upper-cased, Happ as-is
		if (currentPackage != "com.happproxy" && currentPackage != "su.happ.proxyutility" &&
			currentPackage != "com.v2raytun.android") return
		val tvClass = XposedHelpers.findClassIfExists("android.widget.TextView", classLoader) ?: return
		try {
			XposedBridge.hookAllMethods(tvClass, "setText", object : XC_MethodHook() {
				override fun afterHookedMethod(param: MethodHookParam) {
					guardHook("hookHwidLabels/after") {
						val textView = param.thisObject ?: return
						val text = try { XposedHelpers.callMethod(textView,
							"getText")?.toString() } catch (_: Throwable) { null } ?: return
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
							hwidViews.removeAll { it.first.get() == null || it.first.get() === textView }
							hwidViews.add(Triple(WeakReference<Any>(textView),
								template, isUpper))
						}
					}
				}
			})
		} catch (_: Throwable) {}
	}

	// Re-set the HWID text on the UI thread so the label matches the current spoof state without a restart
	private fun refreshHwidViews() {
		val baseId = (if (isHwidSpoofActive) cachedId else realAndroidId)?.takeIf { it.isNotEmpty() }
			?: return
		val handler = Handler(Looper.getMainLooper())
		synchronized(hwidViews) {
			val iter = hwidViews.iterator()
			while (iter.hasNext()) {
				val entry = iter.next()
				val textView = entry.first.get()
				if (textView == null) { iter.remove(); continue }
				val newId = if (entry.third) baseId.uppercase() else baseId
				val newText = entry.second.replace(HWID_MARKER, newId)
				handler.post {
					try { XposedHelpers.callMethod(textView, "setText", newText) } catch (_: Throwable) {}
				}
			}
		}
	}

	// The isEncoded field hides edit/share in the UI; its name survives obfuscation, its getter
	// doesn't - this build even exposes it under two different method names - so every no-arg
	// boolean getter that actually tracks the field is found by probing, like hookHideSettings below.
	private fun hookV2RayTunEncodedFlag(clazz: Class<*>) {
		val field = try {
			clazz.getDeclaredField("isEncoded").apply { isAccessible = true }
		} catch (_: Throwable) { return }
		if (field.type != Boolean::class.javaPrimitiveType) return

		val patchLock = Any()
		val targetMethods = mutableListOf<Method>()
		val activeUnhooks = mutableListOf<XC_MethodHook.Unhook>()
		val probed = AtomicBoolean(false)
		val ctorUnhooks = Collections.synchronizedList(mutableListOf<XC_MethodHook.Unhook>())

		val applyPatches = {
			synchronized(patchLock) {
				if (activeUnhooks.isEmpty()) {
					for (method in targetMethods) {
						try {
							activeUnhooks.add(XposedBridge.hookMethod(method,
								XC_MethodReplacement.returnConstant(false)))
						} catch (_: Throwable) {}
					}
				}
			}
		}

		val removePatches = { unhookAll(patchLock, activeUnhooks) }

		// On the first instance: toggle the field and keep every getter whose result follows it.
		val ctorHook = object : XC_MethodHook() {
			override fun afterHookedMethod(param: MethodHookParam) {
				guardHook("hookV2RayTunEncodedFlag/after") {
					if (!probed.compareAndSet(false, true)) return
					val probe = param.thisObject ?: run { probed.set(false); return }
					try {
						val original = field.getBoolean(probe)
						try {
							for (method in clazz.declaredMethods) {
								if (method.parameterTypes.isNotEmpty()) continue
								if (method.returnType != Boolean::class.javaPrimitiveType) continue
								if (!Modifier.isPublic(method.modifiers)) continue
								try {
									method.isAccessible = true
									field.setBoolean(probe, false)
									val whenFalse = method.invoke(probe) as Boolean
									field.setBoolean(probe, true)
									val whenTrue = method.invoke(probe) as Boolean
									if (!whenFalse && whenTrue) {
										synchronized(patchLock) { targetMethods.add(method) }
									}
								} catch (_: Throwable) {}
							}
						} finally {
							try { field.setBoolean(probe, original) } catch (_: Throwable) {}
						}
						followUnlockSetting(applyPatches, removePatches)
					} catch (error: Throwable) {
						Log.e(ModuleIds.LOG_LSP, "hookV2RayTunEncodedFlag probe: ${error.message}")
					} finally {
						synchronized(ctorUnhooks) {
							ctorUnhooks.forEach { try { it.unhook() } catch (_: Throwable) {} }
							ctorUnhooks.clear()
						}
					}
				}
			}
		}

		for (ctor in clazz.declaredConstructors) {
			try { ctorUnhooks.add(XposedBridge.hookMethod(ctor, ctorHook)) } catch (_: Throwable) {}
		}
	}

	// Undoes every hook in the list under its lock; a hook that fails to come off is left behind.
	private fun unhookAll(lock: Any, unhooks: MutableList<XC_MethodHook.Unhook>) {
		synchronized(lock) {
			for (hook in unhooks) {
				try { hook.unhook() } catch (_: Throwable) {}
			}
			unhooks.clear()
		}
	}

	private fun hookIContentProvider(classLoader: ClassLoader) {
		val queryHook = object : XC_MethodHook() {
			override fun afterHookedMethod(param: MethodHookParam) {
				guardHook("hookIContentProvider/after") {
					val uri = findUriInArgs(param.args) ?: return
					val cursor = param.result as? Cursor ?: return

					val uriString = uri.toString()
					if (uriString.contains("settings")) {
						logTrace("IContentProvider.query: Intercepting settings URI: $uriString")
						// Read the volatile once: checking and dereferencing are two reads, and an
						// NPE from another thread's change in between would take down the hooked app.
						val id = cachedId
						if (isHwidSpoofActive && !id.isNullOrEmpty()) {
							param.result = SettingsCursorWrapper(cursor, id)
						} else {
							param.result = SettingsCursorWrapper(cursor, null)
						}
					}
				}
			}
		}

		try {
			val proxyClass = XposedHelpers.findClass("android.content.ContentProviderProxy", classLoader)

			try {
				XposedHelpers.findAndHookMethod(proxyClass, "query",
					String::class.java, String::class.java, Uri::class.java,
						Array<String>::class.java, Bundle::class.java,
					XposedHelpers.findClass("android.os.ICancellationSignal", classLoader), queryHook)
			} catch (_: Throwable) {}

			try {
				XposedHelpers.findAndHookMethod(proxyClass, "query",
					String::class.java, Uri::class.java, Array<String>::class.java, Bundle::class.java,
					XposedHelpers.findClass("android.os.ICancellationSignal", classLoader), queryHook)
			} catch (_: Throwable) {}

			try {
				XposedHelpers.findAndHookMethod(proxyClass, "query",
					String::class.java, Uri::class.java, Array<String>::class.java,
						String::class.java, Array<String>::class.java, String::class.java,
					XposedHelpers.findClass("android.os.ICancellationSignal", classLoader), queryHook)
			} catch (_: Throwable) {}

		} catch (error: Throwable) {
			Log.e(ModuleIds.LOG_LSP, "Failed to hook IContentProvider: ${error.message}")
		}
	}

	private fun findUriInArgs(args: Array<Any?>): Uri? {
		for (arg in args) {
			if (arg is Uri) return arg
		}
		return null
	}

	// Cursor that swaps android_id's value and type for the spoofed id
	private class SettingsCursorWrapper(cursor: Cursor,
		private val spoofedId: String?) : CursorWrapper(cursor) {
		private val nameIdx by lazy {
			try { cursor.getColumnIndex("name") } catch (_: Exception) { -1 }
		}
		private val valueIdx by lazy {
			try { cursor.getColumnIndex("value") } catch (_: Exception) { -1 }
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
				} catch (_: Exception) {}
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
				} catch (_: Exception) {}
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

	// Pull settings via the provider call() and cache them in RAM
	private fun initCacheWithResolver(resolver: ContentResolver) {
		try {
			// Anomaly worth seeing: the provider was reached before the flag was resolved.
			if (appIsPatched == null) Log.w(ModuleIds.LOG_LSP,
				"Provider call before patch detection ran, sending patched=${patchedFlag()}")
			val extras = Bundle().apply { putBoolean(SettingsProvider.EXTRA_PATCHED, patchedFlag()) }
			val bundle = resolver.call(SETTINGS_URI, SettingsProvider.METHOD_GET_SETTINGS, null, extras)
			if (bundle != null) {
				cachedId = bundle.getString(PrefsManager.PREF_CUSTOM_HWID)
				isHwidSpoofActive = bundle.getBoolean(PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION, false)
				isInterceptEnabled = bundle.getBoolean(PrefsManager.PREF_INTERCEPT_ENABLED, true)
				applyUnlockEnabled(bundle.getBoolean(PrefsManager.PREF_HOOK_HAPP_UNLOCK_SETTINGS, false))
				isRedirectEnabled = bundle.getBoolean(PrefsManager.PREF_REDIRECT_INTENTS, false)
				Log.d(ModuleIds.LOG_LSP, "Cache initialized via Provider: ID=$cachedId, " +
					"Spoof=$isHwidSpoofActive, Unlock=$isUnlockHookEnabled")
				refreshHwidViews()
			}
		} catch (error: Exception) {
			Log.e(ModuleIds.LOG_LSP, "Provider unreachable (Package Visibility issue?): ${error.message}")
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
					isHwidSpoofActive = intent.getBooleanExtra(
						PrefsManager.PREF_USE_CUSTOM_HWID_SUBSTITUTION, false)
					isInterceptEnabled = intent.getBooleanExtra(PrefsManager.PREF_INTERCEPT_ENABLED, true)
					applyUnlockEnabled(intent.getBooleanExtra(
						PrefsManager.PREF_HOOK_HAPP_UNLOCK_SETTINGS, false))
					isRedirectEnabled = intent.getBooleanExtra(PrefsManager.PREF_REDIRECT_INTENTS, false)
					Log.d(ModuleIds.LOG_LSP, "RAM Cache updated via Broadcast: ID=$cachedId, " +
						"Spoof=$isHwidSpoofActive, Unlock=$isUnlockHookEnabled")
					refreshHwidViews()
				} else {
					initCache(context)
				}
			}
		}
		// Exported: the settings come from Happwner, a different app from the one hooked here.
		ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_EXPORTED)
	}

	// Tier 1 hooks java.net.URL and Uri.parse - boot classpath, so obfuscation cannot rename them.
	// Tier 2 adds okhttp3 when present, each hook guarded so a missing class skips instead of throwing.
	private fun installLinkCapture(lpparam: XC_LoadPackage.LoadPackageParam) {
		val pkg = lpparam.packageName
		val loader = lpparam.classLoader

		// 1a. java.net.URL(String): HttpURLConnection and anything that constructs a URL.
		try {
			XposedHelpers.findAndHookConstructor(URL::class.java, String::class.java,
				object : XC_MethodHook() {
				override fun beforeHookedMethod(param: MethodHookParam) =
					guardHook("linkCapture") { maybeSaveHttpLink(param.args.getOrNull(0), pkg) }
			})
		} catch (error: Throwable) { Log.e(ModuleIds.LOG_LSP,
			"link capture: URL ctor hook failed: ${error.message}") }

		// 1b. Uri.parse(String): the near-universal "I have a URL string" point on Android.
		try {
			XposedHelpers.findAndHookMethod(Uri::class.java, "parse", String::class.java,
				object : XC_MethodHook() {
				override fun beforeHookedMethod(param: MethodHookParam) =
					guardHook("linkCapture") { maybeSaveHttpLink(param.args.getOrNull(0), pkg) }
			})
		} catch (error: Throwable) { Log.e(ModuleIds.LOG_LSP,
			"link capture: Uri.parse hook failed: ${error.message}") }

		// 2a. okhttp3.Request.Builder.url(String); the URL/HttpUrl overloads are caught upstream.
		XposedHelpers.findClassIfExists("okhttp3.Request\$Builder", loader)?.let { builderClass ->
			try {
				XposedBridge.hookAllMethods(builderClass, "url", object : XC_MethodHook() {
					override fun beforeHookedMethod(param: MethodHookParam) =
						guardHook("linkCapture") { maybeSaveHttpLink(param.args.getOrNull(0), pkg) }
				})
			} catch (error: Throwable) { Log.e(ModuleIds.LOG_LSP,
				"link capture: okhttp Builder.url hook failed: ${error.message}") }
		}

		// 2b. okhttp3.HttpUrl.get/parse(String) - the other common entry; only one of the two
		// exists per okhttp version, so a miss on the other is expected.
		XposedHelpers.findClassIfExists("okhttp3.HttpUrl", loader)?.let { httpUrlClass ->
			for (methodName in arrayOf("get", "parse")) {
				try {
					XposedHelpers.findAndHookMethod(httpUrlClass, methodName, String::class.java,
						object : XC_MethodHook() {
						override fun beforeHookedMethod(param: MethodHookParam) =
							guardHook("linkCapture") { maybeSaveHttpLink(param.args.getOrNull(0), pkg) }
					})
				} catch (_: Throwable) {}
			}
		}
	}

	// http(s) only - other schemes (incy://, vless://, content://, ...) are dropped, since only
	// subscription URLs matter here. No dedup: Happwner dedups on the receiving side.
	private fun maybeSaveHttpLink(raw: Any?, pkg: String) {
		if (!isInterceptEnabled) return
		val text = raw as? CharSequence ?: return
		val isHttp = text.regionMatches(0, "http://", 0, 7, ignoreCase = true) ||
					 text.regionMatches(0, "https://", 0, 8, ignoreCase = true)
		if (!isHttp || text.length > 8192) return
		saveUrlAsync(text.toString(), pkg)
	}

	// Off-thread: fires for every captured link (URL ctor, Uri.parse, OkHttp), so one bounded
	// worker handles it and a full queue just drops the capture.
	private fun saveUrlAsync(url: String, pkg: String) {
		try {
			urlSaveExecutor.execute {
				try {
					val activityThread = XposedHelpers.callStaticMethod(XposedHelpers.findClass(
						"android.app.ActivityThread", null), "currentActivityThread")
					val context = XposedHelpers.callMethod(activityThread, "getApplication") as? Context
					context?.contentResolver?.call(
						SETTINGS_URI,
						SettingsProvider.METHOD_SAVE_URL,
						url,
						Bundle().apply {
							putString(SettingsProvider.EXTRA_PACKAGE, pkg)
							// A missing flag falls back to "patched", putting framework-hooked apps
							// back in the list.
							putBoolean(SettingsProvider.EXTRA_PATCHED, patchedFlag())
						}
					)
				} catch (_: Exception) {}
			}
		} catch (_: RejectedExecutionException) {
			// The history is a convenience, not worth blocking the host app's thread over.
		}
	}
}

// Tell the app the real android_id we observed (for history/UI)
private fun sendIdCapturedBroadcast(originalId: String) {
	if (originalId.isEmpty()) return
	try {
		val context = (XposedHelpers.callStaticMethod(XposedHelpers.findClass(
			"android.app.ActivityThread", null), "currentActivityThread") as? Any)
			?.let { XposedHelpers.callMethod(it, "getApplication") as? Context }
			?: return

		// ModuleIds, not the class constant: this function sits outside the class, so
		// MODULE_PACKAGE isn't in scope here.
		val intent = Intent(ModuleIds.ACTION_ID_CAPTURED).apply {
			setPackage(ModuleIds.PACKAGE)
			putExtra(SettingsProvider.EXTRA_ORIGINAL_ID, originalId)
		}
		context.sendBroadcast(intent)
	} catch (_: Exception) {}
}
