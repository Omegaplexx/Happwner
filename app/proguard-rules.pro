# Keep the Xposed entry class
-keep class com.happwner.hook.MainHook { *; }

# Keep the module status method, so Xposed can find it by name
-keep class com.happwner.data.ModuleStatus {
	public boolean isModuleActive();
}

# Keep members other components reach from outside (via Intent, for example)
-keepclassmembers class * extends android.content.BroadcastReceiver {
	public void onReceive(android.content.Context, android.content.Intent);
}

# App Startup, and the initializers it looks up by name from the merged manifest
-keep class androidx.startup.InitializationProvider { *; }
-keep class * implements androidx.startup.Initializer { *; }

# The converters name the exception in the note they leave behind, and a note reading
# "internal error (a)" says nothing. Keeping the names does not keep the classes: an unused one is
# still removed, it just is not renamed.
-keepnames class * extends java.lang.Throwable

# Debug logging stays out of release builds: those lines print subscription links, device ids and
# user agents, and a bug report a person shares would carry them along.
-assumenosideeffects class android.util.Log {
	public static int v(...);
	public static int d(...);
}
