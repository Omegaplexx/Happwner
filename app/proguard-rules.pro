# Сохраняем класс входа для Xposed
-keep class com.happwner.MainHook { *; }

# Сохраняем метод проверки статуса модуля, чтобы Xposed мог его найти по имени
-keep class com.happwner.ModuleStatus {
    public boolean isModuleActive();
}

# Если используются другие классы, на которые завязаны внешние вызовы (например, через Intent)
-keepclassmembers class * extends android.content.BroadcastReceiver {
    public void onReceive(android.content.Context, android.content.Intent);
}

# --- AndroidX WorkManager & Room (Fixes NoSuchMethodException in Full Mode) ---

# Keep the generated WorkDatabase_Impl and its constructor
-keep class androidx.work.impl.WorkDatabase_Impl {
    public <init>();
}

# General rule to keep all Room Database implementations and their constructors
-keep class * extends androidx.room.RoomDatabase {
    public <init>();
}

# Keep WorkManager internal components
-keep class androidx.work.impl.background.systemalarm.RescheduleReceiver { *; }
-keep class androidx.work.impl.background.systemalarm.ConstraintProxy { *; }
-keep class androidx.work.impl.background.systemalarm.ConstraintProxy$* { *; }
-keep class androidx.work.impl.background.systemjob.SystemJobService { *; }
-keep class androidx.work.impl.foreground.SystemForegroundService { *; }

# WorkManager Initializers and App Startup
-keep class androidx.work.WorkManagerInitializer { *; }
-keep class androidx.startup.InitializationProvider { *; }

# Keep App Startup Initializers
-keep class * implements androidx.startup.Initializer { *; }
