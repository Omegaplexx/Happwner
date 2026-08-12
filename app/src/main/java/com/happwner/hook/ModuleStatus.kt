package com.happwner.hook

// The name the hook looks up: a code package, not the application id, which an automated build
// changes. A const so the hook inlines it; ModuleStatusNameTest pins it to the real class.
internal const val MODULE_STATUS_CLASS = "com.happwner.hook.ModuleStatus"

object ModuleStatus {
    fun isModuleActive(): Boolean {
        // This method is hooked by Xposed to return true
        return false
    }
}
