package com.happwner.hook

import org.junit.Assert.assertEquals
import org.junit.Test

// MODULE_STATUS_CLASS is spelled out rather than taken from the class, so that the hook inlines it
// instead of loading one of ours inside a foreign process. This is what keeps the two in step.
class ModuleStatusNameTest {

    @Test
    fun constantNamesTheRealClass() {
        assertEquals(ModuleStatus::class.java.name, MODULE_STATUS_CLASS)
    }

    // The application id may differ from the code package in an automated build, so the hook target
    // must not be built from it - that is the failure this constant exists to prevent.
    @Test
    fun constantIsACodePackageNotAnApplicationId() {
        assertEquals("com.happwner.hook", MODULE_STATUS_CLASS.substringBeforeLast('.'))
        assertEquals(ModuleStatus::class.java.`package`?.name, MODULE_STATUS_CLASS.substringBeforeLast('.'))
    }
}
