package android.content

// A SharedPreferences that lives in a map: the android.jar stubs a unit test compiles against throw
// on every method, so anything reading settings needs a real implementation to be testable at all.
class InMemorySharedPreferences(
    initial: Map<String, Any?> = emptyMap()
) : SharedPreferences {

    private val values = LinkedHashMap<String, Any?>(initial)
    private val listeners = mutableSetOf<SharedPreferences.OnSharedPreferenceChangeListener>()

    override fun getAll(): MutableMap<String, *> = LinkedHashMap(values)

    override fun getString(key: String?, defValue: String?): String? =
        values[key] as? String ?: defValue

    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
        (values[key] as? Set<String>)?.toMutableSet() ?: defValues

    override fun getInt(key: String?, defValue: Int): Int = values[key] as? Int ?: defValue

    override fun getLong(key: String?, defValue: Long): Long = values[key] as? Long ?: defValue

    override fun getFloat(key: String?, defValue: Float): Float = values[key] as? Float ?: defValue

    override fun getBoolean(key: String?, defValue: Boolean): Boolean =
        values[key] as? Boolean ?: defValue

    override fun contains(key: String?): Boolean = values.containsKey(key)

    override fun edit(): SharedPreferences.Editor = EditorImpl()

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) {
        listener?.let { listeners.add(it) }
    }

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) {
        listener?.let { listeners.remove(it) }
    }

    private inner class EditorImpl : SharedPreferences.Editor {
        // Staged until apply or commit, the way the real one behaves.
        private val pending = LinkedHashMap<String, Any?>()
        private val removed = mutableSetOf<String>()
        private var clearAll = false

        override fun putString(key: String, value: String?) = stage(key, value)
        override fun putStringSet(key: String, values: MutableSet<String>?) = stage(key, values)
        override fun putInt(key: String, value: Int) = stage(key, value)
        override fun putLong(key: String, value: Long) = stage(key, value)
        override fun putFloat(key: String, value: Float) = stage(key, value)
        override fun putBoolean(key: String, value: Boolean) = stage(key, value)

        override fun remove(key: String): SharedPreferences.Editor {
            removed.add(key)
            pending.remove(key)
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            clearAll = true
            return this
        }

        override fun commit(): Boolean {
            write()
            return true
        }

        override fun apply() = write()

        private fun stage(key: String, value: Any?): SharedPreferences.Editor {
            pending[key] = value
            removed.remove(key)
            return this
        }

        private fun write() {
            val changed = mutableListOf<String>()
            if (clearAll) {
                changed.addAll(values.keys)
                values.clear()
            }
            for (key in removed) if (values.remove(key) != null) changed.add(key)
            for ((key, value) in pending) {
                if (values[key] != value) changed.add(key)
                values[key] = value
            }
            for (key in changed) {
                for (l in listeners.toList()) l.onSharedPreferenceChanged(this@InMemorySharedPreferences, key)
            }
        }
    }
}
