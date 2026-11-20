package com.happwner.data

import android.content.SharedPreferences
import androidx.core.content.edit
import com.happwner.bridge.RequestIdentity
import java.util.UUID
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

// An identity the person saved: a name and every field of a request as it was, the empty ones included.
class SavedIdentity(val id: String, val name: String, val identity: RequestIdentity)

// The saved identities, newest first until they are moved, and which of them the fields on screen are taken to be.
class IdentityStore(private val prefs: SharedPreferences) {

	// What the fields amount to: a saved identity, or none; modified when they started from it and have changed.
	class Standing(val saved: SavedIdentity?, val modified: Boolean)

	var activeId: String?
		get() = prefs.getString(PrefsManager.PREF_IDENTITY_ACTIVE, null)
		set(value) = prefs.edit { putString(PrefsManager.PREF_IDENTITY_ACTIVE, value) }

	// The note on how to manage the list goes for good once the person has held an identity.
	var hintDone: Boolean
		get() = prefs.getBoolean(PrefsManager.PREF_IDENTITY_HINT_DONE, false)
		set(value) = prefs.edit { putBoolean(PrefsManager.PREF_IDENTITY_HINT_DONE, value) }

	fun all(): List<SavedIdentity> {
		val text = prefs.getString(PrefsManager.PREF_IDENTITIES, null) ?: return emptyList()
		return try {
			val array = JSONArray(text)
			(0 until array.length()).mapNotNull { fromJson(array.optJSONObject(it)) }
		} catch (_: JSONException) {
			emptyList()
		}
	}

	fun find(id: String?): SavedIdentity? = all().firstOrNull { it.id == id }

	// Goes to the top and becomes the one in use.
	fun add(name: String, identity: RequestIdentity): SavedIdentity {
		val list = all()
		val saved = SavedIdentity(UUID.randomUUID().toString(), uniqueName(name, list.map { it.name }), identity)
		write(listOf(saved) + list)
		activeId = saved.id
		return saved
	}

	fun overwrite(id: String, identity: RequestIdentity) =
		write(all().map { if (it.id == id) SavedIdentity(id, it.name, identity) else it })

	fun rename(id: String, name: String) {
		val list = all()
		val taken = list.filter { it.id != id }.map { it.name }
		write(list.map { if (it.id == id) SavedIdentity(id, uniqueName(name, taken), it.identity) else it })
	}

	fun reorder(ids: List<String>) {
		val list = all()
		if (list.map { it.id } == ids) return
		val byId = list.associateBy { it.id }
		write(ids.mapNotNull { byId[it] })
	}

	fun remove(ids: Set<String>) {
		write(all().filter { it.id !in ids })
		val active = activeId
		if (active != null && active in ids) activeId = null
	}

	// An identity the fields equal is the one in use, and is remembered as that; failing it, the one they came from.
	fun resolve(current: RequestIdentity): Standing {
		val list = all()
		val active = list.firstOrNull { it.id == activeId }
		val equal = active?.takeIf { it.identity == current } ?: list.firstOrNull { it.identity == current }
		if (equal != null) {
			if (equal.id != activeId) activeId = equal.id
			return Standing(equal, modified = false)
		}
		return Standing(active, modified = active != null)
	}

	private fun write(list: List<SavedIdentity>) {
		val array = JSONArray()
		list.forEach { array.put(toJson(it)) }
		prefs.edit { putString(PrefsManager.PREF_IDENTITIES, array.toString()) }
	}

	private fun toJson(saved: SavedIdentity): JSONObject {
		val identity = saved.identity
		val headers = JSONArray()
		identity.headers.forEach { (name, value) -> headers.put(JSONArray().put(name).put(value)) }
		return JSONObject()
			.put("id", saved.id)
			.put("name", saved.name)
			.put("hwid", identity.hwid)
			.put("ua", identity.userAgent)
			.put("model", identity.model)
			.put("os", identity.os)
			.put("osver", identity.osVersion)
			.put("headers", headers)
	}

	private fun fromJson(json: JSONObject?): SavedIdentity? {
		val id = json?.optString("id").orEmpty()
		val name = json?.optString("name").orEmpty()
		if (json == null || id.isEmpty() || name.isEmpty()) return null
		val headers = json.optJSONArray("headers")?.let { array ->
			(0 until array.length()).mapNotNull { index ->
				val pair = array.optJSONArray(index)
				if (pair == null || pair.length() != 2) null else pair.optString(0) to pair.optString(1)
			}
		}.orEmpty()
		val identity = RequestIdentity(
			hwid = json.optString("hwid"), userAgent = json.optString("ua"), model = json.optString("model"),
			os = json.optString("os"), osVersion = json.optString("osver"), headers = headers
		)
		return SavedIdentity(id, name, identity)
	}

	companion object {
		// A name already taken gets a number after it: "Pixel 5 (2)".
		fun uniqueName(wanted: String, taken: Collection<String>): String {
			val base = wanted.trim()
			if (base !in taken) return base
			var number = 2
			while ("$base ($number)" in taken) number++
			return "$base ($number)"
		}
	}
}
