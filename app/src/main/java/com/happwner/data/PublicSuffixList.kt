package com.happwner.data

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader

// Public Suffix List matcher: finds the registrable label of a host (e.g. "example" for both
// "example.com" and "api.sub.example.co.uk"), using assets/public_suffix_list.dat.
object PublicSuffixList {
	private const val ASSET_NAME = "public_suffix_list.dat"

	private class Rules(
		val exact: Set<String>,
		val wildcardTargets: Set<String>,
		val exceptions: Set<String>
	)

	@Volatile
	private var rules: Rules? = null

	private fun load(context: Context): Rules {
		rules?.let { return it }
		synchronized(this) {
			rules?.let { return it }
			val exact = HashSet<String>()
			val wildcardTargets = HashSet<String>()
			val exceptions = HashSet<String>()
			try {
				context.applicationContext.assets.open(ASSET_NAME).use { stream ->
					BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).useLines { lines ->
						for (raw in lines) {
							val line = raw.trim()
							if (line.isEmpty() || line.startsWith("//")) continue
							when {
								line.startsWith("!") -> exceptions.add(line.substring(1).lowercase())
								line.startsWith("*.") -> wildcardTargets.add(line.substring(2).lowercase())
								else -> exact.add(line.lowercase())
							}
						}
					}
				}
			} catch (_: Exception) {
				// Missing/unreadable asset: falls through to the "no rule matched" default below.
			}
			val loaded = Rules(exact, wildcardTargets, exceptions)
			rules = loaded
			return loaded
		}
	}

	// The registrable label for [host], e.g. "example" for "api.sub.example.co.uk".
	// Null when host is the public suffix itself or shorter (e.g. "co.uk").
	fun registrableLabel(context: Context, host: String): String? {
		val rules = load(context)
		val labels = host.lowercase().split(".")
		// split(".") always yields at least one element, so only an empty host needs guarding.
		if (labels.size == 1 && labels[0].isEmpty()) return null

		var suffixLen = 1
		var bestIsException = false
		for (labelCount in 1..labels.size) {
			val candidate = labels.takeLast(labelCount).joinToString(".")
			val isException = candidate in rules.exceptions
			val isExact = candidate in rules.exact
			val isWildcard = labelCount >= 2 &&
				labels.takeLast(labelCount - 1).joinToString(".") in rules.wildcardTargets
			if (isException || isExact || isWildcard) {
				suffixLen = labelCount
				bestIsException = isException
			}
		}
		val publicSuffixLen = if (bestIsException) suffixLen - 1 else suffixLen
		val labelIndex = labels.size - publicSuffixLen - 1
		return labels.getOrNull(labelIndex)
	}
}
