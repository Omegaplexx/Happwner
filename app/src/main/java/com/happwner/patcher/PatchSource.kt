package com.happwner.patcher

// What the patcher works on: a release it downloads, or an app as it is installed.
sealed interface PatchSource {
	val packageName: String
	val label: String

	class Release(val target: PatchTarget) : PatchSource {
		override val packageName: String get() = target.packageName
		override val label: String get() = target.displayName
	}

	class Installed(val app: InstalledApp) : PatchSource {
		override val packageName: String get() = app.packageName
		override val label: String get() = app.label
	}
}
