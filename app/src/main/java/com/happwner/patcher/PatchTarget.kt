package com.happwner.patcher

// Apps that are downloaded from GitHub and patched. cacheFileName is where the download lands.
enum class PatchTarget(
	val displayName: String,
	val packageName: String,
	val source: ReleaseSource,
	val cacheFileName: String
) {
	HAPP(
		"Happ", "su.happ.proxyutility",
		ReleaseSource.named("Happ-proxy/happ-android") { it.equals("Happ.apk", ignoreCase = true) },
		"happ-latest.apk"
	),
	V2RAYTUN(
		"v2RayTun", "com.v2raytun.android",
		ReleaseSource.named("DigneZzZ/v2raytun") { it.endsWith(".apk", ignoreCase = true) },
		"v2raytun-latest.apk"
	)
}
