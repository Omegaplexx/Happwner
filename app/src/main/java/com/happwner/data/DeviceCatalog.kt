package com.happwner.data

import android.content.res.Resources
import com.happwner.R
import java.security.SecureRandom
import java.util.UUID
import org.xmlpull.v1.XmlPullParser

// The devices a request can claim to be, read from res/xml/device_catalog.xml: platforms with their versions,
// and ready-made devices. The companion writes a device id the way each platform's app writes it.
class DeviceCatalog(resources: Resources) {

	enum class HwidFormat { HEX8, HEX16, UUID_LOWER, UUID_UPPER }

	// header is the value x-device-os carries.
	class Platform(val header: String, val versions: List<String>, val hwid: HwidFormat)

	class Preset(val model: String, val platform: Platform, val osVersion: String) {
		val title = "$model · ${platform.header} $osVersion".trim()
	}

	val platforms: List<Platform>
	val presets: List<Preset>

	init {
		val platformList = mutableListOf<Platform>()
		val presetList = mutableListOf<Preset>()
		val parser = resources.getXml(R.xml.device_catalog)
		fun attr(name: String) = parser.getAttributeValue(null, name).orEmpty()
		try {
			while (parser.next() != XmlPullParser.END_DOCUMENT) {
				if (parser.eventType != XmlPullParser.START_TAG) continue
				when (parser.name) {
					"platform" -> platformList += Platform(
						attr("name"),
						attr("versions").split(' ').filter { it.isNotEmpty() },
						HwidFormat.valueOf(attr("hwid").uppercase())
					)
					"preset" -> {
						val name = attr("platform")
						val platform = platformList.firstOrNull { it.header == name }
							?: error("device_catalog.xml: preset of an unknown platform $name")
						presetList += Preset(attr("model"), platform, attr("version"))
					}
				}
			}
		} finally {
			parser.close()
		}
		platforms = platformList
		presets = presetList
	}

	fun platformOf(header: String): Platform? =
		platforms.firstOrNull { it.header.equals(header, ignoreCase = true) }

	companion object {
		private val APP_NAMES = mapOf("happ" to "Happ", "v2raytun" to "v2RayTun", "incy" to "INCY")

		private val random = SecureRandom()

		// The app a User-Agent names, as its makers write it: the agent may be in any case.
		fun appName(userAgent: String): String {
			val token = userAgent.trim().substringBefore('/').substringBefore(' ')
			return APP_NAMES[token.lowercase()] ?: token
		}

		// "Pixel 8 Pro · Happ"; whichever of the two is missing is left out.
		fun summary(model: String, userAgent: String): String =
			listOf(model.trim(), appName(userAgent)).filter { it.isNotEmpty() }.joinToString(" · ")

		// INCY writes its id its own way whatever the platform; with no platform named, the id is an Android one.
		fun generateHwid(platform: Platform?, userAgent: String): String {
			if (appName(userAgent) == "INCY") return groups(randomHex(16)).uppercase()
			return when (platform?.hwid ?: HwidFormat.HEX8) {
				HwidFormat.HEX8 -> randomHex(8)
				HwidFormat.HEX16 -> randomHex(16)
				HwidFormat.UUID_LOWER -> UUID.randomUUID().toString()
				HwidFormat.UUID_UPPER -> UUID.randomUUID().toString().uppercase()
			}
		}

		private fun randomHex(bytes: Int): String =
			ByteArray(bytes).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }

		// 8-4-4-4-12, as a UUID is cut.
		private fun groups(hex: String): String =
			listOf(0..7, 8..11, 12..15, 16..19, 20..31).joinToString("-") { hex.substring(it) }
	}
}
