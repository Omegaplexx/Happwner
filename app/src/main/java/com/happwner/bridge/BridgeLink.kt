package com.happwner.bridge

import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.SocketException
import java.net.URL
import java.net.URLDecoder
import java.net.URLEncoder
import java.net.UnknownHostException

// The address the bridge hands out, written and read in one place: a link travels, so one phone
// builds it and another pastes it back into its own fields.
internal object BridgeLink {

	// What a client on this phone is handed, and what the bridge listens on unless LAN mode is on.
	const val LOOPBACK = "127.0.0.1"

	// How a client elsewhere can reach this phone: Wi-Fi, its own hotspot, wired, or USB.
	private val LOCAL_INTERFACES = listOf("wlan", "ap", "swlan", "eth", "usb", "rndis")

	// Null for a parameter not carried; older links that always wrote "&hwid=&ua=" send empty
	// instead, and both must overwrite nothing.
	data class Parts(val url: String?, val hwid: String?, val userAgent: String?)

	// Empty fields are left out, not sent empty: the bridge reads both the same, so this leaves
	// whoever pastes the link's own fields as they are.
	fun build(url: String, hwid: String, userAgent: String, address: String): String =
		buildString {
			append(address).append("/url=").append(encode(url))
			if (hwid.isNotEmpty()) append("&hwid=").append(encode(hwid))
			if (userAgent.isNotEmpty()) append("&ua=").append(encode(userAgent))
		}

	// A link in the bridge's shape, with whatever address it was built on - this phone's or another's.
	fun matches(text: String): Boolean =
		text.startsWith("http://") && text.contains(":${SubscriptionService.BRIDGE_PORT}/url=")

	fun parse(link: String): Parts? {
		if (!link.contains("/url=")) return null
		var url: String? = null
		var hwid: String? = null
		var userAgent: String? = null
		for (parameter in ("url=" + link.substringAfter("/url=")).split("&")) {
			val pair = parameter.split("=", limit = 2)
			if (pair.size < 2) continue
			val value = decode(pair[1]).ifEmpty { null }
			when (pair[0]) {
				"url" -> url = value
				"hwid" -> hwid = value
				"ua" -> userAgent = value
			}
		}
		return Parts(url, hwid, userAgent)
	}

	// IPv4 only: this address goes to another device, and a link-local IPv6 carries a scope
	// that means nothing there.
	fun hostFor(lanMode: Boolean): String =
		if (lanMode) pickHost(localHosts()) ?: LOOPBACK else LOOPBACK

	// Built from the port the service owns, so the two cannot drift apart.
	fun addressFor(lanMode: Boolean): String =
		"http://${hostFor(lanMode)}:${SubscriptionService.BRIDGE_PORT}"

	// Handing the bridge its own address is a loop - each hop ties up a server slot waiting on
	// the next, until they all time out. Only the bridge's own port is checked.
	fun leadsHere(url: String): Boolean {
		val host = hostOnOwnPort(url) ?: return false
		return host == "localhost" || host == "::1" || host == "0.0.0.0" ||
			host.startsWith("127.") || localHosts().any { it.second == host }
	}

	// Rebuilt from checked parts so nothing else - no userinfo or fragment - reaches the
	// connection. The host stays a name (an address there would fail an https cert), and the
	// lookup a moment later hits the platform's 2s address cache, so it resolves the same way.
	fun forNetworkClient(address: URL): URL? {
		val rebuilt = URL(address.protocol, address.host, address.port, address.file)
		return if (leadsIntoThisDevice(rebuilt)) null else rebuilt
	}

	// Catches any way to write this bridge's own address - a name, 127.1, 2130706433,
	// [::ffff:127.0.0.1]. Resolves the name, so call it off the main thread.
	fun resolvesToThisBridge(address: URL): Boolean =
		address.port == SubscriptionService.BRIDGE_PORT && leadsIntoThisDevice(address)

	// A name that won't resolve counts as the phone - fail toward "this is us".
	private fun leadsIntoThisDevice(address: URL): Boolean {
		val resolved = try {
			InetAddress.getAllByName(address.host)
		} catch (_: UnknownHostException) {
			return true
		}
		return resolved.any {
			it.isLoopbackAddress || it.isAnyLocalAddress || it.isLinkLocalAddress || carriedHere(it)
		}
	}

	// True for loopback or one of this phone's own addresses: an app on this phone shows up that way
	// when it uses the link with the network address. An unreadable interface list means a stranger.
	fun cameFromThisPhone(peer: InetAddress): Boolean = peer.isLoopbackAddress || try {
		NetworkInterface.getByInetAddress(peer) != null
	} catch (_: SocketException) {
		false
	}

	// Unreadable counts as carrying it too - nothing that could be it gets the benefit of the doubt.
	private fun carriedHere(address: InetAddress): Boolean = try {
		NetworkInterface.getByInetAddress(address) != null
	} catch (_: SocketException) {
		true
	}

	internal fun hostOnOwnPort(url: String): String? {
		val authority = url.substringAfter("://", "")
			.substringBefore('/').substringBefore('?').substringAfterLast('@')
		val port = ":${SubscriptionService.BRIDGE_PORT}"
		if (!authority.endsWith(port)) return null
		return authority.removeSuffix(port).removeSurrounding("[", "]").lowercase()
	}

	// A link-local address is excluded - nothing has handed it out yet.
	private fun localHosts(): List<Pair<String, String>> {
		val faces = try {
			NetworkInterface.getNetworkInterfaces() ?: return emptyList()
		} catch (_: Exception) {
			return emptyList()
		}
		val found = mutableListOf<Pair<String, String>>()
		for (face in faces) {
			val carries = try { face.isUp && !face.isLoopback } catch (_: Exception) { false }
			if (!carries) continue
			for (address in face.inetAddresses) {
				val host = address.hostAddress
				if (host != null && address is Inet4Address && !address.isLinkLocalAddress) {
					found += face.name to host
				}
			}
		}
		return found
	}

	// Wi-Fi first, then any other local interface - cellular has its own address but nothing
	// beyond it can reach this phone.
	internal fun pickHost(found: List<Pair<String, String>>): String? {
		val local = found.filter { (name, _) -> LOCAL_INTERFACES.any { name.startsWith(it) } }
		return (local.firstOrNull { it.first.startsWith("wlan") } ?: local.firstOrNull())?.second
	}

	private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")

	// Mangled input is kept as-is rather than costing the whole parameter.
	private fun decode(value: String): String = try {
		URLDecoder.decode(value, "UTF-8")
	} catch (_: Exception) {
		value
	}
}
