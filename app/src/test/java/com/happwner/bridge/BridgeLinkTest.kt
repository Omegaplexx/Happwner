package com.happwner.bridge

import java.net.InetAddress
import java.net.NetworkInterface
import java.net.URL
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// The bridge link, both ways. A link is passed from one person to another, so an empty field must
// not travel as an empty parameter: on the other phone it would overwrite an id and agent of their
// own with nothing.
class BridgeLinkTest {

	private val subscription = "https://example.com/sub?token=abc&x=1"
	private val encodedUrl = "url=https%3A%2F%2Fexample.com"
	private val loopback = BridgeLink.addressFor(lanMode = false)

	@Test
	fun `a link carries what it was given and comes back as it went in, with no empty parameter`() {
		assertEquals("http://127.0.0.1:${SubscriptionService.BRIDGE_PORT}", loopback)
		val link = BridgeLink.build(subscription, "", "", loopback)
		assertEquals(
			"$loopback/url=https%3A%2F%2Fexample.com%2Fsub%3Ftoken%3Dabc%26x%3D1",
			link
		)
		assertFalse(link, link.contains("hwid="))
		assertFalse(link, link.contains("ua="))
		val onlyUa = BridgeLink.build(subscription, "", "Happ/4.2.0", loopback)
		assertFalse(onlyUa, onlyUa.contains("hwid="))
		assertTrue(onlyUa, onlyUa.contains("&ua=Happ%2F4.2.0"))

		val parts = BridgeLink.parse(BridgeLink.build(subscription, "ABC-123", "Happ/4.2.0 (test)", loopback))
		assertEquals(subscription, parts?.url)
		assertEquals("ABC-123", parts?.hwid)
		// The space went out as "+", which reads as a space only when decoded the same way.
		assertEquals("Happ/4.2.0 (test)", parts?.userAgent)
		val bare = BridgeLink.parse(link)
		assertEquals(subscription, bare?.url)
		assertNull(bare?.hwid)
		assertNull(bare?.userAgent)

		// The empty parameters of an older link say nothing either; one that arrived mangled keeps its text.
		val older = BridgeLink.parse("$loopback/$encodedUrl&hwid=&ua=")
		assertEquals("https://example.com", older?.url)
		assertNull(older?.hwid)
		assertNull(older?.userAgent)
		assertEquals("9%ZZ", BridgeLink.parse("$loopback/$encodedUrl&hwid=9%ZZ")?.hwid)

		// A link for another device carries that address and parses the same.
		val address = "http://192.168.1.5:${SubscriptionService.BRIDGE_PORT}"
		val other = BridgeLink.build(subscription, "ABC-123", "", address)
		assertTrue(other, other.startsWith("$address/url="))
		assertTrue(other, BridgeLink.matches(other))
		assertEquals(subscription, BridgeLink.parse(other)?.url)
		assertEquals("ABC-123", BridgeLink.parse(other)?.hwid)

		assertNull(BridgeLink.parse("https://example.com/sub?token=abc"))
		assertNull(BridgeLink.parse("happ://add/aHR0cHM6Ly9leGFtcGxlLmNvbQ"))
		assertFalse(BridgeLink.matches("https://example.com/sub?token=abc"))
		assertFalse(BridgeLink.matches("happ://add/aHR0cHM6Ly9leGFtcGxlLmNvbQ"))
	}

	@Test
	fun `the address handed out is the one another device can reach`() {
		// Wi-Fi over the cellular interface, which has an address of its own and no way in.
		assertEquals("192.168.1.5", BridgeLink.pickHost(
			listOf("rmnet_data0" to "10.71.3.4", "wlan0" to "192.168.1.5")))
		// A hotspot or a wired link will do where there is no Wi-Fi.
		assertEquals("192.168.43.1", BridgeLink.pickHost(
			listOf("rmnet_data0" to "10.71.3.4", "ap0" to "192.168.43.1")))
		// Cellular alone is no local network.
		assertNull(BridgeLink.pickHost(listOf("rmnet_data0" to "10.71.3.4")))
		assertNull(BridgeLink.pickHost(emptyList()))
	}

	@Test
	fun `an address that is the bridge itself is turned away, and the host is read off one that names its port`() {
		val port = SubscriptionService.BRIDGE_PORT
		assertTrue(BridgeLink.leadsHere("$loopback/$encodedUrl"))
		assertTrue(BridgeLink.leadsHere("http://localhost:$port/"))
		assertTrue(BridgeLink.leadsHere("http://[::1]:$port/url=x"))
		assertTrue(BridgeLink.leadsHere("HTTP://127.0.0.5:$port"))
		assertFalse(BridgeLink.leadsHere(subscription))
		// Another app's server on this phone is somebody else's, and so is the world at large.
		assertFalse(BridgeLink.leadsHere("http://127.0.0.1:${port + 1}/url=x"))
		assertFalse(BridgeLink.leadsHere("http://example.com:$port/sub"))

		assertEquals("127.0.0.1", BridgeLink.hostOnOwnPort("http://user@127.0.0.1:$port/url=x"))
		assertEquals("192.168.1.5", BridgeLink.hostOnOwnPort("http://192.168.1.5:$port"))
		assertNull(BridgeLink.hostOnOwnPort("https://example.com/sub?port=$port"))
		assertNull(BridgeLink.hostOnOwnPort("127.0.0.1:$port/url=x"))
	}

	@Test
	fun `a request from the network is refused an address that is this device, and the rest is rebuilt from the parts checked`() {
		// Loopback however written, the wildcard, IPv6 loopback and an IPv4-mapped one, link-local
		// on both families, and a userinfo in front: each is numeric or in the hosts file.
		for (address in listOf(
			"http://127.0.0.1:9090/connections", "http://127.9.9.9:9090/", "http://0.0.0.0:9090/",
			"http://localhost/x", "http://[::1]:9090/", "http://[::ffff:127.0.0.1]:9090/",
			"http://169.254.13.7:9090/", "http://[fe80::1]:9090/",
			"http://user@127.0.0.1:9090/"
		)) {
			assertNull(address, BridgeLink.forNetworkClient(URL(address)))
		}
		// Protocol, host, port, path and query go through; a userinfo part and a fragment do not.
		assertEquals("http://93.184.216.34:8080/sub?x=1", BridgeLink.forNetworkClient(
			URL("http://user@93.184.216.34:8080/sub?x=1#part"))?.toString())
	}

	@Test
	fun `a connection from one of this machine's own addresses counts as its own`() {
		// Loopback on both families, and every address an interface here carries - the one an app
		// on the phone comes from over the network link. An address no interface carries is not.
		assertTrue(BridgeLink.cameFromThisPhone(InetAddress.getByName("127.0.0.1")))
		assertTrue(BridgeLink.cameFromThisPhone(InetAddress.getByName("::1")))
		for (face in NetworkInterface.getNetworkInterfaces()) {
			for (address in face.inetAddresses) {
				assertTrue(address.toString(), BridgeLink.cameFromThisPhone(address))
			}
		}
		assertFalse(BridgeLink.cameFromThisPhone(InetAddress.getByName("93.184.216.34")))
	}
}
