package com.happwner.convert

import java.net.URLDecoder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Port hopping as Xray 26.9 writes it, a udphop mask in finalmask.udp, read alike by every pass: the server
// ports and the interval carried, what no core does named, a mask Xray refuses left out with its reason.
class UdpHopMaskTest {
	private fun hysteria(port: Int, mask: String): String {
		val address = """"address":"h.example.com"""" + if (port > 0) ""","port":$port""" else ""
		val stream = """{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"pw"},""" +
			""""security":"tls","tlsSettings":{"serverName":"h.example.com"},""" +
			""""finalmask":{"udp":[{"type":"udphop","settings":$mask}]}}"""
		return """{"remarks":"hop","outbounds":[{"protocol":"hysteria","tag":"proxy",""" +
			""""settings":{$address,"version":2},"streamSettings":$stream}]}"""
	}

	private fun links(body: String) = SubscriptionConverter.convertWithStats(body, jsonToUri = true)

	private fun singBoxNode(body: String): Pair<JSONObject, List<String>> {
		val result = SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok
		val outbounds = result.config.getJSONArray("outbounds")
		val node = (0 until outbounds.length()).map { outbounds.getJSONObject(it) }
			.first { it.optString("type") == "hysteria2" }
		return node to result.notes
	}

	private fun mihomo(body: String) = MihomoConverter.convert(body) as MihomoConverter.Result.Ok

	@Test
	fun `the server ports and the interval of a remote mode reach every pass`() {
		val body = hysteria(443, """{"mode":"intervalRemote","remotePorts":"20000-30000","interval":"5"}""")
		val link = links(body).text
		assertTrue(link, link.startsWith("hysteria2://pw@h.example.com:443/?"))
		assertTrue(link, "mport=20000-30000&mportHopInt=5" in link)
		val (node, _) = singBoxNode(body)
		assertEquals(443, node.getInt("server_port"))
		assertEquals("20000:30000", node.getJSONArray("server_ports").getString(0))
		assertEquals("5s", node.getString("hop_interval"))
		val yaml = mihomo(body).yaml
		assertTrue(yaml, "ports: 20000-30000" in yaml && "hop-interval: 5" in yaml)
	}

	// Xray dials only the server ports in a remote mode, so a node naming no port of its own is dialled
	// at the first of them, the same in every pass.
	@Test
	fun `with no port of its own the node dials the first server port`() {
		val mask = """{"mode":"intervalRemote","remotePorts":"20000-30000,40000","interval":"5-10"}"""
		val body = hysteria(0, mask)
		assertTrue(links(body).text, links(body).text.startsWith("hysteria2://pw@h.example.com:20000/?"))
		val (node, _) = singBoxNode(body)
		assertEquals(20000, node.getInt("server_port"))
		val ports = node.getJSONArray("server_ports")
		val written = (0 until ports.length()).map { ports.getString(it) }
		assertEquals(listOf("20000:30000", "40000:40000"), written)
		val yaml = mihomo(body).yaml
		assertTrue(yaml, "port: 20000" in yaml && "ports: 20000-30000,40000" in yaml)
		assertTrue(yaml, "hop-interval: 5-10" in yaml)
	}

	@Test
	fun `what the mask asks that no core does is named, and a local mode leaves the node its own port`() {
		val local = hysteria(443, """{"mode":"intervalLocal","interval":"30"}""")
		assertFalse(links(local).text, "mport=" in links(local).text)
		val (localNode, localNotes) = singBoxNode(local)
		assertFalse("$localNode", localNode.has("server_ports"))
		assertTrue("$localNotes", localNotes.any { "intervalLocal" in it })
		val perConnection = hysteria(443, """{"mode":"perConnRemote","remotePorts":"20000-30000"}""")
		assertTrue(links(perConnection).text, "mport=20000-30000" in links(perConnection).text)
		val perConnectionNotes = mihomo(perConnection).notes
		assertTrue("$perConnectionNotes", perConnectionNotes.any { "perConnRemote" in it })
		val addresses = hysteria(443,
			"""{"mode":"intervalRemote","remotePorts":"20000-30000","remoteIPs":["1.2.3.4","10.0.0.0/8"]}""")
		assertTrue(links(addresses).text, "mport=20000-30000" in links(addresses).text)
		assertTrue("${links(addresses).notes}", links(addresses).notes.any { "remoteIPs" in it })
	}

	@Test
	fun `a mask Xray refuses the configuration over is a node every pass leaves out, for that reason`() {
		val refused = listOf(
			"""{"remotePorts":"20000-30000"}""" to "names no mode",
			"""{"mode":"intervalRemote, intervalLocal","remotePorts":"20000-30000"}""" to
				"names the mode \" intervallocal\"",
			"""{"mode":"hop","remotePorts":"20000-30000"}""" to "names the mode \"hop\""
		)
		for ((mask, reason) in refused) {
			val body = hysteria(443, mask)
			val link = links(body)
			assertFalse(link.text, "://" in link.text)
			assertEquals("${link.notes}", 1, link.notes.size)
			assertTrue("${link.notes}", reason in link.notes.single())
			val singBox = SingBoxConverter.convert(body, "N")
			assertTrue("$singBox", singBox is SingBoxConverter.Result.Unsupported && reason in "$singBox")
			val mihomo = MihomoConverter.convert(body)
			assertTrue("$mihomo", mihomo is MihomoConverter.Result.Unsupported && reason in "$mihomo")
		}
	}

	// What else Xray refuses in a mask it reads itself - an interval padded or under 5 seconds, a remote
	// IP that is none - the passes correct: the node hops from 5 seconds, on its own address.
	@Test
	fun `an interval or a remote IP the passes correct keeps the node, hopping from 5 seconds`() {
		for ((interval, note) in listOf(" 5" to null, "3" to "is under 5 seconds")) {
			val mask = """{"mode":"intervalRemote","remotePorts":"20000-30000","interval":"$interval"}"""
			val body = hysteria(443, mask)
			val link = links(body)
			assertTrue(link.text, "mport=20000-30000&mportHopInt=5#" in link.text)
			val (node, notes) = singBoxNode(body)
			assertEquals("5s", node.getString("hop_interval"))
			val converted = mihomo(body)
			assertTrue(converted.yaml, "hop-interval: 5\n" in converted.yaml)
			for (said in listOf(link.notes, notes, converted.notes)) {
				assertEquals("$said", note != null, said.any { "is under 5 seconds" in it })
			}
		}
		// A range from 0 is under 5 seconds too; no time at all - 0, 0-0, 0s - is unset, to Xray as to the
		// cores, and goes as 0.
		val hopping = """{"mode":"intervalRemote","remotePorts":"20000-30000","interval":"""
		val fromZero = hysteria(443, "$hopping\"0-10\"}")
		assertTrue(mihomo(fromZero).yaml, "hop-interval: 5-10\n" in mihomo(fromZero).yaml)
		assertEquals("5s", singBoxNode(fromZero).first.getString("hop_interval"))
		for (zero in listOf("0", "0-0", "0s")) {
			val unset = hysteria(443, "$hopping\"$zero\"}")
			val converted = mihomo(unset)
			assertTrue(converted.yaml, "hop-interval: 0\n" in converted.yaml)
			val (node, notes) = singBoxNode(unset)
			assertEquals("0s", node.getString("hop_interval"))
			assertTrue(links(unset).text, "mportHopInt=0#" in links(unset).text)
			for (said in listOf(links(unset).notes, notes, converted.notes)) {
				assertTrue("$said", said.none { "hop interval" in it })
			}
		}
		val ips = """{"mode":"intervalRemote","remotePorts":"20000-30000","remoteIPs":["not-an-ip"]}"""
		val addresses = hysteria(443, ips)
		assertTrue(links(addresses).text, "@h.example.com:443/?" in links(addresses).text)
		val (_, singBoxNotes) = singBoxNode(addresses)
		assertTrue("$singBoxNotes", singBoxNotes.any { "remoteIPs" in it })
		assertTrue("${mihomo(addresses).notes}", mihomo(addresses).notes.any { "remoteIPs" in it })
	}

	// Outside Hysteria no core hops ports, and the node's own port may be one its server does not listen
	// on; a link carries the mask whole in fm, which Xray reads.
	@Test
	fun `a node off Hysteria sent to server ports alone is left out by the cores and kept by the link`() {
		val user = """{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}"""
		val mask = """{"type":"udphop","settings":{"mode":"intervalRemote","remotePorts":"20000-30000"}}"""
		val stream = """{"network":"kcp","finalmask":{"udp":[$mask]}}"""
		val vnext = """{"vnext":[{"address":"k.example.com","port":443,"users":[$user]}]}"""
		val fields = """"settings":$vnext,"streamSettings":$stream"""
		val body = """{"outbounds":[{"protocol":"vless","tag":"k",$fields}]}"""
		val reason = "server ports in remotePorts alone"
		assertTrue(SingBoxConverter.convert(body, "N").toString().contains(reason))
		assertTrue(MihomoConverter.convert(body).toString().contains(reason))
		val link = links(body).text
		assertTrue(link, link.startsWith("vless://") && "udphop" in URLDecoder.decode(link, "UTF-8"))
		// A mask Xray refuses the configuration over is no link either, fm or not.
		val unread = body.replace(""""mode":"intervalRemote",""", "")
		val refused = links(unread)
		assertFalse(refused.text, "://" in refused.text)
		assertTrue("${refused.notes}", refused.notes.any { "names no mode" in it })
		// The link's fm holds the mask as written, so an interval Xray will not take is no link either.
		val short = links(body.replace(""""remotePorts"""", """"interval":"3","remotePorts""""))
		assertFalse(short.text, "://" in short.text)
		assertTrue("${short.notes}", short.notes.any { "has the interval \"3\"" in it })
	}
}
