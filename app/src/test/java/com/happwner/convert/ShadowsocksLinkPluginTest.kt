package com.happwner.convert

import java.net.URLDecoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// A Shadowsocks plugin performs the obfuscation the server expects. A link without it points at a
// server that will not answer, while looking perfectly well formed.
class ShadowsocksLinkPluginTest {

	private fun link(extra: String): String {
		val body = """
            {"outbounds":[{"type":"shadowsocks","tag":"S","server":"a.com","server_port":8388,
             "method":"aes-256-gcm","password":"pw"$extra}]}
		""".trimIndent()
		return SubscriptionConverter.convert(body, jsonToUri = true,
			base64Result = false).trim().lines().first()
	}

	@Test
	fun a_plugin_and_its_options_reach_the_link() {
		val out = link(",\"plugin\":\"obfs-local\",\"plugin_opts\":\"obfs=http;obfs-host=www.bing.com\"")
		assertTrue("expected an ss link, got $out", out.startsWith("ss://"))
		val pluginParam = out.substringAfter("/?plugin=", "").substringBefore("#")
		assertTrue("no plugin in $out", pluginParam.isNotEmpty())
		assertEquals("obfs-local;obfs=http;obfs-host=www.bing.com", URLDecoder.decode(pluginParam, "UTF-8"))
	}

	// The options can arrive as an object rather than a string; both describe one plugin.
	@Test
	fun object_options_are_serialized_too() {
		val out = link(",\"plugin\":\"obfs-local\",\"plugin_opts\":{\"obfs\":\"tls\"}")
		val pluginParam = URLDecoder.decode(out.substringAfter("/?plugin=", "").substringBefore("#"), "UTF-8")
		assertTrue("options missing from $out",
			pluginParam.startsWith("obfs-local;") && pluginParam.contains("obfs=tls"))
	}

	// A WebSocket transport is the v2ray-plugin in websocket mode: carried, so nothing is dropped, and
	// a note saying so would be false.
	@Test
	fun a_transport_the_plugin_carries_gets_no_note_of_being_dropped() {
		val body = """
			{"outbounds":[{"protocol":"shadowsocks","tag":"S","settings":{"servers":[{"address":"a.com",
			 "port":443,"method":"aes-256-gcm","password":"pw"}]},"streamSettings":{"network":"ws",
			 "security":"tls","wsSettings":{"path":"/ws"},"tlsSettings":{"serverName":"a.com"}}}]}
		""".trimIndent()
		val stats = SubscriptionConverter.convertWithStats(body, jsonToUri = true, base64Result = false)
		val query = stats.text.trim().substringAfter("/?plugin=", "").substringBefore("#")
		val plugin = URLDecoder.decode(query, "UTF-8")
		assertTrue("the transport should ride the plugin: ${stats.text}",
			plugin.startsWith("v2ray-plugin;") && plugin.contains("mode=websocket") && plugin.contains("tls"))
		assertTrue("nothing was dropped: ${stats.notes}", stats.notes.none { it.contains("no place for") })
	}

	// Without a plugin the link keeps the shape every client already reads.
	@Test
	fun no_plugin_means_no_query() {
		val out = link("")
		assertTrue("expected an ss link, got $out", out.startsWith("ss://"))
		assertFalse("nothing should be added: $out", out.contains("plugin="))
		assertFalse("no stray path either: $out", out.substringBefore("#").endsWith("/?"))
	}
}
