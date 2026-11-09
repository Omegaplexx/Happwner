package com.happwner.convert

import org.junit.Assert.assertTrue
import org.junit.Test

// Both cores' passes explain a balancer's strategy in the same words: Xray reads none as random, and
// the strategy is named as the configuration spells it.
class BalancerStrategyTest {
	private fun node(tag: String) = """{"tag":"$tag","protocol":"vless",
		"settings":{"vnext":[{"address":"$tag.example.com","port":443,
		"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
		"streamSettings":{"network":"tcp","security":"tls",
		"tlsSettings":{"serverName":"$tag.example.com"}}}"""

	// Notes from both passes for one configuration whose balancer carries the given strategy field.
	private fun notesOf(strategy: String): List<List<String>> {
		val body = """{"outbounds":[${node("a")},${node("b")}],
			"routing":{"balancers":[{"tag":"bal","selector":["a","b"]$strategy}],
			"rules":[{"type":"field","network":"tcp,udp","balancerTag":"bal"}]}}"""
		val singBox = (SingBoxConverter.convert(body, "N") as SingBoxConverter.Result.Ok).notes
		val mihomo = (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).notes
		return listOf(singBox, mihomo)
	}

	@Test
	fun `a balancer that names no strategy is random in both passes`() {
		for (notes in notesOf("")) {
			assertTrue("$notes", notes.any { "names no strategy, so it ran Xray's default, random" in it })
		}
	}

	// The mihomo document for the same configuration.
	private fun mihomoOf(strategy: String): String {
		val body = """{"outbounds":[${node("a")},${node("b")}],
			"routing":{"balancers":[{"tag":"bal","selector":["a","b"]$strategy}],
			"rules":[{"type":"field","network":"tcp,udp","balancerTag":"bal"}]}}"""
		return (MihomoConverter.convert(body) as MihomoConverter.Result.Ok).yaml
	}

	@Test
	fun `roundRobin is carried exactly by mihomo and named, as spelled, by sing-box`() {
		val roundRobin = ""","strategy":{"type":"roundRobin"}"""
		val (singBox, mihomo) = notesOf(roundRobin)
		assertTrue("$singBox", singBox.any { "uses the roundRobin strategy" in it })
		assertTrue("$mihomo", mihomo.none { "strategy" in it })
		val group = mihomoOf(roundRobin).substringAfter("strategy roundRobin").substringAfter("- name:")
			.substringBefore("- name:")
		assertTrue(group, "type: load-balance" in group && "strategy: round-robin" in group)
	}

	@Test
	fun `random spreads in mihomo too, taking the nodes in turn`() {
		val random = ""","strategy":{"type":"random"}"""
		val group = mihomoOf(random).substringAfter("strategy random").substringAfter("- name:")
			.substringBefore("- name:")
		assertTrue(group, "type: load-balance" in group && "strategy: round-robin" in group)
		assertTrue(notesOf(random)[1].toString(), notesOf(random)[1].any { "takes the nodes in turn" in it })
	}

	@Test
	fun `leastPing is what both groups do, so neither pass explains it`() {
		for (notes in notesOf(""","strategy":{"type":"leastPing"}""")) {
			val explained = notes.filter { "spreads traffic" in it || "picks by" in it || "strategy" in it }
			assertTrue("$explained", explained.isEmpty())
		}
	}
}
