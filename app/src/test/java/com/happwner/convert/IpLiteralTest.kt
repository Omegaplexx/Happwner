package com.happwner.convert

import com.happwner.text.canonicalIp
import com.happwner.text.isIpLiteral
import com.happwner.text.parseInet4
import com.happwner.text.parseInet6
import com.happwner.text.splitHostPort
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Recognising an IP literal, which filters dns.hosts down to what sing-box takes as predefined answers.
// One malformed address is answered with `must expand to at least one field of zeros`.
class IpLiteralTest {

	@Test
	fun `dotted quads are recognized`() {
		for (literal in listOf("0.0.0.0", "255.255.255.255", "192.168.1.1", "1.2.3.4")) {
			assertTrue(literal, parseInet4(literal))
		}
	}

	@Test
	fun `IPv4 refuses padding, wrong arity and non-digits`() {
		// A leading zero is not merely ugly: it is octal in some parsers and
		// decimal in others, so the safe answer is to refuse it.
		for (literal in listOf(
			"01.2.3.4", "010.1.1.1", "1.2.3.04",
			"1.2.3", "1.2.3.4.5", "1.2.3.", ".1.2.3", "1..2.3",
			"256.1.1.1", "1.2.3.-1", "1.2.3.a", ""
		)) {
			assertFalse(literal, parseInet4(literal))
		}
	}

	@Test
	fun `the ordinary forms are recognized`() {
		for (literal in listOf(
			"::", "::1", "1::", "fe80::1", "2001:db8::1",
			"1:2:3:4:5:6:7:8", "0:0:0:0:0:0:0:0",
			"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
			"1::8", "1:2::8", "1:2:3::8", "1:2:3:4::8", "1:2:3:4:5::8", "1:2:3:4:5:6::8",
			"1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8"
		)) {
			assertTrue(literal, parseInet6(literal))
		}
	}

	@Test
	fun `an embedded IPv4 tail is recognized`() {
		for (literal in listOf(
			"::ffff:1.2.3.4", "0:0:0:0:0:ffff:1.2.3.4", "::1.2.3.4",
			"64:ff9b::1.2.3.4", "1:2:3:4:5:6:1.2.3.4", "1:2:3::5:6:1.2.3.4"
		)) {
			assertTrue(literal, parseInet6(literal))
		}
	}

	@Test
	fun `a zone identifier is ignored rather than rejected`() {
		for (literal in listOf("fe80::1%eth0", "fe80::1%25eth0", "2001:db8::1%1", "::%eth0")) {
			assertTrue(literal, parseInet6(literal))
		}
		// Everything past the '%' is dropped before parsing, so an empty zone leaves a valid
		// address rather than an invalid one.
		assertTrue("1::%", parseInet6("1::%"))
	}

	@Test
	fun `the double colon must cover at least one group of zeros`() {
		// Eight groups are already spelled out, so there is nothing left for "::" to stand for.
		assertFalse("::1:2:3:4:5:6:7:8", parseInet6("::1:2:3:4:5:6:7:8"))
		assertFalse("1:2:3:4:5:6:7:8::", parseInet6("1:2:3:4:5:6:7:8::"))
		// The same count with an embedded IPv4 tail, which folds into two
		// groups: 4 + 2 + 2 is already eight, so "::" has nothing to cover.
		assertFalse("1:2:3:4:5::6:1.2.3.4", parseInet6("1:2:3:4:5::6:1.2.3.4"))
		assertFalse("1:2:3:4::5:6:1.2.3.4", parseInet6("1:2:3:4::5:6:1.2.3.4"))
		// And one group short is still fine.
		assertTrue("::1:2:3:4:5:6:7", parseInet6("::1:2:3:4:5:6:7"))
	}

	@Test
	fun `malformed IPv6 is refused`() {
		for (literal in listOf(
			"1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7",
			"1::2::3", "2001:db8:::1", "2001::db8::1", ":::",
			":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:",
			"12345::", "gggg::1", "-1::",
			"::ffff:1.2.3.4.5", "::ffff:256.1.1.1", "::ffff:01.2.3.4",
			"%eth0", "", "1.2.3.4", "[::1]"
		)) {
			assertFalse(literal, parseInet6(literal))
		}
	}

	@Test
	fun `isIpLiteral answers for both families and nothing else`() {
		for (literal in listOf("1.2.3.4", "::1", "fe80::1%eth0")) {
			assertTrue(literal, isIpLiteral(literal))
		}
		for (literal in listOf("example.com", "geosite:ads", "", "1.2.3", "::1:2:3:4:5:6:7:8")) {
			assertFalse(literal, isIpLiteral(literal))
		}
		// Only strings are addresses; a number or a null is not.
		assertFalse(isIpLiteral(null))
		assertFalse(isIpLiteral(42))
	}

	@Test
	fun `host and port split apart, brackets and all`() {
		assertTrue(splitHostPort("a.example.com:443").let { it.host == "a.example.com" && it.port == 443 })
		assertTrue(splitHostPort("a.example.com").let { it.host == "a.example.com" && it.port == null })
		assertTrue(splitHostPort("[2001:db8::1]:443").let { it.host == "2001:db8::1" && it.port == 443 })
		assertTrue(splitHostPort("[2001:db8::1]").let { it.host == "2001:db8::1" && it.port == null })
		// A bare IPv6 has many colons and no port; it must not be cut apart.
		assertTrue(splitHostPort("2001:db8::1").let { it.host == "2001:db8::1" && it.port == null })
		assertTrue(splitHostPort("").let { it.host == "" && it.port == null })
		// A non-numeric port is not a port.
		assertTrue(splitHostPort("a.example.com:http").let { it.host == "a.example.com:http" &&
			it.port == null })
	}

	@Test
	fun `a tag is made unique by counting up`() {
		val used = mutableSetOf<String>()
		assertTrue(SingBoxUtil.makeUniqueTag("n", used) == "n")
		used.add("n")
		assertTrue(SingBoxUtil.makeUniqueTag("n", used) == "n (2)")
		used.add("n (2)")
		assertTrue(SingBoxUtil.makeUniqueTag("n", used) == "n (3)")
		// A name that already looks like a numbered one is left alone when free.
		assertTrue(SingBoxUtil.makeUniqueTag("n (7)", used) == "n (7)")
	}

	@Test
	fun `canonicalIp makes every spelling of one address compare equal`() {
		assertEquals(canonicalIp("fd00::2"), canonicalIp("FD00:0:0:0:0:0:0:0002"))
		assertEquals(canonicalIp("::ffff:1.2.3.4"), canonicalIp("::FFFF:102:304"))
		assertTrue(canonicalIp("1.2.3.4") != canonicalIp("::ffff:1.2.3.4"))
		assertTrue(canonicalIp("fe80::1%eth0") != canonicalIp("fe80::1%eth1"))
		assertEquals("1.2.3.4", canonicalIp("1.2.3.4"))
		assertNull(canonicalIp("example.com"))
		assertNull(canonicalIp("01.2.3.4"))
	}
}
