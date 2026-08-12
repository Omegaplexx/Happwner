package com.happwner.convert

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Recognising an IP literal, which filters dns.hosts down to what sing-box takes as predefined answers.
// Measured on 1.13.15: one malformed address is answered with `must expand to at least one field of zeros`.
class IpLiteralTest {

    // --------------------------------------------------------------- IPv4 ----

    @Test
    fun `dotted quads are recognised`() {
        for (s in listOf("0.0.0.0", "255.255.255.255", "192.168.1.1", "1.2.3.4")) {
            assertTrue(s, SingBoxUtil.parseInet4(s))
        }
    }

    @Test
    fun `IPv4 refuses padding, wrong arity and non-digits`() {
        // A leading zero is not merely ugly: it is octal in some parsers and
        // decimal in others, so the safe answer is to refuse it.
        for (s in listOf(
            "01.2.3.4", "010.1.1.1", "1.2.3.04",
            "1.2.3", "1.2.3.4.5", "1.2.3.", ".1.2.3", "1..2.3",
            "256.1.1.1", "1.2.3.-1", "1.2.3.a", ""
        )) {
            assertFalse(s, SingBoxUtil.parseInet4(s))
        }
    }

    // --------------------------------------------------------------- IPv6 ----

    @Test
    fun `the ordinary forms are recognised`() {
        for (s in listOf(
            "::", "::1", "1::", "fe80::1", "2001:db8::1",
            "1:2:3:4:5:6:7:8", "0:0:0:0:0:0:0:0",
            "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
            "1::8", "1:2::8", "1:2:3::8", "1:2:3:4::8", "1:2:3:4:5::8", "1:2:3:4:5:6::8",
            "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8"
        )) {
            assertTrue(s, SingBoxUtil.parseInet6(s))
        }
    }

    @Test
    fun `an embedded IPv4 tail is recognised`() {
        for (s in listOf(
            "::ffff:1.2.3.4", "0:0:0:0:0:ffff:1.2.3.4", "::1.2.3.4",
            "64:ff9b::1.2.3.4", "1:2:3:4:5:6:1.2.3.4", "1:2:3::5:6:1.2.3.4"
        )) {
            assertTrue(s, SingBoxUtil.parseInet6(s))
        }
    }

    @Test
    fun `a zone identifier is ignored rather than rejected`() {
        for (s in listOf("fe80::1%eth0", "fe80::1%25eth0", "2001:db8::1%1", "::%eth0")) {
            assertTrue(s, SingBoxUtil.parseInet6(s))
        }
        // Everything past the '%' is dropped before parsing, so an empty zone leaves a valid
        // address rather than an invalid one.
        assertTrue("1::%", SingBoxUtil.parseInet6("1::%"))
    }

    @Test
    fun `the double colon must cover at least one group of zeros`() {
        // The case that used to pass: eight groups are already spelled out, so
        // there is nothing left for "::" to stand for.
        assertFalse("::1:2:3:4:5:6:7:8", SingBoxUtil.parseInet6("::1:2:3:4:5:6:7:8"))
        assertFalse("1:2:3:4:5:6:7:8::", SingBoxUtil.parseInet6("1:2:3:4:5:6:7:8::"))
        // The same count with an embedded IPv4 tail, which folds into two
        // groups: 4 + 2 + 2 is already eight, so "::" has nothing to cover.
        assertFalse("1:2:3:4:5::6:1.2.3.4", SingBoxUtil.parseInet6("1:2:3:4:5::6:1.2.3.4"))
        assertFalse("1:2:3:4::5:6:1.2.3.4", SingBoxUtil.parseInet6("1:2:3:4::5:6:1.2.3.4"))
        // And one group short is still fine.
        assertTrue("::1:2:3:4:5:6:7", SingBoxUtil.parseInet6("::1:2:3:4:5:6:7"))
    }

    @Test
    fun `malformed IPv6 is refused`() {
        for (s in listOf(
            "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7",
            "1::2::3", "2001:db8:::1", "2001::db8::1", ":::",
            ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:",
            "12345::", "gggg::1", "-1::",
            "::ffff:1.2.3.4.5", "::ffff:256.1.1.1", "::ffff:01.2.3.4",
            "%eth0", "", "1.2.3.4", "[::1]"
        )) {
            assertFalse(s, SingBoxUtil.parseInet6(s))
        }
    }

    @Test
    fun `isIpLiteral answers for both families and nothing else`() {
        for (s in listOf("1.2.3.4", "::1", "fe80::1%eth0")) {
            assertTrue(s, SingBoxUtil.isIpLiteral(s))
        }
        for (s in listOf("example.com", "geosite:ads", "", "1.2.3", "::1:2:3:4:5:6:7:8")) {
            assertFalse(s, SingBoxUtil.isIpLiteral(s))
        }
        // Only strings are addresses; a number or a null is not.
        assertFalse(SingBoxUtil.isIpLiteral(null))
        assertFalse(SingBoxUtil.isIpLiteral(42))
    }

    // ------------------------------------------------------- host and port ----

    @Test
    fun `host and port split apart, brackets and all`() {
        assertTrue(SingBoxUtil.splitHostPort("a.example.com:443").let { it.host == "a.example.com" && it.port == 443 })
        assertTrue(SingBoxUtil.splitHostPort("a.example.com").let { it.host == "a.example.com" && it.port == null })
        assertTrue(SingBoxUtil.splitHostPort("[2001:db8::1]:443").let { it.host == "2001:db8::1" && it.port == 443 })
        assertTrue(SingBoxUtil.splitHostPort("[2001:db8::1]").let { it.host == "2001:db8::1" && it.port == null })
        // A bare IPv6 has many colons and no port; it must not be cut apart.
        assertTrue(SingBoxUtil.splitHostPort("2001:db8::1").let { it.host == "2001:db8::1" && it.port == null })
        assertTrue(SingBoxUtil.splitHostPort("").let { it.host == "" && it.port == null })
        // A non-numeric port is not a port.
        assertTrue(SingBoxUtil.splitHostPort("a.example.com:http").let { it.host == "a.example.com:http" && it.port == null })
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
}
