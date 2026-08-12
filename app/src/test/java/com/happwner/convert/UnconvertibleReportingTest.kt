package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// What is said when something cannot be carried: dropping a server without a word is the worst outcome,
// because the document still loads and nobody looks. Everything dropped is named.
class UnconvertibleReportingTest {

    // ---- H7: empty shadowsocks method ----

    @Test
    fun `empty shadowsocks method is rejected with a reason`() {
        val xray = """{"outbounds":[{"protocol":"shadowsocks","tag":"p","settings":
            {"servers":[{"address":"e.com","port":8388,"method":"","password":"pw"}]}}]}"""
        val r = SingBoxConverter.convert(xray, "")
        assertTrue("an empty method must not be substituted with a cipher", r is SingBoxConverter.Result.Unsupported)
        val notes = (r as SingBoxConverter.Result.Unsupported).notes
        assertTrue("the reason did not reach the notes: $notes", notes.any { it.contains("method is empty") })
    }
    @Test
    fun `absent shadowsocks method still defaults to aes256gcm`() {
        val xray = """{"outbounds":[{"protocol":"shadowsocks","tag":"p","settings":
            {"servers":[{"address":"e.com","port":8388,"password":"pw"}]}}]}"""
        val r = SingBoxConverter.convertToOutbounds(xray, "")
        assertTrue(r is SingBoxConverter.OutboundsResult.Ok)
        assertEquals("aes-256-gcm", (r as SingBoxConverter.OutboundsResult.Ok).outbounds[0].getString("method"))
    }
    // ---- H6: the removed branch was genuinely unreachable ----

    @Test
    fun `absent stream security is supported`() {
        val xray = """{"outbounds":[{"protocol":"vless","tag":"p","settings":
            {"vnext":[{"address":"e.com","port":443,"users":[{"id":"u"}]}]},
            "streamSettings":{"network":"tcp"}}]}"""
        assertTrue(SingBoxConverter.convert(xray, "") is SingBoxConverter.Result.Ok)
    }
    // ------------------------------- reasons for a wholesale mihomo failure ----

    // An Xray config whose only outbound mihomo cannot express.
    private val allUnsupported = """
        {"remarks":"S","outbounds":[{"protocol":"vless","tag":"n",
         "settings":{"vnext":[{"address":"a.example.com","port":443,
           "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
         "streamSettings":{"network":"quic","security":"none"}}]}
    """.trimIndent().replace("\n", "")
    @Test
    fun `a total mihomo failure still says why`() {
        // Partial failures reached a log through Ok.notes, while "every node was dropped" - the one
        // worth reading - used to arrive as a bare object with nothing attached.
        val r = MihomoConverter.convert(allUnsupported)
        assertTrue("expected Unsupported, got $r", r is MihomoConverter.Result.Unsupported)
        val notes = (r as MihomoConverter.Result.Unsupported).notes
        assertTrue("the drop must be explained, notes were $notes", notes.isNotEmpty())
        assertTrue(
            "the reason should name the transport, was $notes",
            notes.any { it.contains("QUIC", ignoreCase = true) }
        )
    }
    @Test
    fun `a total mihomo failure carries its reasons without eating the body`() {
        // The pass produces no document, so the body belongs to the conversions
        // that run after it - carrying the reasons out must not cost the text.
        val stats = LinkConverter.convertWithStats(
            allUnsupported, jsonToUri = true, base64Result = false, xrayToSb = false, xrayToMihomo = true
        )
        assertTrue("the reasons must survive the fall-through", stats.notes.isNotEmpty())
        assertTrue(
            "the body must still be there, was ${stats.text.take(40)}",
            stats.text.isNotEmpty()
        )
    }
    // ------------------------------------- what the sing-box core will load ----

    private fun `vlessWith`(stream: String) = """
        {"remarks":"Q","outbounds":[{"protocol":"vless","tag":"n","settings":{"vnext":[
         {"address":"a.example.com","port":443,"users":[
          {"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
         "streamSettings":$stream}]}
    """.trimIndent().replace("\n", "")
    // sing-box's QUIC transport is TLS-only and refuses the whole configuration at load without one
    // - "quic: TLS required", measured against 1.13.15.
    @Test
    fun `quic without tls is dropped rather than emitted unloadable`() {
        for (sec in listOf(
            """{"network":"quic","security":"none"}""",
            """{"network":"quic"}"""
        )) {
            val r = SingBoxConverter.convert(vlessWith(sec), "N")
            assertTrue("expected a drop for $sec, got $r", r is SingBoxConverter.Result.Unsupported)
            assertTrue(
                "the reason should name the missing TLS, was ${(r as SingBoxConverter.Result.Unsupported).notes}",
                r.notes.any { it.contains("quic transport needs TLS") }
            )
        }
    }
    @Test
    fun `quic with tls or reality still converts`() {
        for (sec in listOf(
            """{"network":"quic","security":"tls","tlsSettings":{"serverName":"a.example.com"}}""",
            """{"network":"quic","security":"reality","realitySettings":{"serverName":"a.example.com","publicKey":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","shortId":"aa"}}"""
        )) {
            val r = SingBoxConverter.convert(vlessWith(sec), "N")
            assertTrue("both load in the core and must keep converting: $sec, got $r", r is SingBoxConverter.Result.Ok)
        }
    }
    // An outbound of an unimplemented protocol has to say so. The reason used to be asked for only after a
    // "is it one we know" test, so the one case it exists for - an unknown protocol - never produced it.
    @Test
    fun `an unimplemented protocol is named rather than dropped in silence`() {
        val unknown = """{"remarks":"H","outbounds":[{"protocol":"shadowsocksr","tag":"n","settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]}}]}"""
        val r = SingBoxConverter.convert(unknown, "N")
        assertTrue("expected a drop, got $r", r is SingBoxConverter.Result.Unsupported)
        assertTrue(
            "the protocol must be named, notes were ${(r as SingBoxConverter.Result.Unsupported).notes}",
            r.notes.any { it.contains("shadowsocksr") }
        )
    }
    @Test
    fun `a dropped outbound is reported even when the rest converts`() {
        val mixed = """{"remarks":"M","outbounds":[
            {"protocol":"vless","tag":"a","settings":{"vnext":[{"address":"a.example.com","port":443,
              "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}},
            {"protocol":"shadowsocksr","tag":"b","settings":{"servers":[{"address":"b.example.com","port":443,"password":"pw"}]}}]}"""
            .trimIndent().replace("\n", "")
        val r = SingBoxConverter.convert(mixed, "N")
        assertTrue("the vless node must still convert, got $r", r is SingBoxConverter.Result.Ok)
        assertTrue(
            "the dropped one must be in the notes, they were ${(r as SingBoxConverter.Result.Ok).notes}",
            r.notes.any { it.contains("shadowsocksr") }
        )
    }
    @Test
    fun `auxiliary outbounds are not reported as unsupported`() {
        // freedom, blackhole, dns and loopback are not proxies; they are handled
        // elsewhere and must not turn into noise in the log.
        val withAux = """{"remarks":"A","outbounds":[
            {"protocol":"vless","tag":"a","settings":{"vnext":[{"address":"a.example.com","port":443,
              "users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}},
            {"protocol":"freedom","tag":"direct"},
            {"protocol":"blackhole","tag":"block"}]}"""
            .trimIndent().replace("\n", "")
        val r = SingBoxConverter.convert(withAux, "N")
        assertTrue("expected Ok, got $r", r is SingBoxConverter.Result.Ok)
        val notes = (r as SingBoxConverter.Result.Ok).notes
        assertTrue("aux outbounds must not be reported: $notes", notes.none {
            it.contains("freedom") || it.contains("blackhole")
        })
    }
}
