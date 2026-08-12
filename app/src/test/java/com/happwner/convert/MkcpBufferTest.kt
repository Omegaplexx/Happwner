package com.happwner.convert

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Xray counts the mKCP buffers in megabytes and mihomo in bytes. That is a conversion, and dropping
// it left a node running on mihomo's defaults instead of the sizes the source had chosen.
class MkcpBufferTest {

    private fun yaml(kcp: String): String {
        val xray = """
            {"remarks":"K","outbounds":[{"tag":"v","protocol":"vmess",
             "settings":{"vnext":[{"address":"a.com","port":443,
               "users":[{"id":"11111111-2222-3333-4444-555555555555","security":"auto"}]}]},
             "streamSettings":{"network":"kcp","security":"none","kcpSettings":{$kcp}}}]}
        """.trimIndent()
        val r = MihomoConverter.convert(xray)
        assertTrue("expected Ok, got $r", r is MihomoConverter.Result.Ok)
        return (r as MihomoConverter.Result.Ok).yaml
    }

    @Test
    fun megabytes_become_bytes() {
        val out = yaml("\"readBufferSize\":2,\"writeBufferSize\":4")
        assertTrue("2 MB should be 2097152 bytes:\n$out", out.contains("read-buffer: 2097152"))
        assertTrue("4 MB should be 4194304 bytes:\n$out", out.contains("write-buffer: 4194304"))
    }

    // Absent and zero both mean "the source did not choose", so mihomo keeps its own default.
    @Test
    fun unset_buffers_are_left_alone() {
        for (unset in listOf("", "\"readBufferSize\":0,\"writeBufferSize\":0")) {
            val out = yaml(unset.ifEmpty { "\"mtu\":1350" })
            assertFalse("nothing should be written for $unset:\n$out", out.contains("read-buffer"))
            assertFalse("nothing should be written for $unset:\n$out", out.contains("write-buffer"))
        }
    }

    // A figure absurd enough to wrap the multiplication must not come out as a negative size,
    // which mihomo would read as a setting rather than as nonsense.
    @Test
    fun an_absurd_size_is_left_out_rather_than_wrapped() {
        val out = yaml("\"readBufferSize\":9223372036854775807")
        assertFalse("nothing should be written for an absurd size:\n${'$'}out", out.contains("read-buffer"))
    }

    // A figure large enough to overflow an Int once multiplied out must still come through.
    @Test
    fun a_large_size_does_not_overflow() {
        val out = yaml("\"readBufferSize\":4096")
        assertTrue("4096 MB should be 4294967296 bytes:\n$out", out.contains("read-buffer: 4294967296"))
    }
}
