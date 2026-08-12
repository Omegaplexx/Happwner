package com.happwner.convert

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

// Tests for the shared Xray reading layer. These describe the contract the converters will rely on,
// so they are written against the accessors directly rather than through a converter.
class XrayJsonTest {

    private fun obj(json: String) = JSONObject(json)

    private val sample = obj(
        """
        {"s":"text","padded":"  spaced  ","n":443,"quoted":"443","float":1.9,
         "bTrue":true,"bFalse":false,"one":1,"zero":0,"yes":"YES","off":"off",
         "nul":null,"o":{"k":"v"},"arr":[1,2],"empty":"","big":"9007199254740993"}
        """.trimIndent()
    )

    // ------------------------------------------------------------------ xOpt

    @Test
    fun `xOpt maps a missing key and json null alike`() {
        assertNull(sample.xOpt("absent"))
        assertNull(sample.xOpt("nul"))
    }

    @Test
    fun `xOpt on a null receiver is safe`() {
        val missing: JSONObject? = null
        assertNull(missing.xOpt("anything"))
    }

    @Test
    fun `xOpt returns the value untouched when present`() {
        assertEquals(443, sample.xOpt("n"))
    }

    // ---------------------------------------------------------- xObj  / xArr

    @Test
    fun `xObj and xArr return null for the wrong type`() {
        assertEquals("v", sample.xObj("o")?.optString("k"))
        assertNull("a string is not an object", sample.xObj("s"))
        assertNull("an array is not an object", sample.xObj("arr"))

        assertEquals(2, sample.xArr("arr")?.length())
        assertNull("an object is not an array", sample.xArr("o"))
        assertNull(sample.xArr("absent"))
    }

    // ------------------------------------------------------------------ xStr

    @Test
    fun `xStr trims and coerces scalars`() {
        assertEquals("text", sample.xStr("s"))
        assertEquals("spaced", sample.xStr("padded"))
        assertEquals("443", sample.xStr("n"))
        assertEquals("true", sample.xStr("bTrue"))
    }

    @Test
    fun `xStr yields empty for containers, nulls and missing keys`() {
        assertEquals("", sample.xStr("o"))
        assertEquals("", sample.xStr("arr"))
        assertEquals("", sample.xStr("nul"))
        assertEquals("", sample.xStr("absent"))
    }

    @Test
    fun `xStrOf takes the first non-empty spelling`() {
        assertEquals("text", sample.xStrOf("absent", "empty", "s"))
        assertEquals("", sample.xStrOf("absent", "empty", "nul"))
        // Order matters: the earlier key wins even when both are set.
        assertEquals("text", sample.xStrOf("s", "quoted"))
    }

    // ------------------------------------------------------------ xInt xLong

    @Test
    fun `xInt accepts numbers, quoted numbers and floats`() {
        assertEquals(443, sample.xInt("n"))
        assertEquals(443, sample.xInt("quoted"))
        // Truncation, not rounding.
        assertEquals(1, sample.xInt("float"))
    }

    @Test
    fun `xInt yields zero for anything it cannot read`() {
        assertEquals(0, sample.xInt("s"))
        assertEquals(0, sample.xInt("bTrue"))
        assertEquals(0, sample.xInt("nul"))
        assertEquals(0, sample.xInt("absent"))
        assertEquals(0, sample.xInt("o"))
    }

    @Test
    fun `xLong keeps precision an int would lose`() {
        assertEquals(9007199254740993L, sample.xLong("big"))
        assertEquals(443L, sample.xLong("quoted"))
        assertEquals(0L, sample.xLong("absent"))
    }

    // ----------------------------------------------------------------- xBool

    @Test
    fun `xBool reads the spellings generators actually emit`() {
        assertTrue(sample.xBool("bTrue"))
        assertTrue(sample.xBool("one"))
        assertTrue("case insensitive", sample.xBool("yes"))

        assertFalse(sample.xBool("bFalse"))
        assertFalse(sample.xBool("zero"))
        assertFalse(sample.xBool("off"))
        assertFalse(sample.xBool("s"))
        assertFalse(sample.xBool("nul"))
        assertFalse(sample.xBool("absent"))
    }

    // ------------------------------------------------------------------ xHas

    @Test
    fun `xHas distinguishes present from null and missing`() {
        assertTrue(sample.xHas("s"))
        assertTrue("false is still present", sample.xHas("bFalse"))
        assertTrue("an empty string is still present", sample.xHas("empty"))
        assertFalse(sample.xHas("nul"))
        assertFalse(sample.xHas("absent"))
    }

    // -------------------------------------------------------------- xStrList

    @Test
    fun `xStrList reads a json array`() {
        val o = obj("""{"alpn":["h2"," http/1.1 "]}""")
        assertEquals(listOf("h2", "http/1.1"), o.xStrList("alpn"))
    }

    @Test
    fun `xStrList accepts a comma separated string, as Xray's StringList does`() {
        val o = obj("""{"alpn":"h2, http/1.1"}""")
        assertEquals(listOf("h2", "http/1.1"), o.xStrList("alpn"))
    }

    @Test
    fun `xStrList drops empty entries and json nulls`() {
        assertEquals(listOf("a", "b"), obj("""{"v":["a",null,"","  ","b"]}""").xStrList("v"))
        assertEquals(listOf("a", "b"), obj("""{"v":"a,,  ,b"}""").xStrList("v"))
    }

    @Test
    fun `xStrList coerces non-string members`() {
        assertEquals(listOf("1", "true"), obj("""{"v":[1,true]}""").xStrList("v"))
    }

    @Test
    fun `xStrList is empty for missing, null and container values`() {
        assertEquals(emptyList<String>(), sample.xStrList("absent"))
        assertEquals(emptyList<String>(), sample.xStrList("nul"))
        assertEquals(emptyList<String>(), sample.xStrList("o"))
    }

    // -------------------------------------------------------------- xObjList

    @Test
    fun `xObjList keeps only the objects`() {
        val o = obj("""{"users":[{"id":"a"},null,"nope",7,{"id":"b"}]}""")
        val users = o.xObjList("users")
        assertEquals(2, users.size)
        assertEquals(listOf("a", "b"), users.map { it.optString("id") })
    }

    @Test
    fun `xObjList is empty when the field is not an array`() {
        assertEquals(emptyList<JSONObject>(), sample.xObjList("o"))
        assertEquals(emptyList<JSONObject>(), sample.xObjList("absent"))
        assertEquals(emptyList<JSONObject>(), sample.xObjList("nul"))
    }

    @Test
    fun `xObjList hands back the live objects, not copies`() {
        val o = obj("""{"users":[{"id":"a"}]}""")
        val first = o.xObjList("users")[0]
        assertSame(o.getJSONArray("users").getJSONObject(0), first)
    }

    // --------------------------------------------------------- null receiver

    @Test
    fun `every accessor tolerates a null receiver`() {
        val n: JSONObject? = null
        assertNull(n.xObj("k"))
        assertNull(n.xArr("k"))
        assertEquals("", n.xStr("k"))
        assertEquals("", n.xStrOf("a", "b"))
        assertEquals(0, n.xInt("k"))
        assertEquals(0L, n.xLong("k"))
        assertFalse(n.xBool("k"))
        assertFalse(n.xHas("k"))
        assertEquals(emptyList<String>(), n.xStrList("k"))
        assertEquals(emptyList<JSONObject>(), n.xObjList("k"))
    }

    // ---------------------------------------------------------- xScalarString

    @Test
    fun `xScalarString is the coercion the rest is built on`() {
        assertEquals("", xScalarString(null))
        assertEquals("raw", xScalarString("raw"))
        assertEquals("7", xScalarString(7))
        assertEquals("false", xScalarString(false))
        assertEquals("", xScalarString(JSONObject()))
        assertEquals("", xScalarString(JSONArray()))
    }


    // ---- H1: secrets must not be trimmed ----

    @Test
    fun `xStrRaw keeps surrounding whitespace where xStr strips it`() {
        val o = JSONObject().put("password", "  s3cr3t  ")
        assertEquals("s3cr3t", o.xStr("password"))
        assertEquals("  s3cr3t  ", o.xStrRaw("password"))
    }
    @Test
    fun `xStrRaw still maps missing and null to empty`() {
        val o = JSONObject().put("a", JSONObject.NULL)
        assertEquals("", o.xStrRaw("a"))
        assertEquals("", o.xStrRaw("absent"))
        assertEquals("", (null as JSONObject?).xStrRaw("a"))
    }
    @Test
    fun `xStrRawOf picks first non empty without trimming`() {
        val o = JSONObject().put("auth", "").put("password", " pw ")
        assertEquals(" pw ", o.xStrRawOf("auth", "password"))
    }
}
