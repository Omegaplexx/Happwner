package com.happwner.convert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// Comment text is not inert.
class YamlCommentTest {

    private fun render(comment: String): String {
        val entry = YamlMap().set("name", "n").set("type", "url-test")
        val doc = YamlMap().set("proxy-groups", YamlSeq(listOf(YamlCommented(comment, entry))))
        return encodeYaml(doc)
    }

    // Every line of the output is either a comment or indented under a key.
    private fun noEscapedContent(yaml: String): Boolean =
        yaml.lines().drop(1).none { it.isNotEmpty() && !it.startsWith(" ") && !it.startsWith("#") }

    @Test
    fun `a carriage return in a tag cannot break out of its comment`() {
        val yaml = render("Xray balancer \"a\rinjected: value\", strategy random")
        assertTrue("the escaped half must stay commented:\n$yaml", noEscapedContent(yaml))
        assertFalse(yaml.contains("\n" + "injected"))
    }

    @Test
    fun `the other YAML line breaks are handled too`() {
        // NEL, LINE SEPARATOR and PARAGRAPH SEPARATOR all end a comment for a
        // YAML 1.1 scanner even though none of them is \n.
        for (br in listOf("\u0085", "\u2028", "\u2029")) {
            val yaml = render("tag${br}injected: value")
            assertTrue("U+%04X escaped:\n%s".format(br[0].code, yaml), noEscapedContent(yaml))
        }
    }

    @Test
    fun `a newline in a tag becomes a second comment line, not content`() {
        val yaml = render("first\nsecond")
        assertTrue(yaml.contains("# first"))
        assertTrue(yaml.contains("# second"))
        assertTrue(noEscapedContent(yaml))
    }

    @Test
    fun `control characters are dropped from comments`() {
        val yaml = render("tag\u0000with\u0007control")
        assertTrue(yaml.contains("# tagwithcontrol"))
    }

    @Test
    fun `an ordinary comment still reads normally`() {
        val yaml = render("Xray balancer \"bal\", strategy leastPing")
        assertTrue(yaml.contains("""# Xray balancer "bal", strategy leastPing"""))
    }

    // A commented item at the head of a nested sequence shares the parent's line, giving "- # text" with the
    // value below. Verified through a YAML parser for a scalar, a mapping, a nested sequence and a comment.
    @Test
    fun `a commented item keeps its place in a nested sequence`() {
        val inner = YamlSeq(listOf(YamlCommented("why", "member-a"), "member-b"))
        val yaml = encodeYaml(YamlMap().set("groups", YamlSeq(listOf(inner))))
        assertTrue(yaml.contains("# why"))
        assertTrue(yaml.contains("- member-a"))
        assertTrue(yaml.contains("- member-b"))
        // Two entries in the inner sequence, not three: no empty one was added.
        assertEquals(2, yaml.lines().count { it.trimStart().startsWith("- member") })
        // And no trailing whitespace, which a "give the comment its own line"
        // rewrite would introduce on the parent's dash.
        assertTrue("no line may end in whitespace", yaml.lines().none { it != it.trimEnd() })
    }

    @Test
    fun `a balancer tag carrying a line break survives conversion intact`() {
        val input = """
            { "remarks": "Sub", "outbounds": [
                { "protocol": "vless", "tag": "n1",
                  "settings": { "vnext": [{ "address": "a.example.com", "port": 443,
                    "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] }] } },
                { "protocol": "vless", "tag": "n2",
                  "settings": { "vnext": [{ "address": "b.example.com", "port": 443,
                    "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30812" }] }] } }],
              "routing": { "rules": [{ "type": "field", "balancerTag": "b\rrules:\n- MATCH,DIRECT", "network": "tcp" }],
                "balancers": [{ "tag": "b\rrules:\n- MATCH,DIRECT", "selector": ["n"] }] } }
        """.trimIndent()
        val r = MihomoConverter.convert(input)
        assertTrue("expected a document, got $r", r is MihomoConverter.Result.Ok)
        val yaml = (r as MihomoConverter.Result.Ok).yaml
        val topLevel = yaml.lines().filter { it.isNotEmpty() && !it.first().isWhitespace() }

        // The document has one "rules:" key of its own. A second one, or a
        // sequence entry at column zero, would be the tag having escaped.
        assertEquals(
            "the injected key reached the document:\n$yaml",
            1,
            topLevel.count { it.startsWith("rules:") }
        )
        assertTrue(
            "a sequence entry escaped to column zero:\n$yaml",
            topLevel.none { it.startsWith("- ") }
        )
        // Every top-level line is a key of ours or a comment - nothing else.
        assertTrue(
            "unexpected top-level content:\n$yaml",
            topLevel.all { it.startsWith("#") || Regex("^[a-z0-9-]+:").containsMatchIn(it) }
        )
    }

    @Test
    fun `proxy names are still stripped of control characters`() {
        assertEquals("ab", sanitizeName("a\u0000b"))
        assertEquals("proxy", sanitizeName("\u0001\u0002"))
    }
}
