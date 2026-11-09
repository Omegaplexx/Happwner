package com.happwner.convert

import java.net.URLDecoder
import org.junit.Assert.assertTrue

// Readers the link tests share: a link's query and a conversion's notes, read one way everywhere.

// The parameters of a link, decoded.
internal fun queryOf(uri: String): Map<String, String> {
	val query = uri.substringAfter('?', "").substringBefore('#')
	if (query.isEmpty()) return emptyMap()
	return query.split("&").mapNotNull { pair ->
		val equals = pair.indexOf('=')
		if (equals < 0) {
			null
		} else {
			URLDecoder.decode(pair.substring(0, equals), "UTF-8") to
				URLDecoder.decode(pair.substring(equals + 1), "UTF-8")
		}
	}.toMap()
}

// What a link puts before the "@": the credential, not the query.
internal fun userInfoOf(uri: String): String = uri.substringAfter("://").substringBefore("@")

// The notes of a sing-box conversion that is expected to succeed.
internal fun singBoxNotesOf(xray: String): List<String> {
	val result = SingBoxConverter.convertToOutbounds(xray)
	assertTrue("expected Ok, got $result", result is SingBoxConverter.OutboundsResult.Ok)
	return (result as SingBoxConverter.OutboundsResult.Ok).notes
}

// A real self-signed certificate - one a core can read - as a JSON string with its line breaks.
internal val TEST_CERTIFICATE_JSON = listOf(
	"-----BEGIN CERTIFICATE-----",
	"MIIBhTCCASugAwIBAgIUMB/k82WRxi+BSNoWANL9eplJB7YwCgYIKoZIzj0EAwIw",
	"FzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMCAXDTI2MDkyNDAyMzE1M1oYDzIxMjYw",
	"ODMxMDIzMTUzWjAXMRUwEwYDVQQDDAx0ZXN0LmV4YW1wbGUwWTATBgcqhkjOPQIB",
	"BggqhkjOPQMBBwNCAAQMJfyJelOeNmwTMspeAEB3FzUSVjlXjMYRunui7zOUnSQI",
	"hQXmwz6CPUGrJu0FQyq7pkM970rfwlqCl1s4Y4gvo1MwUTAdBgNVHQ4EFgQUS+iZ",
	"xrDVaAa4Fr+C5s51y1CGLiMwHwYDVR0jBBgwFoAUS+iZxrDVaAa4Fr+C5s51y1CG",
	"LiMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA0FOntslprby/",
	"ZKbXVQGerVa2yEUmRRL+qhRvmjQ469kCIH1SWUNg9xQmh4wj40a6go1BolFGnECR",
	"0RNnHF1Chkli",
	"-----END CERTIFICATE-----"
).joinToString("\\n")

// A server's own self-signed certificate, as a Hysteria server's often is - for h.example.com,
// *.w.example.com, 192.0.2.10 and 2001:db8::1 - and one for h.example.com marked to sign others.
internal val OWN_CERTIFICATE_LINES = listOf(
	"-----BEGIN CERTIFICATE-----",
	"MIIBzDCCAXKgAwIBAgIUMemC5RNBPB3wZYmrx1iDRXLjUy4wCgYIKoZIzj0EAwIw",
	"GDEWMBQGA1UEAwwNaC5leGFtcGxlLmNvbTAgFw0yNjEwMTAwNzMxMTBaGA8yMTI2",
	"MDkxNjA3MzExMFowGDEWMBQGA1UEAwwNaC5leGFtcGxlLmNvbTBZMBMGByqGSM49",
	"AgEGCCqGSM49AwEHA0IABLDbmKIxDMKyqvlYlXCJoqa3lV9RXSiojqAmqHHHLq18",
	"BvlC19GhvDKX8B6So7eYuAbjlxCkGpB0KDp460NvnwqjgZcwgZQwHQYDVR0OBBYE",
	"FJ2Num9GHECX4F8ghf/Lja8IiyO4MB8GA1UdIwQYMBaAFJ2Num9GHECX4F8ghf/L",
	"ja8IiyO4MA8GA1UdEwEB/wQFMAMBAf8wQQYDVR0RBDowOIINaC5leGFtcGxlLmNv",
	"bYIPKi53LmV4YW1wbGUuY29thwTAAAIKhxAgAQ24AAAAAAAAAAAAAAABMAoGCCqG",
	"SM49BAMCA0gAMEUCIQDZaE7raXNw7ua8a6gToj572MSXl47mY6EAhVJDy45QjwIg",
	"ddLUxZs/ZccVZI7p8lTdUzGe9j3rKO91urrU6NKKSlQ=",
	"-----END CERTIFICATE-----",
)
internal val ISSUING_CERTIFICATE_LINES = listOf(
	"-----BEGIN CERTIFICATE-----",
	"MIIBsDCCAVegAwIBAgIULoTyJ+e+JA84Lc3iVwkoZ/RliU8wCgYIKoZIzj0EAwIw",
	"GDEWMBQGA1UEAwwNaC5leGFtcGxlLmNvbTAgFw0yNjEwMTAwNzMxMTBaGA8yMTI2",
	"MDkxNjA3MzExMFowGDEWMBQGA1UEAwwNaC5leGFtcGxlLmNvbTBZMBMGByqGSM49",
	"AgEGCCqGSM49AwEHA0IABJgCRah0ly5TZzz2zGUluUnDZZU7VMXQjIPfmLOM6j2o",
	"shAJJrya2ZOpHkiKI7LdBzI9RnhFI3d4o4CEDhgdf0ejfTB7MB0GA1UdDgQWBBRX",
	"+GshW/OebZ+AGd+xLrnJTmxVVDAfBgNVHSMEGDAWgBRX+GshW/OebZ+AGd+xLrnJ",
	"TmxVVDAPBgNVHRMBAf8EBTADAQH/MBgGA1UdEQQRMA+CDWguZXhhbXBsZS5jb20w",
	"DgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIC4jxxuXkFM2bEBNuotl",
	"ioVkLCWzKqukiqM25KLtE9gkAiBEsxWCJzY3AXvznS9RKJhUo/ny367rCdMhUzvM",
	"5godIw==",
	"-----END CERTIFICATE-----",
)

// SHA-256 of each certificate's DER, as openssl prints it.
internal const val OWN_CERTIFICATE_PIN =
	"1c07a6f2c3e9466577479174edfea27a3371b25b63c19357a7430fd8edfa0072"
internal const val ISSUING_CERTIFICATE_PIN =
	"9c954b7b56b321c3cfbe8e4c9b431f49b35bf06033ffcc4ed8c5475bbc0d5b1e"

// The certificate as Xray's tlsSettings takes a CA to verify the server against.
internal fun verifying(lines: List<String>): String =
	"""[{"usage":"verify","certificate":[${lines.joinToString(",") { "\"$it\"" }}]}]"""
