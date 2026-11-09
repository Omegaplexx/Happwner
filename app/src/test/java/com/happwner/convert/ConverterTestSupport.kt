package com.happwner.convert

// The converter's entry point with each flag as a named argument, and its text alone - the forms the
// tests read best in.
internal fun SubscriptionConverter.convertWithStats(
	input: String,
	jsonToUri: Boolean = true,
	base64Result: Boolean = false,
	xrayToSingBox: Boolean = false,
	xrayToMihomo: Boolean = false,
	dropIncompatibleMihomo: Boolean = false
): SubscriptionConverter.ConversionResult = convertWithStats(input, ConversionFlags(
	jsonToUri = jsonToUri, xrayToSingBox = xrayToSingBox, xrayToMihomo = xrayToMihomo,
	base64Result = base64Result,
	dropIncompatibleMihomo = dropIncompatibleMihomo))

internal fun SubscriptionConverter.convert(
	input: String,
	jsonToUri: Boolean = true,
	base64Result: Boolean = false,
	xrayToSingBox: Boolean = false,
	xrayToMihomo: Boolean = false,
	dropIncompatibleMihomo: Boolean = false
): String =
	convertWithStats(input, jsonToUri, base64Result, xrayToSingBox, xrayToMihomo, dropIncompatibleMihomo).text
