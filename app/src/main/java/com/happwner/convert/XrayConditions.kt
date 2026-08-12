package com.happwner.convert

// What an entry of an Xray routing condition means.
internal object XrayConditions {

    // A name condition, already stripped of its prefix.
    internal sealed class Name {
        data class Exact(val value: String) : Name()
        data class Suffix(val value: String) : Name()
        data class Keyword(val value: String) : Name()
        data class Pattern(val value: String) : Name()
        data class Geosite(val value: String) : Name()
        // Names a file that ships with Xray, which neither core reads.
        object External : Name()
        // Empty, malformed, or a pattern that will not compile.
        object Unusable : Name()
    }

    // An address condition, already normalised.
    internal sealed class Address {
        data class Cidr(val value: String) : Address()
        data class Country(val code: String) : Address()
        data class NotCountry(val code: String) : Address()
        object Private : Address()
        object External : Address()
        object Unusable : Address()
    }

    internal fun name(raw: String): Name {
        val e = raw.trim()
        if (e.isEmpty()) return Name.Unusable
        // A leading "!" is Xray's exclusion marker, which neither core mirrors
        // for names; the entry is dropped rather than inverted by accident.
        if (e.startsWith("!")) return Name.Unusable
        fun value(prefix: String) = e.removePrefix(prefix).trim()
        return when {
            e.startsWith("full:") -> value("full:").ifEmpty { null }?.let { Name.Exact(it) } ?: Name.Unusable
            e.startsWith("domain:") -> value("domain:").ifEmpty { null }?.let { Name.Suffix(it) } ?: Name.Unusable
            e.startsWith("keyword:") -> value("keyword:").ifEmpty { null }?.let { Name.Keyword(it) } ?: Name.Unusable
            e.startsWith("geosite:") -> value("geosite:").ifEmpty { null }?.let { Name.Geosite(it) } ?: Name.Unusable
            e.startsWith("regexp:") -> {
                val p = value("regexp:")
                if (SingBoxUtil.isUsableRegex(p)) Name.Pattern(p) else Name.Unusable
            }
            e.startsWith("ext:") || e.startsWith("ext-domain:") -> Name.External
            else -> Name.Keyword(e)
        }
    }

    internal fun address(raw: String): Address {
        val e = raw.trim()
        if (e.isEmpty()) return Address.Unusable
        if (e.startsWith("!")) return Address.Unusable
        return when {
            e == "geoip:private" -> Address.Private
            e.startsWith("geoip:!") ->
                e.removePrefix("geoip:!").trim().ifEmpty { null }?.let { Address.NotCountry(it) }
                    ?: Address.Unusable
            e.startsWith("geoip:") ->
                e.removePrefix("geoip:").trim().ifEmpty { null }?.let { Address.Country(it) }
                    ?: Address.Unusable
            e.startsWith("ext:") || e.startsWith("ext-ip:") -> Address.External
            else -> SingBoxUtil.normalizedCidr(e)?.let { Address.Cidr(it) } ?: Address.Unusable
        }
    }
}
