package com.happwner.client

// What opening an encrypted v2RayTun or INCY link came to.
sealed class CryptLinkResult {
	data class Decrypted(val plaintext: String) : CryptLinkResult()
	object NotCryptLink : CryptLinkResult()
	data class Error(val reason: String) : CryptLinkResult()
}
