package com.trustlink.server

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/** Stands in for the device Keystore key: same curve, same signature algorithm. */
object TestKeys {

    fun generate(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    fun pem(keyPair: KeyPair): String {
        val encoded = Base64.getEncoder().encodeToString(keyPair.public.encoded)
        return "-----BEGIN PUBLIC KEY-----\n" +
            encoded.chunked(64).joinToString("\n") +
            "\n-----END PUBLIC KEY-----"
    }

    fun sign(keyPair: KeyPair, payload: String): String {
        val signature = Signature.getInstance(Verifier.SIGNATURE_ALGORITHM).apply {
            initSign(keyPair.private)
            update(payload.toByteArray(Charsets.UTF_8))
        }
        return Base64.getEncoder().encodeToString(signature.sign())
    }

    fun payload(
        challenge: Challenge,
        tagFingerprint: String,
        timestampSeconds: Long,
    ): String = listOf(
        Verifier.PAYLOAD_PREFIX,
        challenge.sessionId,
        challenge.nonce,
        challenge.origin,
        tagFingerprint,
        timestampSeconds.toString(),
    ).joinToString("|")
}
