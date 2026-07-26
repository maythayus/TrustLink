package com.trustlink.server

import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Verifies the assertion signed on the device. The signature is the only proof of identity:
 * it can only exist if the enrolled hardware key was unlocked by a strong biometric.
 */
object Verifier {

    const val PAYLOAD_PREFIX = "trustlink/v1"
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    /** Accepted clock skew between the device timestamp and the server clock. */
    const val TIMESTAMP_TOLERANCE_SECONDS = 120L

    data class ParsedPayload(
        val sessionId: String,
        val nonce: String,
        val origin: String,
        val tagFingerprint: String,
        val timestampSeconds: Long,
    )

    fun parsePayload(payload: String): ParsedPayload? {
        val parts = payload.split('|')
        if (parts.size != 6 || parts[0] != PAYLOAD_PREFIX) return null
        val timestamp = parts[5].toLongOrNull() ?: return null
        if (parts.subList(1, 5).any { it.isBlank() }) return null
        return ParsedPayload(
            sessionId = parts[1],
            nonce = parts[2],
            origin = parts[3],
            tagFingerprint = parts[4],
            timestampSeconds = timestamp,
        )
    }

    fun publicKeyFromPem(pem: String): PublicKey {
        val body = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .filterNot { it.isWhitespace() }
        val spec = X509EncodedKeySpec(Base64.getDecoder().decode(body))
        return KeyFactory.getInstance("EC").generatePublic(spec)
    }

    fun verifySignature(payload: String, signatureBase64: String, publicKeyPem: String): Boolean =
        try {
            Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initVerify(publicKeyFromPem(publicKeyPem))
                update(payload.toByteArray(Charsets.UTF_8))
                verify(Base64.getDecoder().decode(signatureBase64))
            }
        } catch (e: Exception) {
            false
        }

    /**
     * Full verification of a `/verify` request. Consumes the challenge on success so the nonce
     * can never be replayed; a failed attempt also burns it, which prevents brute forcing a
     * signature against a live nonce.
     */
    fun verify(store: Store, request: VerifyRequest, nowSeconds: Long): VerifyResponse {
        val challenge = store.consumeChallenge(request.sessionId)
            ?: return refuse(Refusal.UNKNOWN_SESSION)
        if (nowSeconds > challenge.expiresAtSeconds) return refuse(Refusal.EXPIRED_CHALLENGE)

        val parsed = parsePayload(request.payload) ?: return refuse(Refusal.MALFORMED_PAYLOAD)
        if (parsed.sessionId != challenge.sessionId ||
            parsed.nonce != challenge.nonce ||
            parsed.origin != challenge.origin
        ) {
            return refuse(Refusal.PAYLOAD_MISMATCH)
        }
        if (Math.abs(nowSeconds - parsed.timestampSeconds) > TIMESTAMP_TOLERANCE_SECONDS) {
            return refuse(Refusal.STALE_TIMESTAMP)
        }

        val device = store.deviceByFingerprint(parsed.tagFingerprint)
            ?: return refuse(Refusal.UNKNOWN_DEVICE)
        // The key used for verification is the enrolled one, never a key sent in the request.
        if (!verifySignature(request.payload, request.signatureBase64, device.publicKeyPem)) {
            return refuse(Refusal.BAD_SIGNATURE)
        }

        return VerifyResponse(granted = true, deviceId = device.deviceId)
    }

    private fun refuse(refusal: Refusal) =
        VerifyResponse(granted = false, reason = refusal.reason)
}
