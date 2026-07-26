package com.trustlink.server

import kotlinx.serialization.Serializable

@Serializable
data class EnrollRequest(
    val tagFingerprint: String,
    val publicKeyPem: String,
)

@Serializable
data class EnrollResponse(
    val deviceId: String,
    val enrolledAtSeconds: Long,
)

@Serializable
data class ChallengeResponse(
    /** Exact string the client encodes into the QR code. */
    val qrPayload: String,
    val sessionId: String,
    val expiresAtSeconds: Long,
)

@Serializable
data class VerifyRequest(
    val sessionId: String,
    /** "trustlink/v1|sid|nonce|origin|tagFingerprint|ts" as signed by the device. */
    val payload: String,
    val signatureBase64: String,
)

@Serializable
data class VerifyResponse(
    val granted: Boolean,
    val deviceId: String? = null,
    val reason: String? = null,
)

@Serializable
data class ErrorResponse(val error: String)

/** A device that completed NFC enrollment: its tag fingerprint bound to its public key. */
data class Device(
    val deviceId: String,
    val tagFingerprint: String,
    val publicKeyPem: String,
    val enrolledAtSeconds: Long,
)

data class Challenge(
    val sessionId: String,
    val nonce: String,
    val origin: String,
    val expiresAtSeconds: Long,
) {
    /** Serialized form scanned by the app — mirrors `QrChallenge` on the Android side. */
    fun toQrPayload(): String =
        """{"v":1,"sid":"$sessionId","nonce":"$nonce","origin":"$origin","exp":$expiresAtSeconds}"""
}

/** Why a verification was refused. Never expose more than the client needs to know. */
enum class Refusal(val reason: String) {
    UNKNOWN_SESSION("unknown or already consumed session"),
    EXPIRED_CHALLENGE("challenge expired"),
    MALFORMED_PAYLOAD("malformed payload"),
    PAYLOAD_MISMATCH("payload does not match the issued challenge"),
    STALE_TIMESTAMP("device timestamp outside the accepted window"),
    UNKNOWN_DEVICE("no device enrolled for this tag fingerprint"),
    BAD_SIGNATURE("signature verification failed"),
}
