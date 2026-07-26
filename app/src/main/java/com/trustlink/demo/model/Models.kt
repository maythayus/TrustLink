package com.trustlink.demo.model

/**
 * Identity enrolled on the device: fingerprint of the NFC tag (never the raw UID) bound to a
 * non-exportable private key protected by biometrics.
 */
data class Enrollment(
    val tagFingerprint: String,
    val tagTechnologies: List<String>,
    val publicKeyPem: String,
    val enrolledAtMillis: Long,
)

/**
 * Authentication challenge carried by the QR code displayed by the remote service.
 *
 * Expected JSON shape:
 * {"v":1,"sid":"...","nonce":"...","origin":"https://...","exp":1758000000}
 */
data class QrChallenge(
    val version: Int,
    val sessionId: String,
    val nonce: String,
    val origin: String,
    val expiresAtSeconds: Long,
) {
    val isExpired: Boolean
        get() = expiresAtSeconds > 0 && System.currentTimeMillis() / 1000 > expiresAtSeconds
}

/** Factual context submitted to the risk engine. */
data class AuthContext(
    val origin: String,
    val sessionId: String,
    val challengeAgeSeconds: Long,
    val secondsSinceEnrollment: Long,
    val tagFingerprintPrefix: String,
    val tagMatchesEnrollment: Boolean,
    val biometricStrongAvailable: Boolean,
    val deviceModel: String,
    val androidSdk: Int,
    val failedBiometricAttempts: Int,
    val previousAuthenticationsLastHour: Int,
)

enum class RiskVerdict { ALLOW, CHALLENGE, DENY }

data class RiskAssessment(
    val score: Int,
    val verdict: RiskVerdict,
    val rationale: String,
    val signals: List<String>,
    val fromModel: Boolean,
)

data class SignedAssertion(
    val sessionId: String,
    val payload: String,
    val signatureBase64: String,
    val publicKeyPem: String,
)
