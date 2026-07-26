package com.trustlink.demo.model

/**
 * Identité enrôlée sur l'appareil : empreinte du support NFC (jamais l'UID en clair)
 * associée à une clé privée non exportable protégée par la biométrie.
 */
data class Enrollment(
    val tagFingerprint: String,
    val tagTechnologies: List<String>,
    val publicKeyPem: String,
    val enrolledAtMillis: Long,
)

/**
 * Challenge d'authentification transporté par le QR code affiché par le service distant.
 *
 * Format attendu (JSON) :
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

/** Contexte factuel soumis au moteur d'analyse de risque. */
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
