package com.trustlink.server

import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.UUID

/**
 * In-memory state of the prototype: enrolled devices and pending challenges. A production
 * deployment would back this with a database, but the single-use nonce semantics are the same.
 */
class Store(
    private val random: SecureRandom = SecureRandom(),
    private val clockSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
) {

    private val devices = ConcurrentHashMap<String, Device>()
    private val challenges = ConcurrentHashMap<String, Challenge>()

    fun enroll(request: EnrollRequest): Device {
        // Reject a key we cannot parse rather than discovering it at verification time.
        Verifier.publicKeyFromPem(request.publicKeyPem)
        val device = Device(
            deviceId = UUID.randomUUID().toString(),
            tagFingerprint = request.tagFingerprint,
            publicKeyPem = request.publicKeyPem,
            enrolledAtSeconds = clockSeconds(),
        )
        devices[request.tagFingerprint] = device
        return device
    }

    fun deviceByFingerprint(fingerprint: String): Device? = devices[fingerprint]

    fun issueChallenge(origin: String, ttlSeconds: Long = DEFAULT_TTL_SECONDS): Challenge {
        purgeExpired()
        val challenge = Challenge(
            sessionId = "s-" + randomHex(8),
            nonce = randomHex(16),
            origin = origin,
            expiresAtSeconds = clockSeconds() + ttlSeconds,
        )
        challenges[challenge.sessionId] = challenge
        return challenge
    }

    /** Returns the challenge and removes it: a nonce is valid for exactly one attempt. */
    fun consumeChallenge(sessionId: String): Challenge? = challenges.remove(sessionId)

    fun pendingChallenges(): Int = challenges.size

    private fun purgeExpired() {
        val now = clockSeconds()
        challenges.values.removeIf { now > it.expiresAtSeconds }
    }

    private fun randomHex(bytes: Int): String {
        val buffer = ByteArray(bytes)
        random.nextBytes(buffer)
        return buffer.joinToString("") { "%02x".format(it) }
    }

    companion object {
        const val DEFAULT_TTL_SECONDS = 120L
    }
}
