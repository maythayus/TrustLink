package com.trustlink.server

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class VerifierTest {

    private val fingerprint = "a".repeat(64)
    private val keyPair = TestKeys.generate()
    private val now = 1_700_000_000L

    private fun storeWithDevice(): Store = Store(clockSeconds = { now }).apply {
        enroll(EnrollRequest(tagFingerprint = fingerprint, publicKeyPem = TestKeys.pem(keyPair)))
    }

    private fun request(
        challenge: Challenge,
        tagFingerprint: String = fingerprint,
        timestamp: Long = now,
        signingKey: java.security.KeyPair = keyPair,
    ): VerifyRequest {
        val payload = TestKeys.payload(challenge, tagFingerprint, timestamp)
        return VerifyRequest(
            sessionId = challenge.sessionId,
            payload = payload,
            signatureBase64 = TestKeys.sign(signingKey, payload),
        )
    }

    @Test
    fun `grants access for a valid assertion`() {
        val store = storeWithDevice()
        val challenge = store.issueChallenge("https://service.fr")
        val response = Verifier.verify(store, request(challenge), now)
        assertTrue(response.granted)
        assertEquals(store.deviceByFingerprint(fingerprint)?.deviceId, response.deviceId)
    }

    @Test
    fun `refuses a replayed nonce`() {
        val store = storeWithDevice()
        val challenge = store.issueChallenge("https://service.fr")
        val request = request(challenge)
        assertTrue(Verifier.verify(store, request, now).granted)

        val replay = Verifier.verify(store, request, now)
        assertFalse(replay.granted)
        assertEquals(Refusal.UNKNOWN_SESSION.reason, replay.reason)
        assertEquals(0, store.pendingChallenges())
    }

    @Test
    fun `refuses an expired challenge`() {
        val store = storeWithDevice()
        val challenge = store.issueChallenge("https://service.fr", ttlSeconds = 60)
        val response = Verifier.verify(store, request(challenge), now + 61)
        assertFalse(response.granted)
        assertEquals(Refusal.EXPIRED_CHALLENGE.reason, response.reason)
    }

    @Test
    fun `refuses a signature from another key`() {
        val store = storeWithDevice()
        val challenge = store.issueChallenge("https://service.fr")
        val response = Verifier.verify(
            store,
            request(challenge, signingKey = TestKeys.generate()),
            now,
        )
        assertFalse(response.granted)
        assertEquals(Refusal.BAD_SIGNATURE.reason, response.reason)
    }

    @Test
    fun `refuses an unenrolled tag fingerprint`() {
        val store = storeWithDevice()
        val challenge = store.issueChallenge("https://service.fr")
        val response = Verifier.verify(
            store,
            request(challenge, tagFingerprint = "b".repeat(64)),
            now,
        )
        assertFalse(response.granted)
        assertEquals(Refusal.UNKNOWN_DEVICE.reason, response.reason)
    }

    @Test
    fun `refuses a payload bound to another challenge`() {
        val store = storeWithDevice()
        val challenge = store.issueChallenge("https://service.fr")
        val other = store.issueChallenge("https://service.fr")
        val payload = TestKeys.payload(other, fingerprint, now)
        val response = Verifier.verify(
            store,
            VerifyRequest(
                sessionId = challenge.sessionId,
                payload = payload,
                signatureBase64 = TestKeys.sign(keyPair, payload),
            ),
            now,
        )
        assertFalse(response.granted)
        assertEquals(Refusal.PAYLOAD_MISMATCH.reason, response.reason)
    }

    @Test
    fun `refuses a device timestamp outside the tolerance`() {
        val store = storeWithDevice()
        val challenge = store.issueChallenge("https://service.fr")
        val response = Verifier.verify(
            store,
            request(challenge, timestamp = now - Verifier.TIMESTAMP_TOLERANCE_SECONDS - 1),
            now,
        )
        assertFalse(response.granted)
        assertEquals(Refusal.STALE_TIMESTAMP.reason, response.reason)
    }

    @Test
    fun `rejects a malformed payload`() {
        assertNull(Verifier.parsePayload("trustlink/v1|s|n|o|f"))
        assertNull(Verifier.parsePayload("other/v1|s|n|o|f|1"))
        assertNull(Verifier.parsePayload("trustlink/v1|s|n|o|f|not-a-number"))
        assertNull(Verifier.parsePayload("trustlink/v1|s||o|f|1"))
    }

    @Test
    fun `challenge qr payload is parseable by the app format`() {
        val challenge = Challenge("s-1", "abc", "https://service.fr", 4_102_444_800L)
        assertEquals(
            """{"v":1,"sid":"s-1","nonce":"abc","origin":"https://service.fr","exp":4102444800}""",
            challenge.toQrPayload(),
        )
    }
}
