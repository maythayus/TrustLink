package com.trustlink.demo

import com.trustlink.demo.qr.InvalidChallengeException
import com.trustlink.demo.qr.QrChallengeScanner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QrChallengeScannerTest {

    @Test
    fun `parse un challenge valide`() {
        val challenge = QrChallengeScanner.parse(
            """{"v":1,"sid":"s-123","nonce":"abcdef","origin":"https://service.fr","exp":4102444800}"""
        )
        assertEquals("s-123", challenge.sessionId)
        assertEquals("https://service.fr", challenge.origin)
        assertFalse(challenge.isExpired)
    }

    @Test
    fun `detecte un challenge expire`() {
        val challenge = QrChallengeScanner.parse(
            """{"v":1,"sid":"s","nonce":"n","origin":"o","exp":1}"""
        )
        assertTrue(challenge.isExpired)
    }

    @Test(expected = InvalidChallengeException::class)
    fun `rejette une version inconnue`() {
        QrChallengeScanner.parse("""{"v":9,"sid":"s","nonce":"n"}""")
    }

    @Test(expected = InvalidChallengeException::class)
    fun `rejette un nonce manquant`() {
        QrChallengeScanner.parse("""{"v":1,"sid":"s"}""")
    }

    @Test(expected = InvalidChallengeException::class)
    fun `rejette un contenu non json`() {
        QrChallengeScanner.parse("https://exemple.fr")
    }
}
