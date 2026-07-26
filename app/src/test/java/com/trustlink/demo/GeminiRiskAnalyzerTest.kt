package com.trustlink.demo

import com.trustlink.demo.ai.GeminiRiskAnalyzer
import com.trustlink.demo.model.AuthContext
import com.trustlink.demo.model.RiskVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GeminiRiskAnalyzerTest {

    private val analyzer = GeminiRiskAnalyzer(apiKey = "")

    private fun context(
        tagMatches: Boolean = true,
        challengeAge: Long = 5,
        failures: Int = 0,
        authsLastHour: Int = 1,
    ) = AuthContext(
        origin = "https://service.fr",
        sessionId = "s-1",
        challengeAgeSeconds = challengeAge,
        secondsSinceEnrollment = 86_400,
        tagFingerprintPrefix = "ab12cd34",
        tagMatchesEnrollment = tagMatches,
        biometricStrongAvailable = true,
        deviceModel = "Google Pixel 9",
        androidSdk = 36,
        failedBiometricAttempts = failures,
        previousAuthenticationsLastHour = authsLastHour,
    )

    @Test
    fun `nominal autorise`() {
        val assessment = analyzer.heuristicAssessment(context(), "test")
        assertEquals(RiskVerdict.ALLOW, assessment.verdict)
        assertFalse(assessment.fromModel)
    }

    @Test
    fun `support nfc different refuse`() {
        val assessment = analyzer.heuristicAssessment(context(tagMatches = false), "test")
        assertEquals(RiskVerdict.DENY, assessment.verdict)
        assertTrue(assessment.signals.any { it.contains("NFC") })
    }

    @Test
    fun `challenge perime et echecs biometriques declenchent une verification`() {
        val assessment = analyzer.heuristicAssessment(
            context(challengeAge = 300, failures = 3),
            "test",
        )
        assertEquals(RiskVerdict.CHALLENGE, assessment.verdict)
    }

    @Test
    fun `sans cle api le modele est desactive`() {
        assertFalse(analyzer.isModelConfigured)
    }
}
