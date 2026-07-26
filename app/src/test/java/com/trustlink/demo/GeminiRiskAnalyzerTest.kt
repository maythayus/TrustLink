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
    fun `nominal attempt is allowed`() {
        val assessment = analyzer.heuristicAssessment(context(), "test")
        assertEquals(RiskVerdict.ALLOW, assessment.verdict)
        assertFalse(assessment.fromModel)
    }

    @Test
    fun `different nfc tag is denied`() {
        val assessment = analyzer.heuristicAssessment(context(tagMatches = false), "test")
        assertEquals(RiskVerdict.DENY, assessment.verdict)
        assertTrue(assessment.signals.any { it.contains("NFC") })
    }

    @Test
    fun `expired challenge and biometric failures trigger a step up`() {
        val assessment = analyzer.heuristicAssessment(
            context(challengeAge = 300, failures = 3),
            "test",
        )
        assertEquals(RiskVerdict.CHALLENGE, assessment.verdict)
    }

    @Test
    fun `model is disabled without an api key`() {
        assertFalse(analyzer.isModelConfigured)
    }
}
