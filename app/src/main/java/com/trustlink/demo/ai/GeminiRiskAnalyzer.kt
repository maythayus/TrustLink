package com.trustlink.demo.ai

import com.trustlink.demo.BuildConfig
import com.trustlink.demo.model.AuthContext
import com.trustlink.demo.model.RiskAssessment
import com.trustlink.demo.model.RiskVerdict
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject

/**
 * Gemini-powered risk analysis of an authentication attempt.
 *
 * The model never sees biometric data nor the raw NFC UID: only derived contextual signals.
 * It is advisory — the cryptographic signature remains the only proof of identity, Gemini just
 * adds a risk decision (allow / challenge / deny). Without an API key, the local rule-based
 * analysis takes over.
 */
class GeminiRiskAnalyzer(
    private val apiKey: String = BuildConfig.GEMINI_API_KEY,
    private val model: String = "gemini-flash-lite-latest",
    private val client: OkHttpClient = defaultClient,
) {

    val isModelConfigured: Boolean get() = apiKey.isNotBlank()

    suspend fun assess(context: AuthContext): RiskAssessment = withContext(Dispatchers.IO) {
        if (!isModelConfigured) return@withContext heuristicAssessment(context, "no Gemini key")
        try {
            callGemini(context)
        } catch (e: Exception) {
            heuristicAssessment(context, "Gemini unreachable: ${e.message}")
        }
    }

    private fun callGemini(context: AuthContext): RiskAssessment {
        val url = "https://generativelanguage.googleapis.com/v1beta/models/$model:generateContent"
        val body = buildRequestBody(context).toString().toRequestBody(JSON)
        val request = Request.Builder()
            .url(url)
            .header("x-goog-api-key", apiKey)
            .post(body)
            .build()

        client.newCall(request).execute().use { response ->
            val raw = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw IllegalStateException("HTTP ${response.code} ${raw.take(200)}")
            }
            return parseResponse(raw)
        }
    }

    private fun buildRequestBody(context: AuthContext): JSONObject {
        val signals = JSONObject()
            .put("origin", context.origin)
            .put("session_id", context.sessionId)
            .put("challenge_age_seconds", context.challengeAgeSeconds)
            .put("seconds_since_enrollment", context.secondsSinceEnrollment)
            .put("nfc_tag_matches_enrollment", context.tagMatchesEnrollment)
            .put("nfc_fingerprint_prefix", context.tagFingerprintPrefix)
            .put("strong_biometric_available", context.biometricStrongAvailable)
            .put("device_model", context.deviceModel)
            .put("android_sdk", context.androidSdk)
            .put("failed_biometric_attempts", context.failedBiometricAttempts)
            .put("authentications_last_hour", context.previousAuthenticationsLastHour)

        val prompt = """
            You are an anti-fraud engine for a three-factor strong authentication flow:
            possession (enrolled NFC tag), device (private key in the hardware Keystore) and
            biometrics (fingerprint/face authorizing the use of that key).

            Assess the attempt described by the JSON signals below and answer with a JSON
            object ONLY, no surrounding text, using this shape:
            {"score":<0-100>,"verdict":"ALLOW|CHALLENGE|DENY","rationale":"<one short sentence>","signals":["<notable signal>", ...]}

            Rules: score is the probability of fraud. An NFC tag that does not match the
            enrollment, an expired challenge (age > 120s), repeated biometric failures or an
            abnormal authentication frequency raise the score sharply. DENY above 70,
            CHALLENGE between 35 and 70, ALLOW below.

            Signals: $signals
        """.trimIndent()

        return JSONObject()
            .put(
                "contents",
                JSONArray().put(
                    JSONObject().put(
                        "parts",
                        JSONArray().put(JSONObject().put("text", prompt))
                    )
                )
            )
            .put(
                "generationConfig",
                JSONObject()
                    .put("temperature", 0)
                    .put("responseMimeType", "application/json")
            )
    }

    private fun parseResponse(raw: String): RiskAssessment {
        val text = JSONObject(raw)
            .getJSONArray("candidates")
            .getJSONObject(0)
            .getJSONObject("content")
            .getJSONArray("parts")
            .getJSONObject(0)
            .getString("text")

        val verdictJson = JSONObject(text.trim().removePrefix("```json").removeSuffix("```").trim())
        val score = verdictJson.optInt("score", 50).coerceIn(0, 100)
        val signalsArray = verdictJson.optJSONArray("signals") ?: JSONArray()

        return RiskAssessment(
            score = score,
            verdict = runCatching {
                RiskVerdict.valueOf(verdictJson.getString("verdict").uppercase())
            }.getOrElse { verdictFor(score) },
            rationale = verdictJson.optString("rationale", "Gemini assessment without rationale"),
            signals = (0 until signalsArray.length()).map { signalsArray.getString(it) },
            fromModel = true,
        )
    }

    /** Deterministic fallback: same thresholds as the prompt, without any network call. */
    internal fun heuristicAssessment(context: AuthContext, reason: String): RiskAssessment {
        var score = 5
        val signals = mutableListOf<String>()

        if (!context.tagMatchesEnrollment) {
            score += 70
            signals += "NFC tag differs from the enrolled one"
        }
        if (context.challengeAgeSeconds > 120) {
            score += 25
            signals += "Expired QR challenge (${context.challengeAgeSeconds}s)"
        }
        if (context.failedBiometricAttempts >= 3) {
            score += 20
            signals += "${context.failedBiometricAttempts} recent biometric failures"
        }
        if (context.previousAuthenticationsLastHour > 10) {
            score += 15
            signals += "Abnormal authentication frequency"
        }
        if (!context.biometricStrongAvailable) {
            score += 30
            signals += "Strong biometrics unavailable on this device"
        }
        if (context.secondsSinceEnrollment < 60) {
            score += 10
            signals += "Very recent enrollment"
        }

        score = score.coerceIn(0, 100)
        return RiskAssessment(
            score = score,
            verdict = verdictFor(score),
            rationale = "Local rule-based assessment ($reason)",
            signals = signals,
            fromModel = false,
        )
    }

    private fun verdictFor(score: Int): RiskVerdict = when {
        score > 70 -> RiskVerdict.DENY
        score >= 35 -> RiskVerdict.CHALLENGE
        else -> RiskVerdict.ALLOW
    }

    private companion object {
        val JSON = "application/json; charset=utf-8".toMediaType()
        val defaultClient = OkHttpClient.Builder()
            .callTimeout(20, TimeUnit.SECONDS)
            .build()
    }
}
