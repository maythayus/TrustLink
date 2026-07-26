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
 * Analyse de risque de la tentative d'authentification par Gemini.
 *
 * Le modèle ne voit jamais de donnée biométrique ni l'UID du support NFC : uniquement des
 * signaux contextuels dérivés. Il est consultatif — la signature cryptographique reste la
 * seule preuve d'identité, Gemini ne fait qu'ajouter une décision de risque (allow /
 * challenge / deny). En l'absence de clé API, l'analyse locale par règles prend le relais.
 */
class GeminiRiskAnalyzer(
    private val apiKey: String = BuildConfig.GEMINI_API_KEY,
    private val model: String = "gemini-flash-lite-latest",
    private val client: OkHttpClient = defaultClient,
) {

    val isModelConfigured: Boolean get() = apiKey.isNotBlank()

    suspend fun assess(context: AuthContext): RiskAssessment = withContext(Dispatchers.IO) {
        if (!isModelConfigured) return@withContext heuristicAssessment(context, "Clé Gemini absente")
        try {
            callGemini(context)
        } catch (e: Exception) {
            heuristicAssessment(context, "Gemini injoignable : ${e.message}")
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
            Tu es un moteur anti-fraude pour une authentification forte à trois facteurs :
            possession (support NFC enrôlé), appareil (clé privée du Keystore matériel) et
            biométrie (empreinte/visage validant l'usage de la clé).

            Évalue la tentative décrite par les signaux JSON ci-dessous et réponds
            UNIQUEMENT par un objet JSON, sans texte autour, au format :
            {"score":<0-100>,"verdict":"ALLOW|CHALLENGE|DENY","rationale":"<1 phrase en français>","signals":["<signal marquant>", ...]}

            Règles : score = probabilité de fraude. Un tag NFC ne correspondant pas à
            l'enrôlement, un challenge périmé (age > 120s), des échecs biométriques
            répétés ou une fréquence anormale d'authentifications augmentent fortement le
            score. DENY au-dessus de 70, CHALLENGE entre 35 et 70, ALLOW en dessous.

            Signaux : $signals
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
            rationale = verdictJson.optString("rationale", "Analyse Gemini sans justification"),
            signals = (0 until signalsArray.length()).map { signalsArray.getString(it) },
            fromModel = true,
        )
    }

    /** Repli déterministe : mêmes seuils que le prompt, sans appel réseau. */
    internal fun heuristicAssessment(context: AuthContext, reason: String): RiskAssessment {
        var score = 5
        val signals = mutableListOf<String>()

        if (!context.tagMatchesEnrollment) {
            score += 70
            signals += "Support NFC différent de celui enrôlé"
        }
        if (context.challengeAgeSeconds > 120) {
            score += 25
            signals += "Challenge QR périmé (${context.challengeAgeSeconds}s)"
        }
        if (context.failedBiometricAttempts >= 3) {
            score += 20
            signals += "${context.failedBiometricAttempts} échecs biométriques récents"
        }
        if (context.previousAuthenticationsLastHour > 10) {
            score += 15
            signals += "Fréquence d'authentification anormale"
        }
        if (!context.biometricStrongAvailable) {
            score += 30
            signals += "Biométrie forte indisponible sur l'appareil"
        }
        if (context.secondsSinceEnrollment < 60) {
            score += 10
            signals += "Enrôlement très récent"
        }

        score = score.coerceIn(0, 100)
        return RiskAssessment(
            score = score,
            verdict = verdictFor(score),
            rationale = "Analyse locale par règles ($reason)",
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
