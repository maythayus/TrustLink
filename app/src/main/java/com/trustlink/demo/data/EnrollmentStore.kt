package com.trustlink.demo.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.trustlink.demo.model.Enrollment
import org.json.JSONArray
import org.json.JSONObject

/**
 * Stockage chiffré de l'enrôlement local (empreinte du support NFC + clé publique).
 * Aucune donnée biométrique n'est stockée : elle ne quitte jamais le TEE de l'appareil.
 */
class EnrollmentStore(context: Context) {

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        "trustlink_enrollment",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun load(): Enrollment? {
        val raw = prefs.getString(KEY_ENROLLMENT, null) ?: return null
        val json = JSONObject(raw)
        val technologies = json.optJSONArray("technologies") ?: JSONArray()
        return Enrollment(
            tagFingerprint = json.getString("tagFingerprint"),
            tagTechnologies = (0 until technologies.length()).map { technologies.getString(it) },
            publicKeyPem = json.getString("publicKeyPem"),
            enrolledAtMillis = json.getLong("enrolledAtMillis"),
        )
    }

    fun save(enrollment: Enrollment) {
        val json = JSONObject()
            .put("tagFingerprint", enrollment.tagFingerprint)
            .put("technologies", JSONArray(enrollment.tagTechnologies))
            .put("publicKeyPem", enrollment.publicKeyPem)
            .put("enrolledAtMillis", enrollment.enrolledAtMillis)
        prefs.edit().putString(KEY_ENROLLMENT, json.toString()).apply()
    }

    fun clear() = prefs.edit().remove(KEY_ENROLLMENT).apply()

    fun recordAuthentication(timestampMillis: Long = System.currentTimeMillis()) {
        val history = (authenticationHistory() + timestampMillis).takeLast(50)
        prefs.edit().putString(KEY_HISTORY, history.joinToString(",")).apply()
    }

    fun authenticationsSince(sinceMillis: Long): Int =
        authenticationHistory().count { it >= sinceMillis }

    private fun authenticationHistory(): List<Long> =
        prefs.getString(KEY_HISTORY, "")
            ?.split(',')
            ?.mapNotNull { it.toLongOrNull() }
            ?: emptyList()

    private companion object {
        const val KEY_ENROLLMENT = "enrollment"
        const val KEY_HISTORY = "auth_history"
    }
}
