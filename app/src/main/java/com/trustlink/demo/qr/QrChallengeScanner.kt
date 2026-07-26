package com.trustlink.demo.qr

import android.content.Context
import com.google.android.gms.tasks.Task
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import com.trustlink.demo.model.QrChallenge
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject

class InvalidChallengeException(message: String) : Exception(message)

/** Scanne le QR code du service distant et en extrait le challenge d'authentification. */
object QrChallengeScanner {

    suspend fun scan(context: Context): QrChallenge {
        val options = GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .enableAutoZoom()
            .build()
        val scanner = GmsBarcodeScanning.getClient(context, options)

        val raw = suspendCancellableCoroutine<String> { continuation ->
            val task: Task<Barcode> = scanner.startScan()
            task.addOnSuccessListener { barcode ->
                val value = barcode.rawValue
                if (value.isNullOrBlank()) {
                    continuation.resumeWithException(InvalidChallengeException("QR code vide"))
                } else {
                    continuation.resume(value)
                }
            }
            task.addOnFailureListener { continuation.resumeWithException(it) }
            task.addOnCanceledListener { continuation.cancel() }
        }

        return parse(raw)
    }

    fun parse(raw: String): QrChallenge {
        val json = try {
            JSONObject(raw)
        } catch (e: Exception) {
            throw InvalidChallengeException("QR code non reconnu : format JSON attendu")
        }

        val version = json.optInt("v", 0)
        if (version != 1) throw InvalidChallengeException("Version de challenge non supportée : $version")

        val sessionId = json.optString("sid")
        val nonce = json.optString("nonce")
        if (sessionId.isBlank() || nonce.isBlank()) {
            throw InvalidChallengeException("Challenge incomplet : 'sid' et 'nonce' sont requis")
        }

        return QrChallenge(
            version = version,
            sessionId = sessionId,
            nonce = nonce,
            origin = json.optString("origin", "inconnu"),
            expiresAtSeconds = json.optLong("exp", 0L),
        )
    }
}
