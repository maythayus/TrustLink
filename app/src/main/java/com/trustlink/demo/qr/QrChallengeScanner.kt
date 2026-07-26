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

/** Scans the remote service's QR code and extracts the authentication challenge from it. */
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
                    continuation.resumeWithException(InvalidChallengeException("Empty QR code"))
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
            throw InvalidChallengeException("Unrecognized QR code: JSON payload expected")
        }

        val version = json.optInt("v", 0)
        if (version != 1) throw InvalidChallengeException("Unsupported challenge version: $version")

        val sessionId = json.optString("sid")
        val nonce = json.optString("nonce")
        if (sessionId.isBlank() || nonce.isBlank()) {
            throw InvalidChallengeException("Incomplete challenge: 'sid' and 'nonce' are required")
        }

        return QrChallenge(
            version = version,
            sessionId = sessionId,
            nonce = nonce,
            origin = json.optString("origin", "unknown"),
            expiresAtSeconds = json.optLong("exp", 0L),
        )
    }
}
