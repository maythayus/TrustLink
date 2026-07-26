package com.trustlink.demo.security

import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.trustlink.demo.model.SignedAssertion
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

class BiometricUnavailableException(val code: Int) :
    Exception("Biométrie forte indisponible (code $code)")

class BiometricCancelledException(val code: Int, val reason: CharSequence) :
    Exception(reason.toString())

/**
 * Signe le payload d'authentification avec la clé du Keystore : la signature ne peut être
 * produite que si l'utilisateur valide le BiometricPrompt (CryptoObject lié à la clé).
 */
object BiometricSigner {

    private const val AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_STRONG

    fun isStrongBiometricAvailable(activity: FragmentActivity): Boolean =
        BiometricManager.from(activity).canAuthenticate(AUTHENTICATORS) ==
            BiometricManager.BIOMETRIC_SUCCESS

    suspend fun signWithBiometrics(
        activity: FragmentActivity,
        sessionId: String,
        payload: String,
        title: String = "Confirmer votre identité",
        subtitle: String = "Signature de la demande d'authentification",
    ): SignedAssertion = suspendCancellableCoroutine { continuation ->
        val status = BiometricManager.from(activity).canAuthenticate(AUTHENTICATORS)
        if (status != BiometricManager.BIOMETRIC_SUCCESS) {
            continuation.resumeWithException(BiometricUnavailableException(status))
            return@suspendCancellableCoroutine
        }

        val signature = try {
            KeystoreManager.initSignature()
        } catch (e: Exception) {
            continuation.resumeWithException(e)
            return@suspendCancellableCoroutine
        }

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (continuation.isActive) {
                    continuation.resumeWithException(BiometricCancelledException(errorCode, errString))
                }
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (!continuation.isActive) return
                try {
                    val cryptoSignature = requireNotNull(result.cryptoObject?.signature) {
                        "CryptoObject absent du résultat biométrique"
                    }
                    cryptoSignature.update(payload.toByteArray(Charsets.UTF_8))
                    val signed = cryptoSignature.sign()
                    continuation.resume(
                        SignedAssertion(
                            sessionId = sessionId,
                            payload = payload,
                            signatureBase64 = Base64.encodeToString(signed, Base64.NO_WRAP),
                            publicKeyPem = KeystoreManager.publicKeyPem(),
                        )
                    )
                } catch (e: Exception) {
                    continuation.resumeWithException(e)
                }
            }
        }

        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Annuler")
            .setAllowedAuthenticators(AUTHENTICATORS)
            .setConfirmationRequired(true)
            .build()

        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
        continuation.invokeOnCancellation { prompt.cancelAuthentication() }
    }
}
