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
    Exception("Strong biometrics unavailable (code $code)")

class BiometricCancelledException(val code: Int, val reason: CharSequence) :
    Exception(reason.toString())

/**
 * Signs the authentication payload with the Keystore key: the signature can only be produced
 * if the user confirms the BiometricPrompt (CryptoObject bound to the key).
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
        title: String,
        subtitle: String,
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
                        "CryptoObject missing from the biometric result"
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
            .setNegativeButtonText(activity.getString(android.R.string.cancel))
            .setAllowedAuthenticators(AUTHENTICATORS)
            .setConfirmationRequired(true)
            .build()

        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
        continuation.invokeOnCancellation { prompt.cancelAuthentication() }
    }
}
