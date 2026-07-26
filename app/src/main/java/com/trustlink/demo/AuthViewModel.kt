package com.trustlink.demo

import android.app.Application
import android.os.Build
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.trustlink.demo.ai.GeminiRiskAnalyzer
import com.trustlink.demo.data.EnrollmentStore
import com.trustlink.demo.model.AuthContext
import com.trustlink.demo.model.Enrollment
import com.trustlink.demo.model.QrChallenge
import com.trustlink.demo.model.RiskAssessment
import com.trustlink.demo.model.RiskVerdict
import com.trustlink.demo.model.SignedAssertion
import com.trustlink.demo.nfc.NfcTagInfo
import com.trustlink.demo.qr.QrChallengeScanner
import com.trustlink.demo.security.BiometricSigner
import com.trustlink.demo.security.KeystoreManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

enum class Step {
    IDLE,
    WAITING_TAG_ENROLLMENT,
    WAITING_QR,
    WAITING_TAG_AUTH,
    WAITING_BIOMETRIC,
    ANALYZING_RISK,
    DONE,
}

data class UiState(
    val step: Step = Step.IDLE,
    val enrollment: Enrollment? = null,
    val challenge: QrChallenge? = null,
    val assertion: SignedAssertion? = null,
    val assessment: RiskAssessment? = null,
    val message: String? = null,
    val error: String? = null,
    val geminiConfigured: Boolean = false,
    val busy: Boolean = false,
)

/**
 * Orchestrates the loop: QR (challenge) → NFC (possession) → biometrics (Keystore signature)
 * → Gemini risk analysis → verdict.
 */
class AuthViewModel(application: Application) : AndroidViewModel(application) {

    private val store = EnrollmentStore(application)
    private val analyzer = GeminiRiskAnalyzer()

    private val _state = MutableStateFlow(
        UiState(
            enrollment = store.load(),
            geminiConfigured = analyzer.isModelConfigured,
        )
    )
    val state: StateFlow<UiState> = _state.asStateFlow()

    private var challengeScannedAtMillis: Long = 0
    private var failedBiometricAttempts: Int = 0

    fun startEnrollment() {
        _state.update {
            it.copy(
                step = Step.WAITING_TAG_ENROLLMENT,
                error = null,
                assertion = null,
                assessment = null,
                message = string(R.string.msg_tap_tag_to_enroll),
            )
        }
    }

    fun resetEnrollment() {
        store.clear()
        KeystoreManager.deleteKey()
        _state.value = UiState(geminiConfigured = analyzer.isModelConfigured)
    }

    fun cancel() {
        _state.update { it.copy(step = Step.IDLE, message = null, busy = false) }
    }

    fun startAuthentication(activity: FragmentActivity) {
        val enrollment = _state.value.enrollment
        if (enrollment == null) {
            _state.update { it.copy(error = string(R.string.err_no_enrollment)) }
            return
        }
        viewModelScope.launch {
            _state.update {
                it.copy(
                    step = Step.WAITING_QR,
                    busy = true,
                    error = null,
                    assertion = null,
                    assessment = null,
                    message = string(R.string.msg_scan_qr),
                )
            }
            try {
                val challenge = QrChallengeScanner.scan(activity)
                challengeScannedAtMillis = System.currentTimeMillis()
                _state.update {
                    it.copy(
                        step = Step.WAITING_TAG_AUTH,
                        challenge = challenge,
                        busy = false,
                        message = string(R.string.msg_challenge_received, challenge.origin),
                    )
                }
            } catch (e: Exception) {
                _state.update {
                    it.copy(
                        step = Step.IDLE,
                        busy = false,
                        error = e.message ?: string(R.string.err_scan_cancelled),
                    )
                }
            }
        }
    }

    /** Callback of the NFC foreground dispatch. */
    fun onNfcTag(activity: FragmentActivity, tag: NfcTagInfo) {
        when (_state.value.step) {
            Step.WAITING_TAG_ENROLLMENT -> completeEnrollment(tag)
            Step.WAITING_TAG_AUTH -> continueAuthentication(activity, tag)
            else -> Unit
        }
    }

    private fun completeEnrollment(tag: NfcTagInfo) {
        try {
            KeystoreManager.createKey()
            val enrollment = Enrollment(
                tagFingerprint = tag.fingerprint,
                tagTechnologies = tag.technologies,
                publicKeyPem = KeystoreManager.publicKeyPem(),
                enrolledAtMillis = System.currentTimeMillis(),
            )
            store.save(enrollment)
            _state.update {
                it.copy(
                    step = Step.IDLE,
                    enrollment = enrollment,
                    message = string(R.string.msg_enrolled),
                    error = null,
                )
            }
        } catch (e: Exception) {
            _state.update {
                it.copy(
                    step = Step.IDLE,
                    error = string(R.string.err_enrollment_failed, e.message.orEmpty()),
                )
            }
        }
    }

    private fun continueAuthentication(activity: FragmentActivity, tag: NfcTagInfo) {
        val enrollment = _state.value.enrollment ?: return
        val challenge = _state.value.challenge ?: return
        val tagMatches = tag.fingerprint == enrollment.tagFingerprint

        viewModelScope.launch {
            var assertion: SignedAssertion? = null
            if (tagMatches && !challenge.isExpired) {
                _state.update {
                    it.copy(
                        step = Step.WAITING_BIOMETRIC,
                        message = string(R.string.msg_confirm_biometric),
                    )
                }
                assertion = try {
                    BiometricSigner.signWithBiometrics(
                        activity = activity,
                        sessionId = challenge.sessionId,
                        payload = payloadFor(challenge, enrollment),
                        title = string(R.string.biometric_title),
                        subtitle = string(R.string.biometric_subtitle),
                    )
                } catch (e: Exception) {
                    failedBiometricAttempts++
                    _state.update {
                        it.copy(
                            error = string(R.string.err_biometric_refused, e.message.orEmpty())
                        )
                    }
                    null
                }
            }

            _state.update {
                it.copy(step = Step.ANALYZING_RISK, message = string(R.string.msg_analyzing_risk))
            }

            val assessment = analyzer.assess(
                AuthContext(
                    origin = challenge.origin,
                    sessionId = challenge.sessionId,
                    challengeAgeSeconds = (System.currentTimeMillis() - challengeScannedAtMillis) / 1000,
                    secondsSinceEnrollment = (System.currentTimeMillis() - enrollment.enrolledAtMillis) / 1000,
                    tagFingerprintPrefix = tag.fingerprint.take(8),
                    tagMatchesEnrollment = tagMatches,
                    biometricStrongAvailable = BiometricSigner.isStrongBiometricAvailable(activity),
                    deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}",
                    androidSdk = Build.VERSION.SDK_INT,
                    failedBiometricAttempts = failedBiometricAttempts,
                    previousAuthenticationsLastHour = store.authenticationsSince(
                        System.currentTimeMillis() - 3_600_000
                    ),
                )
            )

            val granted = assertion != null && assessment.verdict != RiskVerdict.DENY
            if (granted) {
                store.recordAuthentication()
                failedBiometricAttempts = 0
            }

            _state.update {
                it.copy(
                    step = Step.DONE,
                    assertion = assertion,
                    assessment = assessment,
                    message = string(
                        when {
                            granted && assessment.verdict == RiskVerdict.ALLOW ->
                                R.string.msg_access_granted
                            granted -> R.string.msg_access_granted_step_up
                            !tagMatches -> R.string.msg_tag_unknown
                            challenge.isExpired -> R.string.msg_challenge_expired
                            else -> R.string.msg_access_denied
                        }
                    ),
                )
            }
        }
    }

    private fun string(resId: Int, vararg args: Any): String =
        getApplication<Application>().getString(resId, *args)

    /** Data actually signed, sent to the server alongside the signature. */
    private fun payloadFor(challenge: QrChallenge, enrollment: Enrollment): String =
        listOf(
            "trustlink/v1",
            challenge.sessionId,
            challenge.nonce,
            challenge.origin,
            enrollment.tagFingerprint,
            (System.currentTimeMillis() / 1000).toString(),
        ).joinToString("|")
}
