package com.trustlink.demo.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.trustlink.demo.R
import com.trustlink.demo.Step
import com.trustlink.demo.UiState
import com.trustlink.demo.model.RiskAssessment
import com.trustlink.demo.model.RiskVerdict

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrustLinkScreen(
    state: UiState,
    nfcAvailable: Boolean,
    onEnroll: () -> Unit,
    onAuthenticate: () -> Unit,
    onCancel: () -> Unit,
    onReset: () -> Unit,
) {
    Scaffold(topBar = { TopAppBar(title = { Text(stringResource(R.string.app_title)) }) }) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (!nfcAvailable) {
                InfoCard(
                    title = stringResource(R.string.nfc_unavailable_title),
                    body = stringResource(R.string.nfc_unavailable_body),
                    container = MaterialTheme.colorScheme.errorContainer,
                )
            }

            StatusCard(state)

            state.enrollment?.let { enrollment ->
                InfoCard(
                    title = stringResource(R.string.enrollment_title),
                    body = stringResource(
                        R.string.enrollment_body,
                        enrollment.tagFingerprint.take(16),
                        enrollment.tagTechnologies.joinToString(),
                    ),
                )
            }

            state.assessment?.let { RiskCard(it) }

            state.assertion?.let { assertion ->
                InfoCard(
                    title = stringResource(R.string.assertion_title),
                    body = stringResource(
                        R.string.assertion_body,
                        assertion.sessionId,
                        assertion.payload,
                        assertion.signatureBase64.take(88),
                    ),
                    monospace = true,
                )
            }

            state.error?.let {
                InfoCard(
                    title = stringResource(R.string.error_title),
                    body = it,
                    container = MaterialTheme.colorScheme.errorContainer,
                )
            }

            Spacer(Modifier.height(4.dp))

            when {
                state.step in setOf(
                    Step.WAITING_TAG_ENROLLMENT,
                    Step.WAITING_QR,
                    Step.WAITING_TAG_AUTH,
                ) -> OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.action_cancel))
                }

                state.enrollment == null -> Button(
                    onClick = onEnroll,
                    enabled = nfcAvailable,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.action_enroll)) }

                else -> {
                    Button(
                        onClick = onAuthenticate,
                        enabled = nfcAvailable && !state.busy,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(stringResource(R.string.action_authenticate)) }
                    OutlinedButton(onClick = onReset, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.action_reset))
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusCard(state: UiState) {
    val stepLabel = stringResource(
        when (state.step) {
            Step.IDLE -> R.string.step_idle
            Step.WAITING_TAG_ENROLLMENT -> R.string.step_enrollment_tag
            Step.WAITING_QR -> R.string.step_scan_qr
            Step.WAITING_TAG_AUTH -> R.string.step_auth_tag
            Step.WAITING_BIOMETRIC -> R.string.step_biometric
            Step.ANALYZING_RISK -> R.string.step_risk
            Step.DONE -> R.string.step_done
        }
    )

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(stepLabel, style = MaterialTheme.typography.titleMedium)
            state.message?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            Text(
                stringResource(
                    if (state.geminiConfigured) R.string.risk_engine_gemini
                    else R.string.risk_engine_local
                ),
                style = MaterialTheme.typography.labelMedium,
            )
            if (state.step in setOf(Step.ANALYZING_RISK, Step.WAITING_QR) || state.busy) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(modifier = Modifier.height(18.dp))
                }
            }
        }
    }
}

@Composable
private fun RiskCard(assessment: RiskAssessment) {
    val container = when (assessment.verdict) {
        RiskVerdict.ALLOW -> Color(0xFFD7F2D8)
        RiskVerdict.CHALLENGE -> Color(0xFFFFF0C7)
        RiskVerdict.DENY -> MaterialTheme.colorScheme.errorContainer
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = container),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                stringResource(R.string.risk_header, assessment.score, assessment.verdict.name),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            LinearProgressIndicator(
                progress = { assessment.score / 100f },
                modifier = Modifier.fillMaxWidth(),
            )
            Text(assessment.rationale, style = MaterialTheme.typography.bodyMedium)
            assessment.signals.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            Text(
                stringResource(
                    if (assessment.fromModel) R.string.risk_from_model
                    else R.string.risk_from_rules
                ),
                style = MaterialTheme.typography.labelSmall,
            )
        }
    }
}

@Composable
private fun InfoCard(
    title: String,
    body: String,
    container: Color = MaterialTheme.colorScheme.surfaceVariant,
    monospace: Boolean = false,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = container,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(
                body,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
            )
        }
    }
}
