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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
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
    Scaffold(topBar = { TopAppBar(title = { Text("TrustLink — NFC · QR · Biométrie") }) }) { padding ->
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
                    title = "NFC indisponible",
                    body = "Activez le NFC dans les réglages : la lecture du support est requise pour le facteur de possession.",
                    container = MaterialTheme.colorScheme.errorContainer,
                )
            }

            StatusCard(state)

            state.enrollment?.let { enrollment ->
                InfoCard(
                    title = "Identité enrôlée",
                    body = "Empreinte du support : ${enrollment.tagFingerprint.take(16)}…\n" +
                        "Technologies : ${enrollment.tagTechnologies.joinToString()}\n" +
                        "Clé publique EC P-256 liée à la biométrie, non exportable.",
                )
            }

            state.assessment?.let { RiskCard(it) }

            state.assertion?.let { assertion ->
                InfoCard(
                    title = "Assertion signée",
                    body = "Session : ${assertion.sessionId}\n\nPayload :\n${assertion.payload}\n\n" +
                        "Signature (base64) :\n${assertion.signatureBase64.take(88)}…",
                    monospace = true,
                )
            }

            state.error?.let {
                InfoCard(
                    title = "Erreur",
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
                    Text("Annuler")
                }

                state.enrollment == null -> Button(
                    onClick = onEnroll,
                    enabled = nfcAvailable,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Enrôler mon support NFC") }

                else -> {
                    Button(
                        onClick = onAuthenticate,
                        enabled = nfcAvailable && !state.busy,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("S'authentifier (scanner le QR code)") }
                    OutlinedButton(onClick = onReset, modifier = Modifier.fillMaxWidth()) {
                        Text("Réinitialiser l'enrôlement")
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusCard(state: UiState) {
    val stepLabel = when (state.step) {
        Step.IDLE -> "Prêt"
        Step.WAITING_TAG_ENROLLMENT -> "1/4 — Enrôlement : lecture du support NFC"
        Step.WAITING_QR -> "1/4 — Scan du QR code (challenge)"
        Step.WAITING_TAG_AUTH -> "2/4 — Preuve de possession : approchez le support NFC"
        Step.WAITING_BIOMETRIC -> "3/4 — Signature biométrique"
        Step.ANALYZING_RISK -> "4/4 — Analyse de risque Gemini"
        Step.DONE -> "Terminé"
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(stepLabel, style = MaterialTheme.typography.titleMedium)
            state.message?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            Text(
                if (state.geminiConfigured) "Moteur de risque : Gemini"
                else "Moteur de risque : règles locales (clé Gemini absente)",
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
                "Risque ${assessment.score}/100 · ${assessment.verdict}",
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
                if (assessment.fromModel) "Évaluation produite par Gemini"
                else "Évaluation locale (repli)",
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
