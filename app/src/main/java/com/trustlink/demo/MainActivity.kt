package com.trustlink.demo

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import com.trustlink.demo.nfc.NfcController
import com.trustlink.demo.ui.TrustLinkScreen
import com.trustlink.demo.ui.theme.TrustLinkTheme

class MainActivity : FragmentActivity() {

    private val viewModel: AuthViewModel by viewModels()
    private lateinit var nfcController: NfcController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        nfcController = NfcController(this)

        setContent {
            TrustLinkTheme {
                val state by viewModel.state.collectAsState()
                TrustLinkScreen(
                    state = state,
                    nfcAvailable = nfcController.isSupported && nfcController.isEnabled,
                    onEnroll = viewModel::startEnrollment,
                    onAuthenticate = { viewModel.startAuthentication(this) },
                    onCancel = viewModel::cancel,
                    onReset = viewModel::resetEnrollment,
                )
            }
        }

        intent?.let(::dispatchNfc)
    }

    override fun onResume() {
        super.onResume()
        nfcController.enableForegroundDispatch()
    }

    override fun onPause() {
        nfcController.disableForegroundDispatch()
        super.onPause()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        dispatchNfc(intent)
    }

    private fun dispatchNfc(intent: Intent) {
        nfcController.readTag(intent)?.let { viewModel.onNfcTag(this, it) }
    }
}
