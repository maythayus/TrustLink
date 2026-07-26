package com.trustlink.demo.nfc

import android.app.Activity
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Build
import java.security.MessageDigest

/** Result of reading an NFC medium (card, badge, tag). */
data class NfcTagInfo(
    val fingerprint: String,
    val technologies: List<String>,
)

/**
 * NFC reading through foreground dispatch: the app captures tags while it is in the
 * foreground, bypassing the system dispatch.
 */
class NfcController(private val activity: Activity) {

    private val adapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(activity)

    val isSupported: Boolean get() = adapter != null
    val isEnabled: Boolean get() = adapter?.isEnabled == true

    fun enableForegroundDispatch() {
        val adapter = adapter ?: return
        val intent = Intent(activity, activity.javaClass)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            android.app.PendingIntent.FLAG_MUTABLE
        } else {
            0
        }
        val pendingIntent = android.app.PendingIntent.getActivity(activity, 0, intent, flags)
        adapter.enableForegroundDispatch(activity, pendingIntent, null, null)
    }

    fun disableForegroundDispatch() {
        adapter?.disableForegroundDispatch(activity)
    }

    /** Extracts the tag from an NFC intent and reduces it to a non-reversible fingerprint. */
    fun readTag(intent: Intent): NfcTagInfo? {
        val tag: Tag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
        } ?: return null

        return NfcTagInfo(
            fingerprint = fingerprintOf(tag.id),
            technologies = tag.techList.map { it.substringAfterLast('.') },
        )
    }

    companion object {
        /**
         * The raw UID is never kept nor transmitted: only a SHA-256 fingerprint salted with
         * the application domain is stored.
         */
        fun fingerprintOf(uid: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("trustlink/v1".toByteArray(Charsets.UTF_8))
            return digest.digest(uid).joinToString("") { "%02x".format(it) }
        }
    }
}
