package com.trustlink.demo.nfc

import android.app.Activity
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Build
import java.security.MessageDigest

/** Résultat de la lecture d'un support NFC (carte, badge, tag). */
data class NfcTagInfo(
    val fingerprint: String,
    val technologies: List<String>,
)

/**
 * Lecture NFC en foreground dispatch : l'application capte les tags tant qu'elle est au
 * premier plan, sans passer par le dispatch système.
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

    /** Extrait le tag d'un intent NFC et le réduit à une empreinte non réversible. */
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
         * L'UID brut n'est jamais conservé ni transmis : seule une empreinte SHA-256
         * salée par le domaine applicatif est stockée.
         */
        fun fingerprintOf(uid: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("trustlink/v1".toByteArray(Charsets.UTF_8))
            return digest.digest(uid).joinToString("") { "%02x".format(it) }
        }
    }
}
