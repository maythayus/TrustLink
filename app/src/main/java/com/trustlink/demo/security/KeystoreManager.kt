package com.trustlink.demo.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import android.util.Base64

/**
 * Owns the EC P-256 key pair stored in the hardware Keystore (StrongBox when available).
 * The private key can only be used right after a strong biometric authentication, and is
 * invalidated automatically when the user enrolls a new biometric.
 */
object KeystoreManager {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "trustlink_identity_key"
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    fun hasKey(): Boolean = keyStore.containsAlias(KEY_ALIAS)

    fun deleteKey() {
        if (hasKey()) keyStore.deleteEntry(KEY_ALIAS)
    }

    /**
     * Creates the identity key. When [useStrongBox] is not supported by the hardware, the
     * generation is retried without it.
     */
    fun createKey(useStrongBox: Boolean = true): PublicKey {
        deleteKey()
        return try {
            generate(useStrongBox)
        } catch (e: Exception) {
            if (useStrongBox) generate(false) else throw e
        }
    }

    private fun generate(useStrongBox: Boolean): PublicKey {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        generator.initialize(builder.build())
        return generator.generateKeyPair().public
    }

    private fun privateKey(): PrivateKey =
        keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("No identity key: enrollment required")

    fun publicKey(): PublicKey =
        keyStore.getCertificate(KEY_ALIAS)?.publicKey
            ?: throw IllegalStateException("No identity key: enrollment required")

    /** Initialized [Signature] object, to be handed to the BiometricPrompt CryptoObject. */
    fun initSignature(): Signature =
        Signature.getInstance(SIGNATURE_ALGORITHM).apply { initSign(privateKey()) }

    fun publicKeyPem(): String {
        val encoded = Base64.encodeToString(publicKey().encoded, Base64.NO_WRAP)
        return "-----BEGIN PUBLIC KEY-----\n" +
            encoded.chunked(64).joinToString("\n") +
            "\n-----END PUBLIC KEY-----"
    }
}
