package com.otus.myapplication.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.MasterKey
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

private const val STORE_PROVIDER = "AndroidKeyStore"

private const val RSA_ALGORITHM = "RSA"
private const val RSA_KEY_ALIAS = "RSA_DEMO"

private const val AES_ALGORITHM = "AES"
private const val AES_KEY_ALIAS = "AES_DEMO"

class Keys(
    private val applicationContext: Context
) {

    private val keyStore by lazy {
        KeyStore.getInstance(STORE_PROVIDER).apply {
            load(null)
        }
    }

    fun createAesSecretKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM, STORE_PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            AES_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setRandomizedEncryptionRequired(false)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    fun createRsaSecretKey(): KeyPair {
        val spec = KeyGenParameterSpec.Builder(
            RSA_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .build()
        val kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM, STORE_PROVIDER)
        kpg.initialize(spec)
        return kpg.generateKeyPair()
    }

    fun getAesKey(): SecretKey {
        return keyStore.getKey(AES_KEY_ALIAS, null) as SecretKey
    }

    fun getRsaKey(): KeyPair {
        val privateKey = keyStore.getKey(RSA_KEY_ALIAS, null) as PrivateKey
        val publicKey = keyStore.getCertificate(RSA_KEY_ALIAS).publicKey
        return KeyPair(publicKey, privateKey)
    }

    fun getMasterKey(keyScheme: MasterKey.KeyScheme): MasterKey {
        return createOrGetMasterKey(keyScheme)
    }

    private fun createOrGetMasterKey(keyScheme: MasterKey.KeyScheme): MasterKey {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val spec = KeyGenParameterSpec.Builder(
                MasterKey.DEFAULT_MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()

            MasterKey.Builder(applicationContext)
                .setKeyGenParameterSpec(spec)
                .build()

        } else {
            MasterKey.Builder(applicationContext)
                .setKeyScheme(keyScheme)
                .build()
        }
    }
}