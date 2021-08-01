package com.otus.myapplication.crypto

import android.util.Base64
import java.math.BigInteger
import java.security.Key
import java.security.MessageDigest
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec

private const val RSA_RANSFORMATION = "RSA/ECB/PKCS1Padding"
private const val AES_TRANSFORMATION = "AES/ECB/PKCS7Padding"

class Security {

    private val FIXED_IV = byteArrayOf(55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44)

    /* Хеширование
    https://developer.android.com/reference/kotlin/java/security/MessageDigest
    */
    fun md5(plaintext: CharSequence): String {
        return createHash(plaintext.toString(), "MD5")
    }

    fun sha256(plaintext: CharSequence): String {
        return createHash(plaintext.toString(), "SHA-256")
    }

    private fun createHash(plaintext: String, type: String): String {
        val md = MessageDigest.getInstance(type)
        val bigInt = BigInteger(1, md.digest(plaintext.toByteArray(Charsets.UTF_8)))
        return String.format("%032x", bigInt)
    }

    /* Хеширование одноключевое
    https://developer.android.com/reference/javax/crypto/Mac
    */

    fun hmacMD5(plaintext: CharSequence, key: Key): String {
        return createHash(plaintext.toString(), "HmacMD5", key)
    }

    fun hmacSHA256(plaintext: CharSequence, key: Key): String {
        return createHash(plaintext.toString(), "HmacSHA256", key)
    }

    private fun createHash(plaintext: String, algorithm: String, key: Key): String {
        val mac = Mac.getInstance(algorithm)
        mac.init(key)
        val dataByteArray = mac.doFinal(plaintext.toByteArray())
        val hash = BigInteger(1, dataByteArray)
        return hash.toString()
    }

    fun encryptAes(plainText: String, key: Key): String {
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key, getInitializationVector())
        val encodedBytes = cipher.doFinal(plainText.toByteArray())
        return Base64.encodeToString(encodedBytes, Base64.NO_WRAP)
    }

    private fun getInitializationVector(): AlgorithmParameterSpec {
        return GCMParameterSpec(128, FIXED_IV)
    }

    fun decryptAes(encrypted: String, key: Key): String {
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, getInitializationVector())
        val decodedBytes = Base64.decode(encrypted, Base64.NO_WRAP)
        val decoded = cipher.doFinal(decodedBytes)
        return String(decoded, Charsets.UTF_8)
    }
}