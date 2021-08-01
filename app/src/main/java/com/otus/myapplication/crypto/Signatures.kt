package com.otus.myapplication.crypto

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

private const val ALGORITHM = "SHA256withECDSA"

class Signatures {

    fun createSignature(message: ByteArray, key: PrivateKey): ByteArray {
        val signatureInstance = Signature.getInstance(ALGORITHM).apply {
            initSign(key)
            update(message)
        }
        return signatureInstance.sign()
    }

    fun verify(message: ByteArray, signature: ByteArray, key: PublicKey): Boolean {
        val signatureInstance = Signature.getInstance(ALGORITHM).apply {
            initVerify(key)
            update(message)
        }
        return signatureInstance.verify(signature)
    }
}