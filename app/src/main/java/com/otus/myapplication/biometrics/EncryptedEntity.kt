package com.otus.myapplication.biometrics

data class EncryptedEntity(
    val ciphertext: ByteArray,
    val iv: ByteArray
)