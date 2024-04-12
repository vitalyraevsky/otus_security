package com.otus.myapplication.storage

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.charset.StandardCharsets

private const val DIRECTORY = "/"

class FileUtils(
    private val applicationContext: Context,
    private val mainKey: MasterKey
) {

    fun readFile(fileToRead: String): String {
        val encryptedFile = EncryptedFile.Builder(
            applicationContext,
            File(DIRECTORY, fileToRead),
            mainKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
        val inputStream = encryptedFile.openFileInput()
        val byteArrayOutputStream = ByteArrayOutputStream()
        var nextByte: Int = inputStream.read()
        while (nextByte != -1) {
            byteArrayOutputStream.write(nextByte)
            nextByte = inputStream.read()
        }
        return byteArrayOutputStream.toByteArray().toString()
    }

    fun writeFile(fileToWrite: String, fileContent: String) {
        val encryptedFile = EncryptedFile.Builder(
            applicationContext,
            File(DIRECTORY, fileToWrite),
            mainKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
        encryptedFile.openFileOutput().apply {
            write(fileContent.toByteArray(StandardCharsets.UTF_8))
            flush()
            close()
        }
    }
}