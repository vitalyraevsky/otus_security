package com.otus.myapplication.storage

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

private const val sharedPrefsFile: String = "securePref"

class PreferencesUtils(
    private val applicationContext: Context,
    private val mainKey: MasterKey
) {

    private val sharedPreferences by lazy {
        EncryptedSharedPreferences.create(
            applicationContext,
            sharedPrefsFile,
            mainKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun set(key: String, value: String) {
        with(sharedPreferences.edit()) {
            putString(key, value)
            apply()
        }
    }

    fun get(key: String): String {
        return sharedPreferences.getString(key, "").orEmpty()
    }
}