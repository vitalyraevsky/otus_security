package com.otus.myapplication

import android.content.Context
import androidx.security.crypto.MasterKey
import com.otus.myapplication.crypto.Keys
import com.otus.myapplication.storage.PreferencesUtils

class DiContainer(val context: Context) {
    val keys = Keys(context)
    val masterKey = keys.getMasterKey(MasterKey.KeyScheme.AES256_GCM)
    val preferences = PreferencesUtils(context, masterKey)

}