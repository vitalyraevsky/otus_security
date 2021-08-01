package com.otus.myapplication

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
import androidx.biometric.auth.AuthPromptErrorException
import androidx.biometric.auth.AuthPromptFailureException
import androidx.biometric.auth.AuthPromptHost
import androidx.biometric.auth.Class2BiometricAuthPrompt
import androidx.biometric.auth.Class3BiometricAuthPrompt
import androidx.biometric.auth.authenticate
import androidx.lifecycle.lifecycleScope
import androidx.security.crypto.MasterKey
import com.otus.myapplication.biometrics.BiometricCipher
import com.otus.myapplication.crypto.Keys
import com.otus.myapplication.crypto.Security
import com.otus.myapplication.databinding.ActivityMainBinding
import com.otus.myapplication.storage.PreferencesUtils
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val secure = Security()
        val keys = Keys(applicationContext)
        // Хеширование
        secure.md5("password")

        // Хранилища
        val masterKey = keys.getMasterKey(MasterKey.KeyScheme.AES256_GCM)
        val preferences = PreferencesUtils(applicationContext, masterKey)
        preferences.set("key", "value")

        // Биометрия
        binding.weakBiometryButton.setOnClickListener {
            val success = BiometricManager.from(this)
                .canAuthenticate(BIOMETRIC_WEAK) == BIOMETRIC_SUCCESS
            if (success) {
                val authPrompt = Class2BiometricAuthPrompt.Builder("Weak biometry", "dismiss").apply {
                    setSubtitle("Input your biometry")
                    setDescription("We need your finger")
                    setConfirmationRequired(true)
                }.build()

                lifecycleScope.launch {
                    try {
                        authPrompt.authenticate(AuthPromptHost(this@MainActivity))
                        Log.d("It works", "Hello from biometry")
                    } catch (e: AuthPromptErrorException) {
                        Log.e("AuthPromptError", e.message ?: "no message")
                    } catch (e: AuthPromptFailureException) {
                        Log.e("AuthPromptFailure", e.message ?: "no message")
                    }
                }
            } else {
                Toast.makeText(this, "Biometry not supported", Toast.LENGTH_LONG).show()
            }
        }
        binding.strongBiometryButton.setOnClickListener {
            val success = BiometricManager.from(this)
                .canAuthenticate(BIOMETRIC_STRONG) == BIOMETRIC_SUCCESS
            if (success) {
                val biometricCipher = BiometricCipher(this.applicationContext)
                val encryptor = biometricCipher.getEncryptor()

                val authPrompt = Class3BiometricAuthPrompt.Builder("Strong biometry", "dismiss").apply {
                    setSubtitle("Input your biometry")
                    setDescription("We need your finger")
                    setConfirmationRequired(true)
                }.build()

                lifecycleScope.launch {
                    try {
                        val authResult = authPrompt.authenticate(AuthPromptHost(this@MainActivity), encryptor)
                        val encryptedEntity = authResult.cryptoObject?.cipher?.let { cipher ->
                            biometricCipher.encrypt("Secret data", cipher)
                        }
                        Log.d(MainActivity::class.simpleName, String(encryptedEntity!!.ciphertext))
                    } catch (e: AuthPromptErrorException) {
                        Log.e("AuthPromptError", e.message ?: "no message")
                    } catch (e: AuthPromptFailureException) {
                        Log.e("AuthPromptFailure", e.message ?: "no message")
                    }
                }
            } else {
                Toast.makeText(this, "Biometry not supported", Toast.LENGTH_LONG).show()
            }
        }
    }
}