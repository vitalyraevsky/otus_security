package com.otus.myapplication

import android.os.Bundle
import android.view.View.GONE
import android.view.View.VISIBLE
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
import androidx.biometric.auth.AuthPromptHost
import androidx.biometric.auth.Class3BiometricAuthPrompt
import androidx.biometric.auth.authenticate
import androidx.lifecycle.lifecycleScope
import com.otus.myapplication.crypto.Security
import com.otus.myapplication.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val diContainer = DiContainer(applicationContext)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        java.security.Security.getProviders()
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                TokenGenerator(diContainer, { token ->
                    binding.tokenText.text = buildString {
                        append("Token: ")
                        append(token.decodeToString())
                    }
                }).generate()
            }
        }

        binding.loginButton.setOnClickListener {
            val email = binding.emailEdit.text.toString()
            val password = binding.passwordEdit.text.toString()
            val token = binding.tokenEdit.text.toString()
            val encrypted = Security().encryptAes(token, diContainer.keys.getAesSecretKey())
            val encryptedToken = diContainer.preferences.getEncryptAuthToken();
            if (email == "otus@test.com" && password == "otus" && encrypted == encryptedToken) {
                Toast.makeText(this, "Login success! Token saved", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Invalid credentials", Toast.LENGTH_SHORT).show()
            }
        }


        binding.biometrySwitch.isChecked = diContainer.preferences.isBiometryEnabled()
        binding.biometrySwitch.setOnCheckedChangeListener { _, isChecked ->
            diContainer.preferences.setBiometryEnabled(isChecked)
            Toast.makeText(
                this,
                "Biometry login is ${if (isChecked) "enabled" else "disabled"}",
                Toast.LENGTH_SHORT
            ).show()
            binding.biometryButton.visibility = if (isChecked) VISIBLE else GONE
        }

        binding.biometryButton.setOnClickListener {
            auth(diContainer)
        }

        if (diContainer.preferences.isBiometryEnabled()) {
            val canAuth = BiometricManager.from(this)
                .canAuthenticate(BIOMETRIC_STRONG or BIOMETRIC_WEAK) == BIOMETRIC_SUCCESS
            if (canAuth) {
                auth(diContainer)
            }
        }
    }

    fun auth(diContainer: DiContainer): Unit {
        val authPrompt =
            Class3BiometricAuthPrompt.Builder("Biometric login", "Cancel").apply {
                setSubtitle("Authenticate to access token")
                setDescription("Biometric login required")
                setConfirmationRequired(true)
            }.build()
        lifecycleScope.launch {
            try {
                authPrompt.authenticate(
                    AuthPromptHost(this@MainActivity), null
                )

                val token =
                    diContainer.preferences.getAuthToken(diContainer.keys.getAesSecretKey())
                if (!token.isNullOrEmpty()) {
                    binding.tokenText.text = "Token: $token (decrypted)"
                }
            } catch (e: Exception) {
                Toast.makeText(
                    this@MainActivity,
                    "Biometry failed: ${e.message}",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }
}
