package com.otus.myapplication

import android.os.Build
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import java.time.Instant
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration
import kotlin.time.toKotlinDuration

class TokenGenerator(
    private val diContainer: DiContainer,
    private val operation: (token: ByteArray) -> Unit
) {

    private val tickerPeriod = 1.minutes
    val keys = diContainer.keys

    // Генерация AES ключа
    val key = keys.getAesSecretKey()
    val preferences = diContainer.preferences
    private lateinit var nextRun: Instant
    suspend fun generate() {
        while (currentCoroutineContext().isActive) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                nextRun = Instant.now().plus(tickerPeriod.toJavaDuration())
            }
            val token = (100000..999999).random().toString()
            preferences.setAuthToken(token.toByteArray(), key)
            operation(token.toByteArray())
            delay(java.time.Duration.between(Instant.now(), nextRun).toKotlinDuration())
        }
    }
}
