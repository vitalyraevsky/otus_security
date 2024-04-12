package com.otus.myapplication.storage

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private const val dataStoreFile: String = "securePref"

class DataStoreUtils(
    private val context: Context
) {

    val ID = intPreferencesKey("ID")

    private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = dataStoreFile)

    suspend fun saveMyId(id: Int) {
        context.dataStore.edit { preferences ->
            preferences[ID] = id
        }
    }

    fun getMyId(): Flow<Int> {
        return context.dataStore.data.map { preferences ->
            preferences[ID] ?: -1
        }
    }
}