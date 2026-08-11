package com.deepdive.app.data

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

interface ServerSettings {
    fun load(): ServerConfig?
    suspend fun save(config: ServerConfig)
}

class SettingsRepository(context: Context) : ServerSettings {
    private val preferences = context.getSharedPreferences("deep_dive_server", Context.MODE_PRIVATE)

    override fun load(): ServerConfig? {
        val baseUrl = preferences.getString(KEY_BASE_URL, null) ?: return null
        val token = preferences.getString(KEY_TOKEN, null) ?: return null
        if (baseUrl.isBlank() || token.isBlank()) return null
        return ServerConfig(baseUrl, token)
    }

    override suspend fun save(config: ServerConfig) = withContext(Dispatchers.IO) {
        check(
            preferences.edit()
                .putString(KEY_BASE_URL, config.baseUrl)
                .putString(KEY_TOKEN, config.token)
                .commit(),
        ) { "Could not save server settings" }
    }

    companion object {
        private const val KEY_BASE_URL = "base_url"
        private const val KEY_TOKEN = "token"
    }
}
