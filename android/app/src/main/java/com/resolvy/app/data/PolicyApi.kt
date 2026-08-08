package com.resolvy.app.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection

data class PolicyDocument(
    val revision: Long,
    val blockedDomains: List<String>,
)

class PolicyApiException(message: String) : Exception(message)

interface PolicyApi {
    suspend fun get(config: ServerConfig): PolicyDocument
    suspend fun replace(
        config: ServerConfig,
        revision: Long,
        blockedDomains: List<String>,
    ): PolicyDocument
}

class HttpPolicyApi : PolicyApi {
    override suspend fun get(config: ServerConfig): PolicyDocument = withContext(Dispatchers.IO) {
        execute(config, HttpURLConnection.HTTP_OK, "GET", null)
    }

    override suspend fun replace(
        config: ServerConfig,
        revision: Long,
        blockedDomains: List<String>,
    ): PolicyDocument = withContext(Dispatchers.IO) {
        val body = JSONObject()
            .put("revision", revision)
            .put("blocked_domains", JSONArray(blockedDomains))
            .toString()
        execute(config, HttpURLConnection.HTTP_OK, "PUT", body)
    }

    private fun execute(
        config: ServerConfig,
        expectedStatus: Int,
        method: String,
        body: String?,
    ): PolicyDocument {
        val connection = URL(config.baseUrl + POLICY_PATH).openConnection() as? HttpsURLConnection
            ?: throw PolicyApiException("The policy server must use HTTPS")

        try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Authorization", "Bearer ${config.token}")
            if (body != null) {
                val bytes = body.toByteArray(Charsets.UTF_8)
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                connection.setFixedLengthStreamingMode(bytes.size)
                connection.outputStream.use { it.write(bytes) }
            }

            val status = connection.responseCode
            val responseBody = (if (status in 200..299) connection.inputStream else connection.errorStream)
                ?.bufferedReader()
                ?.use { it.readText() }
                .orEmpty()
            if (status != expectedStatus) {
                throw PolicyApiException(errorMessage(status, responseBody))
            }
            return decodePolicy(responseBody)
        } catch (error: PolicyApiException) {
            throw error
        } catch (error: Exception) {
            throw PolicyApiException(error.message ?: "Could not connect to the policy server")
        } finally {
            connection.disconnect()
        }
    }

    private fun decodePolicy(body: String): PolicyDocument {
        try {
            val json = JSONObject(body)
            val domains = json.getJSONArray("blocked_domains")
            return PolicyDocument(
                revision = json.getLong("revision"),
                blockedDomains = List(domains.length()) { index -> domains.getString(index) },
            )
        } catch (_: Exception) {
            throw PolicyApiException("The server returned an invalid policy response")
        }
    }

    private fun errorMessage(status: Int, body: String): String {
        if (status == HttpURLConnection.HTTP_UNAUTHORIZED) return "The API token was rejected"
        if (status == HttpURLConnection.HTTP_CONFLICT) {
            return "Policies changed on another device. Refresh and try again"
        }
        val serverMessage = runCatching { JSONObject(body).getString("error") }.getOrNull()
        return serverMessage ?: "The policy server returned HTTP $status"
    }

    companion object {
        private const val POLICY_PATH = "/api/v1/policies/domains"
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 10_000
    }
}
