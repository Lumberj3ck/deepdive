package com.deepdive.app.data

import java.net.URI

data class ServerConfig(
    val baseUrl: String,
    val token: String,
)

fun normalizeServerUrl(value: String): Result<String> = runCatching {
    val input = value.trim()
    require(input.isNotEmpty()) { "Enter your server domain" }

    val withScheme = if ("://" in input) input else "https://$input"
    val uri = URI(withScheme)
    require(uri.scheme.equals("https", ignoreCase = true)) { "The server must use HTTPS" }
    require(uri.host != null) { "Enter a valid server domain" }
    require(uri.userInfo == null && uri.query == null && uri.fragment == null) {
        "Enter only the server domain and optional port"
    }
    require(uri.path.isNullOrEmpty() || uri.path == "/") {
        "Enter only the server domain and optional port"
    }
    require(uri.port == -1 || uri.port in 1..65535) { "Enter a valid server port" }

    URI("https", null, uri.host.lowercase(), uri.port, null, null, null).toString()
}

fun normalizeDomain(value: String): Result<String> = runCatching {
    val domain = value.trim().trimEnd('.').lowercase()
    require(domain.isNotEmpty()) { "Enter a domain to block" }
    require(domain.length <= 253) { "Domain is too long" }
    require(domain.all { it.code in 0..127 }) { "Use an ASCII domain name" }

    val labels = domain.split('.')
    require(labels.size >= 2) { "Enter a complete domain name" }
    require(labels.all { label ->
        label.isNotEmpty() &&
            label.length <= 63 &&
            label.first().isLetterOrDigit() &&
            label.last().isLetterOrDigit() &&
            label.all { it.isLetterOrDigit() || it == '-' }
    }) { "Enter a valid domain name" }

    domain
}
