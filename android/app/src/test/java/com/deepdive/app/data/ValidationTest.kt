package com.deepdive.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ValidationTest {
    @Test
    fun serverDomainGetsHttpsScheme() {
        assertEquals(
            "https://resolver.example.com:8443",
            normalizeServerUrl("resolver.EXAMPLE.com:8443/").getOrThrow(),
        )
    }

    @Test
    fun nonHttpsServerIsRejected() {
        assertTrue(normalizeServerUrl("http://resolver.example.com").isFailure)
    }

    @Test
    fun serverPathIsRejected() {
        assertTrue(normalizeServerUrl("https://resolver.example.com/admin").isFailure)
        assertTrue(normalizeServerUrl("https://resolver.example.com:0").isFailure)
    }

    @Test
    fun domainIsNormalized() {
        assertEquals("ads.example.com", normalizeDomain(" Ads.Example.COM. ").getOrThrow())
    }

    @Test
    fun malformedDomainIsRejected() {
        assertTrue(normalizeDomain("-ads.example.com").isFailure)
        assertTrue(normalizeDomain("localhost").isFailure)
        assertTrue(normalizeDomain("ads..example.com").isFailure)
    }
}
