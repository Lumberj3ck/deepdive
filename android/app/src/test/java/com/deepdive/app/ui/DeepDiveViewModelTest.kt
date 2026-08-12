package com.deepdive.app.ui

import com.deepdive.app.data.PolicyApi
import com.deepdive.app.data.BlockedDomain
import com.deepdive.app.data.PolicyDocument
import com.deepdive.app.data.ServerConfig
import com.deepdive.app.data.ServerSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class DeepDiveViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun connectTestsAndStoresServer() = runTest(dispatcher) {
        val settings = FakeSettings()
        val api = FakePolicyApi(PolicyDocument(4, listOf(BlockedDomain("ads.example"))))
        val viewModel = DeepDiveViewModel(settings, api)

        viewModel.updateServerDraft("resolver.example.com:8443")
        viewModel.updateTokenDraft("secret")
        viewModel.connect()
        advanceUntilIdle()

        assertEquals(ServerConfig("https://resolver.example.com:8443", "secret"), settings.config)
        assertEquals(listOf(BlockedDomain("ads.example")), viewModel.state.value.blockedDomains)
        assertEquals(4, viewModel.state.value.revision)
        assertFalse(viewModel.state.value.showServerSetup)
    }

    @Test
    fun addingDomainReplacesServerPolicy() = runTest(dispatcher) {
        val config = ServerConfig("https://resolver.example.com", "secret")
        val settings = FakeSettings(config)
        val api = FakePolicyApi(PolicyDocument(2, listOf(BlockedDomain("ads.example"))))
        val viewModel = DeepDiveViewModel(settings, api)
        advanceUntilIdle()

        viewModel.addDomain(" Tracker.Example. ") {}
        advanceUntilIdle()

        assertEquals(
            listOf(BlockedDomain("ads.example"), BlockedDomain("tracker.example")),
            api.lastReplacement,
        )
        assertEquals(3, viewModel.state.value.revision)
    }

    @Test
    fun temporarilyUnblockingDomainSendsFutureUnixTimestamp() = runTest(dispatcher) {
        val config = ServerConfig("https://resolver.example.com", "secret")
        val settings = FakeSettings(config)
        val api = FakePolicyApi(PolicyDocument(2, listOf(BlockedDomain("ads.example"))))
        val viewModel = DeepDiveViewModel(settings, api, currentTimeMillis = { 1_700_000_000_000 })
        advanceUntilIdle()

        viewModel.temporarilyUnblock("ads.example", 2) {}
        advanceUntilIdle()

        assertEquals(
            listOf(BlockedDomain("ads.example", 1_700_000_120)),
            api.lastReplacement,
        )
    }

    @Test
    fun failedInitialRefreshDoesNotAllowPolicyReplacement() = runTest(dispatcher) {
        val config = ServerConfig("https://resolver.example.com", "secret")
        val settings = FakeSettings(config)
        val api = FakePolicyApi(PolicyDocument(0, emptyList()), failGet = true)
        val viewModel = DeepDiveViewModel(settings, api)
        advanceUntilIdle()

        assertFalse(viewModel.state.value.canModifyPolicies)
        viewModel.addDomain("ads.example") {}
        advanceUntilIdle()

        assertNull(api.lastReplacement)
        assertEquals("Refresh policies before making changes", viewModel.state.value.error)
    }
}

private class FakeSettings(var config: ServerConfig? = null) : ServerSettings {
    override fun load(): ServerConfig? = config
    override suspend fun save(config: ServerConfig) {
        this.config = config
    }
}

private class FakePolicyApi(
    initial: PolicyDocument,
    private val failGet: Boolean = false,
) : PolicyApi {
    private var document = initial
    var lastReplacement: List<BlockedDomain>? = null

    override suspend fun get(config: ServerConfig): PolicyDocument {
        if (failGet) throw Exception("Server unavailable")
        return document
    }

    override suspend fun replace(
        config: ServerConfig,
        revision: Long,
        blockedDomains: List<BlockedDomain>,
    ): PolicyDocument {
        lastReplacement = blockedDomains
        document = PolicyDocument(document.revision + 1, blockedDomains)
        return document
    }
}
