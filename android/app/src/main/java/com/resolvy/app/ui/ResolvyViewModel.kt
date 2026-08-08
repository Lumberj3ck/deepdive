package com.resolvy.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.resolvy.app.data.PolicyApi
import com.resolvy.app.data.PolicyDocument
import com.resolvy.app.data.ServerConfig
import com.resolvy.app.data.ServerSettings
import com.resolvy.app.data.normalizeDomain
import com.resolvy.app.data.normalizeServerUrl
import kotlinx.coroutines.Job
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class ResolvyUiState(
    val initializing: Boolean = true,
    val config: ServerConfig? = null,
    val editingServer: Boolean = false,
    val serverDraft: String = "",
    val tokenDraft: String = "",
    val blockedDomains: List<String> = emptyList(),
    val revision: Long = 0,
    val policyLoaded: Boolean = false,
    val synced: Boolean = false,
    val busy: Boolean = false,
    val error: String? = null,
) {
    val showServerSetup: Boolean get() = config == null || editingServer
    val canModifyPolicies: Boolean get() = policyLoaded && synced && !busy
}

class ResolvyViewModel(
    private val settings: ServerSettings,
    private val policyApi: PolicyApi,
) : ViewModel() {
    private val mutableState = MutableStateFlow(ResolvyUiState())
    val state: StateFlow<ResolvyUiState> = mutableState.asStateFlow()
    private var operation: Job? = null

    init {
        val config = settings.load()
        if (config == null) {
            mutableState.update { it.copy(initializing = false) }
        } else {
            mutableState.update {
                it.copy(
                    config = config,
                    serverDraft = config.baseUrl,
                    tokenDraft = config.token,
                )
            }
            refresh()
        }
    }

    fun updateServerDraft(value: String) {
        mutableState.update { it.copy(serverDraft = value, error = null) }
    }

    fun updateTokenDraft(value: String) {
        mutableState.update { it.copy(tokenDraft = value, error = null) }
    }

    fun connect() {
        val current = mutableState.value
        val baseUrl = normalizeServerUrl(current.serverDraft).getOrElse {
            mutableState.update { state -> state.copy(error = it.message) }
            return
        }
        val token = current.tokenDraft.trim()
        if (token.isEmpty()) {
            mutableState.update { it.copy(error = "Enter the policy API token") }
            return
        }
        val config = ServerConfig(baseUrl, token)

        launchOperation {
            val document = policyApi.get(config)
            settings.save(config)
            mutableState.update {
                it.withDocument(document).copy(
                    config = config,
                    editingServer = false,
                    serverDraft = config.baseUrl,
                    tokenDraft = config.token,
                )
            }
        }
    }

    fun refresh() {
        val config = mutableState.value.config ?: return
        launchOperation {
            val document = policyApi.get(config)
            mutableState.update { it.withDocument(document) }
        }
    }

    fun addDomain(value: String, onAccepted: () -> Unit) {
        val domain = normalizeDomain(value).getOrElse {
            mutableState.update { state -> state.copy(error = it.message) }
            return
        }
        val current = mutableState.value
        if (!current.canModifyPolicies) {
            mutableState.update { it.copy(error = "Refresh policies before making changes") }
            return
        }
        if (domain in current.blockedDomains) {
            mutableState.update { it.copy(error = "$domain is already blocked") }
            return
        }
        replacePolicies((current.blockedDomains + domain).sorted(), onAccepted)
    }

    fun removeDomain(domain: String) {
        if (!mutableState.value.canModifyPolicies) {
            mutableState.update { it.copy(error = "Refresh policies before making changes") }
            return
        }
        replacePolicies(mutableState.value.blockedDomains - domain)
    }

    fun editServer() {
        val config = mutableState.value.config ?: return
        mutableState.update {
            it.copy(
                editingServer = true,
                serverDraft = config.baseUrl,
                tokenDraft = config.token,
                error = null,
            )
        }
    }

    fun cancelServerEdit() {
        if (mutableState.value.config == null) return
        mutableState.update { it.copy(editingServer = false, error = null) }
    }

    fun clearError() {
        mutableState.update { it.copy(error = null) }
    }

    private fun replacePolicies(domains: List<String>, onSuccess: () -> Unit = {}) {
        val current = mutableState.value
        val config = current.config ?: return
        launchOperation {
            val document = policyApi.replace(config, current.revision, domains)
            mutableState.update { it.withDocument(document) }
            onSuccess()
        }
    }

    private fun launchOperation(block: suspend () -> Unit) {
        if (operation?.isActive == true) return
        operation = viewModelScope.launch {
            mutableState.update { it.copy(busy = true, synced = false, error = null) }
            try {
                block()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                mutableState.update {
                    it.copy(error = error.message ?: "The operation failed")
                }
            } finally {
                mutableState.update { it.copy(initializing = false, busy = false) }
            }
        }
    }

    private fun ResolvyUiState.withDocument(document: PolicyDocument) = copy(
        blockedDomains = document.blockedDomains,
        revision = document.revision,
        policyLoaded = true,
        synced = true,
    )

    class Factory(
        private val settings: ServerSettings,
        private val policyApi: PolicyApi,
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass.isAssignableFrom(ResolvyViewModel::class.java))
            return ResolvyViewModel(settings, policyApi) as T
        }
    }
}
