package com.resolvy.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.resolvy.app.data.HttpPolicyApi
import com.resolvy.app.data.SettingsRepository
import com.resolvy.app.ui.ResolvyApp
import com.resolvy.app.ui.ResolvyTheme
import com.resolvy.app.ui.ResolvyViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ResolvyTheme {
                val viewModel: ResolvyViewModel = viewModel(
                    factory = ResolvyViewModel.Factory(
                        settings = SettingsRepository(applicationContext),
                        policyApi = HttpPolicyApi(),
                    ),
                )
                val state by viewModel.state.collectAsStateWithLifecycle()
                ResolvyApp(state = state, viewModel = viewModel)
            }
        }
    }
}
