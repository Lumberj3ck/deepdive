package com.deepdive.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.deepdive.app.data.HttpPolicyApi
import com.deepdive.app.data.SettingsRepository
import com.deepdive.app.ui.DeepDiveApp
import com.deepdive.app.ui.DeepDiveTheme
import com.deepdive.app.ui.DeepDiveViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            DeepDiveTheme {
                val viewModel: DeepDiveViewModel = viewModel(
                    factory = DeepDiveViewModel.Factory(
                        settings = SettingsRepository(applicationContext),
                        policyApi = HttpPolicyApi(),
                    ),
                )
                val state by viewModel.state.collectAsStateWithLifecycle()
                DeepDiveApp(state = state, viewModel = viewModel)
            }
        }
    }
}
