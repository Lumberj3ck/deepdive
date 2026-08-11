package com.resolvy.app.ui

import android.os.SystemClock
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.delay
import kotlin.random.Random

@Composable
fun ResolvyApp(state: ResolvyUiState, viewModel: ResolvyViewModel) {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        when {
            state.initializing -> LoadingScreen()
            state.showServerSetup -> ServerSetupScreen(
                state = state,
                onServerChange = viewModel::updateServerDraft,
                onTokenChange = viewModel::updateTokenDraft,
                onConnect = viewModel::connect,
                onCancel = viewModel::cancelServerEdit,
                onDismissError = viewModel::clearError,
            )
            else -> PolicyScreen(
                state = state,
                onAdd = viewModel::addDomain,
                onRemove = viewModel::removeDomain,
                onRefresh = viewModel::refresh,
                onEditServer = viewModel::editServer,
                onDismissError = viewModel::clearError,
            )
        }
    }
}

@Composable
private fun LoadingScreen() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

@Composable
private fun ServerSetupScreen(
    state: ResolvyUiState,
    onServerChange: (String) -> Unit,
    onTokenChange: (String) -> Unit,
    onConnect: () -> Unit,
    onCancel: () -> Unit,
    onDismissError: () -> Unit,
) {
    var showToken by rememberSaveable { mutableStateOf(false) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding(),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            modifier = Modifier
                .fillMaxHeight()
                .widthIn(max = 680.dp)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 28.dp),
        ) {
            BrandMark()
            Spacer(Modifier.height(48.dp))
            Text(
                text = if (state.config == null) "Connect to Resolvy" else "Server settings",
                style = MaterialTheme.typography.displayLarge,
            )
            Spacer(Modifier.height(16.dp))
            Text(
                text = "Connect to your Resolvy server to manage blocked domains.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(36.dp))

            Text("SERVER", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = state.serverDraft,
                onValueChange = onServerChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Domain or HTTPS URL") },
                placeholder = { Text("resolver.example.com:8443") },
                singleLine = true,
                enabled = !state.busy,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    imeAction = ImeAction.Next,
                ),
                shape = RoundedCornerShape(14.dp),
            )
            Spacer(Modifier.height(18.dp))
            OutlinedTextField(
                value = state.tokenDraft,
                onValueChange = onTokenChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Policy API token") },
                singleLine = true,
                enabled = !state.busy,
                visualTransformation = if (showToken) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = {
                    TextButton(onClick = { showToken = !showToken }) {
                        Text(if (showToken) "Hide" else "Show")
                    }
                },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done,
                ),
                keyboardActions = KeyboardActions(onDone = { onConnect() }),
                shape = RoundedCornerShape(14.dp),
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = "HTTPS is required. Certificates are checked against Android's trusted certificate authorities.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            state.error?.let {
                Spacer(Modifier.height(20.dp))
                ErrorBanner(message = it, onDismiss = onDismissError)
            }

            Spacer(Modifier.height(28.dp))
            Button(
                onClick = onConnect,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(54.dp),
                enabled = !state.busy,
                shape = RoundedCornerShape(14.dp),
            ) {
                if (state.busy) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(22.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(Modifier.width(10.dp))
                    Text("Checking server")
                } else {
                    Text(if (state.config == null) "Connect" else "Save and reconnect")
                }
            }
            if (state.config != null) {
                TextButton(
                    onClick = onCancel,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                    enabled = !state.busy,
                ) {
                    Text("Cancel")
                }
            }
        }
    }
}

@Composable
private fun PolicyScreen(
    state: ResolvyUiState,
    onAdd: (String, () -> Unit) -> Unit,
    onRemove: (String, () -> Unit) -> Unit,
    onRefresh: () -> Unit,
    onEditServer: () -> Unit,
    onDismissError: () -> Unit,
) {
    var newDomain by rememberSaveable { mutableStateOf("") }
    var removalRequest by remember { mutableStateOf<RemovalRequest?>(null) }
    var taskAssignments by rememberSaveable { mutableStateOf(emptyMap<String, Int>()) }

    removalRequest?.let { request ->
        RemovalChallenge(
            domain = request.domain,
            task = request.task,
            onCancel = { removalRequest = null },
            onComplete = {
                removalRequest = null
                onRemove(request.domain) {
                    taskAssignments = taskAssignments - request.domain
                }
            },
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding(),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 760.dp)
                .fillMaxWidth()
                .padding(horizontal = 20.dp),
        ) {
            Spacer(Modifier.height(20.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                BrandMark()
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onRefresh, enabled = !state.busy) { Text("Refresh") }
                TextButton(onClick = onEditServer, enabled = !state.busy) { Text("Server") }
            }
            Spacer(Modifier.height(34.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Domain policies", style = MaterialTheme.typography.headlineLarge)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = state.config?.baseUrl.orEmpty(),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                StatusBadge(revision = state.revision, synced = state.synced)
            }
            Spacer(Modifier.height(28.dp))
            OutlinedTextField(
                value = newDomain,
                onValueChange = { newDomain = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Block a domain") },
                placeholder = { Text("ads.example.com") },
                supportingText = { Text("Subdomains will be blocked too") },
                singleLine = true,
                enabled = state.canModifyPolicies,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    imeAction = ImeAction.Done,
                ),
                keyboardActions = KeyboardActions(
                    onDone = { onAdd(newDomain) { newDomain = "" } },
                ),
                trailingIcon = {
                    Button(
                        onClick = { onAdd(newDomain) { newDomain = "" } },
                        enabled = state.canModifyPolicies && newDomain.isNotBlank(),
                        contentPadding = ButtonDefaults.ContentPadding,
                    ) {
                        Text("Block")
                    }
                },
                shape = RoundedCornerShape(14.dp),
            )
            state.error?.let {
                Spacer(Modifier.height(14.dp))
                ErrorBanner(message = it, onDismiss = onDismissError)
            }
            if (state.busy) {
                Spacer(Modifier.height(12.dp))
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            Spacer(Modifier.height(24.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("BLOCKED", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
                Spacer(Modifier.width(8.dp))
                Text(
                    state.blockedDomains.size.toString(),
                    modifier = Modifier
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primaryContainer)
                        .padding(horizontal = 9.dp, vertical = 3.dp),
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            Spacer(Modifier.height(10.dp))
        }

        if (state.blockedDomains.isEmpty()) {
            EmptyPolicies(
                loaded = state.policyLoaded,
                modifier = Modifier.weight(1f),
            )
        } else {
            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .widthIn(max = 760.dp)
                    .fillMaxWidth(),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(
                    start = 20.dp,
                    end = 20.dp,
                    bottom = 28.dp,
                ),
            ) {
                items(state.blockedDomains, key = { it }) { domain ->
                    DomainRow(
                        domain = domain,
                        enabled = state.canModifyPolicies,
                        onRemove = {
                            val taskIndex = taskAssignments[domain] ?: Random.nextInt(RemovalTask.entries.size)
                            taskAssignments = taskAssignments + (domain to taskIndex)
                            removalRequest = RemovalRequest(domain, RemovalTask.entries[taskIndex])
                        },
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.surfaceVariant)
                }
            }
        }
    }
}

@Composable
private fun ReviewExcerpt(text: String, source: String? = null) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(18.dp),
    ) {
        Text(
            text = text,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium,
        )
        source?.let {
            Spacer(Modifier.height(12.dp))
            Text(
                text = it,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelSmall,
            )
        }
    }
}

@Composable
private fun ReviewExcerpt(excerpt: PublishedExcerpt) = ReviewExcerpt(excerpt.text, excerpt.source)

private val removalFilingRecords = listOf(
    "Account archive",
    "Annual billing",
    "Asset register",
    "Audit copy",
    "Backup ledger",
    "Billing index",
    "Compliance file",
    "Contact register",
    "Department note",
    "Equipment log",
    "Expense record",
    "Filing request",
    "General archive",
    "Inventory sheet",
    "Meeting minutes",
    "Monthly statement",
    "Office register",
    "Operations copy",
    "Paper trail",
    "Quarterly report",
    "Records ledger",
    "Retention schedule",
    "Service invoice",
    "Storage manifest",
    "Workflow record",
)

@Composable
private fun RemovalChallenge(
    domain: String,
    task: RemovalTask,
    onCancel: () -> Unit,
    onComplete: () -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding(),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            modifier = Modifier
                .fillMaxHeight()
                .widthIn(max = 680.dp)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 28.dp),
        ) {
            BrandMark()
            Spacer(Modifier.height(42.dp))
            Text("Removal review", style = MaterialTheme.typography.displayLarge)
            Spacer(Modifier.height(12.dp))
            Text(
                text = "A removal task has been selected for $domain.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(28.dp))
            Text(
                text = "TASK: ${task.label.uppercase()}",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(16.dp))

            when (task) {
                RemovalTask.Review -> PolicyReviewTask(domain, onComplete)
                RemovalTask.Transcription -> TranscriptionTask(domain, onComplete)
                RemovalTask.DomainEntries -> DomainEntryTask(domain, onComplete)
                RemovalTask.ReverseConfirmation -> ReverseConfirmationTask(domain, onComplete)
                RemovalTask.Filing -> FilingTask(domain, onComplete)
            }

            Spacer(Modifier.height(18.dp))
            TextButton(
                onClick = onCancel,
                modifier = Modifier.align(Alignment.CenterHorizontally),
            ) {
                Text("Keep domain blocked")
            }
        }
    }
}

@Composable
private fun PolicyReviewTask(domain: String, onComplete: () -> Unit) {
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var pageIndex by remember { mutableStateOf(0) }
    var readingSecondsRemaining by remember { mutableStateOf(REVIEW_PAGE_SECONDS) }
    var actionSecondsRemaining by remember { mutableStateOf(0) }
    var timerAttempt by remember { mutableStateOf(0) }

    if (pageIndex == balancedReviewPages.size) {
        RemovalFinishButton(domain, onComplete)
        return
    }

    LaunchedEffect(pageIndex, timerAttempt) {
        var readingMillisRemaining = REVIEW_PAGE_SECONDS * 1_000L
        var previousUpdate = SystemClock.elapsedRealtime()
        readingSecondsRemaining = REVIEW_PAGE_SECONDS
        actionSecondsRemaining = 0
        while (readingMillisRemaining > 0) {
            delay(TIMER_UPDATE_MS)
            val now = SystemClock.elapsedRealtime()
            if (lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
                readingMillisRemaining -= minOf(now - previousUpdate, TIMER_UPDATE_MS)
                readingSecondsRemaining = ((readingMillisRemaining + 999) / 1_000).toInt()
            }
            previousUpdate = now
        }
        readingSecondsRemaining = 0
        val actionDeadline = SystemClock.elapsedRealtime() + REVIEW_ACTION_SECONDS * 1_000L
        actionSecondsRemaining = secondsUntil(actionDeadline)
        while (SystemClock.elapsedRealtime() < actionDeadline) {
            delayUntilNextTimerUpdate(actionDeadline)
            actionSecondsRemaining = secondsUntil(actionDeadline)
        }
        actionSecondsRemaining = 0
        pageIndex = 0
        timerAttempt++
    }

    Text("Review policy record", style = MaterialTheme.typography.titleLarge)
    Spacer(Modifier.height(10.dp))
    Text(
        text = "PAGE ${pageIndex + 1} OF ${balancedReviewPages.size}",
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.Bold,
    )
    Spacer(Modifier.height(16.dp))
    ReviewExcerpt(balancedReviewPages[pageIndex])
    Spacer(Modifier.height(22.dp))
    Button(
        onClick = { pageIndex++ },
        modifier = Modifier.fillMaxWidth(),
        enabled = actionSecondsRemaining > 0,
        shape = RoundedCornerShape(14.dp),
    ) {
        Text(
            if (actionSecondsRemaining > 0) {
                "Continue now ($actionSecondsRemaining seconds)"
            } else {
                "Continue in $readingSecondsRemaining seconds"
            },
        )
    }
}

@Composable
private fun TranscriptionTask(domain: String, onComplete: () -> Unit) {
    var excerptIndex by remember { mutableStateOf(0) }
    var transcription by remember { mutableStateOf("") }

    if (excerptIndex == removalTranscriptions.size) {
        RemovalFinishButton(domain, onComplete)
        return
    }

    val excerpt = removalTranscriptions[excerptIndex]
    Text("Transcribe the record", style = MaterialTheme.typography.titleLarge)
    Spacer(Modifier.height(10.dp))
    Text(
        text = "EXCERPT ${excerptIndex + 1} OF ${removalTranscriptions.size}",
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.Bold,
    )
    Spacer(Modifier.height(16.dp))
    ReviewExcerpt(excerpt)
    Spacer(Modifier.height(18.dp))
    OutlinedTextField(
        value = transcription,
        onValueChange = { transcription = it },
        modifier = Modifier.fillMaxWidth(),
        label = { Text("Transcription") },
        minLines = 4,
        shape = RoundedCornerShape(14.dp),
    )
    Spacer(Modifier.height(18.dp))
    Button(
        onClick = {
            excerptIndex++
            transcription = ""
        },
        modifier = Modifier.fillMaxWidth(),
        enabled = transcription == excerpt.text,
        shape = RoundedCornerShape(14.dp),
    ) {
        Text("Record transcription")
    }
}

@Composable
private fun DomainEntryTask(domain: String, onComplete: () -> Unit) {
    val entriesRequired = remember(domain) { entriesForDomain(domain) }
    var entriesRecorded by remember { mutableStateOf(0) }
    var entry by remember { mutableStateOf("") }

    if (entriesRecorded == entriesRequired) {
        RemovalFinishButton(domain, onComplete)
        return
    }

    Text("Record the domain", style = MaterialTheme.typography.titleLarge)
    Spacer(Modifier.height(10.dp))
    Text(
        text = "Enter the domain exactly. Each entry is recorded separately.",
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(18.dp))
    Text(
        text = "ENTRY ${entriesRecorded + 1} OF $entriesRequired",
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.Bold,
    )
    Spacer(Modifier.height(12.dp))
    OutlinedTextField(
        value = entry,
        onValueChange = { entry = it },
        modifier = Modifier.fillMaxWidth(),
        label = { Text("Domain") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Done),
        shape = RoundedCornerShape(14.dp),
    )
    Spacer(Modifier.height(18.dp))
    Button(
        onClick = {
            entriesRecorded++
            entry = ""
        },
        modifier = Modifier.fillMaxWidth(),
        enabled = entry == domain,
        shape = RoundedCornerShape(14.dp),
    ) {
        Text("Record entry")
    }
}

@Composable
private fun ReverseConfirmationTask(domain: String, onComplete: () -> Unit) {
    val entriesRequired = remember(domain) { entriesForDomain(domain) }
    var entriesRecorded by remember { mutableStateOf(0) }
    var entry by remember { mutableStateOf("") }
    val reversedDomain = domain.reversed()

    if (entriesRecorded == entriesRequired) {
        RemovalFinishButton(domain, onComplete)
        return
    }

    val isReversedEntry = entriesRecorded % 2 == 0
    val expected = if (isReversedEntry) reversedDomain else domain
    Text("Confirm the record", style = MaterialTheme.typography.titleLarge)
    Spacer(Modifier.height(10.dp))
    Text(
        text = "CONFIRMATION ${entriesRecorded + 1} OF $entriesRequired",
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.Bold,
    )
    Spacer(Modifier.height(12.dp))
    Text(
        text = if (isReversedEntry) "Enter the domain in reverse order." else "Enter the domain normally.",
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(12.dp))
    ReviewExcerpt(domain)
    Spacer(Modifier.height(18.dp))
    OutlinedTextField(
        value = entry,
        onValueChange = { entry = it },
        modifier = Modifier.fillMaxWidth(),
        label = { Text("Confirmation") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Done),
        shape = RoundedCornerShape(14.dp),
    )
    Spacer(Modifier.height(18.dp))
    Button(
        onClick = {
            entriesRecorded++
            entry = ""
        },
        modifier = Modifier.fillMaxWidth(),
        enabled = entry == expected,
        shape = RoundedCornerShape(14.dp),
    ) {
        Text("Record confirmation")
    }
}

@Composable
private fun FilingTask(domain: String, onComplete: () -> Unit) {
    val filingRecords = remember(domain) {
        mutableStateListOf<String>().apply {
            addAll(removalFilingRecords.take(20).shuffled(Random(domain.hashCode())))
        }
    }

    Text("File the records", style = MaterialTheme.typography.titleLarge)
    Spacer(Modifier.height(10.dp))
    Text(
        text = "Select the remaining records in alphabetical order.",
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(16.dp))
    Text(
        text = "RECORDS REMAINING ${filingRecords.size}",
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.Bold,
    )
    Spacer(Modifier.height(8.dp))
    filingRecords.forEach { record ->
        TextButton(
            onClick = {
                if (record == filingRecords.minOrNull()) filingRecords.remove(record)
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(record, modifier = Modifier.fillMaxWidth())
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.surfaceVariant)
    }
    if (filingRecords.isEmpty()) RemovalFinishButton(domain, onComplete)
}

@Composable
private fun RemovalFinishButton(domain: String, onComplete: () -> Unit) {
    Spacer(Modifier.height(20.dp))
    Button(
        onClick = onComplete,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
    ) {
        Text("Remove $domain")
    }
}

private fun entriesForDomain(domain: String): Int =
    (160 + domain.length - 1).div(domain.length).coerceIn(8, 20)

private data class RemovalRequest(val domain: String, val task: RemovalTask)

private enum class RemovalTask(val label: String) {
    Review("policy review"),
    Transcription("transcription"),
    DomainEntries("domain record"),
    ReverseConfirmation("reverse confirmation"),
    Filing("record filing"),
}

private data class PublishedExcerpt(val text: String, val source: String = WEALTH_OF_NATIONS_SOURCE)

private val balancedReviewPages = listOf(
    PublishedExcerpt(
        "The annual labour of every nation is the fund which originally supplies it with all the " +
            "necessaries and conveniencies of life which it annually consumes, and which consist " +
            "always either in the immediate produce of that labour, or in what is purchased with " +
            "that produce from other nations.",
    ),
    PublishedExcerpt(
        "The greatest improvements in the productive powers of labour, and the greater part of the " +
            "skill, dexterity, and judgment, with which it is anywhere directed, or applied, seem " +
            "to have been the effects of the division of labour.",
    ),
    PublishedExcerpt(
        "This division of labour, from which so many advantages are derived, is not originally the " +
            "effect of any human wisdom, which foresees and intends that general opulence to which " +
            "it gives occasion.",
    ),
    PublishedExcerpt(
        "As it is the power of exchanging that gives occasion to the division of labour, so the " +
            "extent of this division must always be limited by the extent of that power, or, in " +
            "other words, by the extent of the market.",
    ),
    PublishedExcerpt(
        "Nobody ever saw a dog make a fair and deliberate exchange of one bone for another with " +
            "another dog. Nobody ever saw one animal, by its gestures and natural cries signify to " +
            "another, this is mine, that yours; I am willing to give this for that.",
    ),
)

private const val REVIEW_PAGE_SECONDS = 8
private const val REVIEW_ACTION_SECONDS = 3
private const val TIMER_UPDATE_MS = 250L

private fun secondsUntil(deadline: Long): Int {
    val remaining = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0)
    return ((remaining + 999) / 1_000).toInt()
}

private suspend fun delayUntilNextTimerUpdate(deadline: Long) {
    val remaining = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(1)
    delay(minOf(TIMER_UPDATE_MS, remaining))
}

private val removalTranscriptions = listOf(
    PublishedExcerpt(
        "The effects of the division of labour, in the general business of society, will be more " +
            "easily understood, by considering in what manner it operates in some particular manufactures.",
    ),
    PublishedExcerpt(
        "Every man thus lives by exchanging, or becomes, in some measure, a merchant, and the society " +
            "itself grows to be what is properly a commercial society.",
    ),
)

private const val WEALTH_OF_NATIONS_SOURCE =
    "Adam Smith, The Wealth of Nations (1776). Public-domain text via Project Gutenberg, eBook 3300."

@Composable
private fun BrandMark() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(30.dp)
                .clip(RoundedCornerShape(9.dp))
                .background(MaterialTheme.colorScheme.primaryContainer),
            contentAlignment = Alignment.Center,
        ) {
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .border(3.dp, MaterialTheme.colorScheme.onPrimaryContainer, CircleShape),
            )
        }
        Spacer(Modifier.width(10.dp))
        Text(
            "RESOLVY",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Black,
            letterSpacing = androidx.compose.ui.unit.TextUnit.Unspecified,
        )
    }
}

@Composable
private fun StatusBadge(revision: Long, synced: Boolean) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(
                if (synced) MaterialTheme.colorScheme.primaryContainer
                else MaterialTheme.colorScheme.surfaceVariant,
            )
            .padding(horizontal = 11.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(7.dp)
                .clip(CircleShape)
                .background(
                    if (synced) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                ),
        )
        Spacer(Modifier.width(7.dp))
        Text(
            if (synced) "SYNCED  R$revision" else "REFRESH NEEDED",
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
        )
    }
}

@Composable
private fun DomainRow(domain: String, enabled: Boolean, onRemove: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 15.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
            contentAlignment = Alignment.Center,
        ) {
            Text("X", fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(13.dp))
        Text(
            text = domain,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyLarge,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        TextButton(onClick = onRemove, enabled = enabled) {
            Text("Remove", color = if (enabled) MaterialTheme.colorScheme.error else Color.Unspecified)
        }
    }
}

@Composable
private fun EmptyPolicies(loaded: Boolean, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(36.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(72.dp)
                .border(2.dp, MaterialTheme.colorScheme.outlineVariant, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Box(
                modifier = Modifier
                    .size(28.dp)
                    .border(5.dp, MaterialTheme.colorScheme.primary, CircleShape),
            )
        }
        Spacer(Modifier.height(18.dp))
        Text(
            if (loaded) "No blocked domains" else "Policies unavailable",
            style = MaterialTheme.typography.titleLarge,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            if (loaded) "No domains are blocked."
            else "Refresh to load the current policies before making changes.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ErrorBanner(message: String, onDismiss: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.errorContainer)
            .padding(start = 14.dp, top = 8.dp, bottom = 8.dp, end = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            message,
            modifier = Modifier.weight(1f),
            color = MaterialTheme.colorScheme.onErrorContainer,
            style = MaterialTheme.typography.bodyMedium,
        )
        TextButton(onClick = onDismiss) { Text("Dismiss") }
    }
}
