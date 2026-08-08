package com.resolvy.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private val Ink = Color(0xFF20251F)
private val Paper = Color(0xFFF5F1E8)
private val Moss = Color(0xFF345B42)
private val Acid = Color(0xFFD8F45B)
private val Rust = Color(0xFFAD482F)

private val LightColors = lightColorScheme(
    primary = Moss,
    onPrimary = Color.White,
    primaryContainer = Acid,
    onPrimaryContainer = Ink,
    secondary = Rust,
    background = Paper,
    onBackground = Ink,
    surface = Color(0xFFFFFCF5),
    onSurface = Ink,
    surfaceVariant = Color(0xFFE7E2D7),
    onSurfaceVariant = Color(0xFF555C53),
    error = Color(0xFF9D2D20),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFA7D5AE),
    onPrimary = Color(0xFF12351F),
    primaryContainer = Color(0xFF48652B),
    onPrimaryContainer = Color(0xFFE8FFC1),
    secondary = Color(0xFFFFB4A2),
    background = Color(0xFF181B17),
    onBackground = Color(0xFFE7E4DB),
    surface = Color(0xFF20241F),
    onSurface = Color(0xFFE7E4DB),
    surfaceVariant = Color(0xFF343A33),
    onSurfaceVariant = Color(0xFFC3C9BE),
)

@Composable
fun ResolvyTheme(content: @Composable () -> Unit) {
    val typography = MaterialTheme.typography.copy(
        displayLarge = TextStyle(
            fontFamily = FontFamily.Serif,
            fontWeight = FontWeight.Bold,
            fontSize = 54.sp,
            lineHeight = 56.sp,
        ),
        headlineLarge = TextStyle(
            fontFamily = FontFamily.Serif,
            fontWeight = FontWeight.Bold,
            fontSize = 36.sp,
            lineHeight = 40.sp,
        ),
        titleLarge = TextStyle(
            fontFamily = FontFamily.Serif,
            fontWeight = FontWeight.Bold,
            fontSize = 24.sp,
        ),
    )
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        typography = typography,
        content = content,
    )
}
