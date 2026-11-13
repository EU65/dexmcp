package dev.dexmcp.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import dev.dexmcp.AppLog
import dev.dexmcp.BuildConfig
import dev.dexmcp.FridaManager
import dev.dexmcp.MainState
import dev.dexmcp.Screen
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.basic.ArrowRight
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Copy
import top.yukonga.miuix.kmp.icon.extended.Delete
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.theme.Colors
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Running = Color(0xFF2DBE60)
private val Warning = Color(0xFFFF9F0A)

private class StatusInfo(val value: String, val color: Color, val lines: List<String>)

@Composable
fun DexMcpApp(state: MainState) {
    val dark = isSystemInDarkTheme()
    MiuixTheme(colors = if (dark) darkColorScheme() else lightColorScheme()) {
        val scope = rememberCoroutineScope()
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) scope.launch { state.importFile(uri) }
        }
        val pickFile: () -> Unit = {
            runCatching {
                picker.launch(
                    arrayOf(
                        "application/vnd.android.package-archive",
                        "application/java-archive",
                        "application/zip",
                        "application/octet-stream",
                        "*/*"
                    )
                )
            }
            Unit
        }
        when (state.screen) {
            Screen.Main -> MainScreen(state, pickFile)
            Screen.Logs -> LogScreen(onBack = { state.screen = Screen.Main })
        }
    }
}

@Composable
private fun MainScreen(state: MainState, pickFile: () -> Unit) {
    val scope = rememberCoroutineScope()
    LaunchedEffect(Unit) {
        var ticks = 0
        while (true) {
            state.refreshService(refreshUrls = ticks % 5 == 0)
            ticks++
            delay(1000)
        }
    }
    LaunchedEffect(Unit) {
        state.refreshFrida()
        state.refreshImportSummary()
    }
    var confirmUninstall by remember { mutableStateOf(false) }
    var editPort by remember { mutableStateOf(false) }

    Scaffold(topBar = { SmallTopAppBar(title = "Dex MCP") }) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = padding.calculateTopPadding() + 8.dp,
                bottom = padding.calculateBottomPadding() + 28.dp
            ),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            item { StatusSection(state) }
            item { ServiceSection(state, scope, onEditPort = { editPort = true }) }
            item { FridaSection(state, scope, onUninstall = { confirmUninstall = true }) }
            item { AnalysisSection(state, pickFile) }
            item { LogSection(state) }
            item { Footer() }
        }
    }

    if (editPort) {
        PortDialog(
            current = state.port,
            onConfirm = {
                editPort = false
                state.changePort(it)
            },
            onDismiss = { editPort = false }
        )
    }

    if (confirmUninstall) {
        ConfirmDialog(
            title = "卸载 Frida 运行时",
            message = "将删除 ${FridaManager.BASE_DIR}，结束所有注入会话。下次仍然可以重新安装。",
            confirmText = "卸载",
            onConfirm = {
                confirmUninstall = false
                scope.launch { state.uninstallFrida() }
            },
            onDismiss = { confirmUninstall = false }
        )
    }
}

@Composable
private fun StatusSection(state: MainState) {
    val colors = MiuixTheme.colorScheme
    val port = state.boundPort ?: state.port
    val address = when {
        !state.serviceRunning -> "未监听"
        state.boundHost == "0.0.0.0" ->
            state.remoteUrls.firstOrNull()?.removePrefix("http://")?.removeSuffix("/mcp") ?: "0.0.0.0:$port"
        else -> "127.0.0.1:$port"
    }
    val frida = fridaStatus(state, colors)
    Row(
        modifier = Modifier.fillMaxWidth().height(150.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        StatusBlock(
            modifier = Modifier.weight(1f).fillMaxHeight(),
            label = "MCP 服务",
            value = if (state.serviceRunning) "运行中" else "已停止",
            color = if (state.serviceRunning) Running else colors.onSurfaceVariantSummary,
            lines = listOf(address, if (state.allowRemote) "允许局域网" else "仅本机")
        )
        StatusBlock(
            modifier = Modifier.weight(1f).fillMaxHeight(),
            label = "FRIDA",
            value = frida.value,
            color = frida.color,
            lines = frida.lines
        )
    }
}

@Composable
private fun StatusBlock(
    modifier: Modifier,
    label: String,
    value: String,
    color: Color,
    lines: List<String>
) {
    val colors = MiuixTheme.colorScheme
    Card(modifier = modifier, insideMargin = PaddingValues(14.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                label,
                style = MiuixTheme.textStyles.footnote2,
                color = colors.onSurfaceVariantSummary,
                fontWeight = FontWeight.Medium
            )
            Spacer(Modifier.weight(1f))
            Box(Modifier.size(8.dp).background(color, CircleShape))
        }
        Spacer(Modifier.height(12.dp))
        Text(value, style = MiuixTheme.textStyles.title2, fontWeight = FontWeight.SemiBold, color = color)
        Spacer(Modifier.height(8.dp))
        lines.forEach { line ->
            Text(
                line,
                style = MiuixTheme.textStyles.footnote2,
                color = colors.onSurfaceVariantSummary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(Modifier.height(2.dp))
        }
    }
}

private fun fridaStatus(state: MainState, colors: Colors): StatusInfo {
    val gray = colors.onSurfaceVariantSummary
    val builtIn = FridaManager.VERSION
    val installed = state.fridaInstalled
    val versionLine = when {
        installed == null -> "内置 $builtIn"
        installed != builtIn -> "已装 $installed"
        else -> "$installed · ${MainState.formatBytes(state.fridaSize)}"
    }
    val sessionLine = when {
        state.fridaRunningSessions > 0 -> "会话 ${state.fridaSessions} · 运行 ${state.fridaRunningSessions}"
        state.fridaSessions > 0 -> "会话 ${state.fridaSessions} · 空闲"
        else -> "暂无会话"
    }
    return when {
        state.fridaRoot == false ->
            StatusInfo("无 Root", colors.error, listOf("需要 KernelSU 授权", "内置 $builtIn"))
        state.fridaBusy != null ->
            StatusInfo("处理中", Warning, listOf(versionLine, "运行时操作进行中"))
        !state.fridaEnabled ->
            StatusInfo("已关闭", Warning, listOf(versionLine, "MCP 调用已禁用"))
        installed == null ->
            StatusInfo("未安装", gray, listOf("内置 $builtIn", "运行时约 85 MB"))
        installed != builtIn ->
            StatusInfo("需更新", Warning, listOf("已装 $installed", "内置 $builtIn"))
        else ->
            StatusInfo("已就绪", Running, listOf(versionLine, sessionLine))
    }
}

@Composable
private fun ServiceSection(state: MainState, scope: CoroutineScope, onEditPort: () -> Unit) {
    val colors = MiuixTheme.colorScheme
    val address = if (state.allowRemote) {
        state.remoteUrls.firstOrNull() ?: "http://<平板 IP>:${state.port}/mcp"
    } else {
        "http://127.0.0.1:${state.port}/mcp"
    }
    SectionTitle("服务")
    Card {
        BasicComponent(
            title = "监听端口",
            endActions = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("${state.port}", color = colors.onSurfaceVariantSummary)
                    Spacer(Modifier.size(4.dp))
                    Icon(MiuixIcons.Basic.ArrowRight, null, Modifier.size(18.dp))
                }
            },
            onClick = onEditPort
        )
        HorizontalDivider()
        BasicComponent(
            title = "连接地址",
            summary = address,
            endActions = {
                IconButton(onClick = { state.copy("连接地址", address) }) {
                    Icon(MiuixIcons.Copy, "复制连接地址", Modifier.size(20.dp))
                }
            }
        )
        HorizontalDivider()
        BasicComponent(
            title = "认证 Token",
            summary = state.token,
            endActions = {
                IconButton(onClick = { state.copy("Token", state.token) }) {
                    Icon(MiuixIcons.Copy, "复制 Token", Modifier.size(20.dp))
                }
            }
        )
        HorizontalDivider()
        BasicComponent(
            title = "允许局域网 / 公网连接",
            endActions = {
                Switch(checked = state.allowRemote, onCheckedChange = { state.toggleRemote(it) })
            }
        )
        HorizontalDivider()
        BasicComponent(
            title = "允许读取任意路径",
            endActions = {
                Switch(checked = state.allowAnyFile, onCheckedChange = { state.toggleAnyFile(it) })
            }
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Button(
                onClick = { state.startService() },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColorsPrimary()
            ) { Text("启动服务") }
            Button(
                onClick = { state.stopService() },
                modifier = Modifier.weight(1f),
                enabled = state.serviceRunning
            ) { Text("停止服务") }
        }
        if (state.serviceError != null) {
            NoteText("启动失败：${state.serviceError}", colors.error)
        }
    }
}

@Composable
private fun FridaSection(state: MainState, scope: CoroutineScope, onUninstall: () -> Unit) {
    val colors = MiuixTheme.colorScheme
    val installed = state.fridaInstalled
    val needsUpdate = installed != null && installed != FridaManager.VERSION
    SectionHeader("Frida 动态分析") {
        IconButton(onClick = { scope.launch { state.refreshFrida() } }) {
            Icon(MiuixIcons.Refresh, "刷新 Frida 状态", Modifier.size(18.dp))
        }
    }
    Card {
        BasicComponent(
            title = "Root",
            endActions = {
                val text: String
                val color: Color
                when (state.fridaRoot) {
                    true -> {
                        text = "可用"
                        color = Running
                    }
                    false -> {
                        text = "不可用"
                        color = colors.error
                    }
                    null -> {
                        text = if (state.fridaLoading) "检测中…" else "未检测"
                        color = colors.onSurfaceVariantSummary
                    }
                }
                Text(text, color = color, fontWeight = FontWeight.Medium)
            }
        )
        HorizontalDivider()
        BasicComponent(
            title = "允许 MCP 调用 Frida",
            summary = if (state.fridaEnabled) "MCP 可调用 android_frida_*" else "MCP 调用已关闭",
            endActions = {
                Switch(checked = state.fridaEnabled, onCheckedChange = { scope.launch { state.toggleFrida(it) } })
            }
        )
        HorizontalDivider()
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Button(
                onClick = { scope.launch { state.installFrida(force = installed != null) } },
                modifier = Modifier.weight(1f),
                enabled = state.fridaBusy == null && state.fridaRoot == true,
                colors = ButtonDefaults.buttonColorsPrimary()
            ) {
                Text(
                    when {
                        installed == null -> "安装运行时"
                        needsUpdate -> "更新运行时"
                        else -> "重新安装"
                    }
                )
            }
            TextButton(
                text = "卸载",
                onClick = onUninstall,
                modifier = Modifier.weight(1f),
                enabled = state.fridaBusy == null && installed != null,
                colors = ButtonDefaults.textButtonColors(textColor = colors.error)
            )
        }
        state.fridaBusy?.let { NoteText(it, colors.onSurfaceVariantSummary) }
        state.fridaError?.let { NoteText(it, colors.error) }
    }
}

@Composable
private fun AnalysisSection(state: MainState, pickFile: () -> Unit) {
    SectionTitle("静态分析")
    Card {
        BasicComponent(
            title = "导入 APK / JAR / DEX",
            summary = state.importSummary,
            endActions = { Icon(MiuixIcons.Basic.ArrowRight, null, Modifier.size(20.dp)) },
            onClick = pickFile
        )
    }
}

@Composable
private fun LogSection(state: MainState) {
    val logs by AppLog.entries.collectAsState()
    val last = logs.lastOrNull()
    SectionTitle("日志")
    Card {
        BasicComponent(
            title = "运行日志",
            summary = if (last == null) "暂无日志" else "${formatTime(last.time)} ${last.message.oneline()}".take(80),
            endActions = { Icon(MiuixIcons.Basic.ArrowRight, null, Modifier.size(20.dp)) },
            onClick = { state.screen = Screen.Logs }
        )
    }
}

@Composable
private fun Footer() {
    Text(
        text = "Dex MCP ${BuildConfig.VERSION_NAME} · ${android.os.Build.MODEL} · Android ${android.os.Build.VERSION.RELEASE} (SDK ${android.os.Build.VERSION.SDK_INT})",
        style = MiuixTheme.textStyles.footnote2,
        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        modifier = Modifier.fillMaxWidth().padding(top = 6.dp)
    )
}

@Composable
private fun LogScreen(onBack: () -> Unit) {
    val entries by AppLog.entries.collectAsState()
    val context = LocalContext.current
    val listState = rememberLazyListState()
    LaunchedEffect(entries.size) {
        if (entries.isNotEmpty()) listState.animateScrollToItem(entries.lastIndex)
    }
    androidx.activity.compose.BackHandler { onBack() }
    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = "运行日志",
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(MiuixIcons.Back, "返回", Modifier.size(22.dp))
                    }
                },
                actions = {
                    IconButton(onClick = {
                        val text = entries.joinToString("\n") { "${formatTime(it.time)} ${it.level.name} ${it.message}" }
                        runCatching {
                            context.getSystemService(android.content.ClipboardManager::class.java)
                                .setPrimaryClip(android.content.ClipData.newPlainText("dexmcp-log", text))
                        }
                    }) { Icon(MiuixIcons.Copy, "复制全部", Modifier.size(20.dp)) }
                    IconButton(onClick = { AppLog.clear() }) {
                        Icon(MiuixIcons.Delete, "清空", Modifier.size(20.dp))
                    }
                }
            )
        }
    ) { padding ->
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = padding.calculateTopPadding() + 8.dp,
                bottom = padding.calculateBottomPadding() + 24.dp
            ),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            if (entries.isEmpty()) {
                item {
                    Text(
                        "暂无日志。启动服务、安装 Frida 或注入时这里会出现记录。",
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                    )
                }
            }
            items(entries) { entry -> LogRow(entry) }
        }
    }
}

@Composable
private fun LogRow(entry: AppLog.Entry) {
    val colors = MiuixTheme.colorScheme
    val levelColor = when (entry.level) {
        AppLog.Level.INFO -> colors.onSurfaceVariantSummary
        AppLog.Level.WARN -> Warning
        AppLog.Level.ERROR -> colors.error
    }
    Card(insideMargin = PaddingValues(horizontal = 14.dp, vertical = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                formatTime(entry.time),
                style = MiuixTheme.textStyles.footnote2,
                color = colors.onSurfaceVariantSummary
            )
            Spacer(Modifier.size(8.dp))
            Text(
                entry.level.name,
                style = MiuixTheme.textStyles.footnote2,
                color = levelColor,
                fontWeight = FontWeight.Medium
            )
        }
        Text(
            entry.message,
            style = MiuixTheme.textStyles.body2.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
            color = colors.onSurface,
            modifier = Modifier.padding(top = 2.dp)
        )
    }
}

@Composable
private fun SectionTitle(text: String) {
    SmallTitle(text)
}

@Composable
private fun SectionHeader(text: String, trailing: @Composable (() -> Unit)? = null) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 8.dp, top = 6.dp, bottom = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text,
            style = MiuixTheme.textStyles.footnote1,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            fontWeight = FontWeight.Medium
        )
        Spacer(Modifier.weight(1f))
        if (trailing != null) trailing()
    }
}

@Composable
private fun NoteText(text: String, color: Color) {
    Text(
        text = text,
        style = MiuixTheme.textStyles.footnote2,
        color = color,
        modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 6.dp)
    )
}

@Composable
private fun PortDialog(current: Int, onConfirm: (Int) -> Unit, onDismiss: () -> Unit) {
    var text by remember { mutableStateOf(current.toString()) }
    val parsed = text.toIntOrNull()
    val valid = parsed != null && parsed in 1024..65535
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.widthIn(min = 280.dp, max = 360.dp),
            insideMargin = PaddingValues(20.dp)
        ) {
            Text("监听端口", style = MiuixTheme.textStyles.title4, fontWeight = FontWeight.Medium)
            Spacer(Modifier.height(12.dp))
            TextField(
                value = text,
                onValueChange = { text = it.filter { c -> c.isDigit() }.take(5) },
                modifier = Modifier.fillMaxWidth(),
                label = "1024 – 65535",
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
            )
            if (!valid && text.isNotEmpty()) {
                Text(
                    "端口需在 1024 – 65535 之间",
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
            Spacer(Modifier.height(16.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = onDismiss, modifier = Modifier.weight(1f)) { Text("取消") }
                Button(
                    onClick = { parsed?.let(onConfirm) },
                    modifier = Modifier.weight(1f),
                    enabled = valid,
                    colors = ButtonDefaults.buttonColorsPrimary()
                ) { Text("保存") }
            }
        }
    }
}

@Composable
private fun ConfirmDialog(
    title: String,
    message: String,
    confirmText: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.widthIn(min = 280.dp, max = 360.dp),
            insideMargin = PaddingValues(20.dp)
        ) {
            Text(title, style = MiuixTheme.textStyles.title4, fontWeight = FontWeight.Medium)
            Spacer(Modifier.height(8.dp))
            Text(
                message,
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary
            )
            Spacer(Modifier.height(18.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = onDismiss, modifier = Modifier.weight(1f)) { Text("取消") }
                Button(
                    onClick = onConfirm,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColorsPrimary()
                ) { Text(confirmText) }
            }
        }
    }
}

private fun formatTime(time: Long): String =
    SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(time))

private fun String.oneline(): String = replace('\n', ' ').trim()
