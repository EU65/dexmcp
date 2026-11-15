package dev.dexmcp.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.dexmcp.AgentApp
import dev.dexmcp.MainState
import dev.dexmcp.ScopeClient
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
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
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
fun AgentsScreen(state: MainState, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    val xposedConnected by ScopeClient.connected.collectAsState()
    val xposedScope by ScopeClient.scope.collectAsState()
    BackHandler { onBack() }
    LaunchedEffect(Unit) { state.loadAgents() }
    val query = state.agentQuery.trim()
    val filtered = remember(state.agents, query) {
        if (query.isEmpty()) state.agents
        else state.agents.filter {
            it.label.contains(query, ignoreCase = true) || it.packageName.contains(query, ignoreCase = true)
        }
    }
    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = "启动注入",
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(MiuixIcons.Back, "返回", Modifier.size(22.dp)) }
                },
                actions = {
                    IconButton(onClick = { scope.launch { state.loadAgents() } }) {
                        Icon(MiuixIcons.Refresh, "刷新", Modifier.size(20.dp))
                    }
                }
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = padding.calculateTopPadding() + 8.dp,
                bottom = padding.calculateBottomPadding() + 24.dp
            ),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item {
                TextField(
                    value = state.agentQuery,
                    onValueChange = { state.agentQuery = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = "搜索应用名或包名"
                )
            }
            item { FrameworkCard(xposedConnected) }
            item { MasterCard(state) }
            if (state.agentsLoading) {
                item {
                    Text(
                        "正在读取应用列表…",
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }
            if (!state.agentsLoading && filtered.isEmpty()) {
                item {
                    Text(
                        "没有匹配的应用。",
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }
            items(filtered, key = { it.packageName }) { app ->
                AgentRow(state, app, app.packageName in xposedScope)
            }
        }
    }
}

@Composable
private fun FrameworkCard(connected: Boolean) {
    Card {
        BasicComponent(
            title = "LSPosed",
            summary = if (connected) {
                "已连接 · 打开应用开关时会自动申请作用域，LSPosed 会弹出确认"
            } else {
                "未连接 · 请先在 LSPosed 里启用 Dex MCP；未连接时需要在 LSPosed 里手动勾选作用域"
            }
        )
    }
}

@Composable
private fun MasterCard(state: MainState) {
    Card {
        BasicComponent(
            title = "总开关",
            summary = if (state.autostartEnabled) "已开启 · 列表里启用的应用会在启动时注入" else "已关闭 · 所有应用都不会注入",
            endActions = {
                Switch(checked = state.autostartEnabled, onCheckedChange = { state.toggleAutostart(it) })
            }
        )
    }
}

@Composable
private fun AgentRow(
    state: MainState,
    app: AgentApp,
    inScope: Boolean
) {
    val summary = buildString {
        append(app.packageName)
        append(" · ")
        append(if (app.scriptBytes > 0) "脚本 ${MainState.formatBytes(app.scriptBytes)}" else "没有脚本")
        if (app.enabled && !inScope) append(" · 未授权作用域")
    }
    Card {
        BasicComponent(
            title = app.label,
            summary = summary,
            endActions = {
                Switch(
                    checked = app.enabled,
                    onCheckedChange = { enabled ->
                        state.toggleAgent(app.packageName, enabled)
                        if (enabled && app.scriptBytes == 0L) {
                            state.toast("还没有脚本，点进这一项写入")
                        }
                    }
                )
            },
            onClick = { state.openScript(app.packageName) }
        )
    }
}

@Composable
fun ScriptScreen(state: MainState, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    BackHandler { onBack() }
    LaunchedEffect(state.editingPackage) { state.loadScript() }
    val pkg = state.editingPackage ?: ""
    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = state.agents.firstOrNull { it.packageName == pkg }?.label ?: pkg,
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(MiuixIcons.Back, "返回", Modifier.size(22.dp)) }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 16.dp)
        ) {
            Text(
                pkg,
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary
            )
            Spacer(Modifier.height(4.dp))
            Text(
                "在 Application.onCreate 之前执行，保存后自动启用。console.log 输出可以在会话日志里读取。",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary
            )
            Spacer(Modifier.height(10.dp))
            if (state.scriptLoading) {
                Text(
                    "加载中…",
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary
                )
            } else {
                Card(
                    modifier = Modifier.fillMaxWidth().weight(1f),
                    insideMargin = PaddingValues(12.dp)
                ) {
                    BasicTextField(
                        value = state.scriptText,
                        onValueChange = {
                            state.scriptText = it
                            state.scriptDirty = true
                        },
                        modifier = Modifier.fillMaxWidth().weight(1f),
                        textStyle = TextStyle(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            color = MiuixTheme.colorScheme.onSurface
                        ),
                        cursorBrush = SolidColor(MiuixTheme.colorScheme.onSurface)
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    onClick = { scope.launch { state.saveScript() } },
                    modifier = Modifier.weight(1f),
                    enabled = !state.scriptLoading,
                    colors = ButtonDefaults.buttonColorsPrimary()
                ) { Text("保存并启用") }
                TextButton(
                    text = "删除脚本",
                    onClick = { scope.launch { state.deleteScript() } },
                    modifier = Modifier.weight(1f),
                    enabled = !state.scriptLoading,
                    colors = ButtonDefaults.textButtonColors(textColor = MiuixTheme.colorScheme.error)
                )
            }
            if (state.scriptDirty) {
                Text(
                    "有未保存的修改",
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }
    }
}
