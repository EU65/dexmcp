package dev.dexmcp

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

enum class Screen { Main, Logs, Agents, Script }

/** One installed app in the startup-injection list. */
data class AgentApp(
    val packageName: String,
    val label: String,
    val enabled: Boolean,
    val scriptBytes: Long
)

/** UI state and actions for the Miuix screen; all actions that touch root run on IO. */
class MainState(private val context: Context) {
    private val frida = FridaManager.get(context)

    var screen by mutableStateOf(Screen.Main)

    var serviceRunning by mutableStateOf(McpService.running)
    var boundHost by mutableStateOf(McpService.boundHost)
    var boundPort by mutableStateOf(McpService.boundPort)
    var serviceError by mutableStateOf(McpService.lastError)
    var allowRemote by mutableStateOf(ServerConfig.allowRemote(context))
    var allowAnyFile by mutableStateOf(ServerConfig.allowAnyFile(context))
    var remoteUrls by mutableStateOf(ServerConfig.remoteUrls(context))
    val token: String = ServerConfig.token(context)
    var port by mutableStateOf(ServerConfig.port(context))

    var fridaLoading by mutableStateOf(false)
    var fridaRoot by mutableStateOf<Boolean?>(null)
    var fridaEnabled by mutableStateOf(ServerConfig.fridaEnabled(context))
    var fridaInstalled by mutableStateOf<String?>(null)
    var fridaSize by mutableStateOf(0L)
    var fridaSessions by mutableStateOf(0)
    var fridaRunningSessions by mutableStateOf(0)
    var fridaError by mutableStateOf<String?>(null)
    var fridaBusy by mutableStateOf<String?>(null)
    var autostartEnabled by mutableStateOf(ServerConfig.autostartEnabled(context))
    var agentScripts by mutableStateOf(0)
    var agentEnabled by mutableStateOf(0)
    var selinux by mutableStateOf("")

    var agents by mutableStateOf<List<AgentApp>>(emptyList())
    var agentsLoading by mutableStateOf(false)
    var agentQuery by mutableStateOf("")
    var editingPackage by mutableStateOf<String?>(null)
    var scriptText by mutableStateOf("")
    var scriptLoading by mutableStateOf(false)
    var scriptDirty by mutableStateOf(false)

    var importSummary by mutableStateOf(summaryOfImports(context))

    fun refreshService(refreshUrls: Boolean = false) {
        serviceRunning = McpService.running
        boundHost = McpService.boundHost
        boundPort = McpService.boundPort
        serviceError = McpService.lastError
        port = ServerConfig.port(context)
        if (refreshUrls) remoteUrls = ServerConfig.remoteUrls(context)
    }

    suspend fun refreshFrida() {
        if (fridaLoading) return
        fridaLoading = true
        try {
            val status = withContext(Dispatchers.IO) { frida.uiStatus() }
            fridaRoot = status.optBoolean("root")
            fridaInstalled = if (status.isNull("installed_version")) null else status.optString("installed_version").takeIf { it.isNotBlank() }
            fridaSize = status.optLong("binary_bytes")
            fridaSessions = status.optInt("sessions")
            fridaRunningSessions = status.optInt("running_sessions")
            autostartEnabled = status.optBoolean("autostart_enabled", autostartEnabled)
            agentScripts = status.optInt("agent_scripts", 0)
            agentEnabled = status.optInt("agent_enabled", 0)
            selinux = status.optString("selinux")
            fridaError = null
        } catch (t: Throwable) {
            fridaError = t.message ?: t.javaClass.simpleName
        } finally {
            fridaLoading = false
        }
    }

    suspend fun installFrida(force: Boolean) {
        if (fridaBusy != null) return
        fridaBusy = if (force) "正在更新 Frida 运行时（约 85 MB）…" else "正在安装 Frida 运行时（约 85 MB）…"
        try {
            withContext(Dispatchers.IO) { frida.prepare(JSONObject().put("force", force)) }
        } catch (t: Throwable) {
            AppLog.error("Frida: 安装失败：${t.message ?: t.javaClass.simpleName}")
        } finally {
            fridaBusy = null
            refreshFrida()
        }
    }

    suspend fun uninstallFrida() {
        if (fridaBusy != null) return
        fridaBusy = "正在卸载 Frida 运行时…"
        try {
            withContext(Dispatchers.IO) { frida.uninstall() }
        } catch (t: Throwable) {
            AppLog.error("Frida: 卸载失败：${t.message ?: t.javaClass.simpleName}")
        } finally {
            fridaBusy = null
            refreshFrida()
        }
    }

    suspend fun toggleFrida(enabled: Boolean) {
        fridaEnabled = enabled
        ServerConfig.setFridaEnabled(context, enabled)
        if (enabled) {
            AppLog.info("设置：MCP 侧 Frida 已启用")
        } else {
            val stopped = withContext(Dispatchers.IO) { runCatching { frida.stopAllSessions() }.getOrDefault(0) }
            AppLog.warn("设置：MCP 侧 Frida 已禁用" + if (stopped > 0) "，已停止 $stopped 个会话" else "")
        }
        refreshFrida()
    }

    fun toggleAutostart(enabled: Boolean) {
        autostartEnabled = enabled
        ServerConfig.setAutostartEnabled(context, enabled)
        AppLog.info("设置：启动注入 ${if (enabled) "已启用" else "已关闭"}")
    }

    suspend fun loadAgents() {
        if (agentsLoading) return
        agentsLoading = true
        try {
            val scripts = withContext(Dispatchers.IO) {
                runCatching { frida.listAgentScripts() }.getOrNull()?.optJSONArray("items")
            }
            val sizes = HashMap<String, Long>()
            if (scripts != null) {
                for (index in 0 until scripts.length()) {
                    val item = scripts.optJSONObject(index) ?: continue
                    sizes[item.optString("package")] = item.optLong("bytes")
                }
            }
            val enabled = AgentStore.enabledPackages(context)
            val pm = context.packageManager
            val apps = withContext(Dispatchers.IO) {
                pm.getInstalledApplications(0)
                    .asSequence()
                    .filter { it.packageName != context.packageName }
                    .map { info ->
                        AgentApp(
                            packageName = info.packageName,
                            label = runCatching { pm.getApplicationLabel(info).toString() }
                                .getOrDefault(info.packageName),
                            enabled = info.packageName in enabled,
                            scriptBytes = sizes[info.packageName] ?: 0L
                        )
                    }
                    .sortedBy { it.label.lowercase() }
                    .toList()
            }
            agents = apps
            agentEnabled = apps.count { it.enabled }
        } catch (t: Throwable) {
            AppLog.error("启动注入：读取应用列表失败 ${t.message ?: t.javaClass.simpleName}")
        } finally {
            agentsLoading = false
        }
    }

    fun toggleAgent(pkg: String, enabled: Boolean) {
        AgentStore.setEnabled(context, pkg, enabled)
        agents = agents.map { if (it.packageName == pkg) it.copy(enabled = enabled) else it }
        agentEnabled = agents.count { it.enabled }
        AppLog.info("设置：启动注入 ${if (enabled) "已启用" else "已关闭"} $pkg")
    }

    fun openScript(pkg: String) {
        editingPackage = pkg
        scriptText = ""
        scriptDirty = false
        scriptLoading = true
        screen = Screen.Script
    }

    suspend fun loadScript() {
        val pkg = editingPackage ?: return
        scriptLoading = true
        val text = withContext(Dispatchers.IO) { runCatching { frida.readAgentScript(pkg) }.getOrNull() }
        scriptText = text ?: DEFAULT_AGENT_SCRIPT
        scriptDirty = text == null
        scriptLoading = false
    }

    suspend fun saveScript() {
        val pkg = editingPackage ?: return
        val script = scriptText
        if (script.isBlank()) {
            toast("脚本不能为空")
            return
        }
        try {
            withContext(Dispatchers.IO) { frida.setAgentScript(pkg, script) }
            val bytes = script.toByteArray().size.toLong()
            agents = agents.map {
                if (it.packageName == pkg) it.copy(enabled = true, scriptBytes = bytes) else it
            }
            agentEnabled = agents.count { it.enabled }
            agentScripts = agents.count { it.scriptBytes > 0 }
            scriptDirty = false
            AppLog.info("启动注入：已保存 $pkg 的脚本（${bytes} 字节）")
            toast("已保存并启用")
        } catch (t: Throwable) {
            AppLog.error("启动注入：保存 $pkg 失败 ${t.message ?: t.javaClass.simpleName}")
            toast("保存失败：${t.message}")
        }
    }

    suspend fun deleteScript() {
        val pkg = editingPackage ?: return
        try {
            withContext(Dispatchers.IO) { frida.deleteAgentScript(pkg) }
            agents = agents.map {
                if (it.packageName == pkg) it.copy(enabled = false, scriptBytes = 0L) else it
            }
            agentEnabled = agents.count { it.enabled }
            agentScripts = agents.count { it.scriptBytes > 0 }
            scriptText = ""
            scriptDirty = false
            toast("已删除脚本")
        } catch (t: Throwable) {
            toast("删除失败：${t.message}")
        }
    }

    suspend fun setSelinux(state: String) {
        try {
            val result = withContext(Dispatchers.IO) { frida.selinux(JSONObject().put("state", state)) }
            selinux = result.optString("current")
            val error = if (result.isNull("error")) "" else result.optString("error")
            if (error.isNotBlank()) AppLog.error("SELinux: $error")
        } catch (t: Throwable) {
            AppLog.error("SELinux: ${t.message ?: t.javaClass.simpleName}")
        }
    }

    fun toggleRemote(enabled: Boolean) {
        allowRemote = enabled
        ServerConfig.setAllowRemote(context, enabled)
        startService()
        remoteUrls = ServerConfig.remoteUrls(context)
        AppLog.info("设置：局域网 / 公网连接 ${if (enabled) "已允许" else "已关闭"}")
    }

    fun toggleAnyFile(enabled: Boolean) {
        allowAnyFile = enabled
        ServerConfig.setAllowAnyFile(context, enabled)
        AppLog.info("设置：任意路径读取 ${if (enabled) "已允许" else "已关闭"}")
    }

    fun changePort(newPort: Int) {
        if (newPort !in 1024..65535 || newPort == port) return
        val wasRunning = McpService.running
        port = newPort
        ServerConfig.setPort(context, newPort)
        remoteUrls = ServerConfig.remoteUrls(context)
        AppLog.info("设置：端口改为 $newPort" + if (wasRunning) "，正在重新监听" else "")
        if (wasRunning) startService()
        refreshService(refreshUrls = true)
    }

    fun startService() {
        runCatching {
            ContextCompat.startForegroundService(context, Intent(context, McpService::class.java))
        }.onFailure { AppLog.error("服务：启动请求失败 ${it.message}") }
        refreshService()
    }

    fun stopService() {
        context.stopService(Intent(context, McpService::class.java))
        refreshService()
    }

    suspend fun importFile(uri: Uri) {
        try {
            val file = withContext(Dispatchers.IO) { ImportStore(context).import(uri) }
            importSummary = summaryOfImports(context)
            AppLog.info("导入：${file.name}（${formatBytes(file.size)}），import_id ${file.id}")
            toast("导入成功：${file.name}")
        } catch (t: Throwable) {
            AppLog.error("导入失败：${t.message ?: t.javaClass.simpleName}")
            toast("导入失败：${t.message}")
        }
    }

    fun copy(label: String, text: String) {
        runCatching {
            context.getSystemService(ClipboardManager::class.java)
                .setPrimaryClip(ClipData.newPlainText(label, text))
            toast("已复制$label")
        }
    }

    fun copyConnection() {
        copy("连接信息", ServerConfig.connectionInfo(context))
    }

    fun toast(message: String) {
        runCatching { Toast.makeText(context, message, Toast.LENGTH_SHORT).show() }
    }

    fun refreshImportSummary() {
        importSummary = summaryOfImports(context)
    }

    companion object {
        const val DEFAULT_AGENT_SCRIPT = """Java.perform(function () {
  console.log('[startup] script loaded');
});"""
        fun summaryOfImports(context: Context): String {
            val files = ImportStore(context).list()
            return if (files.isEmpty()) "尚未导入文件" else "已导入 ${files.size} 个文件；最近：${files.first().name}"
        }

        fun formatBytes(bytes: Long): String = when {
            bytes <= 0 -> "0 B"
            bytes >= 1024L * 1024L * 1024L -> String.format("%.1f GB", bytes / 1024.0 / 1024.0 / 1024.0)
            bytes >= 1024L * 1024L -> String.format("%.1f MB", bytes / 1024.0 / 1024.0)
            bytes >= 1024L -> String.format("%.1f KB", bytes / 1024.0)
            else -> "$bytes B"
        }
    }
}
