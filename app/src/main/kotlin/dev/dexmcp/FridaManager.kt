package dev.dexmcp

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Dynamic analysis without adb or frida-server: the APK ships frida-inject (arm64),
 * extracts it to /data/adb/dexmcp with a root shell and runs it against the
 * target app. /data/adb is root-only, so other apps cannot enumerate the injected
 * files the way they can under /data/local/tmp. frida-inject attaches/spawns the
 * process, loads the JavaScript file and prints console output, which is redirected
 * to a per-session log the agent polls.
 */
class FridaManager private constructor(private val context: Context) {
    companion object {
        const val VERSION = "17.26.2"
        /**
         * The bundled frida-inject is patched by tools/patch-frida.py (Florida-style
         * anti-detection). The flavor marker makes an existing stock 17.26.2 install
         * look outdated, so it gets replaced on first use after an app update.
         */
        const val RUNTIME_FLAVOR = "florida-1"
        const val BASE_DIR = "/data/adb/dexmcp"
        const val AGENTS_DIR = "$BASE_DIR/agents"
        const val BINARY = "$BASE_DIR/frida-inject"
        const val SESSIONS_DIR = "$BASE_DIR/sessions"
        private const val ASSET = "frida/frida-inject"
        private const val BRIDGE_ASSET = "frida/bridge.js"
        private val ANSI = Regex("\u001b\\[[0-9;]*[A-Za-z]")

        private var instance: FridaManager? = null

        fun get(context: Context): FridaManager = instance ?: synchronized(this) {
            instance ?: FridaManager(context.applicationContext).also { instance = it }
        }

        /**
         * frida-inject only flushes stdout for "frida:stdout" messages; plain console
         * output sits in stdio buffers when redirected to a file. Bridging console to
         * that message type keeps polling latency low. The Module shims keep scripts
         * written for Frida 16 working after the 17.x API move to module instances.
         */
        private val PRELUDE = """
            (function () {
              if (globalThis.__dexmcpConsole) return;
              globalThis.__dexmcpConsole = true;
              function render(value) {
                if (typeof value === 'string') return value;
                try { return JSON.stringify(value); } catch (e) { return String(value); }
              }
              ['log', 'debug', 'info', 'warn', 'error'].forEach(function (level) {
                var original = console[level];
                console[level] = function () {
                  try {
                    var parts = [];
                    for (var i = 0; i < arguments.length; i++) parts.push(render(arguments[i]));
                    send(['frida:stdout', parts.join(' ') + '\n']);
                  } catch (e) {
                    if (original) original.apply(console, arguments);
                  }
                };
              });
              try {
                setInterval(function () {
                  try { send(['frida:stdout', '']); } catch (e) {}
                }, 400);
              } catch (e) {}
              try {
                var M = Module;
                function moduleOf(name) {
                  if (Process.findModuleByName) return Process.findModuleByName(name);
                  try { return Process.getModuleByName(name); } catch (e) { return null; }
                }
                if (!M.findExportByName) {
                  M.findExportByName = function (moduleName, exportName) {
                    if (arguments.length === 1) return M.findGlobalExportByName(moduleName);
                    if (moduleName === null || moduleName === undefined) return M.findGlobalExportByName(exportName);
                    var m = moduleOf(moduleName);
                    return m === null ? null : m.findExportByName(exportName);
                  };
                }
                if (!M.getExportByName) {
                  M.getExportByName = function (moduleName, exportName) {
                    if (arguments.length === 1) return M.getGlobalExportByName(moduleName);
                    if (moduleName === null || moduleName === undefined) return M.getGlobalExportByName(exportName);
                    return Process.getModuleByName(moduleName).getExportByName(exportName);
                  };
                }
                if (!M.findBaseAddress) {
                  M.findBaseAddress = function (name) {
                    var m = moduleOf(name);
                    return m === null ? null : m.base;
                  };
                }
                if (!M.getBaseAddress) {
                  M.getBaseAddress = function (name) { return Process.getModuleByName(name).base; };
                }
                ['enumerateExports', 'enumerateImports', 'enumerateSymbols'].forEach(function (method) {
                  if (!M[method]) {
                    M[method] = function (name) { return Process.getModuleByName(name)[method](); };
                  }
                });
                ['enumerateModules', 'enumerateThreads', 'enumerateRanges', 'enumerateMallocRanges'].forEach(function (name) {
                  if (!Process[name + 'Sync'] && Process[name]) {
                    Process[name + 'Sync'] = function () { return Process[name].apply(Process, arguments); };
                  }
                });
              } catch (e) {}
            })();
        """.trimIndent() + "\n" +
            "try { send(['frida:stdout', '[dexmcp] ready\\n']); } catch (e) {}\n"
    }

    private val bridgeSource: String by lazy {
        try {
            appContext.assets.open(BRIDGE_ASSET).use { it.readBytes().toString(Charsets.UTF_8) }
        } catch (t: Throwable) {
            ""
        }
    }

    private val appContext = context.applicationContext
    private val store = File(appContext.filesDir, "frida_sessions.json")
    private val live = HashMap<String, Process>()
    private val launcherOutputs = HashMap<String, ByteArrayOutputStream>()
    private val sessions = LinkedHashMap<String, FridaSession>()
    private var loaded = false

    /** Packages whose process was (re)started by an MCP tool a moment ago. */
    private val manualStarts = java.util.concurrent.ConcurrentHashMap<String, Long>()

    fun isRecentlyStartedManually(pkg: String, windowMs: Long = 20_000): Boolean {
        val at = manualStarts[pkg] ?: return false
        return System.currentTimeMillis() - at < windowMs
    }

    class FridaSession(
        val id: String,
        var packageName: String,
        var pid: Int,
        var mode: String,
        val runtime: String,
        val processName: String,
        val scriptName: String,
        val dir: String,
        var createdAt: Long,
        var updatedAt: Long,
        var stopped: Boolean,
        var note: String?
    )

    private data class SessionState(val agentPid: Int?, val agentAlive: Boolean, val logSize: Long)
    private data class LogChunk(val text: String, val nextOffset: Long, val size: Long)

    fun status(): JSONObject {
        val root = RootRunner.isAvailable()
        val installed = if (root) installedVersion()?.takeIf { installedFlavor() == RUNTIME_FLAVOR } else null
        val items = sessionItems()
        return jsonObject(
            "root" to root,
            "arm64" to Build.SUPPORTED_ABIS.contains("arm64-v8a"),
            "bundled_version" to VERSION,
            "installed_version" to installed,
            "binary" to BINARY,
            "base_dir" to BASE_DIR,
            "agents_dir" to AGENTS_DIR,
            "autostart_enabled" to ServerConfig.autostartEnabled(appContext),
            "agent_script_count" to runCatching { agentScriptCount() }.getOrDefault(0),
            "session_count" to items.size,
            "sessions" to JSONArray(items)
        )
    }

    fun prepare(args: JSONObject): JSONObject {
        requireRoot()
        ensureArm64()
        val force = args.optBoolean("force", false)
        ensureInstalled(force)
        AppLog.info("Frida: 运行时就绪（$VERSION）")
        return jsonObject(
            "installed" to true,
            "version" to VERSION,
            "binary" to BINARY,
            "sessions_dir" to SESSIONS_DIR,
            "hint" to "Call android_frida_run with a package and a JavaScript source to start a session."
        )
    }

    @Synchronized
    fun run(args: JSONObject): JSONObject {
        val pkg = args.optString("package").trim()
        require(pkg.isNotEmpty()) { "package is required" }
        require(pkg != appContext.packageName) { "Cannot instrument Dex MCP itself" }
        val script = args.optString("script")
        require(script.isNotBlank()) { "script is required" }
        val mode = args.optString("mode", "attach")
        require(mode == "attach" || mode == "spawn") { "mode must be attach or spawn" }
        val runtime = args.optString("runtime", "qjs")
        require(runtime == "qjs" || runtime == "v8") { "runtime must be qjs or v8" }
        val processName = args.optString("process").trim()
        val scriptName = sanitizeScriptName(args.optString("name", "hook.js"))
        val restart = if (args.has("restart")) args.optBoolean("restart") else !isSystemPackage(pkg)
        val waitMs = args.optLong("wait_ms", 2_500).coerceIn(300, 30_000)

        ensureArm64()
        ensureInstalled(false)
        installedApp(pkg)
        if (restart) manualStarts[pkg] = System.currentTimeMillis()

        val id = newId()
        val dir = "$SESSIONS_DIR/$id"
        sh("mkdir -p '$dir' && chmod 700 '$dir'")
        writeFile("$dir/$scriptName", composeScript(script))
        sh("chmod 644 '$dir/$scriptName'")

        val session = FridaSession(
            id = id,
            packageName = pkg,
            pid = 0,
            mode = mode,
            runtime = runtime,
            processName = processName,
            scriptName = scriptName,
            dir = dir,
            createdAt = now(),
            updatedAt = now(),
            stopped = false,
            note = null
        )
        sessions[id] = session
        persist()

        try {
            val pid = when {
                mode == "spawn" -> {
                    if (restart) RootRunner.run("am force-stop '$pkg' 2>/dev/null || true", 20_000)
                    null
                }
                processName.isNotEmpty() -> {
                    if (restart) restartApp(pkg, 8_000)
                    waitForProcess(processName, waitMs)
                }
                else -> {
                    val running = findPid(pkg)
                    if (restart || running == null) restartApp(pkg, 8_000) else running
                }
            }
            session.pid = pid ?: 0
            launch(session, pid)
            Thread.sleep(waitMs)
            if (session.pid <= 0) session.pid = findPid(processTarget(session)) ?: 0
            session.updatedAt = now()
            persist()
            pruneSessions()
            AppLog.info("Frida: 会话 ${session.id} 已启动 ${pkg} ${mode} pid=${session.pid}")
            val state = probe(session)
            val chunk = readLog(session, 0, 262_144, state.logSize)
            val result = describe(session, chunk, state)
            val selinuxFailure = chunk.text.contains("Unable to save SELinux policy") ||
                chunk.text.contains("Unable to load SELinux policy") ||
                chunk.text.contains("unlabeled") ||
                chunk.text.contains("Agent connection closed")
            if (selinuxFailure) {
                result.put("error", "selinux_patch_failed")
                result.put(
                    "hint",
                    "frida-inject could not patch the SELinux policy before attaching; this is an environment " +
                        "problem, not a script error. Call android_system_selinux with state=permissive, then " +
                        "android_frida_reload, and restore state=enforcing afterwards."
                )
                result.put(
                    "troubleshoot",
                    "SELinux policy patching failed. Call android_system_selinux with state=permissive, " +
                        "then android_frida_reload; restore state=enforcing when finished."
                )
            }
            return result
        } catch (t: Throwable) {
            session.note = t.message ?: t.javaClass.simpleName
            session.stopped = true
            session.updatedAt = now()
            stopInjector(session)
            persist()
            AppLog.error("Frida: ${pkg} 注入失败：${session.note}")
            val state = probe(session)
            return describe(session, readLog(session, 0, 262_144, state.logSize), state)
                .put("error", session.note)
        }
    }

    fun reload(args: JSONObject): JSONObject {
        val session = requireSession(args.optString("session_id"))
        val before = probe(session).logSize
        args.optString("script").takeIf { it.isNotBlank() }?.let {
            writeFile("${session.dir}/${session.scriptName}", composeScript(it))
            sh("chmod 644 '${session.dir}/${session.scriptName}'")
        }
        stopInjector(session)
        var pid = findPid(processTarget(session))
        if (pid == null) {
            require(args.optBoolean("restart", true)) {
                "Target process is gone; call android_frida_run with restart=true"
            }
            restartApp(session.packageName, 8_000)
            pid = waitForProcess(processTarget(session), 5_000)
        }
        session.pid = pid ?: 0
        session.stopped = false
        session.note = null
        session.updatedAt = now()
        launch(session, pid, forceAttach = true)
        Thread.sleep(1_200)
        val state = probe(session)
        persist()
        AppLog.info("Frida: 已重新附加会话 ${session.id} pid=$pid")
        // Only the output produced by this reload; older lines stay behind the offset API.
        return describe(session, readLog(session, before, 262_144, state.logSize), state)
    }

    fun stop(args: JSONObject): JSONObject {
        val session = requireSession(args.optString("session_id"))
        stopInjector(session)
        if (args.optBoolean("kill_app", false)) {
            RootRunner.run("am force-stop '${session.packageName}' 2>/dev/null || true", 20_000)
        }
        session.stopped = true
        session.updatedAt = now()
        persist()
        AppLog.info("Frida: 已断开会话 ${session.id}")
        return describe(session, null, probe(session))
    }

    fun output(args: JSONObject): JSONObject {
        val session = requireSession(args.optString("session_id"))
        val offset = args.optLong("offset", 0).coerceAtLeast(0)
        val maxBytes = args.optInt("max_bytes", 262_144).coerceIn(1, 262_144)
        val state = probe(session)
        val start = if (offset > state.logSize) state.logSize else offset
        return describe(session, readLog(session, start, maxBytes, state.logSize), state)
    }

    fun clearLog(args: JSONObject): JSONObject {
        val session = requireSession(args.optString("session_id"))
        RootRunner.run(": > '${session.dir}/output.log'", 20_000)
        AppLog.info("Frida: 已清空会话 ${session.id} 日志")
        return jsonObject("session_id" to session.id, "cleared" to true, "log_bytes" to 0)
    }

    fun list(): JSONObject {
        val items = sessionItems()
        return jsonObject("items" to JSONArray(items), "count" to items.size)
    }

    fun restart(args: JSONObject): JSONObject {
        val pkg = args.optString("package").trim()
        require(pkg.isNotEmpty()) { "package is required" }
        require(pkg != appContext.packageName) { "Cannot restart Dex MCP itself" }
        ensureArm64()
        installedApp(pkg)
        val waitMs = args.optLong("wait_ms", 8_000).coerceIn(500, 30_000)
        manualStarts[pkg] = System.currentTimeMillis()
        val pid = restartApp(pkg, waitMs)
        return jsonObject("package" to pkg, "pid" to pid, "restarted" to true)
    }

    fun selinux(args: JSONObject): JSONObject {
        requireRoot()
        val requested = args.optString("state", "status")
        require(requested == "status" || requested == "permissive" || requested == "enforcing") {
            "state must be status, permissive or enforcing"
        }
        val before = currentSelinuxMode()
        var error: String? = null
        if (requested != "status") {
            val target = if (requested == "permissive") "0" else "1"
            val result = RootRunner.run(
                "setenforce $target 2>/dev/null || toybox echo $target > /sys/fs/selinux/enforce 2>/dev/null",
                20_000
            )
            if (result.exitCode != 0) error = (result.text + " " + result.stderr).trim().ifBlank { "exit ${result.exitCode}" }
        }
        val current = currentSelinuxMode()
        if (requested != "status" && current != before) {
            AppLog.warn("SELinux: $before -> $current")
        }
        return jsonObject(
            "requested" to requested,
            "before" to before,
            "current" to current,
            "enforcing" to (current == "Enforcing"),
            "changed" to (requested != "status" && current != before),
            "error" to error
        )
    }

    private fun currentSelinuxMode(): String =
        RootRunner.run("getenforce 2>/dev/null || toybox cat /sys/fs/selinux/enforce 2>/dev/null", 15_000).text.trim()

    // region startup injection (LSPosed hook)

    private fun requirePackage(pkg: String) {
        require(pkg.matches(Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$"))) {
            "Invalid package name: $pkg"
        }
    }

    fun listAgentScripts(): JSONObject {
        requireRoot()
        val result = RootRunner.run(
            "for f in '$AGENTS_DIR'/*.js; do [ -f \"\$f\" ] || continue; " +
                "toybox echo \"\${f##*/} \$(toybox wc -c < \"\$f\")\"; done",
            20_000
        )
        val items = JSONArray()
        for (line in result.text.lineSequence()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            val parts = trimmed.split(Regex("\\s+"), limit = 2)
            val name = parts[0]
            if (!name.endsWith(".js")) continue
            items.put(
                jsonObject(
                    "package" to name.removeSuffix(".js"),
                    "bytes" to (parts.getOrNull(1)?.toLongOrNull() ?: 0L)
                )
            )
        }
        return jsonObject("directory" to AGENTS_DIR, "items" to items, "count" to items.length())
    }

    fun agentScriptCount(): Int = listAgentScripts().optInt("count", 0)

    fun hasAgentScript(pkg: String): Boolean = fileSize("$AGENTS_DIR/$pkg.js") != null

    fun setAgentScript(pkg: String, script: String): JSONObject {
        requireRoot()
        requirePackage(pkg)
        require(script.isNotBlank()) { "script is required" }
        sh("mkdir -p '$AGENTS_DIR' && chmod 700 '$AGENTS_DIR'")
        val path = "$AGENTS_DIR/$pkg.js"
        writeFile(path, script)
        sh("chmod 600 '$path'")
        AppLog.info("Frida: 已写入启动脚本 $pkg（${script.toByteArray().size} 字节）")
        return jsonObject("package" to pkg, "path" to path, "bytes" to script.toByteArray().size)
    }

    fun deleteAgentScript(pkg: String): JSONObject {
        requireRoot()
        requirePackage(pkg)
        val result = RootRunner.run("rm -f '$AGENTS_DIR/$pkg.js'", 20_000)
        check(result.exitCode == 0) { "Cannot delete script: ${result.stderr}" }
        AppLog.info("Frida: 已删除启动脚本 $pkg")
        return jsonObject("package" to pkg, "deleted" to true)
    }

    fun findLiveSession(pkg: String, pid: Int): FridaSession? {
        loadIfNeeded()
        val candidates = sessions.values.filter { !it.stopped && it.pid == pid && it.packageName == pkg }
        return candidates.firstOrNull { session ->
            val state = probe(session)
            state.agentAlive || live[session.id]?.isAlive == true
        }
    }

    fun isRuntimeReady(): Boolean = installedVersion() == VERSION && installedFlavor() == RUNTIME_FLAVOR

    /**
     * Attach to an already running process (used by the LSPosed startup hook while the
     * app is paused) and wait until the script runtime reports that it is up.
     */
    @Synchronized
    fun injectStartup(pkg: String, pid: Int, timeoutMs: Long = 6_000): JSONObject {
        requirePackage(pkg)
        require(pid > 0) { "pid is required" }
        require(pkg != appContext.packageName) { "Cannot instrument Dex MCP itself" }
        ensureArm64()
        ensureInstalled(false)
        val script = RootRunner.run("toybox cat '$AGENTS_DIR/$pkg.js' 2>/dev/null", 30_000).stdout
        require(script.isNotEmpty()) { "No startup script for $pkg" }

        // Only one main process per package can be alive; older startup sessions are stale.
        retireSessions(pkg, pid)

        val id = newId()
        val dir = "$SESSIONS_DIR/$id"
        sh("mkdir -p '$dir' && chmod 700 '$dir'")
        val scriptName = "startup.js"
        writeFile("$dir/$scriptName", composeScript(String(script, Charsets.UTF_8)))
        sh("chmod 644 '$dir/$scriptName'")
        val session = FridaSession(
            id = id,
            packageName = pkg,
            pid = pid,
            mode = "attach",
            runtime = "qjs",
            processName = "",
            scriptName = scriptName,
            dir = dir,
            createdAt = now(),
            updatedAt = now(),
            stopped = false,
            note = null
        )
        sessions[id] = session
        persist()
        launch(session, pid)
        val deadline = System.currentTimeMillis() + timeoutMs
        var ready = false
        while (System.currentTimeMillis() < deadline) {
            val state = probe(session)
            val chunk = readLog(session, 0, 65_536, state.logSize)
            if (chunk.text.contains("dexmcp] ready")) {
                ready = true
                break
            }
            if (!state.agentAlive && live[id]?.isAlive != true) break
            Thread.sleep(100)
        }
        session.updatedAt = now()
        persist()
        pruneSessions()
        val state = probe(session)
        val output = readLog(session, 0, 65_536, state.logSize).text
        AppLog.info("Frida: 启动注入 $pkg pid=$pid · ${if (ready) "脚本已加载" else "未确认脚本加载"}")
        return jsonObject(
            "session_id" to id,
            "package" to pkg,
            "pid" to pid,
            "ready" to ready,
            "running" to state.agentAlive,
            "log" to "$dir/output.log",
            "output" to output.take(8_000)
        )
    }

    // endregion

    fun uiStatus(): JSONObject {
        val root = RootRunner.isAvailable()
        var size = 0L
        var installed: String? = null
        var selinux = ""
        if (root) {
            val probe = RootRunner.run(runtimeProbeCommand(), 30_000)
            val lines = probe.text.lines()
            size = lines.getOrNull(0)?.trim()?.toLongOrNull() ?: 0L
            val version = lines.getOrNull(1)?.trim()?.takeIf { it.matches(Regex("\\d+(\\.\\d+){1,3}")) }
            val flavor = lines.getOrNull(2)?.trim()
            installed = if (version == VERSION && flavor == RUNTIME_FLAVOR) version else null
            selinux = currentSelinuxMode()
        }
        val items = sessionItems()
        return jsonObject(
            "root" to root,
            "bundled_version" to VERSION,
            "installed_version" to installed,
            "binary" to BINARY,
            "binary_bytes" to size,
            "autostart_enabled" to ServerConfig.autostartEnabled(appContext),
            "agent_scripts" to runCatching { agentScriptCount() }.getOrDefault(0),
            "sessions" to items.size,
            "running_sessions" to items.count { it.optBoolean("running") },
            "selinux" to selinux
        )
    }

    fun stopAllSessions(): Int {
        var stopped = 0
        sessions.values.toList().forEach { session ->
            if (!session.stopped) {
                runCatching { stopInjector(session) }
                session.stopped = true
                session.updatedAt = now()
                stopped++
            }
        }
        if (stopped > 0) {
            persist()
            AppLog.warn("Frida: 已停止 $stopped 个会话")
        }
        return stopped
    }

    fun uninstall(): JSONObject {
        requireRoot()
        sessions.values.toList().forEach { session -> runCatching { stopInjector(session) } }
        sessions.clear()
        persist()
        val result = RootRunner.run("rm -rf '$BASE_DIR'", 60_000)
        check(result.exitCode == 0) {
            "Cannot remove $BASE_DIR: ${(result.text + " " + result.stderr).trim()}"
        }
        AppLog.info("Frida: 已卸载，删除 $BASE_DIR")
        return jsonObject("uninstalled" to true, "removed" to BASE_DIR, "bundled_version" to VERSION)
    }

    private fun runtimeProbeCommand(): String =
        "if [ -f '$BINARY' ]; then toybox wc -c < '$BINARY' | toybox tr -d ' '; else toybox echo 0; fi; " +
            "if [ -x '$BINARY' ]; then '$BINARY' --version 2>/dev/null; fi; " +
            "toybox cat '$BASE_DIR/flavor' 2>/dev/null"

    // region session internals

    private fun describe(session: FridaSession, chunk: LogChunk?, state: SessionState): JSONObject {
        val running = !session.stopped && (state.agentAlive || live[session.id]?.isAlive == true)
        val exitCode = if (running) null else live[session.id]?.let { runCatching { it.exitValue() }.getOrNull() }
        val launcher = launcherOutputs[session.id]
            ?.let { String(it.toByteArray(), Charsets.UTF_8).trim() }
            ?.takeIf { it.isNotEmpty() }
        return jsonObject(
            "session_id" to session.id,
            "package" to session.packageName,
            "pid" to session.pid,
            "agent_pid" to state.agentPid,
            "mode" to session.mode,
            "runtime" to session.runtime,
            "process" to session.processName,
            "script" to "${session.dir}/${session.scriptName}",
            "log" to "${session.dir}/output.log",
            "running" to running,
            "exit_code" to exitCode,
            "launcher" to launcher,
            "log_bytes" to state.logSize,
            "note" to session.note,
            "output" to (chunk?.text ?: ""),
            "next_offset" to (chunk?.nextOffset ?: 0),
            "hint" to "Poll android_frida_output with next_offset for new console output. Use android_frida_reload to swap the script without restarting the app."
        )
    }

    private fun sessionJson(session: FridaSession): JSONObject {
        val state = probe(session)
        val running = !session.stopped && (state.agentAlive || live[session.id]?.isAlive == true)
        return jsonObject(
            "session_id" to session.id,
            "package" to session.packageName,
            "pid" to session.pid,
            "agent_pid" to state.agentPid,
            "mode" to session.mode,
            "runtime" to session.runtime,
            "process" to session.processName,
            "script" to "${session.dir}/${session.scriptName}",
            "log" to "${session.dir}/output.log",
            "log_bytes" to state.logSize,
            "running" to running,
            "created_at" to session.createdAt,
            "updated_at" to session.updatedAt,
            "note" to session.note
        )
    }

    private fun sessionItems(): List<JSONObject> {
        loadIfNeeded()
        return sessions.values.sortedByDescending { it.createdAt }.map { sessionJson(it) }
    }

    private fun launch(session: FridaSession, pid: Int?, forceAttach: Boolean = false) {
        val target = when {
            session.mode == "spawn" && !forceAttach -> "-f ${session.packageName}"
            session.processName.isNotEmpty() -> "-n ${session.processName}"
            else -> {
                require(pid != null && pid > 0) { "Target process is not running" }
                "-p $pid"
            }
        }
        val script = buildString {
            appendLine("#!/system/bin/sh")
            appendLine("export PATH=/system/bin:/system/xbin")
            appendLine("export TMPDIR=\"${session.dir}/tmp\"")
            appendLine("mkdir -p \"\$TMPDIR\" 2>/dev/null")
            appendLine("cd '${session.dir}' || exit 3")
            appendLine("exec >> output.log 2>&1")
            appendLine("echo \"=== dexmcp ${session.mode} $target \$(date '+%F %T') ===\"")
            appendLine("echo \$\$ > agent.pid")
            appendLine("exec '$BINARY' $target -s '${session.scriptName}' -R '${session.runtime}'")
        }
        writeFile("${session.dir}/run.sh", script)
        sh("chmod 755 '${session.dir}/run.sh'")
        val process = ProcessBuilder("su", "-c", "sh '${session.dir}/run.sh'").start()
        val captured = ByteArrayOutputStream()
        launcherOutputs[session.id] = captured
        val drain = { stream: java.io.InputStream ->
            Thread {
                runCatching {
                    stream.use { input ->
                        val chunk = ByteArray(4096)
                        while (captured.size() < 8192) {
                            val read = input.read(chunk)
                            if (read <= 0) break
                            captured.write(chunk, 0, minOf(read, 8192 - captured.size()))
                        }
                        while (input.read(chunk) > 0) Unit
                    }
                }
            }.start()
        }
        drain(process.inputStream)
        drain(process.errorStream)
        runCatching { process.outputStream.close() }
        live[session.id] = process
    }

    private fun stopInjector(session: FridaSession) {
        val pid = RootRunner.run("cat '${session.dir}/agent.pid' 2>/dev/null", 15_000).text.trim().toIntOrNull()
        if (pid != null && pid > 0) {
            val cmdline = RootRunner.run("toybox cat /proc/$pid/cmdline 2>/dev/null", 15_000).text
            if (cmdline.contains("frida-inject")) {
                RootRunner.run(
                    "kill -TERM $pid 2>/dev/null; sleep 1; if [ -d /proc/$pid ]; then kill -9 $pid 2>/dev/null; fi; true",
                    25_000
                )
            }
        }
        live.remove(session.id)?.let { runCatching { it.destroy() } }
    }

    private fun probe(session: FridaSession): SessionState {
        val result = RootRunner.run(
            "p=\$(cat '${session.dir}/agent.pid' 2>/dev/null); " +
                "echo \"pid=\$p\"; " +
                "[ -n \"\$p\" ] && [ -d \"/proc/\$p\" ] && echo alive; " +
                "toybox wc -c < '${session.dir}/output.log' 2>/dev/null",
            20_000
        )
        val text = result.text
        val pid = Regex("(?m)^pid=(\\d+)$").find(text)?.groupValues?.get(1)?.toIntOrNull()
        val alive = Regex("(?m)^alive$").containsMatchIn(text)
        val size = Regex("(?m)^(\\d+)$").find(text)?.groupValues?.get(1)?.toLongOrNull() ?: 0L
        return SessionState(pid, alive, size)
    }

    private fun readLog(session: FridaSession, offset: Long, maxBytes: Int, size: Long): LogChunk {
        val start = offset.coerceAtLeast(0) + 1
        val cap = maxBytes.coerceIn(1, 262_144)
        val result = RootRunner.run(
            "toybox tail -c +$start '${session.dir}/output.log' 2>/dev/null | toybox head -c $cap",
            30_000
        )
        val body = result.stdout
        return LogChunk(ANSI.replace(String(body, Charsets.UTF_8), ""), offset.coerceAtLeast(0) + body.size, size)
    }

    private fun requireSession(id: String): FridaSession {
        require(id.isNotBlank()) { "session_id is required" }
        loadIfNeeded()
        return sessions[id] ?: error("Unknown session_id: $id")
    }

    /** Mark older startup sessions of a package as stopped before attaching to a new process. */
    private fun retireSessions(pkg: String, keepPid: Int) {
        var changed = false
        for (session in sessions.values) {
            if (!session.stopped && session.packageName == pkg &&
                session.scriptName == "startup.js" && session.pid != keepPid
            ) {
                session.stopped = true
                session.updatedAt = now()
                changed = true
            }
        }
        if (changed) persist()
    }

    private fun pruneSessions() {
        if (sessions.size <= 24) return
        val removable = sessions.values.filter { it.stopped }.sortedBy { it.updatedAt }.take(sessions.size - 24)
        for (session in removable) {
            sessions.remove(session.id)
            RootRunner.run("rm -rf '${session.dir}'", 30_000)
        }
        persist()
    }

    private fun loadIfNeeded() {
        if (loaded) return
        loaded = true
        runCatching {
            val array = JSONArray(store.readText())
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                val id = item.optString("id")
                if (id.isBlank()) continue
                sessions[id] = FridaSession(
                    id = id,
                    packageName = item.optString("package"),
                    pid = item.optInt("pid"),
                    mode = item.optString("mode", "attach"),
                    runtime = item.optString("runtime", "qjs"),
                    processName = item.optString("process"),
                    scriptName = item.optString("script", "hook.js"),
                    dir = item.optString("dir"),
                    createdAt = item.optLong("created_at"),
                    updatedAt = item.optLong("updated_at"),
                    stopped = item.optBoolean("stopped"),
                    note = item.optString("note").takeIf { it.isNotBlank() }
                )
            }
        }
    }

    private fun persist() {
        runCatching {
            val array = JSONArray()
            for (session in sessions.values) {
                array.put(
                    JSONObject()
                        .put("id", session.id)
                        .put("package", session.packageName)
                        .put("pid", session.pid)
                        .put("mode", session.mode)
                        .put("runtime", session.runtime)
                        .put("process", session.processName)
                        .put("script", session.scriptName)
                        .put("dir", session.dir)
                        .put("created_at", session.createdAt)
                        .put("updated_at", session.updatedAt)
                        .put("stopped", session.stopped)
                        .put("note", session.note ?: "")
                )
            }
            store.writeText(array.toString())
        }
    }

    // endregion

    // region target app and installation

    private fun restartApp(pkg: String, waitMs: Long): Int {
        val component = launchComponent(pkg)
            ?: error("Package $pkg has no launcher activity; start it manually, then call android_frida_run with restart=false")
        RootRunner.run("am force-stop '$pkg' 2>/dev/null || true", 20_000)
        Thread.sleep(250)
        val started = RootRunner.run("am start -W -n '$component'", 40_000)
        val combined = (started.text + "\n" + started.stderr).trim()
        if (started.exitCode != 0 || combined.contains("Error:")) {
            error("Cannot launch $pkg: $combined")
        }
        val deadline = System.currentTimeMillis() + waitMs
        while (System.currentTimeMillis() < deadline) {
            findPid(pkg)?.let { return it }
            Thread.sleep(200)
        }
        error("Timed out waiting for the $pkg process; increase wait_ms or start the app manually")
    }

    private fun waitForProcess(name: String, waitMs: Long): Int? {
        val deadline = System.currentTimeMillis() + waitMs
        while (System.currentTimeMillis() < deadline) {
            findPid(name)?.let { return it }
            Thread.sleep(200)
        }
        return null
    }

    private fun processTarget(session: FridaSession): String =
        if (session.processName.isNotEmpty()) session.processName else session.packageName

    private fun findPid(pkg: String): Int? {
        val listing = RootRunner.run(
            "ps -A -o PID,ARGS 2>/dev/null; ps -A -o pid,args 2>/dev/null; " +
                "ps -A -o PID,NAME 2>/dev/null; ps -A -o pid,name 2>/dev/null",
            20_000
        ).text
        for (line in listing.lineSequence()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("PID") || trimmed.startsWith("pid")) continue
            val parts = trimmed.split(Regex("\\s+"), limit = 2)
            if (parts.size < 2) continue
            val pid = parts[0].toIntOrNull() ?: continue
            if (parts[1].trim() == pkg) return pid
        }
        val candidates = RootRunner.run("pidof '$pkg' 2>/dev/null", 15_000).text.trim()
            .split(Regex("\\s+")).mapNotNull { it.toIntOrNull() }.take(4)
        for (candidate in candidates) {
            val name = RootRunner.run(
                "toybox cat /proc/$candidate/cmdline 2>/dev/null | toybox tr '\\0' '\\n' | toybox head -n 1",
                15_000
            ).text.trim()
            if (name == pkg) return candidate
        }
        return candidates.firstOrNull()
    }

    private fun launchComponent(pkg: String): String? {
        val intent = runCatching { appContext.packageManager.getLaunchIntentForPackage(pkg) }.getOrNull()
        return intent?.component?.flattenToString()
    }

    private fun installedApp(pkg: String) {
        try {
            appContext.packageManager.getPackageInfo(pkg, 0)
        } catch (t: Throwable) {
            error("Package $pkg is not installed or not visible: ${t.message ?: t.javaClass.simpleName}")
        }
    }

    /** System / priv-app packages: restarting them by default can break device services. */
    private fun isSystemPackage(pkg: String): Boolean = runCatching {
        val info = appContext.packageManager.getApplicationInfo(pkg, 0)
        (info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
    }.getOrDefault(false)

    private fun ensureInstalled(force: Boolean) {
        requireRoot()
        ensureArm64()
        if (!force && installedVersion() == VERSION && installedFlavor() == RUNTIME_FLAVOR) return
        install()
    }

    private fun installedVersion(): String? {
        val result = RootRunner.run("[ -x '$BINARY' ] && '$BINARY' --version 2>/dev/null", 30_000)
        val value = result.text.trim().lines().firstOrNull()?.trim().orEmpty()
        return value.takeIf { it.matches(Regex("\\d+(\\.\\d+){1,3}")) }
    }

    private fun installedFlavor(): String? =
        RootRunner.run("toybox cat '$BASE_DIR/flavor' 2>/dev/null", 15_000).text.trim().takeIf { it.isNotEmpty() }

    private fun install() {
        val prepared = RootRunner.run(
            "mkdir -p '$BASE_DIR' '$SESSIONS_DIR' '$AGENTS_DIR' && chmod 700 '$BASE_DIR' '$SESSIONS_DIR' '$AGENTS_DIR' && " +
                "rm -f '$BASE_DIR'/helper-*.dex",
            30_000
        )
        check(prepared.exitCode == 0) { "Cannot create $BASE_DIR: ${prepared.stderr}" }
        val asset = try {
            appContext.assets.open(ASSET)
        } catch (t: Throwable) {
            error("The APK does not contain $ASSET: ${t.message ?: t.javaClass.simpleName}")
        }
        val temp = "$BINARY.tmp"
        RootRunner.run("rm -f '$temp'", 10_000)
        AppLog.info("Frida: 正在写入 frida-inject（$VERSION，约 85 MB）")
        var expected = 0L
        val written = RootRunner.stream("cat > '$temp'", 300_000) { output ->
            asset.use { input ->
                val buffer = ByteArray(256 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    output.write(buffer, 0, read)
                    expected += read
                }
            }
        }
        if (written.exitCode != 0 || written.timedOut) {
            RootRunner.run("rm -f '$temp'", 10_000)
            error("Cannot extract frida-inject: ${written.stderr.ifBlank { "exit ${written.exitCode}" }}")
        }
        val extracted = fileSize(temp)
        if (extracted != expected) {
            RootRunner.run("rm -f '$temp'", 10_000)
            error("frida-inject extraction is incomplete: expected $expected bytes, wrote ${extracted ?: -1}")
        }
        val checked = RootRunner.run(
            "chmod 755 '$temp' && '$temp' --version && mv -f '$temp' '$BINARY'",
            60_000
        )
        if (checked.exitCode != 0 || checked.text.trim() != VERSION) {
            RootRunner.run("rm -f '$temp'", 10_000)
            AppLog.error("Frida: 写入校验失败")
            error("frida-inject is not runnable: ${(checked.text + " " + checked.stderr).trim()}")
        }
        AppLog.info("Frida: 安装完成，$expected 字节")
        RootRunner.run("printf '%s' '$RUNTIME_FLAVOR' > '$BASE_DIR/flavor'", 15_000)
    }

    private fun ensureArm64() {
        check(Build.SUPPORTED_ABIS.contains("arm64-v8a")) {
            "The bundled frida-inject only supports arm64-v8a devices: ${Build.SUPPORTED_ABIS.joinToString()}"
        }
    }

    private fun requireRoot() {
        check(RootRunner.isAvailable()) { "Root shell is unavailable; grant superuser access to Dex MCP first" }
    }

    // endregion

    private fun composeScript(script: String): String {
        check(bridgeSource.isNotBlank()) {
            "The APK does not contain $BRIDGE_ASSET; rebuild with the frida-java-bridge bundle in assets"
        }
        return PRELUDE + bridgeSource + "\n" + script
    }

    private fun sh(command: String, timeoutMs: Long = 30_000): RootResult {
        val result = RootRunner.run(command, timeoutMs)
        check(result.exitCode == 0) {
            "Root command failed: ${(result.text + " " + result.stderr).trim().ifBlank { "exit ${result.exitCode}" }}"
        }
        return result
    }

    private fun writeFile(path: String, content: String) {
        val bytes = content.toByteArray(Charsets.UTF_8)
        val direct = RootRunner.run("cat > '$path'", 120_000, input = bytes)
        if (direct.exitCode != 0 || direct.timedOut || fileSize(path) != bytes.size.toLong()) {
            // Fallback for su variants that do not forward stdin to the command.
            val encoded = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
            RootRunner.run("printf '%s' '$encoded' | toybox base64 -d > '$path'", 120_000)
        }
        val written = fileSize(path)
        check(written == bytes.size.toLong()) {
            "Cannot write $path: expected ${bytes.size} bytes, got ${written ?: -1} (${direct.stderr})"
        }
    }

    private fun fileSize(path: String): Long? =
        RootRunner.run("toybox wc -c < '$path' 2>/dev/null", 20_000).text.trim().toLongOrNull()

    private fun sanitizeScriptName(raw: String): String {
        val base = raw.substringAfterLast('/').replace(Regex("[^A-Za-z0-9._-]"), "_").trim('_')
        val name = if (base.isBlank()) "hook.js" else base
        return (if (name.endsWith(".js")) name else "$name.js").take(64)
    }

    private fun newId(): String =
        SimpleDateFormat("MMdd-HHmmss", Locale.US).format(Date()) + "-" + (0x1000..0xffff).random().toString(16)

    private fun now(): Long = System.currentTimeMillis()
}
