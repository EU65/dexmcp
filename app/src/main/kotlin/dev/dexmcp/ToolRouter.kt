package dev.dexmcp

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.Charset

class ToolRouter(private val context: Context) {
    private val root = RootAccess(context)
    private val imports = ImportStore(context)
    private val workspaces = WorkspaceManager(context, root)
    private val analyzer = DexAnalyzer()
    private val logs = LogRepository(context, root)
    private val diagnostics = SystemDiagnostics(context, root)
    private val exports = FileExports(context, root)
    private val frida = FridaManager.get(context)

    fun toolDefinitions(): JSONArray = jsonArray(
        listOf(
            tool("android_system_export_file", "Prepare a stable copy of a phone file for downloading to the agent workspace. Returns export_id, size and SHA-256; path access follows the App switch.", mapOf("path" to stringSchema("Absolute source file path")), listOf("path")),
            tool("android_system_read_export", "Download one Base64 chunk of a prepared export; decode and write bytes in the agent workspace, repeat until eof.", mapOf("export_id" to stringSchema("Export ID"), "offset" to integerSchema("Byte offset"), "max_bytes" to integerSchema("Chunk bytes, capped at 65536")), listOf("export_id")),
            tool("android_system_delete_export", "Remove a temporary downloaded file copy from App cache.", mapOf("export_id" to stringSchema("Export ID")), listOf("export_id")),
            tool("android_system_get_summary", "Get Android build, ABI and root availability.", emptyMap()),
            tool("android_system_search_packages", "Search installed packages and return UID and APK paths.", mapOf(
                "query" to stringSchema("Package name or label substring"),
                "system_only" to booleanSchema("Only system packages"),
                "cursor" to stringSchema("Cursor returned by the previous call"),
                "limit" to integerSchema("Maximum results, 1-200")
            )),
            tool("android_system_read_file", "Read a bounded byte range; allowed paths follow the App allow-any-file switch. Uses root when needed. ZIP/ELF/PNG/DEX content is reported as is_binary instead of being decoded as text.", mapOf(
                "path" to stringSchema("Absolute path (App path-access policy applies)"),
                "offset" to integerSchema("Byte offset"),
                "max_bytes" to integerSchema("Maximum bytes, capped at 65536"),
                "format" to enumSchema("text", "hex", "base64", "auto")
            ), listOf("path")),
            tool("android_system_list_directory", "List directory entries under the App path-access policy without following symlinks. Entries include files and directories.", mapOf(
                "path" to stringSchema("Absolute directory (App path-access policy applies)"),
                "query" to stringSchema("Case-insensitive filename substring"),
                "cursor" to stringSchema("Cursor from previous call; keep other arguments identical"),
                "limit" to integerSchema("Page size, 1-200")
            ), listOf("path")),
            tool("android_system_find_files", "Discover system files and directories by filename; bounded depth/time, no symlink traversal.", mapOf(
                "path" to stringSchema("Absolute starting directory (App path-access policy applies)"),
                "query" to stringSchema("Case-insensitive filename substring"),
                "max_depth" to integerSchema("Traversal depth, 1-8; default 4"),
                "cursor" to stringSchema("Cursor from previous call; keep other arguments identical"),
                "limit" to integerSchema("Page size, 1-200")
            ), listOf("path")),
            tool("android_system_collect_snapshot", "Collect device, network or stylus diagnostics; saved by default across App restarts. Each section reports errors separately.", mapOf(
                "profile" to enumSchema("network", "device", "stylus"),
                "label" to stringSchema("For example stock-kernel or custom-kernel"),
                "save" to booleanSchema("Persist in App private files; default true")
            ), listOf("profile")),
            tool("android_system_list_snapshots", "List saved diagnostic snapshots, newest first.", emptyMap()),
            tool("android_system_get_snapshot", "Retrieve a saved snapshot or one original section; Markdown is suitable for exporting a report.", mapOf(
                "snapshot_id" to stringSchema("Saved snapshot ID"),
                "section" to stringSchema("Optional exact section name; overrides format"),
                "format" to enumSchema("json", "markdown")
            ), listOf("snapshot_id")),
            tool("android_system_compare_snapshots", "Compare saved diagnostic sections and report changed lines, errors and truncation. Differences are not proof of causation.", mapOf(
                "before_id" to stringSchema("Baseline snapshot ID"),
                "after_id" to stringSchema("Comparison snapshot ID"),
                "sections" to arraySchema(stringSchema("Optional section names")),
                "line_limit" to integerSchema("Added/removed lines per section, 1-500; default 100")
            ), listOf("before_id", "after_id")),
            tool("android_system_delete_snapshot", "Delete one saved diagnostic snapshot from App private storage.", mapOf(
                "snapshot_id" to stringSchema("Saved snapshot ID")
            ), listOf("snapshot_id")),
            tool("android_logs_list", "List available live and persistent KernelSU/LSP log sources.", mapOf(
                "limit" to integerSchema("Maximum historical files, 1-500")
            )),
            tool("android_logs_query", "Search, filter, tail and paginate live or historical logcat, dmesg and LSP logs.", mapOf(
                "source" to enumSchema("logcat_live", "dmesg_live", "ksu_logcat", "ksu_dmesg", "lspd", "all_history"),
                "paths" to arraySchema(stringSchema("Exact historical paths returned by android_logs_list; overrides source discovery")),
                "query" to stringSchema("Literal or regular expression; blank enables tail mode"),
                "regex" to booleanSchema("Interpret query as a regular expression"),
                "ignore_case" to booleanSchema("Case-insensitive matching"),
                "include" to arraySchema(stringSchema("At least one included substring must match")),
                "exclude" to arraySchema(stringSchema("Exclude lines containing any substring")),
                "levels" to arraySchema(enumSchema("V", "D", "I", "W", "E", "F")),
                "tags" to arraySchema(stringSchema("Android log tags or other identifying substrings")),
                "context_before" to integerSchema("Context lines before a hit, 0-20"),
                "context_after" to integerSchema("Context lines after a hit, 0-20"),
                "latest_files" to integerSchema("Historical files per source, 1-20"),
                "live_lines" to integerSchema("Lines requested from a live buffer, 1-5000"),
                "tail_lines" to integerSchema("Lines returned when query is blank, 1-1000"),
                "cursor" to stringSchema("Cursor returned by the previous query"),
                "limit" to integerSchema("Maximum matching lines, 1-300")
            ), listOf("source")),
            tool("android_analysis_list_imports", "List files imported through the Android file picker. No root is required.", emptyMap()),
            tool("android_analysis_open", "Create a read-only APK/JAR/DEX workspace from an import, installed package, or allowlisted path.", mapOf(
                "package" to stringSchema("Installed package name"),
                "path" to stringSchema("Absolute APK/JAR/DEX path"),
                "import_id" to stringSchema("ID returned by android_analysis_list_imports"),
                "title" to stringSchema("Workspace title"),
                "include_splits" to booleanSchema("Include split APK files")
            )),
            tool("android_analysis_close", "Close a workspace and delete its derived cache.", mapOf(
                "workspace_id" to stringSchema("Workspace ID")
            ), listOf("workspace_id")),
            tool("android_analysis_list", "List workspace artifacts, ZIP entries, DEX files, or DEX classes with cursor pagination. zip_entries and dex_classes accept query/regex/artifact_id filters.", mapOf(
                "workspace_id" to stringSchema("Workspace ID"),
                "kind" to enumSchema("artifacts", "zip_entries", "dex_files", "dex_classes"),
                "query" to stringSchema("Filter on entry path or class descriptor"),
                "regex" to booleanSchema("Interpret query as a regular expression"),
                "ignore_case" to booleanSchema("Case-insensitive filter; default true"),
                "artifact_id" to stringSchema("Only entries of this artifact"),
                "cursor" to stringSchema("Opaque cursor returned by the previous call"),
                "limit" to integerSchema("Page size, 1-200")
            ), listOf("workspace_id", "kind")),
            tool("android_analysis_outline_class", "Return fields and methods for an exact DEX class descriptor.", mapOf(
                "workspace_id" to stringSchema("Workspace ID"),
                "class" to stringSchema("Class descriptor, for example Landroid/foo/Bar;")
            ), listOf("workspace_id", "class")),
            tool("android_analysis_search", "Search DEX class, method, field descriptors and string pools; supports regex, a class prefix scope and cross-kind dedupe.", mapOf(
                "workspace_id" to stringSchema("Workspace ID"),
                "query" to stringSchema("Literal substring, or regular expression with regex=true"),
                "regex" to booleanSchema("Interpret query as a regular expression"),
                "in_class_prefix" to stringSchema("Only classes whose descriptor starts with this prefix, for example Lcom/oplus/nfc/; with dex_string it scans strings referenced by those classes"),
                "dedupe" to booleanSchema("Drop dex_string hits already covered by a class/method/field descriptor; default true"),
                "kinds" to arraySchema(enumSchema("class", "method", "field", "dex_string")),
                "ignore_case" to booleanSchema("Case-insensitive matching"),
                "cursor" to stringSchema("Cursor"),
                "limit" to integerSchema("Page size, 1-200")
            ), listOf("workspace_id", "query")),
            tool("android_analysis_read", "Read decoded manifest, ZIP text, class Smali, or method Smali with character pagination. Use ids for batch method/class reads.", mapOf(
                "workspace_id" to stringSchema("Workspace ID"),
                "type" to enumSchema("manifest", "zip_entry", "class", "method"),
                "artifact_id" to stringSchema("Artifact ID for manifest or ZIP reads"),
                "path" to stringSchema("ZIP entry path"),
                "id" to stringSchema("Exact class or method descriptor"),
                "ids" to arraySchema(stringSchema("Batch: several class or method descriptors")),
                "offset" to integerSchema("Character offset for pagination; use next_offset from the previous response"),
                "no_bodies" to booleanSchema("type=class: only fields and method signatures"),
                "max_chars" to integerSchema("Characters per page, default 16000, max 200000")
            ), listOf("workspace_id", "type")),
            tool("android_analysis_xref_dex", "Find DEX instructions referencing a class, field, method or string. Method/field targets without a signature match every overload; context_instructions adds surrounding Smali.", mapOf(
                "workspace_id" to stringSchema("Workspace ID"),
                "target" to stringSchema("DEX descriptor; Lcom/x/Y;->playSound matches all overloads"),
                "context_instructions" to integerSchema("Smali instructions before and after each hit, 0-64"),
                "limit" to integerSchema("Maximum hits, 1-300")
            ), listOf("workspace_id", "target")),
            tool("android_frida_status", "Check root, the bundled frida-inject version and active dynamic-analysis sessions.", emptyMap()),
            tool("android_frida_prepare", "Extract the bundled arm64 frida-inject into /data/adb/dexmcp and verify it runs. Root is required.", mapOf(
                "force" to booleanSchema("Reinstall even when the installed version already matches")
            )),
            tool("android_frida_run", "Start dynamic analysis: optionally restart the target app, attach or spawn it with Frida and load a JavaScript file. Returns a session_id plus the first console output. Root is required. console.log output is captured; use Java.perform/Java.use for Java hooks.", mapOf(
                "package" to stringSchema("Target package name"),
                "script" to stringSchema("Complete JavaScript source for this session"),
                "process" to stringSchema("Optional process name such as com.app:push; default is the app main process"),
                "name" to stringSchema("Script filename inside the session; default hook.js"),
                "mode" to enumSchema("attach", "spawn"),
                "runtime" to enumSchema("qjs", "v8"),
                "restart" to booleanSchema("Force-stop and relaunch the app first; defaults to false for system/priv-app packages, true otherwise"),
                "wait_ms" to integerSchema("Milliseconds to wait for load and first output, 300-30000")
            ), listOf("package", "script")),
            tool("android_frida_output", "Read new Frida console output since a byte offset. Pass next_offset from the previous response.", mapOf(
                "session_id" to stringSchema("Session ID"),
                "offset" to integerSchema("Byte offset; use next_offset from the previous call"),
                "max_bytes" to integerSchema("Maximum new bytes, 1-262144")
            ), listOf("session_id")),
            tool("android_frida_clear_log", "Truncate a session log so the next android_frida_output starts from offset 0.", mapOf(
                "session_id" to stringSchema("Session ID")
            ), listOf("session_id")),
            tool("android_frida_reload", "Optionally replace the session script, detach and re-attach without restarting the app. Falls back to a restart only when the target process is gone.", mapOf(
                "session_id" to stringSchema("Session ID"),
                "script" to stringSchema("New JavaScript source; omit to reload the existing file"),
                "restart" to booleanSchema("Relaunch the app when its process is gone; default true")
            ), listOf("session_id")),
            tool("android_frida_stop", "Detach Frida from the target and optionally force-stop the app.", mapOf(
                "session_id" to stringSchema("Session ID"),
                "kill_app" to booleanSchema("Also force-stop the target app")
            ), listOf("session_id")),
            tool("android_frida_sessions", "List Frida sessions with target package, pid, mode and log length.", emptyMap()),
            tool("android_frida_restart_app", "Force-stop and relaunch an app, then return its main process id.", mapOf(
                "package" to stringSchema("Target package name"),
                "wait_ms" to integerSchema("Milliseconds to wait for the process, 500-30000")
            ), listOf("package")),
            tool("android_frida_agent_scripts", "List startup scripts used by the LSPosed hook: when a selected app launches, Dex MCP attaches Frida and loads /data/adb/dexmcp/agents/<package>.js before the app continues.", emptyMap()),
            tool("android_frida_agent_set", "Create or replace the startup script for a package and enable it. The LSPosed hook injects it on the next launch of that app.", mapOf(
                "package" to stringSchema("Target package name"),
                "script" to stringSchema("JavaScript source, same API as android_frida_run")
            ), listOf("package", "script")),
            tool("android_frida_agent_delete", "Delete the startup script for a package and turn its startup injection off.", mapOf(
                "package" to stringSchema("Target package name")
            ), listOf("package")),
            tool("android_frida_agent_enable", "Turn startup injection on or off for a package without touching its script.", mapOf(
                "package" to stringSchema("Target package name"),
                "enabled" to booleanSchema("true to inject this package's startup script on launch")
            ), listOf("package", "enabled")),
            tool("android_frida_autostart", "Read or change the global startup-injection switch used by the LSPosed hook.", mapOf(
                "enabled" to booleanSchema("true to allow the hook to inject at app launch; omit to read the current value")
            )),
            tool("android_system_selinux", "Read or change the device SELinux mode. Use permissive only as a temporary fallback when injection is blocked by policy and restore enforcing afterwards.", mapOf(
                "state" to enumSchema("status", "permissive", "enforcing")
            ))
        )
    )

    fun call(name: String, args: JSONObject): JSONObject {
        if (name.startsWith("android_frida_") && !ServerConfig.fridaEnabled(context)) {
            return toolResult(
                jsonObject(
                    "error" to "Frida is disabled in the App; enable it on the device before calling $name",
                    "frida_enabled" to false
                ),
                true
            )
        }
        return try {
            val data = when (name) {
                "android_system_export_file" -> exports.prepare(args)
                "android_system_read_export" -> exports.read(args)
                "android_system_delete_export" -> exports.delete(args)
                "android_system_get_summary" -> systemSummary()
                "android_system_search_packages" -> searchPackages(args)
                "android_system_read_file" -> readSystemFile(args)
                "android_system_list_directory" -> diagnostics.discover(args, false)
                "android_system_find_files" -> diagnostics.discover(args, true)
                "android_system_collect_snapshot" -> diagnostics.collect(args)
                "android_system_list_snapshots" -> diagnostics.list()
                "android_system_get_snapshot" -> diagnostics.get(args)
                "android_system_compare_snapshots" -> diagnostics.compare(args)
                "android_system_delete_snapshot" -> diagnostics.delete(args.getString("snapshot_id"))
                "android_logs_list" -> logs.list(args)
                "android_logs_query" -> logs.query(args)
                "android_analysis_list_imports" -> listImports()
                "android_analysis_open" -> openWorkspace(args)
                "android_analysis_close" -> jsonObject("closed" to workspaces.close(args.getString("workspace_id")))
                "android_analysis_list" -> analyzer.list(workspaces.get(args.getString("workspace_id")), args)
                "android_analysis_outline_class" -> analyzer.outlineClass(
                    workspaces.get(args.getString("workspace_id")), args.getString("class")
                )
                "android_analysis_search" -> analyzer.search(workspaces.get(args.getString("workspace_id")), args)
                "android_analysis_read" -> analyzer.read(workspaces.get(args.getString("workspace_id")), args)
                "android_analysis_xref_dex" -> analyzer.xref(workspaces.get(args.getString("workspace_id")), args)
                "android_frida_status" -> frida.status()
                "android_frida_prepare" -> frida.prepare(args)
                "android_frida_run" -> frida.run(args)
                "android_frida_output" -> frida.output(args)
                "android_frida_clear_log" -> frida.clearLog(args)
                "android_frida_reload" -> frida.reload(args)
                "android_frida_stop" -> frida.stop(args)
                "android_frida_sessions" -> frida.list()
                "android_frida_restart_app" -> frida.restart(args)
                "android_frida_agent_scripts" -> frida.listAgentScripts()
                "android_frida_agent_set" -> frida.setAgentScript(
                    args.getString("package").trim(),
                    args.getString("script")
                )
                "android_frida_agent_delete" -> frida.deleteAgentScript(args.getString("package").trim())
                "android_frida_agent_enable" -> frida.setAgentEnabled(
                    args.getString("package").trim(),
                    args.getBoolean("enabled")
                )
                "android_frida_autostart" -> {
                    if (args.has("enabled")) {
                        val enabled = args.getBoolean("enabled")
                        ServerConfig.setAutostartEnabled(context, enabled)
                        AppLog.info("设置：启动注入 ${if (enabled) "已启用" else "已关闭"}")
                    }
                    jsonObject("enabled" to ServerConfig.autostartEnabled(context))
                }
                "android_system_selinux" -> frida.selinux(args)
                else -> error("Unknown tool: $name")
            }
            toolResult(data, false)
        } catch (t: Throwable) {
            toolResult(jsonObject("error" to (t.message ?: t.javaClass.simpleName), "type" to t.javaClass.name), true)
        }
    }

    private fun systemSummary(): JSONObject {
        val access = root.accessStatus()
        return jsonObject(
            "manufacturer" to Build.MANUFACTURER,
            "brand" to Build.BRAND,
            "model" to Build.MODEL,
            "device" to Build.DEVICE,
            "android_release" to Build.VERSION.RELEASE,
            "sdk" to Build.VERSION.SDK_INT,
            "security_patch" to Build.VERSION.SECURITY_PATCH,
            "fingerprint" to Build.FINGERPRINT,
            "abis" to jsonArray(Build.SUPPORTED_ABIS.toList()),
            "privileged_read" to jsonObject(
                "available" to access.available,
                "mode" to access.mode,
                "probe_path" to access.probePath,
                "error" to access.error
            ),
            "allow_any_file" to ServerConfig.allowAnyFile(context),
            "frida_enabled" to ServerConfig.fridaEnabled(context),
            "frida_autostart" to ServerConfig.autostartEnabled(context),
            "read_allowlist" to jsonArray(if (ServerConfig.allowAnyFile(context)) listOf("/") else listOf(
                "/system", "/system_ext", "/product", "/vendor", "/odm", "/apex", "/data/app",
                "/data/adb/ksu/log", "/data/adb/lspd/log",
                "/proc/net", "/sys/class/net", "/sys/fs/bpf"
            ))
        )
    }

    @Suppress("DEPRECATION")
    private fun searchPackages(args: JSONObject): JSONObject {
        val query = args.optString("query").lowercase()
        val systemOnly = args.optBoolean("system_only", false)
        val cursor = args.optString("cursor", "0").toIntOrNull()?.coerceAtLeast(0) ?: 0
        val limit = args.optInt("limit", 100).coerceIn(1, 200)
        val flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or PackageManager.GET_PERMISSIONS
        val matches = context.packageManager.getInstalledPackages(flags).asSequence()
            .filter { info -> !systemOnly || (info.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) != 0) }
            .map { info ->
                val app = info.applicationInfo
                val label = app?.loadLabel(context.packageManager)?.toString().orEmpty()
                info to label
            }
            .filter { (info, label) -> query.isBlank() || info.packageName.lowercase().contains(query) || label.lowercase().contains(query) }
            .sortedBy { it.first.packageName }
            .drop(cursor)
            .take(limit + 1)
            .toList()
        val hasMore = matches.size > limit
        val items = matches.take(limit)
            .map { (info, label) ->
                val app = info.applicationInfo
                jsonObject(
                    "package" to info.packageName,
                    "label" to label,
                    "uid" to app?.uid,
                    "system" to (app?.flags?.and(ApplicationInfo.FLAG_SYSTEM) != 0),
                    "source_dir" to app?.sourceDir,
                    "split_source_dirs" to jsonArray(app?.splitSourceDirs?.toList().orEmpty()),
                    "version_name" to info.versionName,
                    "version_code" to info.longVersionCode,
                    "activities" to jsonArray(info.activities?.map { it.name }.orEmpty()),
                    "services" to jsonArray(info.services?.map { it.name }.orEmpty()),
                    "providers" to jsonArray(info.providers?.map { it.name }.orEmpty()),
                    "receivers" to jsonArray(info.receivers?.map { it.name }.orEmpty()),
                    "requested_permissions" to jsonArray(info.requestedPermissions?.toList().orEmpty())
                )
            }
        return jsonObject(
            "items" to jsonArray(items),
            "cursor" to cursor.toString(),
            "next_cursor" to if (hasMore) (cursor + items.size).toString() else null,
            "truncated" to hasMore
        )
    }

    private fun readSystemFile(args: JSONObject): JSONObject {
        val path = args.getString("path")
        val offset = args.optLong("offset", 0).coerceAtLeast(0)
        val requestedMax = args.optInt("max_bytes", 32_768)
        val bytes = root.read(path, offset, requestedMax)
        val requested = args.optString("format", "auto")
        val detected = if (offset == 0L) detectBinaryFormat(bytes) else null
        // sysfs procfs-style nodes report stat size 0 even though they have content.
        val size = root.fileSize(path)?.takeIf { it > 0 }

        if (detected != null && (requested == "auto" || requested == "text")) {
            return jsonObject(
                "path" to path,
                "is_binary" to true,
                "detected_format" to detected,
                "file_size" to size,
                "offset" to offset,
                "hint" to "Binary file, not decoded as text. Use format=hex for a dump, android_system_export_file to copy it, or android_analysis_open for APK/DEX."
            )
        }

        val format = if (requested == "auto") if (looksText(bytes)) "text" else "hex" else requested
        val content = when (format) {
            "text" -> bytes.toString(Charsets.UTF_8)
            "base64" -> Base64.encodeToString(bytes, Base64.NO_WRAP)
            "hex" -> bytes.asIterable().chunked(16).mapIndexed { row, chunk ->
                "%08x  %s".format(offset + row * 16, chunk.joinToString(" ") { "%02x".format(it.toInt() and 0xff) })
            }.joinToString("\n")
            else -> error("Unsupported format: $format")
        }
        val nextOffset = if (size != null && offset + bytes.size < size) offset + bytes.size
        else if (size == null && bytes.size >= requestedMax.coerceIn(1, 65_536)) offset + bytes.size
        else null
        return jsonObject(
            "path" to path,
            "offset" to offset,
            "bytes_read" to bytes.size,
            "file_size" to size,
            "format" to format,
            "truncated" to (nextOffset != null),
            "next_offset" to nextOffset,
            "content" to content
        )
    }

    /** Returns "zip", "elf", "png", "gzip" or "dex" when the first bytes look like a known binary container. */
    private fun detectBinaryFormat(bytes: ByteArray): String? {
        fun at(index: Int): Int = if (index < bytes.size) bytes[index].toInt() and 0xff else -1
        if (bytes.size >= 4 && at(0) == 0x50 && at(1) == 0x4b && (at(2) == 0x03 || at(2) == 0x05 || at(2) == 0x07)) return "zip"
        if (bytes.size >= 4 && at(0) == 0x7f && at(1) == 0x45 && at(2) == 0x4c && at(3) == 0x46) return "elf"
        if (bytes.size >= 8 && at(0) == 0x89 && at(1) == 0x50 && at(2) == 0x4e && at(3) == 0x47) return "png"
        if (bytes.size >= 2 && at(0) == 0x1f && at(1) == 0x8b) return "gzip"
        if (bytes.size >= 4 && at(0) == 0x64 && at(1) == 0x65 && at(2) == 0x78 && at(3) == 0x0a) return "dex"
        return null
    }

    private fun openWorkspace(args: JSONObject): JSONObject {
        val workspace = workspaces.open(args)
        return jsonObject(
            "workspace_id" to workspace.id,
            "title" to workspace.title,
            "artifacts" to jsonArray(workspace.artifacts.map {
                jsonObject("artifact_id" to it.id, "source_path" to it.sourcePath, "size" to it.size, "sha256" to it.sha256)
            }),
            "hint" to "Call android_analysis_list with kind=dex_files or dex_classes. DEX loading is lazy."
        )
    }

    private fun listImports(): JSONObject = jsonObject(
        "items" to jsonArray(imports.list().map {
            jsonObject("import_id" to it.id, "name" to it.name, "size" to it.size, "modified" to it.file.lastModified())
        })
    )

    private fun toolResult(data: JSONObject, error: Boolean): JSONObject = JSONObject()
        .put("content", JSONArray().put(JSONObject().put("type", "text").put("text", data.toString())))
        .put("structuredContent", data)
        .put("isError", error)

    private fun looksText(bytes: ByteArray): Boolean {
        if (bytes.isEmpty()) return true
        var printable = 0
        for (byte in bytes) {
            val value = byte.toInt() and 0xff
            if (value == 9 || value == 10 || value == 13 || value in 32..126 || value >= 0x80) printable++
        }
        return printable.toDouble() / bytes.size >= 0.85
    }

    private fun tool(name: String, description: String, properties: Map<String, JSONObject>, required: List<String> = emptyList()) =
        jsonObject(
            "name" to name,
            "description" to description,
            "inputSchema" to jsonObject(
                "type" to "object",
                "properties" to JSONObject().apply { properties.forEach(::put) },
                "required" to jsonArray(required),
                "additionalProperties" to false
            )
        )

    private fun stringSchema(description: String) = jsonObject("type" to "string", "description" to description)
    private fun booleanSchema(description: String) = jsonObject("type" to "boolean", "description" to description)
    private fun integerSchema(description: String) = jsonObject("type" to "integer", "description" to description)
    private fun enumSchema(vararg values: String) = jsonObject("type" to "string", "enum" to jsonArray(values.toList()))
    private fun arraySchema(items: JSONObject) = jsonObject("type" to "array", "items" to items)
}

