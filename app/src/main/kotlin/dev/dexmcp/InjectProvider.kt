package dev.dexmcp

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import java.util.concurrent.ConcurrentHashMap

/**
 * Binder endpoint used by the LSPosed startup hook (dev.dexmcp.xposed).
 *
 * The hook runs inside a selected app right before Application.onCreate and calls
 * `content://dev.dexmcp.inject` with its package name and pid. This provider verifies
 * that the pid really belongs to that package, attaches Frida with the startup script
 * from /data/adb/dexmcp/agents/<package>.js, and only then returns, so the app continues
 * with the hooks already installed. Every failure returns quickly and the app starts
 * normally.
 *
 * No permission protects the provider: the caller is the target app itself, so it
 * cannot hold a signature permission. The pid/package check and the fact that scripts
 * are chosen by Dex MCP limit abuse to "instrument a package that already has a script".
 */
class InjectProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val context = context ?: return true
        runCatching { AppLog.init(context) }
        return true
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method != METHOD_INJECT) return null
        val context = context ?: return null
        val pkg = extras?.getString("package")?.trim().orEmpty()
        val pid = extras?.getInt("pid", 0) ?: 0
        val response = runCatching { inject(context, pkg, pid) }
            .getOrElse { fail("error", it.message ?: it.javaClass.simpleName) }
        return Bundle().apply { putString("json", response.toString()) }
    }

    private fun inject(context: android.content.Context, pkg: String, pid: Int): org.json.JSONObject {
        if (!ServerConfig.autostartEnabled(context)) return fail("disabled", "Startup injection is disabled in Dex MCP")
        if (!ServerConfig.fridaEnabled(context)) return fail("disabled", "Frida is disabled in Dex MCP")
        if (!pkg.matches(Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")) || pid <= 0) {
            return fail("bad_request", "package and pid are required")
        }
        if (pkg == context.packageName) return fail("denied", "Dex MCP itself is never instrumented")

        val now = System.currentTimeMillis()
        val previous = lastRequest[pid]
        if (previous != null && now - previous < 3_000) return fail("busy", "Request already handled")
        lastRequest[pid] = now

        val cmdline = RootRunner.run(
            "toybox cat /proc/$pid/cmdline 2>/dev/null | toybox tr '\\0' '\\n' | toybox head -n 1",
            10_000
        ).text.trim()
        if (cmdline != pkg) return fail("pid_mismatch", "pid $pid is '$cmdline', not '$pkg'")

        val frida = FridaManager.get(context)
        if (frida.isRecentlyStartedManually(pkg)) {
            return fail("manual_start", "$pkg was just started by an MCP tool; its session is handled there")
        }
        if (frida.findLiveSession(pkg, pid) != null) {
            return jsonObject("ok" to true, "reason" to "already_running", "package" to pkg, "pid" to pid)
        }
        if (!frida.isRuntimeReady()) {
            return fail("not_installed", "Install the Frida runtime in Dex MCP first")
        }
        if (!frida.hasAgentScript(pkg)) return fail("no_script", "No startup script for $pkg")

        val result = frida.injectStartup(pkg, pid)
        return jsonObject(
            "ok" to true,
            "reason" to if (result.optBoolean("ready")) "ready" else "attached",
            "package" to pkg,
            "pid" to pid,
            "session_id" to result.optString("session_id"),
            "ready" to result.optBoolean("ready"),
            "output" to result.optString("output").take(4_000)
        )
    }

    private fun fail(reason: String, message: String): org.json.JSONObject =
        jsonObject("ok" to false, "reason" to reason, "message" to message)

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    companion object {
        const val METHOD_INJECT = "inject"
        private val lastRequest = ConcurrentHashMap<Int, Long>()
    }
}
