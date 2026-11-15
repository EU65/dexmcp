package dev.dexmcp

import android.app.Application
import android.util.Log
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface

/**
 * LSPosed entry point for the modern Xposed API 102 (see META-INF/xposed/java_init.list).
 *
 * LSPosed only loads this class into apps selected in its scope. For the main process of
 * each such app we hook `Instrumentation.callApplicationOnCreate`, i.e. right before
 * `Application.onCreate()`, ask the Dex MCP process to attach Frida with the configured
 * startup script, and only then let the app continue. If Dex MCP has no script for the
 * package, startup injection is disabled, or the runtime is missing, the app starts
 * normally.
 *
 * Keep this class self-contained: it is loaded inside third-party apps and must not pull
 * in Compose, the MCP server or any other Dex MCP component.
 */
class StartupHook : XposedModule() {

    override fun onPackageLoaded(param: XposedModuleInterface.PackageLoadedParam) {
        // Do not instrument the first (main) package of a process we were not scoped for.
        if (!param.isFirstPackage) return
        val pkg = param.packageName
        if (pkg == "android" || pkg == MCP_PACKAGE) return
        try {
            val method = android.app.Instrumentation::class.java
                .getDeclaredMethod("callApplicationOnCreate", android.app.Application::class.java)
            hook(method).intercept(object : XposedInterface.Hooker {
                override fun intercept(chain: XposedInterface.Chain): Any? {
                    val app = chain.getArg(0) as? android.app.Application
                    if (app != null) inject(app)
                    return chain.proceed()
                }
            })
        } catch (t: Throwable) {
            log(Log.ERROR, TAG, "hook install failed for $pkg", t)
        }
    }

    private fun inject(app: android.app.Application) {
        val pkg = app.packageName ?: return
        // Only the main process of the package; subprocesses (:remote) are skipped here
        // instead of paying for a provider call that would reject them anyway.
        val process = runCatching {
            java.io.File("/proc/self/cmdline").readText().substringBefore('\u0000')
        }.getOrDefault(pkg)
        if (process != pkg) return
        try {
            val extras = android.os.Bundle().apply {
                putString("package", pkg)
                putInt("pid", android.os.Process.myPid())
            }
            val reply = app.contentResolver.call(
                android.net.Uri.parse(INJECT_URI),
                METHOD_INJECT,
                null,
                extras
            )
            log(Log.INFO, TAG, "startup inject $pkg -> ${reply?.getString("json") ?: "no reply"}")
        } catch (t: Throwable) {
            log(Log.WARN, TAG, "startup inject $pkg failed: ${t.message ?: t.javaClass.simpleName}")
        }
    }

    companion object {
        private const val TAG = "DexMCP"
        private const val INJECT_URI = "content://dev.dexmcp.inject"
        private const val METHOD_INJECT = "inject"
        private const val MCP_PACKAGE = "dev.dexmcp"
    }
}
