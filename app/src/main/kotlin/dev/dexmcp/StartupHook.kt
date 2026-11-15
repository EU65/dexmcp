package dev.dexmcp

import android.app.Application
import android.net.Uri
import android.os.Bundle
import android.os.Process
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_LoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers

/**
 * LSPosed entry point. Dex MCP is both the MCP server and the LSPosed module, so the
 * hook ships in the same APK as the management UI.
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
class StartupHook : IXposedHookLoadPackage {

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        val pkg = lpparam.packageName ?: return
        if (pkg == "android" || pkg == MCP_PACKAGE) return
        if (!lpparam.isFirstApplication) return
        if (lpparam.processName != pkg) return
        val classLoader = lpparam.classLoader ?: return

        try {
            XposedHelpers.findAndHookMethod(
                "android.app.Instrumentation",
                classLoader,
                "callApplicationOnCreate",
                Application::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val app = param.args.firstOrNull() as? Application ?: return
                        inject(app)
                    }
                }
            )
        } catch (t: Throwable) {
            XposedBridge.log("[dexmcp] hook install failed for $pkg: $t")
        }
    }

    private fun inject(app: Application) {
        val pkg = app.packageName ?: return
        try {
            val extras = Bundle().apply {
                putString("package", pkg)
                putInt("pid", Process.myPid())
            }
            val reply = app.contentResolver.call(INJECT_URI, METHOD_INJECT, null, extras)
            XposedBridge.log("[dexmcp] startup inject $pkg -> ${reply?.getString("json") ?: "no reply"}")
        } catch (t: Throwable) {
            XposedBridge.log("[dexmcp] startup inject $pkg failed: ${t.message ?: t.javaClass.simpleName}")
        }
    }

    companion object {
        private const val INJECT_URI = "content://dev.dexmcp.inject"
        private const val METHOD_INJECT = "inject"
        private const val MCP_PACKAGE = "dev.dexmcp"
    }
}
