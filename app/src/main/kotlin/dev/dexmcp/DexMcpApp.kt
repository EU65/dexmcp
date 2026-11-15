package dev.dexmcp

import android.app.Application

/**
 * Registered early so the LSPosed framework can hand over its service binder as soon as
 * the app process starts. In target processes LSPosed instantiates the target's own
 * Application, never this one.
 */
class DexMcpApp : Application() {
    override fun onCreate() {
        super.onCreate()
        runCatching { ScopeClient.init(this) }
    }
}
