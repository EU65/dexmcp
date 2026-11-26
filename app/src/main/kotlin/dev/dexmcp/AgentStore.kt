package dev.dexmcp

import android.content.Context

/**
 * Per-package switches for the LSPosed startup hook. Scripts live in
 * /data/adb/dexmcp/agents/<package>.js; this store only records whether a package
 * should be injected, so turning an app off keeps its script around.
 */
object AgentStore {
    private const val PREFS = "agents"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_SCOPE = "scope"

    /** main = only the package main process, all = every process of the package. */
    const val SCOPE_MAIN = "main"
    const val SCOPE_ALL = "all"

    fun enabledPackages(context: Context): Set<String> =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getStringSet(KEY_ENABLED, emptySet())
            ?.toSet()
            .orEmpty()

    fun isEnabled(context: Context, pkg: String): Boolean = pkg in enabledPackages(context)

    fun setEnabled(context: Context, pkg: String, enabled: Boolean) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val current = prefs.getStringSet(KEY_ENABLED, emptySet())?.toMutableSet() ?: mutableSetOf()
        if (enabled) current.add(pkg) else current.remove(pkg)
        prefs.edit().putStringSet(KEY_ENABLED, current).apply()
    }

    fun scope(context: Context, pkg: String): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString("$KEY_SCOPE:$pkg", SCOPE_MAIN)
            ?.takeIf { it == SCOPE_ALL || it == SCOPE_MAIN }
            ?: SCOPE_MAIN

    fun setScope(context: Context, pkg: String, scope: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString("$KEY_SCOPE:$pkg", scope).apply()
    }

    fun count(context: Context): Int = enabledPackages(context).size
}
