package dev.dexmcp

import android.content.Context
import android.util.Base64
import java.security.SecureRandom
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.Collections

object ServerConfig {
    const val DEFAULT_PORT = 8765

    fun port(context: Context): Int =
        context.getSharedPreferences("mcp", Context.MODE_PRIVATE)
            .getInt("port", DEFAULT_PORT)
            .takeIf { it in 1024..65535 } ?: DEFAULT_PORT

    fun setPort(context: Context, port: Int) {
        context.getSharedPreferences("mcp", Context.MODE_PRIVATE).edit()
            .putInt("port", port).apply()
    }

    fun allowAnyFile(context: Context): Boolean =
        context.getSharedPreferences("mcp", Context.MODE_PRIVATE).getBoolean("allow_any_file", false)

    fun setAllowAnyFile(context: Context, enabled: Boolean) {
        context.getSharedPreferences("mcp", Context.MODE_PRIVATE).edit()
            .putBoolean("allow_any_file", enabled).apply()
    }

    fun fridaEnabled(context: Context): Boolean =
        context.getSharedPreferences("mcp", Context.MODE_PRIVATE).getBoolean("frida_enabled", true)

    fun setFridaEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences("mcp", Context.MODE_PRIVATE).edit()
            .putBoolean("frida_enabled", enabled).apply()
    }

    /** Whether the LSPosed startup hook may ask the service to inject a script at app launch. */
    fun autostartEnabled(context: Context): Boolean =
        context.getSharedPreferences("mcp", Context.MODE_PRIVATE).getBoolean("frida_autostart", true)

    fun setAutostartEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences("mcp", Context.MODE_PRIVATE).edit()
            .putBoolean("frida_autostart", enabled).apply()
    }

    fun allowRemote(context: Context): Boolean =
        context.getSharedPreferences("mcp", Context.MODE_PRIVATE).getBoolean("allow_remote", false)

    fun setAllowRemote(context: Context, enabled: Boolean) {
        context.getSharedPreferences("mcp", Context.MODE_PRIVATE).edit()
            .putBoolean("allow_remote", enabled).apply()
    }

    fun bindHost(context: Context): String = if (allowRemote(context)) "0.0.0.0" else "127.0.0.1"

    fun remoteUrls(context: Context): List<String> = runCatching {
        val port = port(context)
        Collections.list(NetworkInterface.getNetworkInterfaces()).filter { it.isUp && !it.isLoopback }
            .sortedBy { if (it.name.startsWith("wlan")) 0 else 1 }
            .flatMap { Collections.list(it.inetAddresses) }
            .filterIsInstance<Inet4Address>()
            .filter { !it.isLoopbackAddress && !it.isLinkLocalAddress }
            .map { "http://${it.hostAddress}:$port/mcp" }.distinct()
    }.getOrDefault(emptyList())

    fun connectionInfo(context: Context): String = buildString {
        val port = port(context)
        appendLine("本机：http://127.0.0.1:$port/mcp")
        if (allowRemote(context)) {
            val urls = remoteUrls(context)
            if (urls.isEmpty()) appendLine("远程：连接网络后使用平板 IP:$port/mcp")
            else urls.forEach { appendLine("远程：$it") }
        }
        append("Authorization: Bearer ${token(context)}")
    }

    fun token(context: Context): String {
        val prefs = context.getSharedPreferences("mcp", Context.MODE_PRIVATE)
        prefs.getString("token", null)?.let { return it }
        val bytes = ByteArray(24).also { SecureRandom().nextBytes(it) }
        val token = Base64.encodeToString(bytes, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
        prefs.edit().putString("token", token).apply()
        return token
    }
}
