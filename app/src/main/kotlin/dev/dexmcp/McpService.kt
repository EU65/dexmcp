package dev.dexmcp

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat

class McpService : Service() {
    private var server: McpHttpServer? = null
    private lateinit var router: ToolRouter

    override fun onCreate() {
        super.onCreate()
        AppLog.init(applicationContext)
        router = ToolRouter(applicationContext)
        createChannel()
        startForeground(1, notification(ServerConfig.bindHost(this), ServerConfig.port(this)))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            AppLog.warn("服务：已通过通知停止")
            stopSelf()
            return START_NOT_STICKY
        }
        val host = ServerConfig.bindHost(this)
        val port = ServerConfig.port(this)
        if (server != null && running && boundHost == host && boundPort == port) return START_STICKY
        server?.stop()
        server = null
        running = false
        boundHost = null
        boundPort = null
        lastError = null
        try {
            val next = McpHttpServer(this, host, port, router)
            try {
                next.start()
            } catch (t: Throwable) {
                next.stop()
                throw t
            }
            server = next
            boundHost = host
            boundPort = port
            running = true
            getSystemService(NotificationManager::class.java).notify(1, notification(host, port))
            AppLog.info("服务：监听 ${if (host == "0.0.0.0") "所有接口" else "127.0.0.1"}，端口 $port")
        } catch (t: Throwable) {
            lastError = t.message ?: t.javaClass.simpleName
            AppLog.error("服务：启动失败 $lastError")
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    private fun notification(host: String, port: Int): android.app.Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopIntent = PendingIntent.getService(
            this, 1, Intent(this, McpService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("Dex MCP 正在运行")
            .setContentText(if (host == "0.0.0.0") "允许远程连接 · 端口 $port" else "仅本机 · 端口 $port")
            .setContentIntent(openIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "停止", stopIntent)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        server?.stop()
        server = null
        running = false
        boundHost = null
        boundPort = null
        AppLog.warn("服务：已停止")
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createChannel() {
        val channel = NotificationChannel(CHANNEL, "Dex MCP server", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    companion object {
        private const val CHANNEL = "dex_mcp_server"
        const val ACTION_STOP = "dev.dexmcp.action.STOP"
        @Volatile var running = false
            private set
        @Volatile var boundHost: String? = null
            private set
        @Volatile var boundPort: Int? = null
            private set
        @Volatile var lastError: String? = null
            private set
    }
}
