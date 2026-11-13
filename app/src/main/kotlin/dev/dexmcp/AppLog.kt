package dev.dexmcp

import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Small in-app log used by the UI (service lifecycle, Frida install/inject, SELinux
 * changes, import results). Kept in memory for the screen and appended to a bounded
 * file so the history survives App restarts.
 */
object AppLog {
    enum class Level { INFO, WARN, ERROR }

    data class Entry(val time: Long, val level: Level, val message: String)

    private const val MAX_ENTRIES = 600
    private const val MAX_FILE_BYTES = 512L * 1024L
    private val format = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

    private var file: File? = null
    private val _entries = MutableStateFlow<List<Entry>>(emptyList())
    val entries: StateFlow<List<Entry>> = _entries.asStateFlow()

    @Synchronized
    fun init(context: Context) {
        if (file != null) return
        val target = File(context.applicationContext.filesDir, "dexmcp.log")
        file = target
        val loaded = runCatching {
            target.readLines().takeLast(MAX_ENTRIES).mapNotNull(::parse)
        }.getOrDefault(emptyList())
        _entries.value = loaded
    }

    fun info(message: String) = append(Level.INFO, message)

    fun warn(message: String) = append(Level.WARN, message)

    fun error(message: String) = append(Level.ERROR, message)

    @Synchronized
    fun clear() {
        _entries.value = emptyList()
        file?.let { target -> runCatching { target.writeText("") } }
    }

    private fun append(level: Level, message: String) {
        val entry = Entry(System.currentTimeMillis(), level, message.trim())
        _entries.value = (_entries.value + entry).takeLast(MAX_ENTRIES)
        val target = file ?: return
        runCatching {
            if (target.exists() && target.length() > MAX_FILE_BYTES) target.writeText("")
            target.appendText(format(entry) + "\n")
        }
    }

    private fun format(entry: Entry): String =
        "${format.format(Date(entry.time))} ${entry.level.name} ${entry.message}"

    private fun parse(line: String): Entry? {
        if (line.length < 22) return null
        val stamp = line.substring(0, 19)
        val level = runCatching { Level.valueOf(line.substring(20).substringBefore(' ')) }.getOrNull() ?: return null
        val message = line.substring(20 + level.name.length).trimStart()
        val time = runCatching { format.parse(stamp)?.time }.getOrNull() ?: return null
        return Entry(time, level, message)
    }
}
