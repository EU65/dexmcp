package dev.dexmcp

import android.content.Context
import android.system.Os
import android.system.OsConstants
import com.topjohnwu.superuser.Shell
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.AccessDeniedException
import java.nio.file.NoSuchFileException
import java.nio.file.NotDirectoryException
import java.nio.file.Paths
import java.util.Base64

class RootAccess(private val context: Context) {
    private val allowedRoots = listOf(
        "/system", "/system_ext", "/system_dlkm", "/product", "/vendor", "/vendor_dlkm", "/odm", "/apex",
        "/my_bigball", "/my_carrier", "/my_company", "/my_engineering",
        "/my_heytap", "/my_manifest", "/my_preload", "/my_product",
        "/my_region", "/my_reserve", "/my_stock",
        "/data/app", "/data/dalvik-cache", "/data/misc/apexdata/com.android.art/dalvik-cache",
        "/data/adb", "/mnt/opex", "/mnt/oplus", "/mnt/vendor", "/proc", "/sys"
    )

    fun allowList(): List<String> = allowedRoots

    private val accessProbePaths = listOf(
        "/data/system/packages.xml",
        "/data/system/packages.list"
    )

    fun accessStatus(): PrivilegedReadStatus {
        val existing = accessProbePaths.firstOrNull { File(it).exists() } ?: accessProbePaths.first()
        if (canDirectRead(File(existing))) {
            return PrivilegedReadStatus(true, "direct", existing, null)
        }
        if (rootShellAvailable()) {
            val result = Shell.cmd("toybox head -c 1 " + quote(existing) + " >/dev/null").exec()
            if (result.isSuccess) return PrivilegedReadStatus(true, "root_shell", existing, null)
            return PrivilegedReadStatus(false, "none", existing, result.err.joinToString("\n").take(1000))
        }
        return PrivilegedReadStatus(
            false,
            "none",
            existing,
            "Protected file cannot be opened directly and a root shell could not be acquired"
        )
    }

    private fun rootShellAvailable(): Boolean =
        runCatching { Shell.getShell().isRoot }.getOrDefault(false)

    fun validateSource(path: String): File {
        require(path.startsWith('/')) { "Absolute path required" }
        val normalized = Paths.get(path).normalize().toFile().absoluteFile
        if (ServerConfig.allowAnyFile(context)) return normalized
        if (!isAllowed(normalized.path)) throw PathDeniedException(normalized.path)
        val real = try {
            normalized.toPath().toRealPath().toString()
        } catch (_: AccessDeniedException) {
            if (!rootShellAvailable()) return normalized
            Shell.cmd("toybox realpath " + quote(normalized.path)).exec()
                .takeIf { it.isSuccess }?.out?.singleOrNull()
                ?: throw java.io.IOException("Unable to resolve source path: ${normalized.path}")
        } catch (_: NoSuchFileException) {
            normalized.canonicalPath
        } catch (_: NotDirectoryException) {
            normalized.canonicalPath
        }
        // /proc/net is the system API for the caller's network namespace.
        val procNetAlias = (normalized.path == "/proc/net" || normalized.path.startsWith("/proc/net/")) &&
            procNetTarget.matches(real)
        if (!isAllowed(real) && !procNetAlias) throw PathDeniedException(normalized.path)
        return normalized
    }

    private fun isAllowed(path: String): Boolean {
        if (allowedRoots.none { path == it || path.startsWith("$it/") }) return false
        if (!path.startsWith("/proc/")) return true
        val name = path.removePrefix("/proc/").substringBefore('/')
        return name !in blockedProcNames && (name.isEmpty() || !name.all { it in '0'..'9' })
    }

    private val procNetTarget = Regex("/proc/[0-9]+/net(?:/.*)?")
    private val blockedProcNames = setOf("self", "thread-self", "kcore", "vmcore", "kmsg")

    fun copyForAnalysis(path: String, destination: File) {
        val source = validateSource(path)
        destination.parentFile?.mkdirs()
        if (canDirectRead(source)) {
            source.inputStream().use { input -> destination.outputStream().use(input::copyTo) }
            return
        }
        require(rootShellAvailable()) { "Neither direct privileged read access nor root shell access is available for $path" }
        try {
            streamRootFile(source, destination)
        } catch (t: Throwable) {
            destination.delete()
            throw t
        }
    }

    fun read(path: String, offset: Long, maxBytes: Int): ByteArray {
        val source = validateSource(path)
        val count = maxBytes.coerceIn(1, 65_536)
        if (canDirectRead(source)) {
            RandomAccessFile(source, "r").use { file ->
                file.seek(offset.coerceAtLeast(0))
                val bytes = ByteArray(count)
                val read = file.read(bytes)
                return if (read < 0) ByteArray(0) else bytes.copyOf(read)
            }
        }
        require(rootShellAvailable()) { "Neither direct privileged read access nor root shell access is available for $path" }
        val position = offset.coerceAtLeast(0)
        val range = if (position % 65536 == 0L) "bs=65536 skip=${position / 65536} count=1" else "bs=1 skip=$position count=$count"
        val command = "set -o pipefail; toybox timeout 15 toybox dd if=${quote(source.path)} $range | toybox base64"
        val result = Shell.cmd(command).exec()
        if (!result.isSuccess) {
            throw java.io.IOException(result.err.joinToString("\n").ifBlank { "Root read failed (exit ${result.code})" })
        }
        val bytes = Base64.getMimeDecoder().decode(result.out.joinToString("\n"))
        return bytes.copyOf(minOf(bytes.size, count))
    }

    /**
     * Extract printable strings on the device instead of shipping the whole file: a 10 MB module
     * becomes a few KB of strings. Falls back to `grep -o` when toybox lacks `strings`.
     */
    fun strings(path: String, minLen: Int, pattern: String?, maxBytes: Int): CommandOutput {
        val source = validateSource(path)
        val min = minLen.coerceIn(1, 128)
        val limit = maxBytes.coerceIn(1024, 262_144)
        val extract = "toybox strings -n $min " + quote(source.path) +
            " 2>/dev/null || toybox grep -aoE " + quote("[ -~]{$min,}") + " " + quote(source.path)
        val filter = pattern?.takeIf { it.isNotBlank() }?.let { " | toybox grep -aE " + quote(it) }.orEmpty()
        return execute("toybox timeout 20 sh -c " + quote(extract + filter + " | toybox head -c $limit"))
    }

    fun fileSize(path: String): Long? {
        val source = validateSource(path)
        if (canDirectRead(source)) return runCatching { source.length() }.getOrNull()
        if (!rootShellAvailable()) return null
        val result = Shell.cmd(
            "toybox stat -c %s " + quote(source.path) + " 2>/dev/null || toybox wc -c < " + quote(source.path) + " 2>/dev/null"
        ).exec()
        return result.out.firstOrNull()?.trim()?.toLongOrNull()
    }

    fun snapshot(profile: String): JSONObjectResult {
        val commands = when (profile) {
            "network" -> linkedMapOf(
                "interfaces" to "ip -details link",
                "addresses" to "ip address",
                "rules" to "ip rule",
                "routes" to "ip route show table all",
                "connectivity" to "dumpsys connectivity",
                "netpolicy" to "dumpsys netpolicy",
                "dnsresolver" to "dumpsys dnsresolver"
            )
            "device" -> linkedMapOf("properties" to "getprop", "packages" to "cmd package list packages -U -f")
            "stylus" -> linkedMapOf(
                "kernel" to "uname -a",
                "properties" to "getprop",
                "input" to "dumpsys input",
                "display" to "dumpsys display",
                "input_devices" to "cat /proc/bus/input/devices",
                "input_nodes" to "ls -l /dev/input",
                "services" to "service list",
                "hal_services" to "lshal",
                "processes" to "ps -A",
                "refresh_settings" to "for k in peak_refresh_rate min_refresh_rate user_refresh_rate; do printf '%s=' \"\$k\"; settings get system \"\$k\"; done",
                "pen_strategy" to "cat /sys/class/touch/touch_dev/pen_connect_strategy",
                "pen_parameters" to "for p in /sys/module/xiaomi_touch/parameters/pipa_pen_debug /sys/module/xiaomi_touch/parameters/pipa_pen_unrestricted; do printf '%s=' \"\$p\"; cat \"\$p\"; done"
            )
            else -> error("Unknown snapshot profile: $profile")
        }
        val sections = linkedMapOf<String, CommandOutput>()
        for ((name, command) in commands) {
            sections[name] = runCatching { execute("toybox timeout 15 sh -c " + quote(command)) }
                .getOrElse { CommandOutput(-1, "", it.message ?: it.javaClass.simpleName) }
        }
        return JSONObjectResult(profile, System.currentTimeMillis(), sections)
    }

    fun listFiles(path: String, limit: Int = 100): List<String> {
        val directory = validateSource(path)
        val max = limit.coerceIn(1, 500)
        if (canDirectRead(directory)) {
            return directory.listFiles().orEmpty()
                .filter(File::isFile)
                .sortedByDescending(File::lastModified)
                .take(max)
                .map(File::getPath)
        }
        require(rootShellAvailable()) { "Privileged access is required to list $path" }
        val result = Shell.cmd("toybox ls -1tA -- " + quote(directory.path)).exec()
        check(result.isSuccess) { "Unable to list " + path + ": " + result.err.joinToString("\n") }
        return result.out.asSequence()
            .filter { it.isNotBlank() && !it.contains('/') }
            .map { File(directory, it).path }
            .take(max)
            .toList()
    }

    // Bound traversal time independently of pagination.
    fun discoverFiles(path: String, recursive: Boolean, maxDepth: Int): CommandOutput {
        val directory = validateSource(path)
        val depth = if (recursive) maxDepth.coerceIn(1, 8) else 1
        // Follow a symlink supplied as the start path, not symlinks found during traversal.
        val start = quote(directory.path)
        val base = "toybox find -H $start -mindepth 1 -maxdepth $depth"
        val procFilter = if (directory.path == "/proc" && !ServerConfig.allowAnyFile(context)) {
            val blocked = (blockedProcNames.map { "/proc/$it" } + "/proc/[0-9]*")
                .joinToString(" -o ") { "-path " + quote(it) }
            " \\( $blocked \\) -prune -o -print"
        } else " -print"
        return execute("toybox timeout 20 sh -c " + quote(base + procFilter))
    }

    fun captureLiveLog(source: String, lines: Int): CommandOutput {
        val count = lines.coerceIn(1, 5_000)
        val command = when (source) {
            "logcat" -> "logcat -d -v threadtime -t $count"
            "dmesg" -> "dmesg | toybox tail -n $count"
            else -> error("Unsupported live log source: $source")
        }
        return execute(command)
    }

    private fun execute(command: String): CommandOutput {
        return if (rootShellAvailable()) {
            val result = Shell.cmd(command).exec()
            CommandOutput(result.code, crop(result.out.joinToString("\n")), crop(result.err.joinToString("\n")))
        } else {
            try {
                val process = ProcessBuilder("sh", "-c", command).redirectErrorStream(false).start()
                val stdout = process.inputStream.bufferedReader().readText()
                val stderr = process.errorStream.bufferedReader().readText()
                CommandOutput(process.waitFor(), crop(stdout), crop(stderr))
            } catch (t: Throwable) {
                CommandOutput(-1, "", t.message ?: t.javaClass.simpleName)
            }
        }
    }

    private fun crop(value: String): String = if (value.length <= 262_144) value else value.take(262_144) + "\n[truncated]"

    private fun canDirectRead(file: File): Boolean {
        return try {
            val fd = Os.open(file.path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC, 0)
            Os.close(fd)
            true
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * The privileged process only reads [source] and writes its existing stdout pipe.
     * The unprivileged app process owns and writes [destination], so the root profile
     * does not need CAP_DAC_OVERRIDE or CAP_CHOWN.
     */
    private fun streamRootFile(source: File, destination: File) {
        destination.parentFile?.mkdirs()
        val child = ProcessBuilder("su", "-c", "toybox timeout 120 toybox cat " + quote(source.path))
            .redirectError(File("/dev/null")).start()
        try {
            child.outputStream.close()
            destination.outputStream().use { output ->
                child.inputStream.use { input ->
                    val buffer = ByteArray(128 * 1024)
                    var total = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        require(total <= 2_147_483_648L) { "Source exceeds 2 GiB" }
                        output.write(buffer, 0, count)
                    }
                }
            }
            check(child.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) && child.exitValue() == 0) {
                "Root file copy failed or timed out"
            }
        } finally {
            child.destroyForcibly()
        }
    }
    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}

data class CommandOutput(val exitCode: Int, val stdout: String, val stderr: String)
data class JSONObjectResult(val profile: String, val timestamp: Long, val sections: Map<String, CommandOutput>)
data class PrivilegedReadStatus(
    val available: Boolean,
    val mode: String,
    val probePath: String,
    val error: String?
)

/** Raised before any syscall when the path is outside the App's read-only allowlist. */
class PathDeniedException(val path: String) :
    IllegalArgumentException("Path is outside the read-only allowlist: $path")


