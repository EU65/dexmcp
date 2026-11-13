package dev.dexmcp

import android.content.Context
import android.system.Os
import android.system.OsConstants
import com.topjohnwu.superuser.Shell
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Paths
import java.util.Base64

class RootAccess(private val context: Context) {
    private val allowedRoots = listOf(
        "/system", "/system_ext", "/product", "/vendor", "/odm", "/apex",
        "/data/app", "/data/adb/ksu/log", "/data/adb/lspd/log",
        "/proc/net", "/sys/class/net", "/sys/fs/bpf"
    )

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
        val value = normalized.path
        require(ServerConfig.allowAnyFile(context) || allowedRoots.any { value == it || value.startsWith("$it/") }) {
            "Path is outside the read-only allowlist: $value"
        }
        return normalized
    }

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
        check(result.isSuccess) { "Root read failed: ${result.err.joinToString("\n")}" }
        val bytes = Base64.getMimeDecoder().decode(result.out.joinToString("\n"))
        return bytes.copyOf(minOf(bytes.size, count))
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

    // Searches do not follow symlinks or cross filesystem boundaries. Limit both
    // traversal time and response size, independently of the caller's page size.
    fun discoverFiles(path: String, recursive: Boolean, maxDepth: Int): CommandOutput {
        val directory = validateSource(path)
        val depth = if (recursive) maxDepth.coerceIn(1, 8) else 1
        val command = "resolved=\$(toybox readlink -f " + quote(directory.path) +
            ") && toybox find \"\$resolved\" -xdev -mindepth 1 -maxdepth $depth"
        return execute("toybox timeout 20 sh -c " + quote(command))
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
        destination.outputStream().buffered(128 * 1024).use { output ->
            var offset = 0L
            while (true) {
                val bytes = read(source.path, offset, 65536)
                output.write(bytes)
                offset += bytes.size
                require(offset <= 2_147_483_648L) { "Source exceeds 2 GiB" }
                if (bytes.size < 65536) break
            }
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


