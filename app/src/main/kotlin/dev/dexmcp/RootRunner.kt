package dev.dexmcp

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit

class RootResult(
    val exitCode: Int,
    val stdout: ByteArray,
    val stderr: String,
    val timedOut: Boolean
) {
    val text: String get() = String(stdout, Charsets.UTF_8)
}

/**
 * Small process based helper for commands that must run as root. libsu is used for
 * the read-only filesystem tools; dynamic analysis needs streaming stdin (multi
 * megabyte binaries), long running children and manual process teardown, which is
 * easier to control with a plain su -c child.
 */
object RootRunner {
    @Volatile
    private var available: Boolean? = null

    fun isAvailable(): Boolean {
        if (available == true) return true
        val ok = runCatching { run("id -u", 20_000).text.trim() == "0" }.getOrDefault(false)
        if (ok) available = true
        return ok
    }

    fun invalidate() {
        available = null
    }

    fun run(command: String, timeoutMs: Long = 30_000, input: ByteArray? = null): RootResult =
        execute(command, timeoutMs) { stream -> if (input != null) stream.write(input) }

    fun stream(command: String, timeoutMs: Long, feed: (OutputStream) -> Unit): RootResult =
        execute(command, timeoutMs, feed)

    private fun execute(command: String, timeoutMs: Long, feed: ((OutputStream) -> Unit)?): RootResult {
        val process = try {
            ProcessBuilder("su", "-c", command).start()
        } catch (t: Throwable) {
            throw IllegalStateException("Unable to start root shell: ${t.message ?: t.javaClass.simpleName}")
        }
        val outBuffer = ByteArrayOutputStream()
        val errBuffer = ByteArrayOutputStream()
        val outReader = Thread { runCatching { process.inputStream.use { it.copyTo(outBuffer) } } }
        val errReader = Thread { runCatching { process.errorStream.use { it.copyTo(errBuffer) } } }
        outReader.start()
        errReader.start()
        val feeder = Thread {
            runCatching { process.outputStream.use { stream -> feed?.invoke(stream) } }
        }
        feeder.start()

        val finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        if (!finished) {
            runCatching { process.destroyForcibly() }
            process.waitFor(2, TimeUnit.SECONDS)
        }
        outReader.join(3_000)
        errReader.join(2_000)
        feeder.join(2_000)
        val exit = if (finished) runCatching { process.exitValue() }.getOrDefault(-1) else -1
        return RootResult(exit, outBuffer.toByteArray(), errBuffer.toString(Charsets.UTF_8).trim(), !finished)
    }
}
