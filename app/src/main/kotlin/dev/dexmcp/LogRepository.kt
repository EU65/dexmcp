package dev.dexmcp

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.util.UUID
import java.util.regex.Pattern

class LogRepository(private val context: Context, private val root: RootAccess) {
    private val ksuDirectory = "/data/adb/ksu/log"
    private val lspdDirectory = "/data/adb/lspd/log"

    fun list(args: JSONObject): JSONObject {
        val max = args.optInt("limit", 100).coerceIn(1, 500)
        val ksu = runCatching { root.listFiles(ksuDirectory, max) }.getOrDefault(emptyList())
            .filter { it.endsWith(".log") }
        val lspd = runCatching { root.listFiles(lspdDirectory, max) }.getOrDefault(emptyList())
            .filter { it.endsWith(".log") }
        return jsonObject(
            "live_sources" to jsonArray(listOf("logcat_live", "dmesg_live")),
            "history" to jsonArray((ksu + lspd).map { path ->
                jsonObject(
                    "path" to path,
                    "source" to when {
                        path.startsWith(lspdDirectory) -> "lspd"
                        File(path).name.startsWith("dmesg") -> "ksu_dmesg"
                        else -> "ksu_logcat"
                    }
                )
            })
        )
    }

    fun query(args: JSONObject): JSONObject {
        val source = args.optString("source", "all_history")
        val latestFiles = args.optInt("latest_files", 3).coerceIn(1, 20)
        val explicitPaths = args.stringList("paths")
        val tempDirectory = File(context.cacheDir, "log-query/" + UUID.randomUUID()).canonicalFile
        tempDirectory.mkdirs()
        return try {
            val inputs = if (explicitPaths.isNotEmpty()) {
                explicitPaths.distinct().mapIndexed { index, path ->
                    val file = File(tempDirectory, index.toString() + "-" + File(path).name)
                    root.copyForAnalysis(path, file)
                    LogInput(sourceForPath(path), path, file)
                }
            } else when (source) {
                "logcat_live", "dmesg_live" -> {
                    val liveName = source.removeSuffix("_live")
                    val output = root.captureLiveLog(liveName, args.optInt("live_lines", 2000))
                    check(output.exitCode == 0) { output.stderr.ifBlank { "Unable to read $source" } }
                    val file = File(tempDirectory, "$source.log")
                    file.writeText(output.stdout)
                    listOf(LogInput(source, source, file))
                }
                else -> resolveHistory(source, latestFiles).mapIndexed { index, path ->
                    val file = File(tempDirectory, index.toString() + "-" + File(path).name)
                    root.copyForAnalysis(path, file)
                    LogInput(sourceForPath(path), path, file)
                }
            }
            scan(inputs, args)
        } finally {
            val expected = File(context.cacheDir, "log-query").canonicalFile
            if (tempDirectory.canonicalPath.startsWith(expected.path + File.separator)) {
                tempDirectory.deleteRecursively()
            }
        }
    }

    private fun resolveHistory(source: String, latestFiles: Int): List<String> {
        val ksu = if (source in setOf("ksu_logcat", "ksu_dmesg", "all_history")) {
            runCatching { root.listFiles(ksuDirectory, 100) }.getOrDefault(emptyList())
        } else emptyList()
        val lspd = if (source in setOf("lspd", "all_history")) {
            runCatching { root.listFiles(lspdDirectory, 100) }.getOrDefault(emptyList())
        } else emptyList()
        return when (source) {
            "ksu_logcat" -> ksu.filter { File(it).name.startsWith("logcat") && it.endsWith(".log") }.take(latestFiles)
            "ksu_dmesg" -> ksu.filter { File(it).name.startsWith("dmesg") && it.endsWith(".log") }.take(latestFiles)
            "lspd" -> lspd.filter { it.endsWith(".log") }.take(latestFiles)
            "all_history" -> (
                ksu.filter { it.endsWith(".log") }.take(latestFiles) +
                    lspd.filter { it.endsWith(".log") }.take(latestFiles)
                )
            else -> error("Unsupported log source: $source")
        }.also { require(it.isNotEmpty()) { "No matching historical log files found for $source" } }
    }

    private fun scan(inputs: List<LogInput>, args: JSONObject): JSONObject {
        val query = args.optString("query")
        val ignoreCase = args.optBoolean("ignore_case", true)
        val regex = args.optBoolean("regex", false)
        val pattern = if (regex && query.isNotBlank()) {
            Pattern.compile(query, if (ignoreCase) Pattern.CASE_INSENSITIVE else 0)
        } else null
        val includes = args.stringList("include")
        val excludes = args.stringList("exclude")
        val levels = args.stringList("levels").map(String::uppercase).toSet()
        val tags = args.stringList("tags")
        val beforeCount = args.optInt("context_before", 2).coerceIn(0, 20)
        val afterCount = args.optInt("context_after", 2).coerceIn(0, 20)
        val cursor = args.optString("cursor", "0").toIntOrNull()?.coerceAtLeast(0) ?: 0
        val limit = args.optInt("limit", 100).coerceIn(1, 300)
        val tailMode = query.isBlank() && includes.isEmpty() && tags.isEmpty() && levels.isEmpty()
        val tailLimit = args.optInt("tail_lines", 200).coerceIn(1, 1000)
        val previous = ArrayDeque<String>()
        val pending = ArrayList<MutableHit>()
        val completed = ArrayList<MutableHit>()
        var matchCount = 0

        for (input in inputs) {
            previous.clear()
            input.file.bufferedReader().useLines { lines ->
                lines.forEachIndexed { index, line ->
                    pending.forEach { hit ->
                        if (hit.after.size < afterCount) hit.after += line
                    }
                    val iterator = pending.iterator()
                    while (iterator.hasNext()) {
                        val hit = iterator.next()
                        if (hit.after.size >= afterCount) {
                            completed += hit
                            iterator.remove()
                        }
                    }

                    if (matches(line, query, pattern, ignoreCase, includes, excludes, levels, tags)) {
                        if (tailMode) {
                            completed += MutableHit(input.source, input.label, index + 1, line, previous.toList(), arrayListOf())
                            while (completed.size > tailLimit) completed.removeAt(0)
                        } else {
                            if (matchCount >= cursor && matchCount < cursor + limit) {
                                pending += MutableHit(input.source, input.label, index + 1, line, previous.toList(), arrayListOf())
                            }
                            matchCount++
                        }
                    }
                    previous += line
                    while (previous.size > beforeCount) previous.removeFirst()
                }
            }
            completed += pending
            pending.clear()
        }

        val selected = if (tailMode) completed.takeLast(tailLimit) else completed.take(limit)
        return jsonObject(
            "items" to jsonArray(selected.map { hit ->
                jsonObject(
                    "source" to hit.source,
                    "file" to hit.file,
                    "line_number" to hit.lineNumber,
                    "line" to hit.line,
                    "before" to jsonArray(hit.before),
                    "after" to jsonArray(hit.after)
                )
            }),
            "next_cursor" to if (!tailMode && matchCount > cursor + limit) (cursor + limit).toString() else null,
            "matched" to if (tailMode) selected.size else matchCount,
            "tail_mode" to tailMode
        )
    }

    private fun matches(
        line: String,
        query: String,
        pattern: Pattern?,
        ignoreCase: Boolean,
        includes: List<String>,
        excludes: List<String>,
        levels: Set<String>,
        tags: List<String>
    ): Boolean {
        if (query.isNotBlank()) {
            val queryMatches = pattern?.matcher(line)?.find() ?: line.contains(query, ignoreCase)
            if (!queryMatches) return false
        }
        if (includes.isNotEmpty() && includes.none { line.contains(it, ignoreCase) }) return false
        if (excludes.any { line.contains(it, ignoreCase) }) return false
        if (levels.isNotEmpty() && levels.none { level ->
                line.contains(" $level ") || line.contains(" $level/")
            }
        ) return false
        if (tags.isNotEmpty() && tags.none { line.contains(it, ignoreCase) }) return false
        return true
    }

    private fun sourceForPath(path: String): String = when {
        path.startsWith(lspdDirectory) -> "lspd"
        File(path).name.startsWith("dmesg") -> "ksu_dmesg"
        else -> "ksu_logcat"
    }
}

private data class LogInput(val source: String, val label: String, val file: File)
private data class MutableHit(
    val source: String,
    val file: String,
    val lineNumber: Int,
    val line: String,
    val before: List<String>,
    val after: ArrayList<String>
)
