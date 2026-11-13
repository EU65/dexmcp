package dev.dexmcp

import android.content.Context
import android.os.Build
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.UUID

class SystemDiagnostics(context: Context, private val root: RootAccess) {
    private val directory = File(context.filesDir, "snapshots")

    fun discover(args: JSONObject, recursive: Boolean): JSONObject {
        val path = args.getString("path")
        val query = args.optString("query")
        val cursor = args.optString("cursor", "0").toIntOrNull()?.coerceAtLeast(0) ?: 0
        val limit = args.optInt("limit", 100).coerceIn(1, 200)
        val output = root.discoverFiles(path, recursive, args.optInt("max_depth", 4))
        val items = output.stdout.lineSequence()
            .filter { it.startsWith('/') && !it.contains("[truncated]") }
            .filter { query.isBlank() || File(it).name.contains(query, ignoreCase = true) }
            .distinct().sorted().toList()
        val page = items.drop(cursor).take(limit)
        val complete = output.exitCode == 0 && !output.stdout.contains("[truncated]")
        return jsonObject(
            "path" to path, "recursive" to recursive,
            "items" to jsonArray(page.map { jsonObject("path" to it, "name" to File(it).name) }),
            "cursor" to cursor.toString(),
            "next_cursor" to if (cursor + page.size < items.size) (cursor + page.size).toString() else null,
            "complete" to complete, "exit_code" to output.exitCode, "stderr" to output.stderr,
            "hint" to "Entries include files and directories; repeat pagination with identical arguments. An incomplete scan can omit matches."
        )
    }

    @Synchronized
    fun collect(args: JSONObject): JSONObject {
        val save = args.optBoolean("save", true)
        if (save) {
            directory.mkdirs()
            check(directory.listFiles().orEmpty().count { it.extension == "json" } < 64) {
                "Snapshot storage limit (64) reached; delete an unneeded snapshot first"
            }
        }
        val snapshot = root.snapshot(args.getString("profile"))
        val result = jsonObject(
            "profile" to snapshot.profile, "timestamp" to snapshot.timestamp,
            "label" to args.optString("label").take(200),
            "fingerprint" to Build.FINGERPRINT, "device" to Build.DEVICE,
            "sections" to JSONObject().apply {
                snapshot.sections.forEach { (name, output) ->
                    put(name, jsonObject("exit_code" to output.exitCode, "stdout" to output.stdout,
                        "stderr" to output.stderr, "sha256" to hash(output.stdout),
                        "truncated" to output.stdout.contains("[truncated]")))
                }
            }
        )
        if (save) {
            val id = UUID.randomUUID().toString()
            result.put("snapshot_id", id)
            val temp = File(directory, "$id.tmp")
            temp.writeText(result.toString(), Charsets.UTF_8)
            check(temp.renameTo(file(id))) { "Unable to save snapshot" }
        }
        return result
    }

    fun list(): JSONObject = jsonObject("items" to jsonArray(directory.listFiles().orEmpty()
        .filter { it.extension == "json" }.sortedByDescending { it.lastModified() }.map {
            val data = JSONObject(it.readText(Charsets.UTF_8))
            jsonObject("snapshot_id" to data.getString("snapshot_id"), "profile" to data.getString("profile"),
                "label" to data.optString("label"), "timestamp" to data.getLong("timestamp"),
                "device" to data.optString("device"), "fingerprint" to data.optString("fingerprint"),
                "bytes" to it.length())
        }))

    fun get(args: JSONObject): JSONObject {
        val data = load(args.getString("snapshot_id"))
        val section = args.optString("section")
        if (section.isNotBlank()) return jsonObject("snapshot_id" to data.getString("snapshot_id"),
            "section" to section, "data" to data.getJSONObject("sections").getJSONObject(section))
        if (args.optString("format", "json") == "markdown") {
            val report = buildString {
                append("# Android diagnostic snapshot\n\n")
                append("ID: ${data.getString("snapshot_id")}\n\n")
                append("Profile: ${data.getString("profile")}\n\n")
                append("Label: ${data.optString("label")}\n\n")
                append("Timestamp (Unix ms): ${data.getLong("timestamp")}\n\n")
                append("Build: ${data.optString("fingerprint")}\n\n")
                val sections = data.getJSONObject("sections")
                for (name in sections.keys().asSequence().sorted()) {
                    val value = sections.getJSONObject(name)
                    val text = value.getString("stdout") + "\n" + value.getString("stderr")
                    // Tilde fences avoid collisions with backticks in diagnostic output.
                    val fence = "~".repeat(maxOf(3, Regex("~+").findAll(text).maxOfOrNull { it.value.length + 1 } ?: 3))
                    append("## $name (exit ${value.getInt("exit_code")})\n\n$fence\n$text\n$fence\n\n")
                }
            }
            return jsonObject("snapshot_id" to data.getString("snapshot_id"), "format" to "markdown", "content" to report)
        }
        return data
    }

    @Synchronized
    fun delete(id: String): JSONObject = jsonObject("snapshot_id" to id, "deleted" to file(id).delete())

    fun compare(args: JSONObject): JSONObject {
        val before = load(args.getString("before_id"))
        val after = load(args.getString("after_id"))
        val oldSections = before.getJSONObject("sections")
        val newSections = after.getJSONObject("sections")
        val limit = args.optInt("line_limit", 100).coerceIn(1, 500)
        val selected = args.stringList("sections").toSet()
        val names = (oldSections.keys().asSequence().toList() + newSections.keys().asSequence().toList())
            .distinct().sorted().filter { selected.isEmpty() || it in selected }
        val changes = names.mapNotNull { name ->
            val old = oldSections.optJSONObject(name)
            val new = newSections.optJSONObject(name)
            if (old != null && new != null && listOf("exit_code", "stdout", "stderr", "truncated")
                    .all { old.opt(it) == new.opt(it) }) return@mapNotNull null
            fun lines(value: JSONObject?) = value?.optString("stdout").orEmpty().lines()
            val oldLines = lines(old)
            val newLines = lines(new)
            val oldSet = oldLines.toSet()
            val newSet = newLines.toSet()
            val removed = oldLines.filter { it !in newSet }
            val added = newLines.filter { it !in oldSet }
            jsonObject("section" to name, "before_exit_code" to old?.optInt("exit_code"),
                "after_exit_code" to new?.optInt("exit_code"),
                "before_stderr" to old?.optString("stderr"), "after_stderr" to new?.optString("stderr"),
                "before_sha256" to old?.optString("sha256"), "after_sha256" to new?.optString("sha256"),
                "removed_lines" to jsonArray(removed.take(limit)), "added_lines" to jsonArray(added.take(limit)),
                "line_order_or_counts_changed" to (oldLines != newLines && removed.isEmpty() && added.isEmpty()),
                "diff_truncated" to (removed.size > limit || added.size > limit),
                "source_truncated" to (old?.optBoolean("truncated") == true || new?.optBoolean("truncated") == true))
        }
        return jsonObject("before_id" to before.getString("snapshot_id"), "after_id" to after.getString("snapshot_id"),
            "same_profile" to (before.getString("profile") == after.getString("profile")),
            "before_fingerprint" to before.optString("fingerprint"), "after_fingerprint" to after.optString("fingerprint"),
            "changed_sections" to jsonArray(changes),
            "hint" to "Exact line membership comparison, not causal analysis. Runtime timestamps/PIDs naturally differ; get original sections to examine order and repeated lines.")
    }

    private fun file(id: String): File {
        require(Regex("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}").matches(id)) { "Invalid snapshot ID" }
        return File(directory, "$id.json")
    }

    private fun load(id: String): JSONObject = JSONObject(file(id).readText(Charsets.UTF_8))
    private fun hash(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it.toInt() and 255) }
}
