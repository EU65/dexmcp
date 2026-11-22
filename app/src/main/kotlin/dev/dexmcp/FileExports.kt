package dev.dexmcp

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipFile

class FileExports(context: Context, private val root: RootAccess) {
    private val directory = File(context.cacheDir, "file-exports")

    fun prepare(args: JSONObject): JSONObject {
        val source = root.validateSource(args.getString("path"))
        return prepare(source.path, source.name) { copy -> root.copyForAnalysis(source.path, copy) }
    }

    fun prepareEntry(artifact: Artifact, entryPath: String): JSONObject {
        // A workspace may also have been created through the app's file picker.
        // Only those explicitly imported files can omit the system path check.
        val source = artifact.sourcePath
        if (!artifact.imported) root.validateSource(source)
        val name = entryPath.substringAfterLast('/')
        require(name.isNotEmpty()) { "ZIP entry must be a file" }
        return prepare(source, name, entryPath, artifact.imported) { copy ->
            ZipFile(artifact.localFile).use { zip ->
                val entry = zip.getEntry(entryPath)?.takeIf { !it.isDirectory && it.name == entryPath }
                    ?: error("ZIP entry not found: $entryPath")
                require(entry.size in 0..MAX_ENTRY_BYTES) { "ZIP entry exceeds 2 GiB or has no size" }
                zip.getInputStream(entry).use { input ->
                    copy.outputStream().use { output ->
                        var remaining = entry.size
                        val buf = ByteArray(128 * 1024)
                        while (remaining > 0) {
                            val count = input.read(buf, 0, minOf(buf.size.toLong(), remaining).toInt())
                            check(count >= 0) { "ZIP entry is truncated" }
                            output.write(buf, 0, count)
                            remaining -= count
                        }
                        check(input.read() < 0) { "ZIP entry exceeds its declared size" }
                    }
                }
            }
        }
    }

    private fun prepare(source: String, filename: String, entry: String? = null, imported: Boolean = false, write: (File) -> Unit): JSONObject {
        directory.mkdirs()
        val id = UUID.randomUUID().toString()
        val copy = File(directory, "$id.bin")
        val metadataFile = File(directory, "$id.json")
        try {
            write(copy)
            val digest = MessageDigest.getInstance("SHA-256")
            copy.inputStream().use { stream ->
                val buffer = ByteArray(128 * 1024)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
            val metadata = jsonObject("export_id" to id, "source_path" to source,
                "filename" to filename, "size" to copy.length(),
                "sha256" to digest.digest().joinToString("") { "%02x".format(it) },
                "chunk_size" to 65536, "zip_entry" to entry, "imported" to imported,
                "download_path" to "/exports/$id", "download_token" to UUID.randomUUID().toString(),
                "download_token_expires_at_ms" to System.currentTimeMillis() + 30 * 60 * 1000L)
            metadataFile.writeText(metadata.toString())
            return metadata.apply { remove("imported") }
        } catch (t: Throwable) {
            copy.delete()
            metadataFile.delete()
            throw t
        }
    }

    private fun metadata(id: String): JSONObject {
        require(UUID.fromString(id).toString() == id) { "Invalid export ID" }
        val metadataFile = File(directory, "$id.json")
        require(metadataFile.isFile) { "Export expired or not found" }
        return JSONObject(metadataFile.readText())
    }

    private fun checkSource(metadata: JSONObject) {
        if (!metadata.optBoolean("imported")) root.validateSource(metadata.getString("source_path"))
    }

    fun download(id: String, authorization: String?, sameDevice: Boolean, serverAuthorized: Boolean): Download? {
        val meta = try { metadata(id) } catch (_: IllegalArgumentException) { return null }
        val localToken = meta.optString("download_token")
        if (!serverAuthorized && !(sameDevice && localToken.isNotEmpty() && authorization == "Bearer $localToken" &&
            System.currentTimeMillis() < meta.optLong("download_token_expires_at_ms"))) return null
        checkSource(meta)
        val file = File(directory, "$id.bin")
        if (!file.isFile) return null
        return Download(file, meta.getLong("size"), meta.getString("sha256"))
    }

    data class Download(val file: File, val size: Long, val sha256: String) {
        fun open(offset: Long): InputStream {
            val input = file.inputStream()
            try {
                input.channel.position(offset)
                return input
            } catch (t: Throwable) {
                input.close()
                throw t
            }
        }
    }

    fun read(args: JSONObject): JSONObject {
        val id = args.getString("export_id")
        checkSource(metadata(id))
        val file = File(directory, "$id.bin")
        val offset = args.optLong("offset", 0)
        require(offset in 0..file.length()) { "Offset outside file" }
        val bytes = ByteArray(minOf(args.optInt("max_bytes", 65536).coerceIn(1, 65536).toLong(), file.length() - offset).toInt())
        RandomAccessFile(file, "r").use { it.seek(offset); it.readFully(bytes) }
        return jsonObject("export_id" to id, "offset" to offset, "bytes_read" to bytes.size,
            "next_offset" to offset + bytes.size, "eof" to (offset + bytes.size == file.length()),
            "content_base64" to Base64.encodeToString(bytes, Base64.NO_WRAP))
    }

    fun delete(args: JSONObject): JSONObject {
        val id = args.getString("export_id")
        require(UUID.fromString(id).toString() == id) { "Invalid export ID" }
        File(directory, "$id.json").delete()
        File(directory, "$id.bin").delete()
        return jsonObject("export_id" to id, "deleted" to true)
    }

    private companion object {
        const val MAX_ENTRY_BYTES = 2L * 1024 * 1024 * 1024
    }
}
