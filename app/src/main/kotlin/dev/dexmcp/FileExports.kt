package dev.dexmcp

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.UUID

class FileExports(context: Context, private val root: RootAccess) {
    private val directory = File(context.cacheDir, "file-exports")

    fun prepare(args: JSONObject): JSONObject {
        val source = root.validateSource(args.getString("path"))
        directory.mkdirs()
        val id = UUID.randomUUID().toString()
        val copy = File(directory, "$id.bin")
        try {
            root.copyForAnalysis(source.path, copy)
            val digest = MessageDigest.getInstance("SHA-256")
            copy.inputStream().use { stream ->
                val buffer = ByteArray(65536)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
            val metadata = jsonObject("export_id" to id, "source_path" to source.path,
                "filename" to source.name, "size" to copy.length(),
                "sha256" to digest.digest().joinToString("") { "%02x".format(it) },
                "chunk_size" to 65536)
            File(directory, "$id.json").writeText(metadata.toString())
            return metadata
        } catch (t: Throwable) {
            copy.delete()
            throw t
        }
    }

    fun read(args: JSONObject): JSONObject {
        val id = args.getString("export_id")
        require(UUID.fromString(id).toString() == id) { "Invalid export ID" }
        val metadataFile = File(directory, "$id.json")
        require(metadataFile.isFile) { "Export expired or not found" }
        val metadata = JSONObject(metadataFile.readText())
        // Closing unrestricted access also revokes access to cached exports.
        root.validateSource(metadata.getString("source_path"))
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
        File(directory, "$id.bin").delete()
        File(directory, "$id.json").delete()
        return jsonObject("export_id" to id, "deleted" to true)
    }
}
