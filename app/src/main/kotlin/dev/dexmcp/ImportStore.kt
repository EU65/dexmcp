package dev.dexmcp

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File
import java.util.UUID

data class ImportedFile(val id: String, val name: String, val file: File, val size: Long)

class ImportStore(private val context: Context) {
    private val directory = File(context.filesDir, "imports").apply { mkdirs() }

    fun import(uri: Uri): ImportedFile {
        val displayName = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        } ?: "artifact.bin"
        val safeName = displayName.replace(Regex("[^A-Za-z0-9._-]"), "_").take(120).ifBlank { "artifact.bin" }
        val id = UUID.randomUUID().toString()
        val output = File(directory, "$id--$safeName")
        try {
            context.contentResolver.openInputStream(uri).use { input ->
                requireNotNull(input) { "Unable to open selected file" }
                output.outputStream().use { input.copyTo(it) }
            }
        } catch (t: Throwable) {
            output.delete()
            throw t
        }
        return ImportedFile(id, safeName, output, output.length())
    }

    fun list(): List<ImportedFile> = directory.listFiles().orEmpty()
        .filter { it.isFile && it.name.contains("--") }
        .map { file ->
            val parts = file.name.split("--", limit = 2)
            ImportedFile(parts[0], parts[1], file, file.length())
        }
        .sortedByDescending { it.file.lastModified() }

    fun get(id: String): ImportedFile = list().firstOrNull { it.id == id }
        ?: error("Imported file not found: $id")
}
