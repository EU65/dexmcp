package dev.dexmcp

import android.content.Context
import android.content.pm.ApplicationInfo
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.MultiDexContainer
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

data class Artifact(
    val id: String,
    val sourcePath: String,
    val localFile: File,
    val size: Long,
    val sha256: String
)

data class DexUnit(
    val artifact: Artifact,
    val entryName: String,
    val dexFile: DexBackedDexFile
)

class AnalysisWorkspace(
    val id: String,
    val title: String,
    val directory: File,
    val artifacts: List<Artifact>
) {
    val dexUnits: List<DexUnit> by lazy {
        artifacts.flatMap { artifact ->
            runCatching {
                val container = DexFileFactory.loadDexContainer(artifact.localFile, Opcodes.getDefault())
                container.dexEntryNames.mapNotNull { name ->
                    @Suppress("UNCHECKED_CAST")
                    val entry = container.getEntry(name) as? MultiDexContainer.DexEntry<DexBackedDexFile>
                    entry?.let { DexUnit(artifact, name, it.dexFile) }
                }
            }.getOrDefault(emptyList())
        }
    }
}

class WorkspaceManager(private val context: Context, private val root: RootAccess) {
    private val workspaces = ConcurrentHashMap<String, AnalysisWorkspace>()
    private val imports = ImportStore(context)

    fun open(args: org.json.JSONObject): AnalysisWorkspace {
        val packageName = args.optString("package").takeIf { it.isNotBlank() }
        val directPath = args.optString("path").takeIf { it.isNotBlank() }
        val importId = args.optString("import_id").takeIf { it.isNotBlank() }
        require(packageName != null || directPath != null || importId != null) { "Provide package, path, or import_id" }

        val imported = importId?.let(imports::get)
        val paths = if (packageName != null) {
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            buildList {
                add(info.sourceDir)
                if (args.optBoolean("include_splits", true)) addAll(info.splitSourceDirs?.toList().orEmpty())
            }
        } else if (directPath != null) listOf(directPath) else listOf(imported!!.file.path)

        val id = UUID.randomUUID().toString()
        val dir = File(context.cacheDir, "workspaces/$id").canonicalFile
        dir.mkdirs()
        val artifacts = try {
            paths.distinct().mapIndexed { index, source ->
                val safeName = File(source).name.replace(Regex("[^A-Za-z0-9._-]"), "_")
                val local = File(dir, "$index-$safeName")
                if (imported != null && imported.file.canonicalPath == File(source).canonicalPath) {
                    imported.file.inputStream().use { input -> local.outputStream().use(input::copyTo) }
                } else {
                    root.copyForAnalysis(source, local)
                }
                val digest = sha256(local)
                Artifact("sha256:$digest", source, local, local.length(), digest)
            }
        } catch (t: Throwable) {
            dir.deleteRecursively()
            throw t
        }
        val defaultTitle = packageName ?: imported?.name ?: File(directPath!!).name
        val workspace = AnalysisWorkspace(id, args.optString("title", defaultTitle), dir, artifacts)
        workspaces[id] = workspace
        return workspace
    }

    fun get(id: String): AnalysisWorkspace = workspaces[id] ?: error("Workspace not found: $id")

    fun close(id: String): Boolean {
        val workspace = workspaces.remove(id) ?: return false
        val expectedRoot = File(context.cacheDir, "workspaces").canonicalFile
        require(workspace.directory.canonicalPath.startsWith(expectedRoot.path + File.separator))
        return workspace.directory.deleteRecursively()
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(128 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
