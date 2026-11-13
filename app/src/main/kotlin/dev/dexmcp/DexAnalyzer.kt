package dev.dexmcp

import com.android.tools.smali.baksmali.Adaptors.ClassDefinition
import com.android.tools.smali.baksmali.Adaptors.MethodDefinition
import com.android.tools.smali.baksmali.BaksmaliOptions
import com.android.tools.smali.baksmali.formatter.BaksmaliWriter
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.util.ReferenceUtil
import net.dongliu.apk.parser.ApkFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.StringWriter
import java.util.zip.ZipFile

class DexAnalyzer {
    fun list(workspace: AnalysisWorkspace, args: JSONObject): JSONObject {
        val kind = args.optString("kind", "artifacts")
        val cursor = args.optString("cursor", "0").toIntOrNull()?.coerceAtLeast(0) ?: 0
        val limit = args.optInt("limit", 100).coerceIn(1, 200)
        val all = when (kind) {
            "artifacts" -> workspace.artifacts.map {
                jsonObject("artifact_id" to it.id, "source_path" to it.sourcePath, "size" to it.size, "sha256" to it.sha256)
            }
            "dex_files" -> workspace.dexUnits.map {
                jsonObject("artifact_id" to it.artifact.id, "entry" to it.entryName, "classes" to it.dexFile.classes.size)
            }
            "dex_classes" -> workspace.dexUnits.flatMap { unit ->
                unit.dexFile.classes.map { jsonObject("artifact_id" to unit.artifact.id, "dex" to unit.entryName, "class" to it.type) }
            }.sortedBy { it.getString("class") }
            "zip_entries" -> workspace.artifacts.flatMap { artifact ->
                runCatching {
                    ZipFile(artifact.localFile).use { zip ->
                        zip.entries().asSequence().map { entry ->
                            jsonObject("artifact_id" to artifact.id, "path" to entry.name, "size" to entry.size, "compressed_size" to entry.compressedSize)
                        }.toList()
                    }
                }.getOrDefault(emptyList())
            }
            else -> error("Unsupported list kind: $kind")
        }
        val page = all.drop(cursor).take(limit)
        return jsonObject(
            "workspace_id" to workspace.id,
            "kind" to kind,
            "items" to jsonArray(page),
            "next_cursor" to if (cursor + page.size < all.size) (cursor + page.size).toString() else null,
            "total" to all.size
        )
    }

    fun outlineClass(workspace: AnalysisWorkspace, descriptor: String): JSONObject {
        val (unit, cls) = findClass(workspace, descriptor)
        val fields = cls.fields.map { field ->
            jsonObject(
                "id" to ReferenceUtil.getFieldDescriptor(field),
                "name" to field.name,
                "type" to field.type,
                "access" to AccessFlags.formatAccessFlagsForField(field.accessFlags)
            )
        }
        val methods = cls.methods.map { method ->
            jsonObject(
                "id" to ReferenceUtil.getMethodDescriptor(method),
                "name" to method.name,
                "return_type" to method.returnType,
                "parameters" to jsonArray(method.parameterTypes),
                "access" to AccessFlags.formatAccessFlagsForMethod(method.accessFlags),
                "has_code" to (method.implementation != null)
            )
        }
        return jsonObject(
            "artifact_id" to unit.artifact.id,
            "dex" to unit.entryName,
            "class" to cls.type,
            "access" to AccessFlags.formatAccessFlagsForClass(cls.accessFlags),
            "superclass" to cls.superclass,
            "interfaces" to jsonArray(cls.interfaces),
            "source_file" to cls.sourceFile,
            "fields" to jsonArray(fields),
            "methods" to jsonArray(methods)
        )
    }

    fun search(workspace: AnalysisWorkspace, args: JSONObject): JSONObject {
        val query = args.getString("query")
        require(query.isNotBlank()) { "query must not be blank" }
        val kinds = args.stringList("kinds").ifEmpty { listOf("class", "method", "field", "dex_string") }.toSet()
        val ignoreCase = args.optBoolean("ignore_case", true)
        val cursor = args.optString("cursor", "0").toIntOrNull()?.coerceAtLeast(0) ?: 0
        val limit = args.optInt("limit", 50).coerceIn(1, 200)
        val hits = ArrayList<JSONObject>()

        fun matches(value: String) = value.contains(query, ignoreCase)
        for (unit in workspace.dexUnits) {
            if ("class" in kinds || "method" in kinds || "field" in kinds) {
                for (cls in unit.dexFile.classes) {
                    if ("class" in kinds && matches(cls.type)) hits += hit(unit, "class", cls.type, cls.type)
                    if ("field" in kinds) for (field in cls.fields) {
                        val id = ReferenceUtil.getFieldDescriptor(field)
                        if (matches(id)) hits += hit(unit, "field", id, id)
                    }
                    if ("method" in kinds) for (method in cls.methods) {
                        val id = ReferenceUtil.getMethodDescriptor(method)
                        if (matches(id)) hits += hit(unit, "method", id, id)
                    }
                }
            }
            if ("dex_string" in kinds) for (stringRef in unit.dexFile.stringReferences) {
                val value = stringRef.string
                if (matches(value)) hits += hit(unit, "dex_string", value, value.take(500))
            }
        }
        val page = hits.drop(cursor).take(limit)
        return jsonObject(
            "workspace_id" to workspace.id,
            "query" to query,
            "items" to jsonArray(page),
            "next_cursor" to if (cursor + page.size < hits.size) (cursor + page.size).toString() else null,
            "total" to hits.size
        )
    }

    fun read(workspace: AnalysisWorkspace, args: JSONObject): JSONObject {
        return when (args.getString("type")) {
            "manifest" -> {
                val artifact = selectArtifact(workspace, args.optString("artifact_id"))
                val text = ApkFile(artifact.localFile).use { it.manifestXml }
                textResult(workspace, artifact, "manifest", text, args)
            }
            "zip_entry" -> {
                val artifact = selectArtifact(workspace, args.optString("artifact_id"))
                val path = args.getString("path")
                val text = ZipFile(artifact.localFile).use { zip ->
                    val entry = zip.getEntry(path) ?: error("ZIP entry not found: $path")
                    require(entry.size <= 2_000_000) { "ZIP text entry is too large" }
                    zip.getInputStream(entry).bufferedReader().use { it.readText() }
                }
                textResult(workspace, artifact, path, text, args)
            }
            "class" -> {
                val descriptor = args.getString("id")
                val (unit, cls) = findClass(workspace, descriptor)
                val options = options(unit)
                val output = StringWriter()
                BaksmaliWriter(output).use { ClassDefinition(options, cls).writeTo(it) }
                textResult(workspace, unit.artifact, descriptor, output.toString(), args)
            }
            "method" -> {
                val id = args.getString("id")
                val (unit, cls, method) = findMethod(workspace, id)
                val classDefinition = ClassDefinition(options(unit), cls)
                val output = StringWriter()
                BaksmaliWriter(output).use { writer ->
                    val implementation = method.implementation
                    if (implementation == null) MethodDefinition.writeEmptyMethodTo(writer, method, classDefinition)
                    else MethodDefinition(classDefinition, method, implementation).writeTo(writer)
                }
                textResult(workspace, unit.artifact, id, output.toString(), args)
            }
            else -> error("Unsupported read type")
        }
    }

    fun xref(workspace: AnalysisWorkspace, args: JSONObject): JSONObject {
        val target = args.getString("target")
        val limit = args.optInt("limit", 100).coerceIn(1, 300)
        val results = ArrayList<JSONObject>()
        for (unit in workspace.dexUnits) {
            for (cls in unit.dexFile.classes) for (method in cls.methods) {
                val impl = method.implementation ?: continue
                var codeOffset = 0
                for (instruction in impl.instructions) {
                    val reference = (instruction as? ReferenceInstruction)?.reference
                    if (reference != null) {
                        val value = runCatching { ReferenceUtil.getReferenceString(reference) }
                            .getOrNull() ?: reference.toString()
                        if (value == target || value.contains(target)) {
                            results += jsonObject(
                                "artifact_id" to unit.artifact.id,
                                "dex" to unit.entryName,
                                "from_method" to ReferenceUtil.getMethodDescriptor(method),
                                "offset_code_units" to codeOffset,
                                "opcode" to instruction.opcode.name,
                                "reference" to value
                            )
                            if (results.size >= limit) break
                        }
                    }
                    codeOffset += instruction.codeUnits
                }
                if (results.size >= limit) break
            }
            if (results.size >= limit) break
        }
        return jsonObject("workspace_id" to workspace.id, "target" to target, "items" to jsonArray(results), "truncated" to (results.size >= limit))
    }

    private fun options(unit: DexUnit) = BaksmaliOptions().apply {
        apiLevel = unit.dexFile.opcodes.api
        parameterRegisters = true
        debugInfo = true
        codeOffsets = true
    }

    private fun textResult(workspace: AnalysisWorkspace, artifact: Artifact, target: String, raw: String, args: JSONObject): JSONObject {
        val maxChars = args.optInt("max_chars", 200_000).coerceIn(1, 500_000)
        val text = raw.take(maxChars)
        return jsonObject(
            "workspace_id" to workspace.id,
            "artifact_id" to artifact.id,
            "target" to target,
            "text" to text,
            "truncated" to (text.length < raw.length)
        )
    }

    private fun hit(unit: DexUnit, kind: String, id: String, snippet: String) = jsonObject(
        "artifact_id" to unit.artifact.id,
        "source_path" to unit.artifact.sourcePath,
        "dex" to unit.entryName,
        "kind" to kind,
        "id" to id,
        "snippet" to snippet
    )

    private fun selectArtifact(workspace: AnalysisWorkspace, id: String): Artifact =
        if (id.isBlank()) workspace.artifacts.first() else workspace.artifacts.firstOrNull { it.id == id }
            ?: error("Artifact not found: $id")

    private fun findClass(workspace: AnalysisWorkspace, descriptor: String): Pair<DexUnit, ClassDef> {
        for (unit in workspace.dexUnits) {
            unit.dexFile.classes.firstOrNull { it.type == descriptor }?.let { return unit to it }
        }
        error("Class not found: $descriptor")
    }

    private fun findMethod(workspace: AnalysisWorkspace, id: String): Triple<DexUnit, ClassDef, Method> {
        for (unit in workspace.dexUnits) for (cls in unit.dexFile.classes) {
            cls.methods.firstOrNull { ReferenceUtil.getMethodDescriptor(it) == id }?.let { return Triple(unit, cls, it) }
        }
        error("Method not found: $id")
    }
}
