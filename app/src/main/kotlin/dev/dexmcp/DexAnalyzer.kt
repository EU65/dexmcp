package dev.dexmcp

import com.android.tools.smali.baksmali.Adaptors.ClassDefinition
import com.android.tools.smali.baksmali.Adaptors.Format.InstructionMethodItemFactory
import com.android.tools.smali.baksmali.Adaptors.MethodDefinition
import com.android.tools.smali.baksmali.BaksmaliOptions
import com.android.tools.smali.baksmali.formatter.BaksmaliWriter
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.Reference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.util.ReferenceUtil
import net.dongliu.apk.parser.ApkFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.StringWriter
import java.util.regex.Pattern
import java.util.zip.ZipFile

class DexAnalyzer {
    fun list(workspace: AnalysisWorkspace, args: JSONObject): JSONObject {
        val kind = args.optString("kind", "artifacts")
        val cursor = args.optString("cursor", "0").toIntOrNull()?.coerceAtLeast(0) ?: 0
        val limit = args.optInt("limit", 100).coerceIn(1, 200)
        val query = args.optString("query", "").trim()
        val ignoreCase = args.optBoolean("ignore_case", true)
        val regex = args.optBoolean("regex", false)
        val artifactFilter = args.optString("artifact_id", "").trim()
        val pattern = if (query.isNotEmpty() && regex) compile(query, ignoreCase) else null

        fun matches(value: String): Boolean = when {
            pattern != null -> pattern.matcher(value).find()
            query.isEmpty() -> true
            else -> value.contains(query, ignoreCase)
        }

        val all = when (kind) {
            "artifacts" -> workspace.artifacts
                .filter { artifactFilter.isEmpty() || it.id == artifactFilter }
                .map {
                    jsonObject("artifact_id" to it.id, "source_path" to it.sourcePath, "size" to it.size, "sha256" to it.sha256)
                }
            "dex_files" -> workspace.dexUnits
                .filter { artifactFilter.isEmpty() || it.artifact.id == artifactFilter }
                .map {
                    jsonObject("artifact_id" to it.artifact.id, "entry" to it.entryName, "classes" to it.dexFile.classes.size)
                }
                .filter { matches(it.getString("entry")) }
            "dex_classes" -> workspace.dexUnits
                .filter { artifactFilter.isEmpty() || it.artifact.id == artifactFilter }
                .flatMap { unit ->
                    unit.dexFile.classes.map { jsonObject("artifact_id" to unit.artifact.id, "dex" to unit.entryName, "class" to it.type) }
                }
                .filter { matches(it.getString("class")) }
                .sortedBy { it.getString("class") }
            "zip_entries" -> workspace.artifacts
                .filter { artifactFilter.isEmpty() || it.id == artifactFilter }
                .flatMap { artifact ->
                    runCatching {
                        ZipFile(artifact.localFile).use { zip ->
                            zip.entries().asSequence()
                                .filter { matches(it.name) }
                                .map { entry ->
                                    jsonObject(
                                        "artifact_id" to artifact.id,
                                        "path" to entry.name,
                                        "size" to entry.size,
                                        "compressed_size" to entry.compressedSize
                                    )
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
            "query" to query.ifBlank { null },
            "items" to jsonArray(page),
            "returned" to page.size,
            "total_matches" to all.size,
            "total" to all.size,
            "next_cursor" to if (cursor + page.size < all.size) (cursor + page.size).toString() else null,
            "complete" to (cursor + page.size >= all.size)
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
        val regex = args.optBoolean("regex", false)
        val scope = args.optString("in_class_prefix", "").trim()
        val dedupe = args.optBoolean("dedupe", true)
        val cursor = args.optString("cursor", "0").toIntOrNull()?.coerceAtLeast(0) ?: 0
        val limit = args.optInt("limit", 50).coerceIn(1, 200)
        val hits = ArrayList<JSONObject>()
        val pattern = if (regex) compile(query, ignoreCase) else null

        fun matches(value: String): Boolean =
            if (pattern != null) pattern.matcher(value).find() else value.contains(query, ignoreCase)

        val descriptorKinds = kinds.filter { it != "dex_string" }.toSet()
        val descriptors = HashSet<String>()

        if (descriptorKinds.isNotEmpty()) {
            for (unit in workspace.dexUnits) {
                for (cls in unit.dexFile.classes) {
                    if (scope.isNotEmpty() && !cls.type.startsWith(scope)) continue
                    if ("class" in descriptorKinds && matches(cls.type)) {
                        hits += hit(unit, "class", cls.type, cls.type)
                        descriptors += cls.type
                    }
                    if ("field" in descriptorKinds) for (field in cls.fields) {
                        val id = ReferenceUtil.getFieldDescriptor(field)
                        if (matches(id)) {
                            hits += hit(unit, "field", id, id)
                            descriptors += id
                        }
                    }
                    if ("method" in descriptorKinds) for (method in cls.methods) {
                        val id = ReferenceUtil.getMethodDescriptor(method)
                        if (matches(id)) {
                            hits += hit(unit, "method", id, id)
                            descriptors += id
                        }
                    }
                }
            }
        }

        if ("dex_string" in kinds) {
            val seen = HashSet<String>()
            if (scope.isNotEmpty()) {
                // Restricted to strings referenced by instructions of classes in the prefix.
                for (unit in workspace.dexUnits) {
                    for (cls in unit.dexFile.classes) {
                        if (!cls.type.startsWith(scope)) continue
                        for (method in cls.methods) {
                            val impl = method.implementation ?: continue
                            for (instruction in impl.instructions) {
                                val reference = (instruction as? ReferenceInstruction)?.reference as? StringReference ?: continue
                                val value = reference.string
                                if (matches(value) && seen.add(value) && !(dedupe && value in descriptors)) {
                                    hits += hit(unit, "dex_string", value, value.take(500))
                                }
                            }
                        }
                    }
                }
            } else {
                for (unit in workspace.dexUnits) {
                    for (stringRef in unit.dexFile.stringReferences) {
                        val value = stringRef.string
                        if (!matches(value)) continue
                        if (dedupe && value in descriptors) continue
                        if (dedupe && !seen.add(value)) continue
                        hits += hit(unit, "dex_string", value, value.take(500))
                    }
                }
            }
        }

        val page = hits.drop(cursor).take(limit)
        return jsonObject(
            "workspace_id" to workspace.id,
            "query" to query,
            "kinds" to jsonArray(kinds.toList()),
            "scoped_to" to scope.ifBlank { null },
            "items" to jsonArray(page),
            "returned" to page.size,
            "total_matches" to hits.size,
            "total" to hits.size,
            "next_cursor" to if (cursor + page.size < hits.size) (cursor + page.size).toString() else null,
            "complete" to (cursor + page.size >= hits.size)
        )
    }

    fun read(workspace: AnalysisWorkspace, args: JSONObject): JSONObject {
        val type = args.getString("type")
        val ids = args.optJSONArray("ids")?.let { array ->
            (0 until array.length()).mapNotNull { array.optString(it).takeIf(String::isNotBlank) }
        }.orEmpty()
        if (ids.isNotEmpty()) {
            require(type == "class" || type == "method") { "ids is only supported for type=class or type=method" }
            return readBatch(workspace, args, type, ids)
        }
        return when (type) {
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
                val noBodies = args.optBoolean("no_bodies", false)
                val text = if (noBodies) classSignatures(cls) else classText(unit, cls)
                val result = textResult(workspace, unit.artifact, descriptor, text, args)
                if (!noBodies) {
                    val previous = result.optString("hint").takeIf { it.isNotBlank() }
                    result.put(
                        "hint",
                        listOfNotNull(previous, "no_bodies=true returns signatures only; outline_class returns structured fields/methods.")
                            .joinToString(" ")
                    )
                }
                result
            }
            "method" -> {
                val id = args.getString("id")
                val (unit, cls, method) = findMethod(workspace, id)
                textResult(workspace, unit.artifact, id, methodText(unit, cls, method), args)
            }
            else -> error("Unsupported read type")
        }
    }

    fun xref(workspace: AnalysisWorkspace, args: JSONObject): JSONObject {
        val target = args.getString("target")
        val limit = args.optInt("limit", 100).coerceIn(1, 300)
        val contextInstructions = args.optInt("context_instructions", 0).coerceIn(0, 64)
        val results = ArrayList<JSONObject>()
        for (unit in workspace.dexUnits) {
            for (cls in unit.dexFile.classes) for (method in cls.methods) {
                val impl = method.implementation ?: continue
                if (contextInstructions == 0) {
                    var address = 0
                    for (instruction in impl.instructions) {
                        val reference = (instruction as? ReferenceInstruction)?.reference
                        if (reference != null) {
                            val value = runCatching { ReferenceUtil.getReferenceString(reference) }
                                .getOrNull() ?: reference.toString()
                            if (referenceMatches(value, target)) {
                                results += jsonObject(
                                    "artifact_id" to unit.artifact.id,
                                    "dex" to unit.entryName,
                                    "from_method" to ReferenceUtil.getMethodDescriptor(method),
                                    "offset_code_units" to address,
                                    "opcode" to instruction.opcode.name,
                                    "reference" to value
                                )
                                if (results.size >= limit) break
                            }
                        }
                        address += instruction.codeUnits
                    }
                    if (results.size >= limit) break
                    continue
                }

                val instructions = impl.instructions.toList()
                if (instructions.isEmpty()) continue
                val addresses = ArrayList<Int>(instructions.size)
                var running = 0
                for (instruction in instructions) {
                    addresses += running
                    running += instruction.codeUnits
                }
                var options: BaksmaliOptions? = null
                var methodDefinition: MethodDefinition? = null

                for (index in instructions.indices) {
                    val instruction = instructions[index]
                    val reference = (instruction as? ReferenceInstruction)?.reference ?: continue
                    val value = runCatching { ReferenceUtil.getReferenceString(reference) }
                        .getOrNull() ?: reference.toString()
                    if (!referenceMatches(value, target)) continue
                    val entry = jsonObject(
                        "artifact_id" to unit.artifact.id,
                        "dex" to unit.entryName,
                        "from_method" to ReferenceUtil.getMethodDescriptor(method),
                        "offset_code_units" to addresses[index],
                        "opcode" to instruction.opcode.name,
                        "reference" to value
                    )
                    if (methodDefinition == null) {
                        options = options(unit)
                        methodDefinition = MethodDefinition(ClassDefinition(options!!, cls), method, impl)
                    }
                    val from = (index - contextInstructions).coerceAtLeast(0)
                    val to = (index + contextInstructions).coerceAtMost(instructions.lastIndex)
                    val context = JSONArray()
                    for (k in from..to) {
                        val code = formatInstruction(options!!, methodDefinition!!, addresses[k], instructions[k])
                        context.put(jsonObject("offset" to addresses[k], "mark" to (k == index), "code" to code))
                    }
                    entry.put("context", context)
                    results += entry
                    if (results.size >= limit) break
                }
                if (results.size >= limit) break
            }
        }
        return jsonObject(
            "workspace_id" to workspace.id,
            "target" to target,
            "items" to jsonArray(results),
            "returned" to results.size,
            "truncated" to (results.size >= limit)
        )
    }

    private fun readBatch(workspace: AnalysisWorkspace, args: JSONObject, type: String, ids: List<String>): JSONObject {
        val budget = args.optInt("max_chars", 60_000).coerceIn(1, 400_000)
        val noBodies = args.optBoolean("no_bodies", false)
        var used = 0
        var skipped = 0
        val items = ArrayList<JSONObject>()
        for (id in ids) {
            if (used >= budget) {
                skipped++
                continue
            }
            val text = runCatching {
                when (type) {
                    "class" -> {
                        val (unit, cls) = findClass(workspace, id)
                        if (noBodies) classSignatures(cls) else classText(unit, cls)
                    }
                    else -> {
                        val (unit, cls, method) = findMethod(workspace, id)
                        methodText(unit, cls, method)
                    }
                }
            }.getOrElse { error ->
                items += jsonObject("id" to id, "error" to (error.message ?: error.javaClass.simpleName))
                continue
            }
            val take = minOf(text.length, budget - used)
            items += jsonObject(
                "id" to id,
                "text" to text.take(take),
                "size_chars" to text.length,
                "truncated" to (take < text.length)
            )
            used += take
        }
        return jsonObject(
            "workspace_id" to workspace.id,
            "type" to type,
            "items" to jsonArray(items),
            "returned" to items.size,
            "budget_chars" to budget,
            "used_chars" to used,
            "skipped" to skipped
        )
    }

    private fun classText(unit: DexUnit, cls: ClassDef): String {
        val output = StringWriter()
        BaksmaliWriter(output).use { ClassDefinition(options(unit), cls).writeTo(it) }
        return output.toString()
    }

    private fun methodText(unit: DexUnit, cls: ClassDef, method: Method): String {
        val classDefinition = ClassDefinition(options(unit), cls)
        val output = StringWriter()
        BaksmaliWriter(output).use { writer ->
            val implementation = method.implementation
            if (implementation == null) MethodDefinition.writeEmptyMethodTo(writer, method, classDefinition)
            else MethodDefinition(classDefinition, method, implementation).writeTo(writer)
        }
        return output.toString()
    }

    private fun classSignatures(cls: ClassDef): String = buildString {
        appendLine(".class ${AccessFlags.formatAccessFlagsForClass(cls.accessFlags)} ${cls.type}".trimEnd())
        cls.superclass?.let { appendLine(".super $it") }
        for (iface in cls.interfaces) appendLine(".implements $iface")
        if (cls.sourceFile != null) appendLine(".source \"${cls.sourceFile}\"")
        val fields = cls.fields.toList()
        if (fields.isNotEmpty()) {
            appendLine()
            for (field in fields) {
                val access = AccessFlags.formatAccessFlagsForField(field.accessFlags)
                appendLine(".field ${if (access.isBlank()) "" else "$access "}${field.name}:${field.type}")
            }
        }
        val methods = cls.methods.toList()
        if (methods.isNotEmpty()) {
            appendLine()
            for (method in methods) {
                val access = AccessFlags.formatAccessFlagsForMethod(method.accessFlags)
                appendLine(".method ${if (access.isBlank()) "" else "$access "}${method.name}(${method.parameterTypes.joinToString("")})${method.returnType}")
                appendLine(".end method")
            }
        }
    }

    private fun options(unit: DexUnit) = BaksmaliOptions().apply {
        apiLevel = unit.dexFile.opcodes.api
        parameterRegisters = true
        debugInfo = true
        codeOffsets = true
    }

    private fun textResult(
        workspace: AnalysisWorkspace,
        artifact: Artifact,
        target: String,
        raw: String,
        args: JSONObject
    ): JSONObject {
        val total = raw.length
        val offset = args.optLong("offset", 0).coerceAtLeast(0).coerceAtMost(total.toLong()).toInt()
        val limit = args.optInt("max_chars", 16_000).coerceIn(1, 200_000)
        val end = minOf(total, offset + limit)
        val text = raw.substring(offset, end)
        val complete = end >= total
        return jsonObject(
            "workspace_id" to workspace.id,
            "artifact_id" to artifact.id,
            "target" to target,
            "text" to text,
            "offset" to offset,
            "next_offset" to if (complete) null else end,
            "size_chars" to total,
            "truncated" to !complete,
            "complete" to complete,
            "hint" to if (complete) null else "Call again with offset=$end for the next $limit characters; outline_class gives signatures without bodies."
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

    private fun compile(query: String, ignoreCase: Boolean): Pattern =
        Pattern.compile(if (ignoreCase) "(?i)$query" else query)

    private fun referenceMatches(value: String, target: String): Boolean {
        if (value == target) return true
        return if (target.contains("->") && !target.contains("(")) {
            // Method or field without signature: match every overload.
            value.startsWith("$target(") || value.startsWith("$target:")
        } else {
            value.contains(target)
        }
    }

    private fun formatInstruction(
        options: BaksmaliOptions,
        methodDefinition: MethodDefinition,
        address: Int,
        instruction: Instruction
    ): String = runCatching {
        val item = InstructionMethodItemFactory.makeInstructionFormatMethodItem(methodDefinition, address, instruction)
        val output = StringWriter()
        BaksmaliWriter(output).use { item.writeTo(it) }
        output.toString().trim()
    }.getOrElse { instruction.toString() }

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
