package dev.dexmcp

import android.content.Context
import fi.iki.elonen.NanoHTTPD
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileNotFoundException
import java.net.InetAddress

/**
 * MCP endpoint. Speaks both protocol eras:
 * - modern (2026-07-28 and later): stateless requests, `server/discover`, `resultType`, `ttlMs`
 * - legacy (2025-11-25 and earlier): `initialize` handshake, JSON-RPC results
 *
 * Request bodies are read here instead of relying on NanoHTTPD's parseBody because that
 * implementation cannot frame `Transfer-Encoding: chunked` bodies: it reads only the part that
 * happened to arrive with the headers, leaves the rest in the socket, and the next request line
 * then starts with the leftover body ("HTTP verb {json}POST unhandled").
 */
class McpHttpServer(
    context: Context,
    host: String = ServerConfig.bindHost(context),
    port: Int = ServerConfig.port(context),
    private val router: ToolRouter = ToolRouter(context.applicationContext)
) : NanoHTTPD(host, port) {
    private val appContext = context.applicationContext
    private val token = ServerConfig.token(appContext)

    private val supportedVersions = JSONArray()
        .put(VERSION_MODERN)
        .put("2025-11-25")
        .put("2025-06-18")
        .put("2025-03-26")
        .put("2024-11-05")
    private val supportedVersionSet = setOf(
        VERSION_MODERN, "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"
    )

    override fun serve(session: IHTTPSession): Response {
        if (session.uri == "/health") {
            drain(session)
            return jsonResponse(JSONObject().put("ok", true).put("service", "dex-mcp"))
        }
        if (session.uri.startsWith("/exports/")) return serveExport(session)
        if (session.uri != "/mcp") {
            drain(session)
            return newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "Not found")
        }
        if (session.headers["authorization"] != "Bearer $token") {
            drain(session)
            return newFixedLengthResponse(Response.Status.UNAUTHORIZED, MIME_PLAINTEXT, "Unauthorized")
        }
        if (session.method == Method.GET) {
            drain(session)
            return newFixedLengthResponse(Response.Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "This server uses JSON responses for Streamable HTTP")
        }
        if (session.method != Method.POST) {
            drain(session)
            return newFixedLengthResponse(Response.Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "POST required")
        }

        return try {
            val raw = readRequestBody(session)
            if (raw.isBlank()) {
                newFixedLengthResponse(Response.Status.ACCEPTED, "application/json", "")
            } else {
                val request = JSONObject(raw)
                val id = request.opt("id")
                val method = request.optString("method")
                val version = protocolVersion(request, session)
                if (version != null && version !in supportedVersionSet) {
                    AppLog.warn("MCP: 不支持的协议版本 $version")
                    return jsonRpcError(
                        id, -32022, "Unsupported protocol version",
                        JSONObject().put("supported", supportedVersions).put("requested", version)
                    )
                }
                if (id == null || id == JSONObject.NULL) {
                    newFixedLengthResponse(Response.Status.ACCEPTED, "application/json", "")
                } else {
                    val result = when (method) {
                        "server/discover" -> discover()
                        "initialize" -> initialize(request.optJSONObject("params"))
                        "ping" -> JSONObject()
                        "tools/list" -> toolsList()
                        "tools/call" -> {
                            val params = request.optJSONObject("params") ?: JSONObject()
                            router.call(params.optString("name"), params.optJSONObject("arguments") ?: JSONObject())
                        }
                        else -> {
                            AppLog.warn("MCP: 未知方法 $method（协议 ${version ?: "未标注"}）")
                            return jsonRpcError(id, -32601, "Method not found: $method")
                        }
                    }
                    jsonRpcResult(id, result)
                }
            }
        } catch (t: Throwable) {
            jsonRpcError(null, -32603, t.message ?: t.javaClass.simpleName)
        }
    }

    private fun serveExport(session: IHTTPSession): Response {
        // Downloads have no request body and never need to buffer one.
        if (session.method != Method.GET || session.headers.containsKey("transfer-encoding") ||
            session.headers["content-length"]?.let { it != "0" } == true) {
            return newFixedLengthResponse(Response.Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "GET required")
                .apply { closeConnection(true) }
        }
        val auth = session.headers["authorization"]
        if (auth == null || !auth.startsWith("Bearer ")) {
            return newFixedLengthResponse(Response.Status.UNAUTHORIZED, MIME_PLAINTEXT, "Unauthorized")
        }
        val loopback = runCatching { InetAddress.getByName(session.remoteIpAddress).isLoopbackAddress }.getOrDefault(false)
        val missing = { newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "Export not found") }
        return try {
            val export = router.openDownload(session.uri.removePrefix("/exports/"), auth, loopback, auth == "Bearer $token")
                ?: return missing()
            val etag = "\"${export.sha256}\""
            val range = session.headers["range"]?.takeIf { session.headers["if-range"]?.let { it == etag } ?: true }
            val bounds = range?.let { parseDownloadRange(it, export.size) }
            if (range != null && bounds == null) {
                return newFixedLengthResponse(Response.Status.RANGE_NOT_SATISFIABLE, MIME_PLAINTEXT, "Invalid Range")
                    .apply { addHeader("Content-Range", "bytes */${export.size}") }
            }
            val start = bounds?.first ?: 0L
            val length = bounds?.let { it.last - it.first + 1 } ?: export.size
            val status = if (bounds == null) Response.Status.OK else Response.Status.PARTIAL_CONTENT
            newFixedLengthResponse(status, "application/octet-stream", export.open(start), length).apply {
                addHeader("Accept-Ranges", "bytes")
                addHeader("ETag", etag)
                addHeader("Cache-Control", "no-store")
                if (bounds != null) addHeader("Content-Range", "bytes ${bounds.first}-${bounds.last}/${export.size}")
            }
        } catch (_: PathDeniedException) {
            missing()
        } catch (_: FileNotFoundException) {
            missing()
        }
    }

    private fun parseDownloadRange(value: String, size: Long): LongRange? {
        if (size <= 0) return null
        val match = Regex("bytes=([0-9]*)-([0-9]*)").matchEntire(value.trim()) ?: return null
        val (left, right) = match.destructured
        if (left.isEmpty()) {
            val suffix = right.toLongOrNull()?.takeIf { it > 0 } ?: return null
            return maxOf(0, size - suffix)..(size - 1)
        }
        val start = left.toLongOrNull()?.takeIf { it < size } ?: return null
        val end = if (right.isEmpty()) size - 1 else minOf(right.toLongOrNull() ?: return null, size - 1)
        return if (end >= start) start..end else null
    }

    private fun discover(): JSONObject = JSONObject()
        .put("resultType", "complete")
        .put("supportedVersions", supportedVersions)
        .put("capabilities", JSONObject().put("tools", JSONObject()))
        .put("_meta", JSONObject().put(META_SERVER_INFO, serverInfo()))
        .put("instructions", INSTRUCTIONS)
        .put("ttlMs", 3_600_000)
        .put("cacheScope", "public")

    private fun initialize(params: JSONObject?): JSONObject {
        val requested = params?.optString("protocolVersion")?.takeIf { it.isNotBlank() }
        val version = requested?.takeIf { it in supportedVersionSet } ?: VERSION_MODERN
        return JSONObject()
            .put("protocolVersion", version)
            .put("capabilities", JSONObject().put("tools", JSONObject().put("listChanged", false)))
            .put("serverInfo", serverInfo())
            .put("instructions", INSTRUCTIONS)
    }

    private fun toolsList(): JSONObject = JSONObject()
        .put("tools", router.toolDefinitions())
        .put("ttlMs", 60_000)
        .put("cacheScope", "public")

    private fun serverInfo(): JSONObject =
        JSONObject().put("name", "android-dex-mcp").put("version", BuildConfig.VERSION_NAME)

    private fun jsonRpcResult(id: Any?, result: JSONObject): Response {
        if (!result.has("resultType")) result.put("resultType", "complete")
        if (!result.has("_meta")) result.put("_meta", JSONObject().put(META_SERVER_INFO, serverInfo()))
        return jsonResponse(
            JSONObject().put("jsonrpc", "2.0").put("id", id).put("result", result)
        )
    }

    private fun jsonRpcError(id: Any?, code: Int, message: String, data: JSONObject? = null): Response {
        val error = JSONObject().put("code", code).put("message", message)
        if (data != null) error.put("data", data)
        return jsonResponse(
            JSONObject().put("jsonrpc", "2.0").put("id", id ?: JSONObject.NULL).put("error", error)
        )
    }

    private fun jsonResponse(body: JSONObject): Response =
        newFixedLengthResponse(Response.Status.OK, "application/json; charset=utf-8", body.toString())

    private fun protocolVersion(request: JSONObject, session: IHTTPSession): String? =
        request.optJSONObject("params")?.optJSONObject("_meta")
            ?.optString(META_PROTOCOL_VERSION)?.takeIf { it.isNotBlank() }
            ?: session.headers["mcp-protocol-version"]?.takeIf { it.isNotBlank() }

    private fun readRequestBody(session: IHTTPSession): String = RequestBody.read(session)

    /** Consume whatever body is left so a keep-alive connection stays in sync for the next request. */
    private fun drain(session: IHTTPSession) = RequestBody.drain(session)

    companion object {
        private const val VERSION_MODERN = "2026-07-28"
        private const val META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
        private const val META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
        private const val INSTRUCTIONS =
            "On-device Android system, APK/DEX analysis and Frida dynamic analysis server. " +
                "Open a workspace before DEX analysis; call android_frida_run for a dynamic session."
    }
}
