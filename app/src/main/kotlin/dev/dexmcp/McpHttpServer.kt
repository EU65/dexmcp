package dev.dexmcp

import android.content.Context
import fi.iki.elonen.NanoHTTPD
import org.json.JSONArray
import org.json.JSONObject

class McpHttpServer(
    context: Context,
    host: String = ServerConfig.bindHost(context),
    port: Int = ServerConfig.port(context),
    private val router: ToolRouter = ToolRouter(context.applicationContext)
) : NanoHTTPD(host, port) {
    private val appContext = context.applicationContext
    private val token = ServerConfig.token(appContext)

    override fun serve(session: IHTTPSession): Response {
        if (session.uri == "/health") {
            return jsonResponse(JSONObject().put("ok", true).put("service", "dex-mcp"))
        }
        if (session.uri != "/mcp") return newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "Not found")
        if (session.headers["authorization"] != "Bearer $token") {
            return newFixedLengthResponse(Response.Status.UNAUTHORIZED, MIME_PLAINTEXT, "Unauthorized")
        }
        if (session.method == Method.GET) {
            return newFixedLengthResponse(Response.Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "This server uses JSON responses for Streamable HTTP")
        }
        if (session.method != Method.POST) {
            return newFixedLengthResponse(Response.Status.METHOD_NOT_ALLOWED, MIME_PLAINTEXT, "POST required")
        }

        return try {
            val files = HashMap<String, String>()
            session.parseBody(files)
            val request = JSONObject(files["postData"] ?: "{}")
            val id = request.opt("id")
            val method = request.optString("method")

            if (id == null || id == JSONObject.NULL) {
                newFixedLengthResponse(Response.Status.ACCEPTED, "application/json", "")
            } else {
                val result = when (method) {
                    "initialize" -> initialize(request.optJSONObject("params"))
                    "ping" -> JSONObject()
                    "tools/list" -> JSONObject().put("tools", router.toolDefinitions())
                    "tools/call" -> {
                        val params = request.optJSONObject("params") ?: JSONObject()
                        router.call(params.optString("name"), params.optJSONObject("arguments") ?: JSONObject())
                    }
                    else -> return jsonRpcError(id, -32601, "Method not found: $method")
                }
                jsonRpcResult(id, result)
            }
        } catch (t: Throwable) {
            jsonRpcError(null, -32603, t.message ?: t.javaClass.simpleName)
        }
    }

    private fun initialize(params: JSONObject?): JSONObject {
        val requested = params?.optString("protocolVersion")?.takeIf { it.isNotBlank() } ?: "2025-06-18"
        return JSONObject()
            .put("protocolVersion", requested)
            .put("capabilities", JSONObject().put("tools", JSONObject().put("listChanged", false)))
            .put("serverInfo", JSONObject().put("name", "android-dex-mcp").put("version", BuildConfig.VERSION_NAME))
            .put("instructions", "On-device Android system, APK/DEX analysis and Frida dynamic analysis server. Open a workspace before DEX analysis; call android_frida_run for a dynamic session.")
    }

    private fun jsonRpcResult(id: Any?, result: JSONObject): Response = jsonResponse(
        JSONObject().put("jsonrpc", "2.0").put("id", id).put("result", result)
    )

    private fun jsonRpcError(id: Any?, code: Int, message: String): Response = jsonResponse(
        JSONObject().put("jsonrpc", "2.0").put("id", id ?: JSONObject.NULL)
            .put("error", JSONObject().put("code", code).put("message", message))
    )

    private fun jsonResponse(body: JSONObject): Response =
        newFixedLengthResponse(Response.Status.OK, "application/json; charset=utf-8", body.toString())
}
