package dev.dexmcp

import fi.iki.elonen.NanoHTTPD
import java.io.ByteArrayOutputStream
import java.io.InputStream

/**
 * Request body reader used by [McpHttpServer].
 *
 * NanoHTTPD's parseBody cannot frame `Transfer-Encoding: chunked` bodies: it falls back to the
 * bytes that happened to arrive with the headers, leaves the rest of the body in the socket, and
 * the next request line then begins with that leftover body. Chunked bodies are decoded here
 * instead; the stream handed to [NanoHTTPD.IHTTPSession.getInputStream] is positioned at the first
 * byte of the body by NanoHTTPD itself (it rewinds and skips the header block).
 */
internal object RequestBody {

    fun isChunked(session: NanoHTTPD.IHTTPSession): Boolean =
        session.headers["transfer-encoding"]?.contains("chunked", ignoreCase = true) == true

    fun read(session: NanoHTTPD.IHTTPSession): String {
        if (isChunked(session)) return readChunked(session.inputStream)
        val files = HashMap<String, String>()
        session.parseBody(files)
        return files["postData"].orEmpty()
    }

    /** Consume whatever body is left so a keep-alive connection stays in sync for the next request. */
    fun drain(session: NanoHTTPD.IHTTPSession) {
        runCatching {
            if (isChunked(session)) readChunked(session.inputStream) else session.parseBody(HashMap())
        }
    }

    fun readChunked(input: InputStream): String {
        val out = ByteArrayOutputStream()
        while (true) {
            val line = readAsciiLine(input) ?: break
            val hex = line.substringBefore(';').trim()
            val size = hex.toIntOrNull(16) ?: break
            if (size == 0) {
                while (true) {
                    val trailer = readAsciiLine(input) ?: break
                    if (trailer.isEmpty()) break
                }
                break
            }
            val buffer = ByteArray(size)
            var offset = 0
            while (offset < size) {
                val count = input.read(buffer, offset, size - offset)
                if (count < 0) break
                offset += count
            }
            out.write(buffer, 0, offset)
            readAsciiLine(input)
        }
        return out.toString("UTF-8")
    }

    private fun readAsciiLine(input: InputStream): String? {
        val builder = StringBuilder()
        while (true) {
            val value = input.read()
            if (value == -1) return if (builder.isEmpty()) null else builder.toString()
            if (value == '\n'.code) break
            if (value != '\r'.code) builder.append(value.toChar())
        }
        return builder.toString()
    }
}
