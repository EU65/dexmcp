package dev.dexmcp

import fi.iki.elonen.NanoHTTPD
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.BufferedInputStream
import java.io.InputStream
import java.net.Socket

class RequestBodyTest {

    private class EchoServer(port: Int) : NanoHTTPD("127.0.0.1", port) {
        override fun serve(session: IHTTPSession): Response {
            val body = RequestBody.read(session)
            return newFixedLengthResponse(Response.Status.OK, "text/plain", "len=${body.toByteArray().size}")
        }
    }

    @Test
    fun chunkedBodyIsReadAndKeepAliveStaysInSync() {
        val server = EchoServer(0)
        server.start(NanoHTTPD.SOCKET_READ_TIMEOUT, true)
        try {
            Socket("127.0.0.1", server.listeningPort).use { socket ->
                val output = socket.getOutputStream()
                val input = BufferedInputStream(socket.getInputStream())
                // Send headers first so the body cannot be buffered together with the header block,
                // which is the case that used to leave the body unread and desync the connection.
                output.write(
                    ("POST /mcp HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n" +
                        "Content-Type: application/json\r\n\r\n").toByteArray()
                )
                output.flush()
                Thread.sleep(100)
                output.write(
                    ("5\r\n{\"a\":\r\n2\r\n1}\r\n0\r\n\r\n" +
                        "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nok").toByteArray()
                )
                output.flush()

                assertEquals("len=7", readBody(input))
                assertEquals("len=2", readBody(input))
            }
        } finally {
            server.stop()
        }
    }

    private fun readBody(input: BufferedInputStream): String {
        var contentLength = -1
        while (true) {
            val line = readLine(input) ?: error("unexpected EOF")
            if (line.isEmpty()) break
            if (line.lowercase().startsWith("content-length:")) {
                contentLength = line.substringAfter(':').trim().toInt()
            }
        }
        check(contentLength >= 0) { "missing Content-Length" }
        val body = ByteArray(contentLength)
        var offset = 0
        while (offset < contentLength) {
            val count = input.read(body, offset, contentLength - offset)
            if (count < 0) break
            offset += count
        }
        return String(body, Charsets.UTF_8)
    }

    private fun readLine(input: InputStream): String? {
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
