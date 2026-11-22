# MCP 连接与协议

## MCP 协议版本

服务端同时支持两代协议，按请求里的 `_meta` / `MCP-Protocol-Version` 判断：

- 现代（2026-07-28 及以后）：无 `initialize` 握手，每个请求在 `_meta` 里带版本和客户端能力。实现了 `server/discover`，返回 `supportedVersions`、`capabilities`、`_meta["io.modelcontextprotocol/serverInfo"]`、`instructions`、`ttlMs`、`cacheScope`；所有结果带 `resultType: "complete"`，`tools/list` 带 `ttlMs` / `cacheScope`。
- 旧版（2025-11-25 及更早）：`initialize` 握手，返回协商后的 `protocolVersion`、capabilities 和 serverInfo。

请求声明了不支持的版本时返回 JSON-RPC `-32022`（`UnsupportedProtocolVersionError`），`data.supported` 列出支持的版本，客户端可以降级重试。HTTP 请求体按 `Content-Length` 或 `Transfer-Encoding: chunked` 读取；chunked 之前会被 NanoHTTPD 读不完整，剩下半个 body 留在 socket 里，下一个请求行变成 `{"jsonrpc":...}POST`，服务端就报 `BAD REQUEST: Syntax error. HTTP verb ... unhandled.`。

`server/discover` 示例：

```bash
curl http://127.0.0.1:8765/mcp \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}'
```

## MCP 请求示例

初始化：

```bash
curl http://127.0.0.1:8765/mcp \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}'
```

列出工具：

```bash
curl http://127.0.0.1:8765/mcp \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

搜索系统下载相关包：

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "android_system_search_packages",
    "arguments": {
      "query": "download",
      "system_only": true,
      "limit": 100
    }
  }
}
```

应用列表按包名稳定排序并支持分页。若响应中的 `next_cursor` 非空，把它原样放入下一次调用的 `cursor`；继续使用相同的 `query`、`system_only` 和 `limit` 条件。

打开包并搜索 DEX：

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "android_analysis_open",
    "arguments": {
      "package": "com.android.providers.downloads",
      "include_splits": true
    }
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "android_analysis_search",
    "arguments": {
      "workspace_id": "上一步返回的 ID",
      "query": "NetworkCapabilities",
      "kinds": ["class", "method", "field", "dex_string"]
    }
  }
}
```
