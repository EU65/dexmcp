# 大文件导出

1. 设备文件调用 `android_system_export_file`。APK 内文件先调用 `android_analysis_open`，再调用 `android_analysis_export_entry`，传入 `workspace_id`、条目的 `path` 和可选的 `artifact_id`。它只解压指定条目，不启动目标 App。
2. 工具返回 `download_path`、`size`、`sha256` 和 `download_token`。从同一台手机的 RikkaHub Ubuntu 工作区下载时，用这个仅对当前导出有效的 30 分钟令牌。远程客户端通过原来的 MCP Bearer Token 认证。
3. HTTP 接口直接传二进制，支持单段 Range。下载完成校验大小和 SHA-256，再调用 `android_system_delete_export` 清理手机缓存。

```bash
# 变量取自工具返回值，8765 改成实际 MCP 端口。
curl --fail --continue-at - --output global-metadata.dat.part \
  -H "Authorization: Bearer $DOWNLOAD_TOKEN" \
  "http://127.0.0.1:8765$DOWNLOAD_PATH"
printf '%s  %s\n' "$SHA256" global-metadata.dat.part | sha256sum -c - && \
  mv global-metadata.dat.part global-metadata.dat
```

`android_system_read_export` 的 64 KiB Base64 接口保留给旧客户端。新接口不会把文件内容塞进工具响应。

在仓库根目录运行 [PowerShell 脚本](../scripts/Export-AndroidFile.ps1)。它默认读取 Codex 的 dexmcp 连接配置，不打印 Token；也支持 `-McpUrl` 和 `DEXMCP_TOKEN` 环境变量：

```powershell
./scripts/Export-AndroidFile.ps1 -RemotePath /vendor/lib64/hw/vendor.xiaomi.hardware.touchfeature@1.0-impl.so -Destination ./workspace/touchfeature-impl.so
```
