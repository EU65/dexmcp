# Android Dex MCP

在 Android 手机上运行的 MCP 服务。Agent 可以直接在手机上查系统信息、分析 APK 和 DEX、导出文件，也可以用内置 Frida 做动态分析，不需要电脑或 ADB 转发。

## 快速开始

1. 从 [GitHub Releases](https://github.com/EU65/dexmcp/releases) 下载 APK，安装并打开 Dex MCP。
2. 在 App 点「复制连接信息」，把 URL 和认证头填进 MCP 客户端。同机运行的 RikkaHub 或 PRoot Ubuntu 可以直接连默认地址：

   ```text
   URL: http://127.0.0.1:8765/mcp
   Authorization: Bearer <App 中显示的 Token>
   ```

3. 查看客户端的工具列表。首次连接时，可以用 `android_system_get_summary` 查看设备信息。

默认只监听本机。要从另一台设备连接，在 App 打开「允许局域网 / 公网连接」，改用手机的局域网 IP，仍须带 Token。服务使用 HTTP，不建议暴露到公网。

## 功能文档

| 想做什么 | 从哪里开始 |
| --- | --- |
| 看 APK 的 Manifest、Smali、类和交叉引用 | [静态分析](docs/static-analysis.md) |
| 下载大文件或只取 APK 里的 `.so`、资源文件 | [大文件导出](docs/file-export.md) |
| 查系统路径、抓日志、采集和对比诊断快照 | [系统诊断](docs/system.md) |
| 用 Frida 附加进程或配置 LSPosed 启动脚本 | [动态分析与启动注入](docs/dynamic-analysis.md) |
| 手写 MCP 请求或排查客户端协议兼容问题 | [MCP 协议与示例](docs/mcp.md) |
| 从源码构建、签名或配置 CI | [构建与签名](docs/build.md) |

通过文件选择器导入 APK / JAR / DEX 不需要 root。读取受保护路径或使用 Frida 时才需要相应权限；Frida 仅支持 arm64。

[更新记录](CHANGELOG.md)
