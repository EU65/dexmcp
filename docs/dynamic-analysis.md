# 动态分析与启动注入

动态分析需要 arm64 设备和 root，不需要 ADB 或 frida-server。App 内置 Frida 17.26.2 和 Java bridge，首次使用会把运行时安装到 `/data/adb/dexmcp`。

## 手动会话

1. 在 App 打开「允许 MCP 调用 Frida」，确认运行时已就绪。
2. `android_frida_run` 开始会话并返回 `session_id`、初始日志和 `next_offset`。普通应用默认先重启再附加；系统应用和特权应用默认不重启。可以用 `restart` 覆盖，用 `process` 指定子进程。
3. 用 `android_frida_output` 读取日志，下次把 `next_offset` 传给 `offset`。调整脚本用 `android_frida_reload`，结束用 `android_frida_stop`。

脚本可直接使用 `Java.perform` 和 `Java.use`。失败时先看返回的 `error` 和 `output`。`selinux_patch_failed` 指向设备策略兼容问题，不等于脚本有错。

关闭「允许 MCP 调用 Frida」会拒绝 `android_frida_*` 工具调用并结束运行中的会话。App 里的运行时安装和卸载仍可用。

## LSPosed 启动注入

Dex MCP 本身就是模块，需要支持 Xposed API 102 的 LSPosed，不用单独安装 `dev.dexmcp.xposed`。

1. 在 LSPosed 启用 Dex MCP。
2. 在 Dex MCP 的「启动注入」页打开总开关，选择应用并确认 LSPosed 的作用域请求。
3. 保存脚本后重开目标应用。只处理主进程；启用时冷启动需要等待脚本就绪。

脚本也可以通过 `android_frida_agent_set`、`android_frida_agent_scripts`、`android_frida_agent_enable` 和 `android_frida_agent_delete` 管理。`android_frida_autostart` 管理总开关。
