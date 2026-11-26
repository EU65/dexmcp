# 动态分析与启动注入

动态分析需要 arm64 设备和 root，不需要 ADB 或 frida-server。App 内置 Frida 17.26.2 和 Java bridge，首次使用会把运行时安装到 `/data/adb/dexmcp`。

## 手动会话

1. 在 App 打开「允许 MCP 调用 Frida」，确认运行时已就绪。
2. `android_frida_run` 开始会话并返回 `session_id`、初始日志和 `next_offset`。普通应用默认先重启再附加；系统应用和特权应用默认不重启。可以用 `restart` 覆盖。附加时可用 `process` 指定完整进程名，Dex MCP 查出 PID 后再附加。`restart=false` 不会自动拉起未运行的应用。
3. 用 `android_frida_output` 读取日志，下次把 `next_offset` 传给 `offset`。调整脚本用 `android_frida_reload`，结束用 `android_frida_stop`。

脚本可直接使用 `Java.perform` 和 `Java.use`。失败时先看返回的 `error` 和 `output`。`running` 只表示注入器存活；`[dexmcp] ready` 只表示脚本运行时已就绪，不代表用户脚本或 Java hook 安装成功。`frida_helper_failed`、`frida_timeout` 和 `selinux_patch_failed` 分开报告，不建议为一般附加失败切换 SELinux 模式。

关闭「允许 MCP 调用 Frida」会拒绝 `android_frida_*` 工具调用并结束运行中的会话。App 里的运行时安装和卸载仍可用。

## LSPosed 启动注入

Dex MCP 本身就是模块，需要支持 Xposed API 102 的 LSPosed，不用单独安装 `dev.dexmcp.xposed`。

1. 在 LSPosed 启用 Dex MCP。
2. 在 Dex MCP 的「启动注入」页打开总开关，选择应用并确认 LSPosed 的作用域请求。
3. 保存脚本后重开目标应用。启用时冷启动会等待脚本运行时启动。

默认只注入包的主进程。用 `android_frida_agent_scope` 把 scope 设为 `all` 后，该包的每个进程，包括 `:unstable`、`:push` 这类子进程，都会在启动时加载同一个脚本；子进程需要单独 hook 时这样做，例如 GMS 的 `com.google.android.gms.unstable`。设回 `main` 即恢复只注入主进程。App 里对应脚本编辑页的「注入所有进程」开关。每个进程各有一个会话，日志分开读。

脚本也可以通过 `android_frida_agent_set`、`android_frida_agent_scripts`、`android_frida_agent_enable` 和 `android_frida_agent_delete` 管理。`android_frida_agent_set` 可以顺带传 `scope`。`android_frida_autostart` 管理总开关。
