# Android Dex MCP

一个在 Android 设备本机运行的 MCP 服务。面向同机运行的 Agent/LLM，提供系统信息、已安装包发现、受限 root 文件读取、APK/JAR/DEX 的 Smali 分析、内置 Frida 的动态分析，以及用 Miuix 重写的状态界面。

当前版本是 `0.4.11`，包含静态分析、系统诊断、内置 Frida 动态分析和 Miuix 界面（无需 adb / frida-server）：

0.4.11 补了充电相关的只读路径（`/vendor_dlkm`、`/proc/charger`、`/proc/charger_cp`、`/proc/oplus_charge_pump`、`/proc/da9313`、`/proc/devinfo/fastchg`）；`list_directory` / `find_files` 改为跟随目录符号链接并按入参路径回显，列出来的路径一定能读；错误返回带 `reason`（`policy_denied` / `eacces` / `eacces_selinux` / `enoent` / `eisdir` / `espipe`）和 `errno`；`android_system_read_file` 新增 `format=strings`，在设备侧抽可打印字符串，大文件不用整份 base64 回传。

0.4.10 默认放开 sysfs 读取：`/sys/class`、`/sys/devices`、`/sys/module`、`/sys/kernel`、`/sys/fs`、`/sys/bus` 都在只读白名单里，触摸/笔/电源/温控节点可以直接读；sysfs 节点 stat 大小为 0 时不再误判截断。

0.4.9 修了 MCP 传输层：支持现代协议 2026-07-28（`server/discover`、`resultType`、`ttlMs`/`cacheScope`、无 `initialize` 握手），并按 `Transfer-Encoding: chunked` 读取请求体。之前 chunked 请求的 body 会被读不完整，残留内容拼到下一个请求行，客户端收到 `BAD REQUEST: Syntax error. HTTP verb ... POST unhandled.`

0.4.8 把模块迁到现代 Xposed API 102（`META-INF/xposed/*`、`module.prop`），并通过 `io.github.libxposed:service` 在 App 内动态申请作用域：打开某个应用的开关后向 LSPosed 请求该包，用户在 LSPosed 通知里确认即可，关闭开关时撤销作用域。

0.4.7 把 LSPosed 模块并进 Dex MCP 本体：同一个 APK 既是 MCP 服务端也是启动注入模块，不再有单独的 `dev.dexmcp.xposed`；主界面新增「启动注入」页面，可以按应用开关、查看和直接编辑每个应用的启动脚本。

0.4.6 按实际使用反馈改了分析接口：方法/类读取分页（`offset` + `next_offset` + `size_chars`）、批量 `ids`、`no_bodies`，二进制文件自动识别、ZIP 条目过滤、搜索支持正则和类前缀作用域并默认去重，xref 可带回指令上下文、方法目标支持省略签名；Frida 侧 reload 只回增量日志、新增清空日志工具、系统应用默认不重启、SELinux patch 失败直接报 `selinux_patch_failed`。

0.4.5 增加 LSPosed 启动注入：勾选的应用在 `Application.onCreate` 之前自动让 Dex MCP 附加 Frida 并加载启动脚本，脚本就绪后应用继续启动。

0.4.4 把内置 frida-inject 换成 Florida 风格的反检测补丁版（RPC 标记、agent/memfd 名、入口符号、线程名、helper dex 路径都改掉），首次使用会自动重装运行时。

0.4.3 把 Frida 运行时目录从 `/data/local/tmp/dexmcp` 换到 `/data/adb/dexmcp`（root 私有，普通 App 枚举不到），升级后需要重新安装一次运行时；旧目录不会自动迁移。

0.4.2 把顶部状态区改成两块大的状态卡（MCP / Frida），版本、安装状态和会话数收进卡片；Root 单独一行只显示可用 / 不可用；监听端口可以在界面上改；常驻通知加了“停止”按钮；去掉了 SELinux 卡片和安装说明式的提示文字。

主界面新增「允许读取任意路径」开关，默认关闭，切换立即生效。开启后文件读取、目录搜索和分析导入解除路径白名单限制；受保护文件仍需 root 权限。关闭后，白名单外的临时导出也无法继续下载。

默认白名单里包含整个 `/sys/class`、`/sys/devices`、`/sys/module`、`/sys/kernel`、`/sys/fs`、`/sys/bus` 子树、`/proc/net`、`/vendor_dlkm` 和几个充电 proc 节点（`/proc/charger`、`/proc/charger_cp`、`/proc/oplus_charge_pump`、`/proc/da9313`、`/proc/devinfo/fastchg`），触摸、笔、屏幕、电源、温控、充电这些节点可以直接用 `android_system_read_file` 读，不需要开「允许读取任意路径」。节点通常只有几行文本，`file_size` 是 `null` 表示 stat 不可靠（procfs/sysfs 的特性），内容本身照常返回。

`list_directory` / `find_files` 会跟随目录符号链接（比如 `/vendor/lib/modules -> /vendor_dlkm/lib/modules`），并且按入参路径回显，所以列表里的路径可以直接交给 `read_file`；`find_files` 不再用 `-xdev`，跨挂载点（`/vendor_dlkm`）也能搜到。

`read_file` 支持 `format=strings`，在设备上用 `strings`/`grep` 抽完再回传：

```json
{"name":"android_system_read_file","arguments":{
  "path":"/vendor/lib/modules/oplus_chg_v2.ko",
  "format":"strings","min_len":6,"grep":"flag|token|seal","max_bytes":65536
}}
```

返回 `strings` 数组、`count` 和 `truncated`；`grep` 是设备侧 `grep -aE` 的扩展正则，`max_strings` 默认 2000。普通读取失败时返回 `error`、`reason`、`errno`、`type`，其中 `policy_denied` 表示路径被 App 白名单拦下（没有发生系统调用），`eacces` / `eacces_selinux` 是内核或 SELinux 拒绝。

远程文件提取：`android_system_export_file` 先将文件复制到 App 缓存，返回 export_id、大小和 SHA-256；`android_system_read_export` 分块返回最多 64 KiB Base64 数据；完成后调用 `android_system_delete_export` 清理副本。电脑端决定目标路径，并校验大小和 SHA-256。

PowerShell 脚本默认读取 Codex 的 dexmcp 连接配置，不打印 Token；也支持 `-McpUrl` 和 `DEXMCP_TOKEN` 环境变量：

```powershell
./scripts/Export-AndroidFile.ps1 -RemotePath /vendor/lib64/hw/vendor.xiaomi.hardware.touchfeature@1.0-impl.so -Destination ./workspace/touchfeature-impl.so
```

```text
Android Agent -> 127.0.0.1 Streamable HTTP -> Android App -> libsu / dexlib2
```

## 已实现工具

- `android_system_get_summary`
- `android_system_search_packages`
- `android_system_read_file`
- `android_system_collect_snapshot`
- `android_system_list_directory`
- `android_system_find_files`
- `android_system_list_snapshots`
- `android_system_get_snapshot`
- `android_system_compare_snapshots`
- `android_system_delete_snapshot`
- `android_logs_list`
- `android_logs_query`
- `android_analysis_list_imports`
- `android_analysis_open`
- `android_analysis_close`
- `android_analysis_list`
- `android_analysis_outline_class`
- `android_analysis_search`
- `android_analysis_read`
- `android_analysis_xref_dex`
- `android_frida_status`
- `android_frida_prepare`
- `android_frida_run`
- `android_frida_output`
- `android_frida_reload`
- `android_frida_stop`
- `android_frida_sessions`
- `android_frida_restart_app`
- `android_frida_agent_scripts`
- `android_frida_agent_set`
- `android_frida_agent_enable`
- `android_frida_agent_delete`
- `android_frida_autostart`
- `android_frida_clear_log`
- `android_system_selinux`

除动态分析外，工作区是只读的。系统源文件只会被读取并复制到 App 私有缓存，DEX/APK 解析在普通 App UID 进程进行，不在 root shell 中解析。

DEX 读取默认分页：`android_analysis_read` 每页 16000 字符，响应带 `offset`、`next_offset`、`size_chars`、`complete`；`ids` 一次批量读多个方法/类（共用 `max_chars` 预算），`no_bodies` 让 `type=class` 只回字段和方法签名。`android_analysis_search` 支持 `regex`、`in_class_prefix`（配合 `dex_string` 时只扫该前缀下类引用到的字符串）和默认去重（字符串命中被同名描述符覆盖时丢弃）。`android_analysis_xref_dex` 的 `context_instructions` 会带上命中点前后各 N 条 smali，`Lcom/x/Y;->playSound` 这种不带签名的目标会匹配所有重载。`android_analysis_list` 的 `zip_entries` / `dex_classes` 支持 `query`（可配 `regex`）和 `artifact_id` 过滤。`android_system_read_file` 读到 ZIP/ELF/PNG/GZIP/DEX 时直接返回 `is_binary` + `detected_format` + `file_size`，不再把二进制解码成乱码；响应同时给出 `next_offset`。

## 构建与安装

项目默认使用 `E:\Android\Sdk`。如 SDK 路径不同，修改本机的 `local.properties`。

```powershell
.\gradlew.bat :app:assembleRelease
```

Gradle 8.11.1 / AGP 8.9.1 / Kotlin 2.3.20 / compileSdk 36 需要 JDK 17 或 21。本机默认的 JDK 25 会在 Kotlin 编译阶段直接抛 `IllegalArgumentException: 25.0.5.0.2`，构建前切到 JDK 21：

```powershell
$env:JAVA_HOME='D:\programs\jdk-21.0.10.7-hotspot'
$env:PATH="$env:JAVA_HOME\bin;$env:PATH"
.\gradlew.bat :app:assembleRelease
```

界面用 Compose + Miuix（`top.yukonga.miuix.kmp` 0.8.8，对应 Compose 1.10 / Kotlin 2.3.20），它会把 `androidx.navigationevent` 带进来，所以 `compileSdk` 必须是 36、AGP 不低于 8.9.1。

现代 Xposed API（`io.github.libxposed:api:102.0.0` 和 `service:102.0.0`）的 AAR 声明需要 compileSdk 37；本机的 SDK 只有 `platforms/android-37.0`（Android 17 的“37.0”平台名），AGP 8.9.1 解析不了这个带小版本号的路径，所以 `gradle.properties` 里关掉了 AAR 的 compileSdk 检查：

```properties
android.experimental.disableCompileSdkChecks=true
```

代码只用到 API 36 及以下的符号，编译和运行都不依赖 SDK 37；以后升级到支持 37.0 的 AGP 后可以去掉这个开关并把 `compileSdk` 提到 37。

安装后打开 App。它会启动前台服务，并显示：

```text
URL: http://127.0.0.1:8765/mcp
Authorization: Bearer <App 中显示的 Token>
```

服务默认只监听 `127.0.0.1:8765`。PRoot Ubuntu 中的 Agent 可直接连接该地址，无需电脑或 ADB 转发。界面上的“监听端口”可以改成 1024–65535 之间的任意端口，保存后立即按新端口重新监听（通知栏和连接地址同步更新）。

打开 App 的“允许局域网 / 公网连接”选项后，监听改为 `0.0.0.0:<端口>`（全部 IPv4 接口），电脑可以使用 `http://平板的局域网IP:<端口>/mcp` 连接。界面及“复制连接信息”会列出当前网络 IPv4 地址和认证 Token；电脑应选择能访问的平板地址，不能将 `0.0.0.0` 或 `127.0.0.1` 当作远程连接地址。

选项会保存，切换时自动重启监听；DEX 工作区继续保留，进行中的连接需要重连。远程 `/mcp` 请求同样必须带 `Authorization: Bearer <Token>`。绑定全部接口不会自动配置路由器端口转发；局域网访问需电脑和平板之间网络可达。当前仍使用 HTTP。常驻通知自带“停止”按钮，点一下即停止前台服务。

安装文件为 `app/build/outputs/apk/release/app-release.apk`，可复制到手机后点击安装，无需 ADB。这是非 debuggable 的 release 构建，个人使用沿用本机 debug 签名，便于覆盖同一签名的旧版本；不是正式发布签名。Kotlin/JVM 代码没有 native 库；APK 内额外放了 arm64 的 `frida-inject`（原始 84.6 MB）和预编译的 `frida-java-bridge`（约 230 KB），加上 Compose 运行时，成品 APK 约 57 MB，不生成 32 位或 x86 包。

## 界面（Miuix / Compose）

主界面顶部是两块大状态卡，下面按分区放设置，打开就能看到服务是否运行、Frida 是否就绪：

- **状态卡**：左边 MCP（运行中 / 已停止、监听地址、仅本机 / 允许局域网），右边 Frida（已就绪 / 未安装 / 需更新 / 无 Root / 已关闭，运行时版本、大小和会话数）。状态用大字和颜色点标出，版本、安装情况不再单列成行。
- **服务**：监听端口（点击修改，1024–65535）、连接地址与 Token 一键复制、局域网 / 任意路径开关、启动 / 停止按钮。
- **Frida**：Root 单独一行，右侧显示可用 / 不可用，标题栏右侧可刷新；「允许 MCP 调用 Frida」开关关闭后 agent 调用任何 `android_frida_*` 都会直接收到错误，同时停掉正在运行的会话；安装 / 更新 / 重新安装与卸载按钮，卸载有二次确认。
- **启动注入**：入口显示已启用的应用数；点进去是应用列表（可搜索），每行一个开关和脚本状态，点行进入脚本编辑页，可直接查看、修改、保存或删除该应用的启动脚本，顶部有总开关。
- **静态分析**：导入 APK / JAR / DEX，显示最近导入的文件。
- **日志**：运行日志入口，点进去是完整列表（时间、级别、等宽内容），右上角可复制全部或清空。

SELinux 状态卡不再放在界面上，需要临时放宽时仍可通过 `android_system_selinux` 工具处理。

日志记录 App 自身事件（服务启停、Frida 安装 / 注入 / 失败、SELinux 切换、导入结果），内存保留最新 600 条并追加到 `files/dexmcp.log`，重启后还能看到历史。主题跟随系统深色模式，界面为 edge-to-edge。


## Frida 动态分析（内置 arm64 frida-inject 17.x，Florida 风格补丁）

APK 的 assets 里带 `frida-inject` 17.26.2（arm64）和预编译的 `frida-java-bridge` 7.0.13。首次调用时由 root shell 把 frida-inject 释放到 `/data/adb/dexmcp/frida-inject` 并校验 `--version`，之后复用；App 升级后版本号变化会自动重装。不需要 adb、不需要 frida-server，电脑端也不用装 frida 客户端。运行时目录放在 `/data/adb` 而不是 `/data/local/tmp`：`/data/adb` 是 root 私有的 700 目录，普通 App 枚举不到注入文件和会话日志，目标 App 也探测不到文件改动。

内置的 frida-inject 不是官方原版，构建前用 `tools/patch-frida.py` 做了 Florida 风格的反检测替换（所有字符串等长，ELF 布局不变）：RPC 标记 `frida:rpc`、agent 名 `frida-agent-<arch>.so`（同时是 memfd 名，也就是目标进程 `/proc/<pid>/maps` 里可见的名字）、入口符号 `frida_agent_main`（连同 `.gnu.hash` / `.hash` 一起改，dlsym 仍能找到）、线程名 `gum-js-loop` / `gmain` / `gdbus`，agent 里的 `FridaScriptEngine`、`GLib-GIO`、`GDBusProxy`、`GumScript` 就地反转。另外 frida 原本会把 Java helper 释放到 `/data/local/tmp/frida-helper-<uuid>.dex`、把控制管道放在 `/data/local/tmp`，这里改成 `/data/adb/dexmcp/helper-<uuid>.dex` 和 `/data/adb`。运行时会记录 `/data/adb/dexmcp/flavor`，老的原版 17.26.2 会被判定为未安装，升级 App 后第一次用 Frida 会自动重装。

这只是基础反检测：能过掉查 memfd 名、线程名、`frida:rpc`、`frida_agent_main` 这类常见特征，但 agent 内存里仍有大量 `Frida`/`frida` 类型名和错误信息字符串，主动扫描匿名映射里 `frida` 字样的检测仍可能命中。重新生成补丁版：

```powershell
curl -LO https://github.com/frida/frida/releases/download/17.26.2/frida-inject-17.26.2-android-arm64.xz
xz -d frida-inject-17.26.2-android-arm64.xz
python tools\patch-frida.py frida-inject
```

Frida 16.7.19 在 Android 17（SDK 37）上读不了内核策略数据库（`libsepol.avtab_read_item: more than one specifier` → `Unable to load SELinux policy from the kernel`），`frida_memfd` 标签注册失败，agent 落到 `unlabeled` 被目标域拒绝，最终报 `Agent connection closed`。17.26.2 的 libsepol 已跟进新格式，所以这里固定在 17.x。

Frida 17 起 runtime 不再内置 Java/ObjC bridge。会话脚本写入前会依次拼上「console 桥接 + Module 兼容层」「预编译的 `frida-java-bridge`（设置 `globalThis.Java`）」「用户脚本」，所以 `Java.perform` / `Java.use` 直接可用，不需要 frida-compile。17 还把 `Module.findExportByName`、`Module.findBaseAddress` 这类静态方法移到了模块实例上；兼容层只在旧接口缺失时补回旧签名，`Module.findExportByName('libc.so','open')`、`Module.getExportByName(null,'open')`、`Module.findBaseAddress(...)` 仍能跑。新脚本建议直接写 `Process.getModuleByName('libc.so').getExportByName('open')`。

会话目录是 `/data/adb/dexmcp/sessions/<session_id>/`，存放 `hook.js`、`run.sh`、`agent.pid` 和 `output.log`。`frida-inject` 以 root 运行，`console.log/warn/error` 在注入前被转成 `frida:stdout` 消息逐条实时写回，不受 stdio 缓冲影响；所有输出合并进 `output.log`，agent 用 `android_frida_output` 按字节偏移增量读取。App 或 MCP 服务重启后，会话仍可按 `session_id` 继续读取。

启动会话（默认重启目标后按 pid 附加）：

```json
{"name":"android_frida_run","arguments":{
  "package":"com.example.app",
  "mode":"attach",
  "restart":true,
  "wait_ms":3000,
  "script":"Java.perform(function () {\n  console.log('attached pid=' + Process.id);\n  var T = Java.use('com.example.app.Target');\n  T.check.overload('java.lang.String').implementation = function (s) {\n    console.log('check(' + s + ') -> true');\n    return true;\n  };\n});"
}}
```

返回 `session_id`、`pid`、`agent_pid`、`running`、首次 `output` 和 `next_offset`。读取新输出：

```json
{"name":"android_frida_output","arguments":{"session_id":"上一步返回的 ID","offset":0}}
```

把响应里的 `next_offset` 作为下一次的 `offset`；`log_bytes` 是当前日志总长，`running` 表示 frida-inject 是否还活着。

- `mode=attach`（默认）：先 `am force-stop` 再 `am start`，等目标主进程出现后按 pid 附加，适合大多数运行时 hook。
- `mode=spawn`：由 frida-inject 通过 RoboLauncher 启动进程，脚本在入口点之前加载，能拿到 `Application.attachBaseContext`、`onCreate` 和静态初始化之前的时机；这条路径会注入 system_server，设备不允许时会在 `output` 里报错，此时用默认的 attach 即可。
- `restart=false`：不重启，直接附加当前进程；进程不存在时会自己启动一次 attach 会话。
- `process`：可选，指定要附加的进程名（例如 `com.example.app:push`），默认是 app 主进程。
- 脚本跑在 qjs 运行时，默认带 Java bridge 和 Module 兼容层；`console` 输出实时回传。
- 换脚本不重启 app：`android_frida_reload` 写入新脚本后断开并重新附加；只有目标进程已消失时才按 `restart` 重启。响应里的 `output` 只含本次 reload 之后新产生的日志，历史用 `android_frida_output` 的 offset 读取。
- 结束：`android_frida_stop`；`kill_app=true` 同时强制停止目标。
- SELinux 策略补丁仍失败时（日志出现 `Unable to load SELinux policy` 或 `Agent connection closed`），先调用 `android_system_selinux` 的 `state=permissive`（即 `setenforce 0`），再 `android_frida_reload`；用完改回 `state=enforcing`。这会全局关闭 SELinux，直到恢复或重启，只作为临时兜底。

其他工具：`android_frida_status`（root、已安装版本、会话）、`android_frida_prepare`（手动释放或 `force=true` 重装）、`android_frida_sessions`、`android_frida_restart_app`（只重启不注入）、`android_frida_clear_log`（清空会话日志，下次 `output` 从 0 开始）、`android_system_selinux`（`status`/`permissive`/`enforcing`）。失败时 `android_frida_run` 也会返回 `session_id` 和 `output`（可能带 `error` / `troubleshoot` 字段），frida-inject 的实际报错就在日志里，例如目标进程不存在、ptrace 被拒、脚本语法错误。脚本还没跑就出现 `Unable to save SELinux policy` / `Unable to load SELinux policy` / `unlabeled` 时，响应会带 `error: selinux_patch_failed`，这是环境问题，不要先去改脚本。

`android_frida_run` 的 `restart` 现在按目标区分：system / priv-app 默认 `false`（避免默认 force-stop NFC、system_server 这类服务），普通应用默认 `true`；需要覆盖时显式传 `restart`。

主界面的「允许 MCP 调用 Frida」开关关闭后，所有 `android_frida_*` 调用直接返回 `Frida is disabled in the App...`，并停止正在运行的会话；`android_system_get_summary` 的 `frida_enabled` 同步显示 `false`。开关只拦截 MCP，界面上的本地安装 / 卸载仍然可用。

第一次调用会触发 KernelSU 授权。frida-inject 和 frida-server 一样会自行 patch SELinux 策略，不需要额外 Magisk 模块；`/data/adb/dexmcp` 由 root 创建并设为 700，dexmcp 自己通过 `su` 读写其中的脚本和日志。旧版本留在 `/data/local/tmp/dexmcp` 的文件不会自动迁移，需要的话手动处理。

更新内置版本：把 `app/src/main/assets/frida/frida-inject` 换成官方 release 里对应版本的 arm64 文件（`.xz` 解压后原样放入），再改 `FridaManager.VERSION`；版本不一致时首次调用会自动重装。Java bridge 用 esbuild 重新打包（entry 只有 `import Java from 'frida-java-bridge'; globalThis.Java = Java;`）：

```bash
esbuild entry.js --bundle --format=iife --target=es2020 --minify --outfile=bridge.js
```

产物放到 `app/src/main/assets/frida/bridge.js`。Frida 17 的 Java bridge 依赖 runtime 的 `Script`、`Process` 等全局对象，只能这样打包后随脚本注入，不能当普通 JS 模块直接跑。


## 启动自动注入（Dex MCP 同时是 LSPosed 模块）

Dex MCP 本体就是 LSPosed 模块（现代 Xposed API 102，包名仍然是 `dev.dexmcp`），不再有单独的 `dev.dexmcp.xposed`。它不自己带 Frida 注入能力，而是在应用启动时让 Dex MCP 的 root 进程做一次附加：

1. 在 LSPosed 里启用「Dex MCP」。作用域不用手动勾：在 Dex MCP 的「启动注入」页面打开某个应用的开关时，App 会通过 `io.github.libxposed.service` 的 `requestScope()` 申请该包，LSPosed 弹出通知/确认，用户同意后自动加进作用域；关掉开关时会 `removeScope()`。
2. 在主界面「启动注入」页面里给应用打开开关、写脚本（脚本存在 `/data/adb/dexmcp/agents/<包名>.js`）。总开关关闭或应用开关关闭时不会注入。
3. 应用进程启动时，模块 hook `android.app.Instrumentation.callApplicationOnCreate`，也就是 `Application.onCreate()` 之前，在主线程上调用 Dex MCP 的 `content://dev.dexmcp.inject`（ContentProvider 的 `call()`），发送包名和 pid。
4. Dex MCP 的 `InjectProvider` 校验 `/proc/<pid>/cmdline` 与包名一致、总开关和应用开关都打开、运行时已安装、脚本存在，然后用内置 frida-inject 以 root 附加这个 pid 并加载脚本，等到脚本运行时发出就绪标记后再返回。
5. 模块拿到返回结果，应用继续往下执行 `onCreate`，这时脚本里的 hook 已经装好。

合并成一个 APK 之后不需要再装第二个模块应用，也没有跨应用的模块通信要维护；但**运行时仍然要经过一次 provider 调用**：hook 跑在目标应用进程（普通 UID，没有 root），真正执行 `frida-inject` 的是 Dex MCP 的进程，这一步无法省掉。

按现代 API 的约定，模块 APK 用 `META-INF/xposed/java_init.list` 声明入口类、`META-INF/xposed/module.prop` 声明 `minApiVersion`/`targetApiVersion`（都是 102），不再使用 `assets/xposed_init` 和 `xposedmodule` 等旧元数据。需要 LSPosed 支持现代 Xposed API 102；旧版 LSPosed 会把 Dex MCP 当成普通应用，不会加载模块。

界面上的「启动注入」页面：

- 顶部一张 LSPosed 状态卡：已连接时会显示“打开开关自动申请作用域”，未连接时提示先到 LSPosed 里启用模块。
- 总开关，下面是可搜索的应用列表（应用名 + 包名）。
- 每一行有开关和一个脚本状态（`没有脚本` / `脚本 1.2 KB`）；已启用但还没拿到作用域的行会标注 `未授权作用域`。
- 点行进入脚本编辑页：等宽文本编辑区，可直接改，底部「保存并启用」写文件并打开该应用开关，「删除脚本」删除文件并关闭开关；没有脚本时打开会带默认模板（`Java.perform(function () { ... });`）。
- 作用域申请结果（`approved` / 失败原因）会写进运行日志并 toast；申请失败时应用开关仍然保持打开，只是会在列表里显示未授权，方便稍后重试。

脚本同样可以用 MCP 工具管理：

```json
{"name":"android_frida_agent_set","arguments":{
  "package":"com.example.app",
  "script":"Java.perform(function () {\n  console.log('startup hook ready');\n  var T = Java.use('com.example.app.Target');\n  T.check.implementation = function () { return true; };\n});"
}}
```

```json
{"name":"android_frida_agent_scripts","arguments":{}}
```

```json
{"name":"android_frida_agent_enable","arguments":{"package":"com.example.app","enabled":true}}
```

```json
{"name":"android_frida_agent_delete","arguments":{"package":"com.example.app"}}
```

```json
{"name":"android_frida_autostart","arguments":{"enabled":true}}
```

模块侧流程是"先脚本、后启动"：注入失败、Dex MCP 没运行、运行时没安装、应用没开开关或没有脚本，模块都直接返回，应用照常启动（不会卡死）。代价是启用的应用冷启动会多等注入时间，正常在 1–3 秒。

几个实现细节：

- 只在主进程注入（进程名等于包名）；`:remote` 之类的子进程不处理。
- `android_frida_run` 自己重启应用时会登记 `manual_start`，模块此时不重复注入，避免两个 frida-inject 同时附加。
- 走 Binder（ContentProvider `call`），目标应用不需要 INTERNET 权限，也不需要 root。Dex MCP 进程被系统回收时，provider 调用会自动拉起它（被用户强行停止的情况除外，那要重新打开一次 App）。
- LSPosed 作用域和 Dex MCP 里的应用开关是两层：作用域没勾的应用连 hook 都不会加载；作用域勾了但开关没开的应用每次启动只多一次 provider 调用（返回 `disabled`），不会注入。
- provider 没有权限保护（调用方是目标应用本身，拿不到 signature 权限）：任意应用都能调，但服务端会核对 pid 对应的进程名、检查开关，且只会加载 Dex MCP 自己存放的脚本。

升级说明：0.4.7 起不再需要旧的 `dev.dexmcp.xposed` 模块，可以直接卸载；在 LSPosed 里改用「Dex MCP」。0.4.8 起作用域在 App 内申请：打开应用开关时如果没有作用域会自动向 LSPosed 请求；之前已经打开但没作用域的应用，把开关关掉再打开即可重新申请。


## 触控笔诊断、系统文件发现和持久化对照

`android_system_collect_snapshot` 新增 `stylus` profile：读取内核版本、系统属性、`dumpsys input/display`、输入设备/节点、Binder/HIDL 服务、进程、常见刷新率设置，以及已知的小米笔策略/debug 参数节点。每个命令限制 15 秒，返回自己的 `exit_code`、`stdout`、`stderr` 和截断标记；不存在的节点、权限不足或系统缺少 `lshal` 都按采集结果保留，不使其他项失败。

不会读取 `/proc/NVTSPI`、固件升级/自检等操作接口，也不发送笔使能、刷新率或固件命令。Root Profile 只有文件读取能力时，部分 `dumpsys`/日志仍可能失败，报告会保留实际错误。

官核和自编核分别保持相同系统设置、屏幕/笔操作，调用：

```json
{"name":"android_system_collect_snapshot","arguments":{"profile":"stylus","label":"stock-kernel"}}
```

```json
{"name":"android_system_collect_snapshot","arguments":{"profile":"stylus","label":"custom-kernel"}}
```

默认 `save=true`，返回 `snapshot_id`；快照写入 App 私有 files 目录，重启服务/App 后仍保留，卸载/清除 App 数据会丢失。最多保留 64 份，满后明确提示，使用 `android_system_delete_snapshot` 删除指定旧快照。`save=false` 只返回当前结果。

```json
{"name":"android_system_list_snapshots","arguments":{}}
```

```json
{"name":"android_system_compare_snapshots","arguments":{"before_id":"官核 snapshot_id","after_id":"自编核 snapshot_id","sections":["kernel","input","display","refresh_settings","pen_strategy"],"line_limit":100}}
```

对比输出新增/消失的完整行、退出码和错误变化；原始行顺序/重复次数不同也会标记。时间/PID 等运行时差异不会被当作故障结论；行数超限与原始采集截断会分别注明。取回完整 JSON、单个 section 或 Markdown 报告：

```json
{"name":"android_system_get_snapshot","arguments":{"snapshot_id":"已有 ID","format":"markdown"}}
```

```json
{"name":"android_system_get_snapshot","arguments":{"snapshot_id":"已有 ID","section":"display"}}
```

Markdown 报告通过 MCP 返回 `content`，agent 可保存成自己的文件；服务不会自行向共享存储写出报告。

系统文件发现沿用 root 文件读取名单，不扩展到用户数据目录：

```json
{"name":"android_system_list_directory","arguments":{"path":"/system/framework","limit":100}}
```

```json
{"name":"android_system_find_files","arguments":{"path":"/vendor","query":"touch","max_depth":4,"limit":100}}
```

按文件名做大小写不敏感的子串匹配，返回完整路径；结果包含文件和目录。搜索深度 1–8、默认 4，遍历限制 20 秒，不跟随子目录符号链接、不跨文件系统。输出超限、权限或超时会标记 `complete=false`，不能把没有结果解释成文件不存在。结果排序分页，继续传回 `next_cursor`，其余参数保持一致；这是重新扫描，不是固定时点索引，文件列表变化会影响分页。

给手机 agent 的排查顺序：先保存两份 `stylus` 快照，再对照触控/显示状态与错误；使用文件发现定位 framework JAR 与 vendor 服务配置；用 DEX 搜索 `MiuiStylusDeviceListener`、`ITouchFeature`、`setTouchMode`，配合日志查实际调用。DEX 功能仍不能分析 ELF HAL；需要运行时验证时用 `android_frida_run` 注入 Frida 脚本。

没有 root 时，可以点击 App 中的“无 Root 导入 APK / JAR / DEX”，通过系统文件选择器导入文件。Agent 先调用 `android_analysis_list_imports` 获取 `import_id`，再调用：

```json
{
  "name": "android_analysis_open",
  "arguments": { "import_id": "文件的 import_id" }
}
```

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

## Root 读取范围

默认只允许以下前缀：

```text
/system
/system_ext
/product
/vendor
/odm
/apex
/data/app
/data/adb/ksu/log
/data/adb/lspd/log
/proc/net
/sys/class/net
/sys/fs/bpf
```

不提供任意 root shell，也不允许读取 `/data/user`、`/data/data` 等用户数据目录。KernelSU 授权通过 libsu 获取。

特权读取检测不会只判断 UID 或 libsu 的缓存授权状态，而会实际尝试从 App 进程打开 `/data/system/packages.xml` 或 `/data/system/packages.list`。因此，通过 KernelSU Profile 单独授予 `CAP_DAC_READ_SEARCH` 时能识别为 `direct` 模式；直接访问失败后会主动建立 `su` shell（首次可能弹出 KernelSU 授权），并通过该 shell 实际读取探针文件。

系统文件复制采用单向 stdout 二进制流：特权 shell 只打开源文件并写管道，App 普通进程负责写自己的缓存。root 侧不再执行 `cp`、`chown` 或 `chmod`，因此不需要 `CAP_DAC_OVERRIDE` 和 `CAP_CHOWN`；保持默认 SELinux context 时，Root Profile 的 capability 只需启用 `CAP_DAC_READ_SEARCH`。

## 当前限制

- Streamable HTTP 当前使用普通 JSON 响应，没有服务端 SSE 进度流。
- 工作区保存在内存中，服务重启后需要重新打开。
- 搜索是即时扫描，尚未使用 Room/FTS 持久化索引。
- 尚未实现资源表查询、AXML 引用、方法切片和任务队列。
- 尚未提取 VDEX/ODEX/OAT；当前分析 APK/JAR/裸 DEX 中可直接读取的 DEX。
- `android_analysis_xref_dex` 当前实现直接引用扫描，不解析虚方法动态分派。
- 动态分析需要 root，只支持 arm64-v8a，依赖内置的 Frida 17.26.2。目标加固、反调试或禁止 ptrace 时会附加失败，具体错误在会话日志里。
- 若设备的策略数据库仍无法被 patch，只能用 `android_system_selinux` 临时切到 permissive（全局关闭 SELinux），用完必须恢复。
- 会话最多保留 24 个，超出时最早停止的会话连同目录一起清理；单次 `android_frida_output` 最多返回 256 KiB。
- 启动注入依赖 Dex MCP 前台服务常驻；服务被停掉、没装 LSPosed 模块或没勾选应用时不会注入。勾选应用的冷启动会多等注入完成（通常 1–3 秒），只在主进程注入，子进程不处理。
- 主界面状态在进入时重新读取，不跨进程保存；会话清单和运行日志会持久化。Compose + Miuix 让 APK 比 0.3.x 大约 15 MB。

这些限制不会影响第一版验证包发现、系统快照、DEX 搜索、Smali 读取和直接 xref 的主流程。

## 日志查询

`android_logs_query` 支持当前 logcat/dmesg 缓冲区，以及 KernelSU、LSPatch/LSPosed 持久化日志：

```json
{
  "source": "all_history",
  "query": "ConnectivityService|DownloadManager",
  "regex": true,
  "levels": ["W", "E"],
  "context_before": 3,
  "context_after": 5,
  "latest_files": 3,
  "limit": 100
}
```

历史目录为 `/data/adb/ksu/log` 和 `/data/adb/lspd/log`。空查询进入 tail 模式；结果包含原文件、行号和上下文。`dmesg_live` 可能受内核 `CAP_SYSLOG` 限制，此时应使用 `ksu_dmesg` 查询持久化文件，不需要额外 capability。

