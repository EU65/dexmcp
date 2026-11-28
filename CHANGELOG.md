# 更新记录

## 0.4.13

- 启动注入支持按包选择范围：默认只注入主进程，设为 `all` 后该包的每个进程（如 `com.google.android.gms.unstable`）都在启动时加载同一个脚本。MCP 用 `android_frida_agent_scope`，App 里是脚本页的「注入所有进程」开关。
- `InjectProvider` 校验 Binder 调用方 PID 和 UID，只接受目标包自己的进程；返回值区分 `runtime_ready` 和 `runtime_not_confirmed`。
- `android_frida_run` 的 `process` 只接受完整进程名，Dex MCP 自己查 PID；`restart=false` 不再自动拉起未运行的应用。
- 附加失败分类为 `frida_helper_failed`、`selinux_patch_failed`、`frida_timeout`、`injector_exited`，不再建议为一般附加失败切 SELinux。
- 启动注入会话按进程区分，不再因为同包另一个进程启动就把还活着的会话标记为已停止。
- 内置 frida-inject 不再自己重载 SELinux policy：读/写路径改到 `/data/adb/dexmcp` 下的可控文件，默认跳过 Frida 的 policy patch。
- 安装运行时时默认安装 KernelSU 模块 `dexmcp_sepolicy`（`module.prop` + `sepolicy.rule`），并用 `ksud sepolicy apply` 立即生效；重启后由模块重新应用。
- 选择兼容模式时给模块写 `disable` 并从 frida 自身加载策略；卸载运行时会删除该模块。
- App 的 Frida 区新增「SELinux 策略」开关；`android_frida_prepare` 支持 `selinux_mode=ksu|compat`，应用失败时自动回退兼容模式并报错。

## 0.4.12

- 默认允许读取 `/data/adb`、`/mnt/opex`、`/mnt/oplus`、`/mnt/vendor` 和 `/system_dlkm`，方便诊断 KernelSU 模块和厂商组件。
- 默认允许设备级 `/proc`、`/sys` 和 ART 的 DEX 缓存目录，继续限制进程和用户数据路径。
- 默认允许读取 OPPO / ColorOS 的 `my_*` 系统分区，支持分析其中的预装 APK。
- 增加 HTTP 二进制流式下载和断点续传，支持单独导出 APK / ZIP 条目。
- 受保护文件通过单个 root 进程流式读取，由 App 写缓存。
- 文档拆分到 `docs/`，界面滚动和日志分享一并调整。

## 0.4.11

补了充电相关的只读路径（`/vendor_dlkm`、`/proc/charger`、`/proc/charger_cp`、`/proc/oplus_charge_pump`、`/proc/da9313`、`/proc/devinfo/fastchg`）；`list_directory` / `find_files` 改为跟随目录符号链接并按入参路径回显；错误返回带 `reason`（`policy_denied` / `eacces` / `eacces_selinux` / `enoent` / `eisdir` / `espipe`）和 `errno`；`android_system_read_file` 新增 `format=strings`，在设备侧抽可打印字符串，大文件不用整份 base64 回传。

## 0.4.10

默认放开 sysfs 读取：`/sys/class`、`/sys/devices`、`/sys/module`、`/sys/kernel`、`/sys/fs`、`/sys/bus` 都在只读白名单里，触摸/笔/电源/温控节点可以直接读；sysfs 节点 stat 大小为 0 时不再误判截断。

## 0.4.9

修了 MCP 传输层：支持现代协议 2026-07-28（`server/discover`、`resultType`、`ttlMs`/`cacheScope`、无 `initialize` 握手），并按 `Transfer-Encoding: chunked` 读取请求体。之前 chunked 请求的 body 会被读不完整，残留内容拼到下一个请求行，客户端收到 `BAD REQUEST: Syntax error. HTTP verb ... POST unhandled.`

## 0.4.8

把模块迁到现代 Xposed API 102（`META-INF/xposed/*`、`module.prop`），并通过 `io.github.libxposed:service` 在 App 内动态申请作用域：打开某个应用的开关后向 LSPosed 请求该包，用户在 LSPosed 通知里确认即可，关闭开关时撤销作用域。

## 0.4.7

把 LSPosed 模块并进 Dex MCP 本体：同一个 APK 既是 MCP 服务端也是启动注入模块，不再有单独的 `dev.dexmcp.xposed`；
