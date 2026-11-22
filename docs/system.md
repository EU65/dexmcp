# 系统文件、诊断与日志

## 文件读取

「允许读取任意路径」默认关闭。开启后不再限制路径前缀，受保护文件仍需系统权限。关闭后，白名单外的缓存导出也不能继续下载。默认允许以下前缀：

```text
/system
/system_ext
/system_dlkm
/product
/vendor
/vendor_dlkm
/odm
/apex
/my_bigball
/my_carrier
/my_company
/my_engineering
/my_heytap
/my_manifest
/my_preload
/my_product
/my_region
/my_reserve
/my_stock
/proc
/sys
/data/app
/data/dalvik-cache
/data/misc/apexdata/com.android.art/dalvik-cache
/data/adb
/mnt/opex
/mnt/oplus
/mnt/vendor
```

`/proc` 默认只开放设备级节点，不开放进程目录、`self`、`thread-self`、`kcore`、`vmcore` 和 `kmsg`。应用私有目录、通讯录、短信、账号存储和共享存储仍不在白名单。DEX 按所在目录判断，不按扩展名放行。符号链接不能绕过路径限制。

读取失败时可查看 `reason` 和 `errno`。`policy_denied` 是 App 白名单拒绝，`eacces` / `eacces_selinux` 是设备权限拒绝。procfs 和 sysfs 的 `file_size` 可能未知，并不代表不能读。导出时由 App 写私有缓存，root 只负责读取源文件。

`android_system_read_file` 会识别常见二进制格式，不会默认把 ELF、DEX 或 ZIP 解码成文本。它也支持 `format=strings`，在设备上用 `strings`/`grep` 抽完再回传：

```json
{"name":"android_system_read_file","arguments":{
  "path":"/vendor/lib/modules/oplus_chg_v2.ko",
  "format":"strings","min_len":6,"grep":"flag|token|seal","max_bytes":65536
}}
```

返回 `strings` 数组、`count` 和 `truncated`；`grep` 是设备侧 `grep -aE` 的扩展正则，`max_strings` 默认 2000。普通读取失败时返回 `error`、`reason`、`errno`、`type`，其中 `policy_denied` 表示路径被 App 白名单拦下，`eacces` / `eacces_selinux` 是内核或 SELinux 拒绝。

## 文件发现

系统文件发现使用相同的路径检查：

```json
{"name":"android_system_list_directory","arguments":{"path":"/system/framework","limit":100}}
```

```json
{"name":"android_system_find_files","arguments":{"path":"/vendor","query":"touch","max_depth":4,"limit":100}}
```

按文件名做大小写不敏感的子串匹配，返回完整路径；结果包含文件和目录。搜索深度 1–8、默认 4，遍历限制 20 秒，可以跨挂载点，只跟随作为搜索起点传入的符号链接，不跟随遍历中遇到的链接。输出超限、权限或超时会标记 `complete=false`，不能把没有结果解释成文件不存在。结果排序分页，继续传回 `next_cursor`，其余参数保持一致；这是重新扫描，不是固定时点索引，文件列表变化会影响分页。

## 诊断快照

`android_system_collect_snapshot` 支持 `device`、`network` 和 `stylus`。`stylus` 会读取内核版本、系统属性、`dumpsys input/display`、输入设备/节点、Binder/HIDL 服务、进程、常见刷新率设置，以及已知的小米笔策略/debug 参数节点。每个命令限制 15 秒，返回自己的 `exit_code`、`stdout`、`stderr` 和截断标记；不存在的节点、权限不足或系统缺少 `lshal` 都按采集结果保留，不使其他项失败。

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
