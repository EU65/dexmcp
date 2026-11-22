# APK / DEX 静态分析

1. 用 `android_analysis_open` 打开已安装包、设备路径或 App 内导入的文件。按返回的 `workspace_id` 调用后续工具。
2. 用 `android_analysis_list` 列出构件、ZIP 条目、DEX 文件和类。分包时用 `artifact_id` 缩小范围。
3. 用 `android_analysis_search` 查符号或字符串，`android_analysis_outline_class` 看类结构，`android_analysis_read` 读 Manifest 或 Smali，`android_analysis_xref_dex` 查直接引用。
4. 完成后用 `android_analysis_close` 清理设备侧工作区。

## 无 Root 导入

没有 root 时，可以点击 App 中的“无 Root 导入 APK / JAR / DEX”，通过系统文件选择器导入文件。Agent 先调用 `android_analysis_list_imports` 获取 `import_id`，再调用：

```json
{
  "name": "android_analysis_open",
  "arguments": { "import_id": "文件的 import_id" }
}
```

## 分页、搜索与引用

- `android_analysis_read` 默认每页 16000 字符；继续读取时传回 `next_offset` 作为 `offset`。`ids` 可批量读取类或方法，共用 `max_chars` 预算；`no_bodies=true` 只读类的字段和方法签名。
- `android_analysis_search` 支持 `regex`、`in_class_prefix` 和 `dedupe`。限定类前缀时，`dex_string` 只搜这些类引用的字符串。
- `android_analysis_xref_dex` 支持 `context_instructions`，方法目标可省略签名以匹配所有重载。不解析动态分派。
- `android_analysis_list` 的 `zip_entries` 和 `dex_classes` 可以用 `query`、`regex` 和 `artifact_id` 过滤。

工作区是只读副本，服务重启后须重新打开。静态分析不解析 ELF 或 VDEX/ODEX/OAT。需要把 APK 中的二进制拿到工作区时，参见[大文件导出](file-export.md)。
