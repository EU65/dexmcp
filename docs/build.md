# 构建与签名

需要 JDK 17 或 21、Android SDK Platform 36。建议用 JDK 21。设置 `ANDROID_HOME` 或在本机的 `local.properties` 设置 `sdk.dir`。

```bash
./gradlew :app:assembleDebug
./gradlew :app:assembleRelease
```

Windows 用 `gradlew.bat`。APK 输出在 `app/build/outputs/apk/`，可以直接复制到手机安装。

项目使用 Gradle 8.11.1、AGP 8.9.1、Kotlin 2.3.20 和 Compose / Miuix。现代 Xposed API 102 的依赖声明要求 SDK 37，但当前代码只使用 SDK 36 及以下符号，因此 `gradle.properties` 暂时关闭了 AAR 的 compileSdk 检查。

## Release 签名

release 默认用本机 Debug key。要用正式签名，在仓库根目录创建 `keystore.properties`，不要提交密钥或密码：

```properties
storeFile=keystore/dexmcp-release.jks
storePassword=...
keyAlias=dexmcp
keyPassword=...
```

只有相同签名的 APK 能覆盖升级。卸载旧版会清除 App 数据。

## GitHub Actions

[`release.yml`](../.github/workflows/release.yml) 在推送 `main`、推送 `v*` 标签或手动运行时构建 APK。标签和手动构建还会发布 GitHub Release。

CI 可用 `DEXMCP_KEYSTORE_BASE64`、`DEXMCP_KEYSTORE_PASSWORD` 和可选的 `DEXMCP_KEY_ALIAS` 配置签名。没有签名配置则用 Debug key。
