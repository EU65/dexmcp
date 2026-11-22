import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release signing: keystore.properties (local, gitignored) or DEXMCP_KEYSTORE_* env vars
// (GitHub Actions). Without either, release builds fall back to the debug key so a plain
// `assembleRelease` still works on a fresh checkout.
val signingProperties = Properties().apply {
    val file = rootProject.file("keystore.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}

fun signingValue(property: String, env: String): String? =
    signingProperties.getProperty(property) ?: System.getenv(env)

val releaseStoreFile = signingValue("storeFile", "DEXMCP_KEYSTORE_FILE")
val releaseStorePassword = signingValue("storePassword", "DEXMCP_KEYSTORE_PASSWORD")
val releaseKeyAlias = signingValue("keyAlias", "DEXMCP_KEY_ALIAS") ?: "dexmcp"
val releaseKeyPassword = signingValue("keyPassword", "DEXMCP_KEY_PASSWORD") ?: releaseStorePassword
val hasReleaseKey = !releaseStoreFile.isNullOrBlank() && !releaseStorePassword.isNullOrBlank()

android {
    namespace = "dev.dexmcp"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.dexmcp"
        minSdk = 28
        targetSdk = 35
        versionCode = 19
        versionName = "0.4.11"
    }

    signingConfigs {
        if (hasReleaseKey) {
            create("release") {
                storeFile = rootProject.file(releaseStoreFile!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // Modern Xposed API 102: compile-time only, LSPosed provides it in target processes.
    compileOnly("io.github.libxposed:api:102.0.0")
    // Framework service used by the module app to request scope dynamically.
    implementation("io.github.libxposed:service:102.0.0")

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    implementation("top.yukonga.miuix.kmp:miuix:0.8.8")
    implementation("top.yukonga.miuix.kmp:miuix-icons:0.8.8")

    implementation("org.nanohttpd:nanohttpd:2.3.1")
    testImplementation("junit:junit:4.13.2")
    implementation("com.github.topjohnwu.libsu:core:6.0.0")

    implementation("com.android.tools.smali:smali-dexlib2:3.0.10")
    implementation("com.android.tools.smali:smali-baksmali:3.0.10")
    implementation("net.dongliu:apk-parser:2.6.10")
}
