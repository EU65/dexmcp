plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.dexmcp"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.dexmcp"
        minSdk = 28
        targetSdk = 35
        versionCode = 16
        versionName = "0.4.8"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Personal-use release APK remains installable and can replace an
            // existing debug build signed with this machine's development key.
            signingConfig = signingConfigs.getByName("debug")
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
    implementation("com.github.topjohnwu.libsu:core:6.0.0")

    implementation("com.android.tools.smali:smali-dexlib2:3.0.10")
    implementation("com.android.tools.smali:smali-baksmali:3.0.10")
    implementation("net.dongliu:apk-parser:2.6.10")
}
