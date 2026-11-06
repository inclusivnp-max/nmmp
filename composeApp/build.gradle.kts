import org.jetbrains.compose.ExperimentalComposeLibrary
import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.jetbrainsCompose)
    alias(libs.plugins.kotlinx.serialization)
}

kotlin {
    jvm("desktop") {
        jvmToolchain(21)
        withJava()
    }
    
    sourceSets {
        val desktopMain by getting
        
        commonMain.dependencies {
            implementation(project(":library"))

            implementation(compose.runtime)
            implementation(compose.foundation)
            implementation(compose.material3)
            implementation(compose.ui)
            @OptIn(ExperimentalComposeLibrary::class)
            implementation(compose.components.resources)

            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
            implementation("org.jetbrains.kotlinx:kotlinx-serialization-json-jvm:1.6.2")

            implementation("com.github.timscriptov:preferences:1.0.4")

            implementation("org.slf4j:slf4j-simple:1.6.1")
        }
        desktopMain.dependencies {
            implementation(compose.desktop.currentOs)
        }
    }
}

tasks.register<JavaExec>("protectApk") {
    group = "nmmp"
    description = "Obfuscate and sign an APK"
    dependsOn("compileKotlinDesktop")
    val desktopCompilation = kotlin.jvm("desktop").compilations.getByName("main")
    classpath = desktopCompilation.runtimeDependencyFiles + desktopCompilation.output.classesDirs
    mainClass.set("ProtectCliKt")
    jvmArgs("-Djdk.util.zip.disableZip64ExtraFieldValidation=true")
    if (project.hasProperty("inputApk")) {
        args(project.property("inputApk") as String)
        if (project.hasProperty("outputApk")) {
            args(project.property("outputApk") as String)
        }
    }
}

compose.desktop {
    application {
        mainClass = "MainKt"
        nativeDistributions {
            targetFormats(TargetFormat.Dmg, TargetFormat.Msi, TargetFormat.Deb)
            packageName = "nmmp"
            packageVersion = "1.3.0"
            description = "Android APK Protector"
            copyright = "© 2023 timscriptov."
            vendor = "timscriptov"
        }
        buildTypes.release.proguard {
            version.set("7.3.2")
            configurationFiles.from("desktop-rules.pro")
            isEnabled.set(true)
            obfuscate.set(true)
        }
        jvmArgs("-Djdk.util.zip.disableZip64ExtraFieldValidation=true")
    }
}
