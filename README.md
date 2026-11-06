# nmmp (WexProtect Edition) — Android DEX VMP & Virtualization Obfuscator

<p align="left">
  <img src="https://img.shields.io/badge/Security-DEX%20Virtualization%20(VMP)-red?style=for-the-badge" alt="DEX VMP" />
  <img src="https://img.shields.io/badge/Obfuscation-Dex2C%20%26%20Polymorphic-blue?style=for-the-badge" alt="Dex2C & Polymorphic" />
  <img src="https://img.shields.io/badge/Crypto-ChaCha20%20%7C%20HMAC--SHA256-orange?style=for-the-badge" alt="ChaCha20 HMAC-SHA256" />
  <img src="https://img.shields.io/badge/Anti--Tamper-APK%20Sig%20Binding%20%7C%20Frida%20Guard-success?style=for-the-badge" alt="Anti-Tamper" />
  <img src="https://img.shields.io/badge/UI-Compose%20Multiplatform-7F52FF?style=for-the-badge&logo=jetpackcompose&logoColor=white" alt="Compose Desktop" />
</p>

Advanced Android DEX virtualization protector and Dex2C engine. Hardened fork of [maoabc/nmmp](https://github.com/maoabc/nmmp) featuring authenticated bytecode encryption, anti-analysis stealth guards, signature binding, and string encryption meshes.

---

## Key Hardening Features (WexProtect)

- **AEAD Bytecode Protection**: Method instruction streams sealed with per-method ChaCha20 keystreams and HMAC-SHA256 authentication; decrypted into volatile scratch buffers immediately before `vmInterpret`.
- **APK Signature Key Binding**: Dynamic key derivation bound to APK Signing Block v2/v3 certificate fold via raw syscalls (`openat`/`pread64`). Any repacked APK decrypts bytecode into garbage.
- **Stealth Anti-Analysis Guard**: High-threshold Frida, tracer and debug detection (`/proc/self/maps`, `/proc/self/task`). Rather than an instant crash, it intermittently and unpredictably taints execution to hinder reverse engineering.
- **Polymorphic Handlers**: Single `HANDLE_OPCODE` per-build mutation injecting volatile sinks, breaking automated bytecode pattern recognition across builds.
- **String Encryption Mesh**: Multi-variant LCG header/tag obfuscation with 128 dynamic decoders eliminating plaintext string references in DEX.
- **ELF & Control-Flow Hardening**: Sectionless ELF patching, anti-objdump headers, and `@WexFlowLock` branch state-machine guards.

---

[![](https://jitpack.io/v/TimScriptov/nmmp.svg)](https://jitpack.io/#TimScriptov/nmmp)

## Original REPO:
https://github.com/maoabc/nmmp

# Screenshots
![Main](/ART/Screenshot.png)

## Add it in your root build.gradle at the end of repositories:
```groovy
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}
```

## Add the dependency:
```groovy
dependencies {
    implementation("com.github.TimScriptov:nmmp:Tag")
    implementation("com.github.TimScriptov:preferences:Tag")
}
```

## Init preferences:
```kotlin
 Preferences(File("path"), "name.json").init()
```

## Environment path:
```kotlin
Prefs.setSdkPath("path") // ANDROID_SDK_HOME
Prefs.setCmakePath("path") // CMAKE_PATH
Prefs.setNdkPath("path") // ANDROID_NDK_HOME
```

## Change lib name and class name:
```kotlin
Prefs.setRegisterNativesClassName("com/nmmedit/protect/NativeUtil")
Prefs.setVmName("nmmvm")
Prefs.setNmmpName("nmmp")
```

## Protect APK:
```kotlin
val input = File("input.apk")
val output = File("output.apk")
val rules = File("rules.txt")
val simpleRules = SimpleRules().apply {
    parse(InputStreamReader(FileInputStream(rules), StandardCharsets.UTF_8))
}
val filterConfig = SimpleConvertConfig(BasicKeepConfig(), simpleRules)
ApkProtect.Builder(ApkFolders(input, output)).apply {
    setInstructionRewriter(RandomInstructionRewriter())
    setFilter(filterConfig)
    setLogger(null)
    setClassAnalyzer(ClassAnalyzer())
}.build().run()
```

## Protect AAR:
```kotlin
val input = File("input.aar")
val output = File("output.aar")
val rules = File("rules.txt")
val simpleRules = SimpleRules().apply {
    parse(InputStreamReader(FileInputStream(rules), StandardCharsets.UTF_8))
}
val filterConfig = SimpleConvertConfig(BasicKeepConfig(), simpleRules)
AarProtect.Builder(AarFolders(input, output)).apply {
    setInstructionRewriter(RandomInstructionRewriter())
    setFilter(filterConfig)
    setLogger(null)
    setClassAnalyzer(ClassAnalyzer())
}.build().run()
```

## Protect AAB:
```kotlin
val input = File("input.aab")
val output = File("output.aab")
val rules = File("rules.txt")
val simpleRules = SimpleRules().apply {
    parse(InputStreamReader(FileInputStream(rules), StandardCharsets.UTF_8))
}
val filterConfig = SimpleConvertConfig(BasicKeepConfig(), simpleRules)
AabProtect.Builder(AabFolders(input, output)).apply {
    setInstructionRewriter(RandomInstructionRewriter())
    setFilter(filterConfig)
    setLogger(null)
    setClassAnalyzer(ClassAnalyzer())
}.build().run()
```
