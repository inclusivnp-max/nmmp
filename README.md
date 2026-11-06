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

## ⚡ Быстрый старт и использование форка

### 1. Требования к окружению
- **JDK 21**
- **Android SDK** (`build-tools 34+`, `platform 34+`)
- **Android NDK** (`r25+` / `r28+`)
- **CMake** `3.22.1+`

---

### 2. Запуск графического интерфейса (Desktop GUI)

Форк включает удобный Compose Desktop GUI для визуальной настройки и запуска защиты:

```bash
./gradlew :composeApp:run
```

В интерфейсе доступны:
- Выбор входного файла (APK / AAB / AAR) и пути сохранения.
- Настройка путей Android SDK, NDK и CMake.
- Редактор и выбор файла правил виртуализации (`rules.txt`).
- Подключение ProGuard/R8 mapping-файла.
- Настройка keystore для автоматической подписи и привязки дешифровки байткода к сертификату (SigCheck).
- Live-терминал с выводом стадий запекания защиты в нативную библиотеку.

![Screenshot](/ART/Screenshot.png)

---

### 3. Автоматизация в CI / Headless CLI

Для сборки в CI/CD или скриптах автоматизации форк предоставляет headless-задачу `protectApk`:

```bash
./gradlew :composeApp:protectApk \
    -PinputApk="/path/to/app-release.apk" \
    -PoutputApk="/path/to/app-protected.apk"
```

При этом автоматически:
1. Загружаются правила из `wex-rules.txt` (или указанные в конфиге).
2. Выполняется виртуализация выбранных методов в C/C++ VM.
3. Собираются нативные библиотеки под целевые архитектуры (`arm64-v8a`, `armeabi-v7a`).
4. Накладывается шифрование байткода и строк.
5. Выполняется выравнивание `zipalign -p -f 4` и подпись `apksigner` (v1–v4).

Также доступен готовый shell-скрипт для сборки WEX:
```bash
./scripts/vmp-wex.sh /path/to/input.apk /path/to/output.apk
```

---

### 4. Синтаксис правил виртуализации (`rules.txt`)

Форк поддерживает расширенные директивы для управления компилятором Dex2C и защитой:

```proguard
# 1. Защита аннотированных методов конечным автоматом (Control Flow Locking):
flowlock-annotation client.wex.annotations.WexFlowLock

# 2. Выбор пакетов и классов для трансляции в нативную VM:
class client.wex.** { *; }
class com.mysecurity.** { *; }

# 3. Исключения (keep — остаются в обычном DEX):
# Исключайте классы с тяжёлым reflection, JNI-мостами или hot-path криптографией:
keep class client.wex.modules.TdJniLoader
keep class client.wex.modules.NativeModuleGate
keep class client.wex.security.Guard$*
```

---

### 5. Использование как библиотеки в Gradle-проекте

Вы можете подключить модуль `library` напрямую в свой проект:

```groovy
dependencies {
    implementation(project(":library"))
}
```

Программный запуск защиты:

```kotlin
val input = File("input.apk")
val output = File("output.apk")
val rules = File("wex-rules.txt")

val simpleRules = SimpleRules().apply {
    parse(InputStreamReader(FileInputStream(rules), StandardCharsets.UTF_8))
}
val filterConfig = SimpleConvertConfig(BasicKeepConfig(), simpleRules)

// Настройка кастомных имён для сокрытия следов nmmp:
Prefs.setNmmpName("wexbase")
Prefs.setVmName("wexbridge")
Prefs.setRegisterNativesClassName("client/wex/internal/NativeBridge")

ApkProtect.Builder(ApkFolders(input, output)).apply {
    setInstructionRewriter(RandomInstructionRewriter())
    setFilter(filterConfig)
    setClassAnalyzer(ClassAnalyzer())
}.build().run()
```

---

## 🛡️ Архитектура глубокой защиты (WexProtect Hardening)

- **AEAD Bytecode Protection**: Инструкции методов запечатаны через ChaCha20 + HMAC-SHA256 с динамическими ключами. Байткод расшифровывается в scratch-память только в момент вызова метода.
- **APK Signature Key Binding**: Привязка к открытому ключу сертификата подписи APK. Механизм читает APK Signing Block v2/v3 напрямую через ядро Linux (`openat`/`pread64`). Переподписанный APK расшифровывает инструкции в кашу.
- **Stealth Anti-Analysis Guard**: Высокоточный детектор Frida, Gum и ptrace-отладчиков. Не завершает приложение мгновенно, а с рандомизированной задержкой искажает возвращаемые значения, ломая логику взломщика.
- **Polymorphic Handlers**: Мутация хэндлеров `HANDLE_OPCODE` уникальными константами для каждого билда, исключающая распознавание по байт-сигнатурам.
- **String Encryption Mesh**: 128 полиморфных декодеров и шифрование string pool, удаляющее любые читаемые литералы из DEX.
- **ELF & Control-Flow Hardening**: Защита заголовков `.so` (anti-objdump) и обфускация графа переходов `@WexFlowLock`.

---

## Оригинальный репозиторий
Основано на открытом проекте [maoabc/nmmp](https://github.com/maoabc/nmmp).
