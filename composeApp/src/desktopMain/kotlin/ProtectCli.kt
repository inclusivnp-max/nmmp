import com.nmmedit.apkprotect.data.Prefs
import data.AppPrefs
import task.ApkVmpTask
import task.SecureSigningProcess
import java.io.File

fun main(args: Array<String>) {
    SetupConfig.apply()
    val configErrors = SetupConfig.validate()
    if (configErrors.isNotEmpty()) {
        configErrors.forEach { System.err.println(it) }
        System.exit(1)
    }

    if (args.isEmpty()) {
        System.err.println("Usage: ProtectCli <input.apk> [output.apk]")
        System.exit(1)
    }

    val input = File(args[0])
    if (!input.exists()) {
        System.err.println("Input APK not found: ${input.absolutePath}")
        System.exit(1)
    }

    val output = if (args.size > 1) {
        File(args[1])
    } else {
        File(input.parentFile, input.nameWithoutExtension + "_vmp.apk")
    }

    val rules = AppPrefs.rulesPath().ifEmpty {
        File(System.getProperty("user.dir"), "wex-rules.txt").absolutePath
    }
    if (!File(rules).exists()) {
        System.err.println("Rules file not found: $rules")
        System.exit(1)
    }

    val logs = mutableListOf<String>()

    println("Input:  ${input.absolutePath}")
    println("Output: ${output.absolutePath}")
    println("Rules:  $rules")
    println("SDK:    ${Prefs.getSdkPath()}")
    println("NDK:    ${Prefs.getNdkPath()}")
    println("CMake:  ${Prefs.getCmakePath()}")

    println("")
    println("---")

    ApkVmpTask(
        input = input.absolutePath,
        output = output.absolutePath,
        rules = rules,
        mapping = AppPrefs.mappingPath(),
        logs = logs,
    ).start()

    logs.forEach { println(it) }

    com.nmmedit.apkprotect.ApkProtect.printProgress(90, "Aligning APK resources (zipalign 4-byte)...")

    if (!fixApkForInstall(output)) {
        System.exit(2)
    }

    com.nmmedit.apkprotect.ApkProtect.printProgress(95, "Signing APK with production keystore (apksigner v1-v4)...")

    val signed = signApk(output)
    if (!signed) {
        System.exit(2)
    }

    com.nmmedit.apkprotect.ApkProtect.printProgress(100, "WexProtect protection complete: ${output.absolutePath}")
    println()
}

private fun findBuildTool(name: String): File? {
    return File(Prefs.getSdkPath(), "build-tools")
        .listFiles()
        ?.filter { it.isDirectory }
        ?.sortedByDescending { it.name }
        ?.map { File(it, name) }
        ?.firstOrNull { it.exists() && it.canExecute() }
}

private fun fixApkForInstall(output: File): Boolean {
    val fixScript = File(System.getProperty("user.dir"), "scripts/fix-apk-resources.py")
    val zipalign = findBuildTool("zipalign") ?: return false
    val fixed = File(output.parentFile, output.name + ".fixed")
    val aligned = File(output.parentFile, output.name + ".aligned")

    val fixCmd = if (fixScript.exists()) {
        listOf("python3", fixScript.absolutePath, output.absolutePath, fixed.absolutePath)
    } else {
        listOf("cp", output.absolutePath, fixed.absolutePath)
    }
    if (ProcessBuilder(fixCmd).inheritIO().start().waitFor() != 0) {
        fixed.delete()
        return false
    }

    val alignCmd = listOf(
        zipalign.absolutePath,
        "-p", "-f", "4",
        fixed.absolutePath,
        aligned.absolutePath,
    )
    println(alignCmd.joinToString(" "))
    if (ProcessBuilder(alignCmd).inheritIO().start().waitFor() != 0) {
        fixed.delete()
        aligned.delete()
        return false
    }

    output.delete()
    fixed.delete()
    aligned.renameTo(output)
    return true
}

private fun signApk(output: File): Boolean {
    val keystore = AppPrefs.keystorePath()
    val pass = AppPrefs.keystorePass()
    val alias = AppPrefs.keystoreAlias()
    val aliasPass = AppPrefs.keystoreAliasPass()

    val sdkApksigner = findBuildTool("apksigner")

    val signedTmp = File(output.parentFile, output.name + ".signed")
    val cmd = mutableListOf(
        sdkApksigner?.absolutePath ?: "java",
    )
    if (sdkApksigner == null) {
        cmd += listOf("-jar", "apksigner.jar")
    }
    cmd += listOf(
        "sign",
        "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true",
        "--v4-signing-enabled", "true",
        "--ks", keystore,
        "--ks-pass", "stdin",
        "--ks-key-alias", alias,
        "--key-pass", "stdin",
        "--out", signedTmp.absolutePath,
        output.absolutePath,
    )

    println(SecureSigningProcess.displayCommand(cmd))
    val exitStatus = SecureSigningProcess.run(
        cmd,
        listOf(pass, aliasPass),
        ::println,
    )
    if (exitStatus != 0) {
        signedTmp.delete()
        return false
    }
    output.delete()
    signedTmp.renameTo(output)
    return true
}
