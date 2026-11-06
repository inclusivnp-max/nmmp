package task

import com.nmmedit.apkprotect.log.VmpLogger
import com.nmmedit.apkprotect.util.FileHelper.copyStream
import com.nmmedit.apkprotect.util.FileUtils
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths

class ApkSignTask(
    private val output: String,
    private val keystorePath: String,
    private val keystorePassword: String,
    private val keystoreAlias: String,
    private val keystoreAliasPassword: String,
    private val logs: MutableList<String>,
) : VmpLogger {
    fun start() {
        if (keystorePath.isEmpty()) {
            info("No keystore, skip sign.")
            return
        }

        if (!Files.exists(Paths.get(keystorePath))) {
            info("Keystore $keystorePath does not exist, skip sign.")
            return
        }

        val apksignerFile = File(FileUtils.getHomePath(), "tools/apksigner.jar")
        if (!apksignerFile.exists()) {
            apksignerFile.parentFile.mkdirs()
            ApkSignTask::class.java.getResourceAsStream("/apksigner.jar").use { inputStream ->
                FileOutputStream(apksignerFile).use { outputStream ->
                    inputStream?.let { copyStream(it, outputStream) }
                }
            }
        }

        try {
            val command = listOf(
                    "java",
                    "-jar",
                    apksignerFile.absolutePath,
                    "sign",
                    "--in",
                    output,
                    "--out",
                    output,
                    "--ks",
                    keystorePath,
                    "--ks-pass",
                    "stdin",
                    "--ks-key-alias",
                    keystoreAlias,
                    "--key-pass",
                    "stdin",
                )
            info(SecureSigningProcess.displayCommand(command))
            val exitStatus = SecureSigningProcess.run(
                command,
                listOf(keystorePassword, keystoreAliasPassword),
                ::info,
            )
            if (exitStatus != 0) {
                throw IOException("apksigner failed with exit status $exitStatus")
            }
        } catch (e: IOException) {
            error(e.message)
        }
    }

    override fun info(msg: String?) {
        if (!msg.isNullOrEmpty()) {
            logs.add("I: $msg")
        }
    }

    override fun error(msg: String?) {
        if (!msg.isNullOrEmpty()) {
            logs.add("E: $msg")
        }
    }

    override fun warning(msg: String?) {
        if (!msg.isNullOrEmpty()) {
            logs.add("W: $msg")
        }
    }
}
