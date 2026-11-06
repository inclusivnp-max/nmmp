package task

import com.nmmedit.apkprotect.log.VmpLogger
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths

class AabSignTask(
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


        try {
            val command = listOf(
                    "jarsigner",
                    "-sigalg",
                    "SHA256withRSA",
                    "-digestalg",
                    "SHA-256",
                    "-keystore",
                    keystorePath,
                    output,
                    keystoreAlias,
                    "-tsa",
                    "http://sha256timestamp.ws.symantec.com/sha256/timestamp"
                )
            info(SecureSigningProcess.displayCommand(command))
            val exitStatus = SecureSigningProcess.run(
                command,
                listOf(keystorePassword, keystoreAliasPassword),
                ::info,
            )
            if (exitStatus != 0) {
                throw IOException("jarsigner failed with exit status $exitStatus")
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
