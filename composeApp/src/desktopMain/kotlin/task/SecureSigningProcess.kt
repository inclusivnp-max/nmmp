package task

import java.io.IOException
import java.nio.charset.StandardCharsets

internal object SecureSigningProcess {
    private val secretOptions = setOf(
        "--ks-pass",
        "--key-pass",
        "-storepass",
        "-keypass",
    )

    fun displayCommand(command: List<String>): String {
        var redactNext = false
        return command.joinToString(" ") { argument ->
            when {
                redactNext -> {
                    redactNext = false
                    "<redacted>"
                }

                argument in secretOptions -> {
                    redactNext = true
                    argument
                }

                argument.startsWith("pass:") -> "<redacted>"
                else -> argument
            }
        }
    }

    @Throws(IOException::class)
    fun run(
        command: List<String>,
        secretLines: List<String>,
        output: (String) -> Unit,
    ): Int {
        val process = ProcessBuilder(command)
            .redirectErrorStream(true)
            .start()

        process.outputStream.bufferedWriter(StandardCharsets.UTF_8).use { writer ->
            secretLines.forEach { secret ->
                writer.write(secret)
                writer.newLine()
            }
        }

        process.inputStream.bufferedReader(StandardCharsets.UTF_8).useLines { lines ->
            lines.forEach(output)
        }

        return try {
            process.waitFor()
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("Signing process interrupted", e)
        }
    }
}
