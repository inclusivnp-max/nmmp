import com.nmmedit.apkprotect.data.Prefs
import com.nmmedit.apkprotect.sign.PublicKeyUtils
import data.AppPrefs
import java.io.File
import java.util.Properties

object SetupConfig {
    private const val SDK = "/home/zapahtravki/Android/Sdk"
    private const val NDK = "/home/zapahtravki/Android/Sdk/ndk/28.2.13676358"
    private const val CMAKE = "/home/zapahtravki/Android/Sdk/cmake/3.22.1"
    private const val RULES = "/home/zapahtravki/Tools/nmmp/wex-rules.txt"
    private const val KEYSTORE = "/home/zapahtravki/.config/wex/signing/pcholkin.jks"
    private const val LEGACY_KEYSTORE =
        "/home/zapahtravki/AndroidStudioProjects/WEX/app/src/main/assets/pcholkin.jks"
    private const val WEX_LOCAL_PROPERTIES =
        "/home/zapahtravki/AndroidStudioProjects/WEX/local.properties"
    private var signatureError: String? = null

    private val signingProperties by lazy {
        Properties().apply {
            val file = File(WEX_LOCAL_PROPERTIES)
            if (file.isFile) file.inputStream().use(::load)
        }
    }

    private fun signingSetting(environmentName: String, propertyName: String): String {
        return System.getenv(environmentName)?.takeIf { it.isNotBlank() }
            ?: signingProperties.getProperty(propertyName).orEmpty()
    }

    fun apply() {
        if (Prefs.getSdkPath().isEmpty()) Prefs.setSdkPath(SDK)
        if (Prefs.getNdkPath().isEmpty()) Prefs.setNdkPath(NDK)
        if (Prefs.getCmakePath().isEmpty()) Prefs.setCmakePath(CMAKE)

        Prefs.setArm(true)
        Prefs.setArm64(true)
        Prefs.setX86(false)
        Prefs.setX64(false)

        // WexProtect branding: no nmmp/nmmvm anywhere in the output.
        Prefs.setNmmpName("wexbase")
        Prefs.setVmName("wexbridge")
        Prefs.setRegisterNativesClassName("client/wex/internal/NativeBridge")

        if (AppPrefs.rulesPath().isEmpty()) AppPrefs.setRulesPath(RULES)

        val mapping = File(
            "/home/zapahtravki/AndroidStudioProjects/WEX/app/build/outputs/mapping/release/mapping.txt",
        )
        if (mapping.isFile) {
            AppPrefs.setMappingPath(mapping.absolutePath)
        }

        val configuredKeyStore = signingSetting("WEX_KEYSTORE_PATH", "wex.keystore.path")
            .ifEmpty { KEYSTORE }
        if (AppPrefs.keystorePath().isEmpty() || AppPrefs.keystorePath() == LEGACY_KEYSTORE) {
            AppPrefs.setKeystorePath(configuredKeyStore)
        }
        if (AppPrefs.keystorePass().isEmpty()) {
            signingSetting("WEX_KEYSTORE_PASSWORD", "wex.keystore.password")
                .takeIf { it.isNotEmpty() }
                ?.let(AppPrefs::setKeystorePass)
        }
        if (AppPrefs.keystoreAlias().isEmpty()) {
            AppPrefs.setKeystoreAlias(
                signingSetting("WEX_KEY_ALIAS", "wex.key.alias").ifEmpty { "pcholkin" },
            )
        }
        if (AppPrefs.keystoreAliasPass().isEmpty()) {
            signingSetting("WEX_KEY_PASSWORD", "wex.key.password")
                .ifEmpty { AppPrefs.keystorePass() }
                .takeIf { it.isNotEmpty() }
                ?.let(AppPrefs::setKeystoreAliasPass)
        }

        // Derive valid build material from the signing cert fingerprint. The
        // raw fingerprint is not emitted into the VM; 0 disables signer binding.
        try {
            check(AppPrefs.keystorePass().isNotEmpty()) {
                "Keystore password is not configured"
            }
            val fold = PublicKeyUtils.getCertificateFold(
                AppPrefs.keystorePath().ifEmpty { configuredKeyStore },
                AppPrefs.keystoreAlias().ifEmpty { "pcholkin" },
                AppPrefs.keystorePass(),
            )
            Prefs.setExpectedSigFold(fold)
            signatureError = null
        } catch (e: Exception) {
            Prefs.setExpectedSigFold(0L)
            signatureError = "Cannot read signing certificate: ${e.cause?.message ?: e.message}"
        }
    }

    fun validate(): List<String> {
        val errors = mutableListOf<String>()
        listOf(
            "SDK" to Prefs.getSdkPath(),
            "NDK" to Prefs.getNdkPath(),
            "CMake" to Prefs.getCmakePath(),
            "Rules" to AppPrefs.rulesPath(),
            "Keystore" to AppPrefs.keystorePath(),
        ).forEach { (name, path) ->
            if (path.isEmpty() || !File(path).exists()) {
                errors.add("$name not found: $path")
            }
        }
        if (AppPrefs.keystorePass().isEmpty()) errors.add("Keystore password is not configured")
        if (AppPrefs.keystoreAlias().isEmpty()) errors.add("Keystore alias is not configured")
        if (AppPrefs.keystoreAliasPass().isEmpty()) errors.add("Key password is not configured")
        signatureError?.let(errors::add)
        return errors
    }
}
