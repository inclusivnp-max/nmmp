package data

import com.mcal.preferences.PreferencesManager
import com.nmmedit.apkprotect.data.Prefs
import com.nmmedit.apkprotect.data.Storage
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

object AppPrefs : PreferencesManager(Storage.binDir, "nmmp_preferences.json") {
    private const val KEYSTORE_PASSWORD = "keystore_pass"
    private const val KEY_PASSWORD = "keystore_alias_pass"

    @Volatile
    private var sessionKeystorePassword = ""

    @Volatile
    private var sessionKeyPassword = ""

    init {
        removePersistedSigningSecrets()
    }

    private fun removePersistedSigningSecrets() {
        Prefs.remove(KEYSTORE_PASSWORD)
        Prefs.remove(KEY_PASSWORD)
        try {
            val preferences = Storage.binDir.resolve("nmmp_preferences.json").toPath()
            if (Files.exists(preferences)) {
                Files.setPosixFilePermissions(
                    preferences,
                    setOf(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                    ),
                )
            }
        } catch (_: UnsupportedOperationException) {
            // Non-POSIX platforms keep their native ACLs.
        }
    }

    /**
     * ApkSigner
     */
    @JvmStatic
    fun keystorePath(): String {
        return Prefs.getString("keystore_path", "")
    }

    @JvmStatic
    fun setKeystorePath(name: String) {
        Prefs.putString("keystore_path", name)
    }

    @JvmStatic
    fun keystorePass(): String {
        return sessionKeystorePassword
    }

    @JvmStatic
    @Synchronized
    fun setKeystorePass(name: String) {
        sessionKeystorePassword = name
        Prefs.remove(KEYSTORE_PASSWORD)
    }

    @JvmStatic
    fun keystoreAlias(): String {
        return Prefs.getString("keystore_alias", "")
    }

    @JvmStatic
    fun setKeystoreAlias(name: String) {
        Prefs.putString("keystore_alias", name)
    }

    @JvmStatic
    fun keystoreAliasPass(): String {
        return sessionKeyPassword
    }

    @JvmStatic
    @Synchronized
    fun setKeystoreAliasPass(name: String) {
        sessionKeyPassword = name
        Prefs.remove(KEY_PASSWORD)
    }

    /**
     * Config
     */
    @JvmStatic
    fun rulesPath(): String {
        return Prefs.getString("rules_path", "")
    }

    @JvmStatic
    fun setRulesPath(name: String) {
        Prefs.putString("rules_path", name)
    }

    @JvmStatic
    fun mappingPath(): String {
        return Prefs.getString("mapping_path", "")
    }

    @JvmStatic
    fun setMappingPath(name: String) {
        Prefs.putString("mapping_path", name)
    }
}
