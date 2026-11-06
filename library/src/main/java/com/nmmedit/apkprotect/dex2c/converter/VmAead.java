package com.nmmedit.apkprotect.dex2c.converter;

import org.jetbrains.annotations.NotNull;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * ChaCha20 + encrypt-then-HMAC-SHA-256 (128-bit tag) used for generated VM
 * blobs. Encryption and authentication keys are independently derived and the
 * tag binds the domain, context, integrity-site cookie, nonce and length.
 */
public final class VmAead {
    public static final int NONCE_BYTES = 12;
    public static final int TAG_BYTES = 16;

    public static final int DOMAIN_INSTRUCTIONS = 0x4e534e49; // "INSN" LE
    public static final int DOMAIN_FLOW_BLOCK = 0x574f4c46;   // "FLOW" LE
    public static final int DOMAIN_TRIES = 0x45495254;        // "TRIE" LE
    public static final int DOMAIN_RESOLVER = 0x4c4f5052;     // "RPOL" LE

    private static final byte[] KDF_LABEL =
            "NMMP-AEAD-KDF2".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] TAG_LABEL =
            "NMMP-AEAD-TAG2".getBytes(StandardCharsets.US_ASCII);

    private VmAead() {
    }

    public static @NotNull Sealed seal(@NotNull VmKeyConfig config,
                                       byte @NotNull [] plaintext,
                                       int domain,
                                       long contextTag,
                                       byte @NotNull [] nonce,
                                       long siteMaterial) {
        validateNonce(nonce);
        final Keys keys = deriveKeys(config, domain, contextTag, siteMaterial);
        try {
            final byte[] ciphertext = crypt(keys.encryptionKey, nonce, plaintext);
            final byte[] tag = computeTag(keys.authenticationKey, domain,
                    contextTag, siteMaterial, nonce, ciphertext);
            return new Sealed(ciphertext, Arrays.copyOf(tag, TAG_BYTES), nonce.clone());
        } finally {
            keys.destroy();
        }
    }

    static byte @NotNull [] openForTest(@NotNull VmKeyConfig config,
                                         @NotNull Sealed sealed,
                                         int domain,
                                         long contextTag,
                                         long siteMaterial) throws GeneralSecurityException {
        final Keys keys = deriveKeys(config, domain, contextTag, siteMaterial);
        try {
            final byte[] actual = computeTag(keys.authenticationKey, domain,
                    contextTag, siteMaterial, sealed.nonce, sealed.ciphertext);
            if (!MessageDigest.isEqual(sealed.tag, Arrays.copyOf(actual, TAG_BYTES))) {
                throw new GeneralSecurityException("VM blob authentication failed");
            }
            return crypt(keys.encryptionKey, sealed.nonce, sealed.ciphertext);
        } finally {
            keys.destroy();
        }
    }

    private static Keys deriveKeys(VmKeyConfig config,
                                   int domain,
                                   long contextTag,
                                   long siteMaterial) {
        final byte[] root = config.getAeadRootKey();
        final byte[] base = ByteBuffer.allocate(
                        KDF_LABEL.length + Long.BYTES + Integer.BYTES
                                + Long.BYTES + Long.BYTES + 1)
                .order(ByteOrder.LITTLE_ENDIAN)
                .put(KDF_LABEL)
                .putLong(config.getValidRuntimeMaterial())
                .putInt(domain)
                .putLong(contextTag)
                .putLong(siteMaterial)
                .put((byte) 1)
                .array();
        final byte[] enc = hmac(root, base);
        base[base.length - 1] = 2;
        final byte[] auth = hmac(root, base);
        Arrays.fill(root, (byte) 0);
        Arrays.fill(base, (byte) 0);
        return new Keys(enc, auth);
    }

    private static byte[] crypt(byte[] key, byte[] nonce, byte[] input) {
        try {
            final Cipher cipher = Cipher.getInstance("ChaCha20");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "ChaCha20"),
                    new ChaCha20ParameterSpec(nonce, 1));
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ChaCha20 is unavailable", e);
        }
    }

    private static byte[] computeTag(byte[] key,
                                     int domain,
                                     long contextTag,
                                     long siteMaterial,
                                     byte[] nonce,
                                     byte[] ciphertext) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(TAG_LABEL);
            mac.update(ByteBuffer.allocate(Integer.BYTES + Long.BYTES + Long.BYTES)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(domain)
                    .putLong(contextTag)
                    .putLong(siteMaterial)
                    .array());
            mac.update(nonce);
            mac.update(ByteBuffer.allocate(Long.BYTES)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putLong(ciphertext.length)
                    .array());
            mac.update(ciphertext);
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    private static byte[] hmac(byte[] key, byte[] input) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    private static void validateNonce(byte[] nonce) {
        if (nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("ChaCha20 nonce must contain 12 bytes");
        }
    }

    public static final class Sealed {
        private final byte[] ciphertext;
        private final byte[] tag;
        private final byte[] nonce;

        private Sealed(byte[] ciphertext, byte[] tag, byte[] nonce) {
            this.ciphertext = ciphertext;
            this.tag = tag;
            this.nonce = nonce;
        }

        public byte @NotNull [] ciphertext() {
            return ciphertext.clone();
        }

        public byte @NotNull [] tag() {
            return tag.clone();
        }

        public byte @NotNull [] nonce() {
            return nonce.clone();
        }
    }

    private static final class Keys {
        private final byte[] encryptionKey;
        private final byte[] authenticationKey;

        private Keys(byte[] encryptionKey, byte[] authenticationKey) {
            this.encryptionKey = encryptionKey;
            this.authenticationKey = authenticationKey;
        }

        private void destroy() {
            Arrays.fill(encryptionKey, (byte) 0);
            Arrays.fill(authenticationKey, (byte) 0);
        }
    }
}
