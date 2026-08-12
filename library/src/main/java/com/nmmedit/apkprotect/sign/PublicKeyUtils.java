package com.nmmedit.apkprotect.sign;

import org.jetbrains.annotations.Nullable;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class PublicKeyUtils {
    public static byte @Nullable [] getPublicKey(String keyStorePath, String alias, String password) {
        try {
            final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(new FileInputStream(keyStorePath), password.toCharArray());
            if (alias == null || alias.isEmpty()) {
                final Enumeration<String> aliases = ks.aliases();
                if (aliases == null) {
                    return null;
                }
                if (aliases.hasMoreElements()) {
                    alias = aliases.nextElement();//取第一个证书别名
                }
            }
            final Certificate[] chain = ks.getCertificateChain(alias);
            if (chain == null || chain.length == 0) {
                throw new RuntimeException(
                        keyStorePath + " entry \"" + alias + "\" does not contain certificates");
            }

            final PublicKey publicKey = chain[0].getPublicKey();
            return publicKey.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 32-bit fold of the signer certificate DER (FNV-1a 64 -> hi^lo). Must match
     * the native vm_sig_delta computation over the same cert bytes read from the
     * APK v2 signing block. Baked into the VM at protect time.
     */
    public static long getCertificateFold(String keyStorePath, String alias, String password) {
        try {
            final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(new FileInputStream(keyStorePath), password.toCharArray());
            if (alias == null || alias.isEmpty()) {
                final Enumeration<String> aliases = ks.aliases();
                if (aliases != null && aliases.hasMoreElements()) {
                    alias = aliases.nextElement();
                }
            }
            final Certificate[] chain = ks.getCertificateChain(alias);
            if (chain == null || chain.length == 0) {
                throw new RuntimeException(
                        keyStorePath + " entry \"" + alias + "\" does not contain certificates");
            }
            final byte[] der = chain[0].getEncoded();
            long h = 0xcbf29ce484222325L;
            for (byte b : der) {
                h ^= (b & 0xffL);
                h *= 0x100000001b3L;
            }
            return ((h >>> 32) ^ (h & 0xffffffffL)) & 0xffffffffL;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
