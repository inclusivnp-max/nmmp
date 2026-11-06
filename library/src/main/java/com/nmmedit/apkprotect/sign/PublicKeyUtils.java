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
            try (FileInputStream input = new FileInputStream(keyStorePath)) {
                ks.load(input, password.toCharArray());
            }
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
     * 64-bit FNV-1a fingerprint of the signer certificate DER. The emitter
     * uses it to derive the valid per-build stream material; the fingerprint
     * itself is not emitted as a native comparison constant.
     */
    public static long getCertificateFold(String keyStorePath, String alias, String password) {
        try {
            final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            try (FileInputStream input = new FileInputStream(keyStorePath)) {
                ks.load(input, password.toCharArray());
            }
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
            long fold = 0;
            for (byte b : der) {
                fold = Long.rotateLeft(fold, 7);
                fold ^= (b & 0xffL);
            }
            return fold;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
