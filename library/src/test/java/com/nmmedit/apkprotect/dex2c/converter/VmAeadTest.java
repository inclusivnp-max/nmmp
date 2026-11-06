package com.nmmedit.apkprotect.dex2c.converter;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.Assert.*;

public class VmAeadTest {
    private static final long BUILD_SEED = 0x1020304050607080L;
    private static final long SIGNER_FOLD = 0x8877665544332211L;

    @Test
    public void roundTripAndDeterministicFixture() throws Exception {
        final VmKeyConfig config = VmKeyConfig.forBuildSeed(BUILD_SEED, SIGNER_FOLD);
        final byte[] plain = "authenticated VM bytecode fixture\0\1\2"
                .getBytes(StandardCharsets.UTF_8);
        final long context = config.methodTag64("Ltest/Auth;->check(Ljava/lang/String;)Z");
        final long site = config.siteCookie("Ltest/Auth;->check(Ljava/lang/String;)Z");
        final byte[] nonce = config.nonce("instructions",
                "Ltest/Auth;->check(Ljava/lang/String;)Z");

        final VmAead.Sealed first = VmAead.seal(config, plain,
                VmAead.DOMAIN_INSTRUCTIONS, context, nonce, site);
        final VmAead.Sealed second = VmAead.seal(config, plain,
                VmAead.DOMAIN_INSTRUCTIONS, context, nonce, site);

        assertArrayEquals(first.ciphertext(), second.ciphertext());
        assertArrayEquals(first.tag(), second.tag());
        assertArrayEquals(plain, VmAead.openForTest(config, first,
                VmAead.DOMAIN_INSTRUCTIONS, context, site));
        assertFalse(Arrays.equals(plain, first.ciphertext()));
        assertEquals(VmAead.NONCE_BYTES, first.nonce().length);
        assertEquals(VmAead.TAG_BYTES, first.tag().length);
    }

    @Test
    public void authenticatesCiphertextTagDomainAndSite() throws Exception {
        final VmKeyConfig config = VmKeyConfig.forBuildSeed(BUILD_SEED, SIGNER_FOLD);
        final byte[] plain = new byte[513];
        for (int i = 0; i < plain.length; i++) plain[i] = (byte) (i * 29 + 11);
        final long context = config.methodTag64("Ltest/Core;->run([B)I");
        final long site = config.siteCookie("Ltest/Core;->run([B)I");
        final VmAead.Sealed sealed = VmAead.seal(config, plain,
                VmAead.DOMAIN_INSTRUCTIONS, context,
                config.nonce("instructions", "Ltest/Core;->run([B)I"), site);

        assertRejected(config, tamperCiphertext(sealed), VmAead.DOMAIN_INSTRUCTIONS, context, site);
        assertRejected(config, tamperTag(sealed), VmAead.DOMAIN_INSTRUCTIONS, context, site);
        assertRejected(config, sealed, VmAead.DOMAIN_TRIES, context, site);
        assertRejected(config, sealed, VmAead.DOMAIN_INSTRUCTIONS, context, site ^ 1L);
    }

    @Test
    public void buildAndMethodDiversificationChangesBlobs() {
        final VmKeyConfig first = VmKeyConfig.forBuildSeed(BUILD_SEED, SIGNER_FOLD);
        final VmKeyConfig second = VmKeyConfig.forBuildSeed(BUILD_SEED + 1, SIGNER_FOLD);
        final byte[] plain = new byte[64];
        final String identity = "Ltest/Feature;->enabled()Z";

        final VmAead.Sealed a = VmAead.seal(first, plain, VmAead.DOMAIN_INSTRUCTIONS,
                first.methodTag64(identity), first.nonce("instructions", identity),
                first.siteCookie(identity));
        final VmAead.Sealed b = VmAead.seal(second, plain, VmAead.DOMAIN_INSTRUCTIONS,
                second.methodTag64(identity), second.nonce("instructions", identity),
                second.siteCookie(identity));
        final String other = identity + ":other";
        final VmAead.Sealed c = VmAead.seal(first, plain, VmAead.DOMAIN_INSTRUCTIONS,
                first.methodTag64(other), first.nonce("instructions", other),
                first.siteCookie(other));

        assertFalse(Arrays.equals(a.ciphertext(), b.ciphertext()));
        assertFalse(Arrays.equals(a.tag(), b.tag()));
        assertFalse(Arrays.equals(a.ciphertext(), c.ciphertext()));
    }

    private static VmAead.Sealed tamperCiphertext(VmAead.Sealed sealed) throws Exception {
        final byte[] ciphertext = sealed.ciphertext();
        ciphertext[ciphertext.length / 2] ^= 0x40;
        return construct(ciphertext, sealed.tag(), sealed.nonce());
    }

    private static VmAead.Sealed tamperTag(VmAead.Sealed sealed) throws Exception {
        final byte[] tag = sealed.tag();
        tag[3] ^= 1;
        return construct(sealed.ciphertext(), tag, sealed.nonce());
    }

    private static VmAead.Sealed construct(byte[] ciphertext, byte[] tag, byte[] nonce)
            throws Exception {
        final var constructor = VmAead.Sealed.class.getDeclaredConstructor(
                byte[].class, byte[].class, byte[].class);
        constructor.setAccessible(true);
        return constructor.newInstance(ciphertext, tag, nonce);
    }

    private static void assertRejected(VmKeyConfig config,
                                       VmAead.Sealed sealed,
                                       int domain,
                                       long context,
                                       long site) {
        try {
            VmAead.openForTest(config, sealed, domain, context, site);
            fail("Tampered VM blob was accepted");
        } catch (GeneralSecurityException expected) {
            assertEquals("VM blob authentication failed", expected.getMessage());
        }
    }
}
