package com.nmmedit.apkprotect.dex2c.converter;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

public class VmKeyConfigTest {
    private static final long BUILD_SEED = 0x1020304050607080L;
    private static final long EXPECTED_FOLD = 0x412063a021d0a0aaL;

    @Test
    public void validSignerUsesNonzeroBuildMaterial() {
        final VmKeyConfig config = VmKeyConfig.forBuildSeed(BUILD_SEED, EXPECTED_FOLD);

        assertNotEquals(0L, config.getValidRuntimeMaterial());
        assertNotEquals(
                config.getValidRuntimeMaterial(),
                config.deriveRuntimeMaterial(EXPECTED_FOLD ^ 0x55aa55aa55aa55aaL));
        assertNotEquals(config.getValidRuntimeMaterial(), config.getParseFailureMaterial());
    }

    @Test
    public void validSignerDecryptsButDifferentSignerDoesNot() {
        final VmKeyConfig config = VmKeyConfig.forBuildSeed(BUILD_SEED, EXPECTED_FOLD);
        final int seed = 0x1234abcd;
        final int tag = VmKeyConfig.methodTag("Ltest/Guard;->isAllowed(I)Z");
        final int[] plain = {0x0012, 0xabcd, 0x7f01, 0xffff, 0x2040, 0x0100};
        final int[] encrypted = transform(
                plain, config.instructionStream(seed, tag, config.getValidRuntimeMaterial()));

        assertArrayEquals(plain, transform(
                encrypted, config.instructionStream(seed, tag, config.getValidRuntimeMaterial())));

        final long wrongMaterial = config.deriveRuntimeMaterial(EXPECTED_FOLD + 1);
        assertFalse(Arrays.equals(plain, transform(
                encrypted, config.instructionStream(seed, tag, wrongMaterial))));
    }

    @Test
    public void legacyZeroDeltaExtractorNoLongerRecoversInstructions() {
        final VmKeyConfig config = VmKeyConfig.forBuildSeed(BUILD_SEED, EXPECTED_FOLD);
        final int seed = 0x33445566;
        final int tag = VmKeyConfig.methodTag("Ltest/Auth;->valid()Z");
        final int[] plain = {0x0012, 0x000f, 0x0212, 0x1028, 0x000e};
        final int[] encrypted = transform(plain, config.instructionStream(seed, tag));

        assertFalse(Arrays.equals(plain, legacyTransform(encrypted, seed)));
    }

    @Test
    public void metadataStreamRoundTripsAndRejectsWrongSigner() {
        final VmKeyConfig config = VmKeyConfig.forBuildSeed(BUILD_SEED, EXPECTED_FOLD);
        final long nonce = 0x76543210fedcba98L;
        final byte[] plain = "client/wex/internal/FeatureEntitlements\0isAllowed\0(I)Z"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        final byte[] encrypted = plain.clone();
        config.cryptMetadata(encrypted, nonce);
        assertFalse(Arrays.equals(plain, encrypted));

        final byte[] decoded = encrypted.clone();
        config.cryptMetadata(decoded, nonce, config.getValidRuntimeMaterial());
        assertArrayEquals(plain, decoded);

        final byte[] wrong = encrypted.clone();
        config.cryptMetadata(wrong, nonce, config.deriveRuntimeMaterial(EXPECTED_FOLD ^ 1));
        assertFalse(Arrays.equals(plain, wrong));
    }

    @Test
    public void nativeConstantsStayAlignedWithEmitter() {
        assertEquals(0x6a09e667f3bcc909L, VmKeyConfig.DISABLED_FOLD);
        assertEquals(0xbb67ae8584caa73bL, VmKeyConfig.FAILURE_FOLD);
        assertEquals(0xd6e8feb86659fd93L, VmKeyConfig.ZERO_KEY_FALLBACK);
    }

    @Test
    public void methodIdentityChangesStream() {
        final VmKeyConfig config = VmKeyConfig.forBuildSeed(BUILD_SEED, EXPECTED_FOLD);
        final VmKeyConfig.InstructionStream first = config.instructionStream(
                7, VmKeyConfig.methodTag("Lx;->a()V"));
        final VmKeyConfig.InstructionStream second = config.instructionStream(
                7, VmKeyConfig.methodTag("Lx;->b()V"));

        assertNotNull(first);
        assertNotEquals(first.nextMask(), second.nextMask());
    }

    private static int[] transform(int[] input, VmKeyConfig.InstructionStream stream) {
        final int[] output = new int[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = (input[i] ^ stream.nextMask()) & 0xffff;
        }
        return output;
    }

    private static int[] legacyTransform(int[] input, int seed) {
        final int[] output = new int[input.length];
        int state = seed;
        for (int i = 0; i < input.length; i++) {
            state = state * 1664525 + 1013904223;
            output[i] = (input[i] ^ ((state >>> 16) & 0xffff)) & 0xffff;
        }
        return output;
    }
}
