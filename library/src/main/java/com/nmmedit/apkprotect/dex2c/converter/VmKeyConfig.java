package com.nmmedit.apkprotect.dex2c.converter;

import com.nmmedit.apkprotect.dex2c.converter.instructionrewriter.InstructionRewriter;
import com.nmmedit.apkprotect.dex2c.converter.instructionrewriter.RandomInstructionRewriter;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Per-build key schedule shared by the Java emitters and the native VM template.
 * All material remains recoverable from a sufficiently analyzed client; this
 * schedule is intended to remove trivial zero-key and repeating-XOR recovery.
 */
public final class VmKeyConfig {
    private static final long BUILD_DOMAIN = 0x4f1bbcdc6762c5d3L;
    private static final long MIX_GAMMA = 0x9e3779b97f4a7c15L;
    // Keep in sync with vm/SigCheck.cpp. The native VM must derive the same
    // runtime material as this emitter; a different schedule decrypts class
    // names to garbage and crashes in NativeBridge.classes*Init0.
    static final long DISABLED_FOLD = 0x6a09e667f3bcc909L;
    static final long FAILURE_FOLD = 0xbb67ae8584caa73bL;
    static final long ZERO_KEY_FALLBACK = 0xd6e8feb86659fd93L;
    private static final long METHOD_DOMAIN = 0x3c6ef372fe94f82bL;
    private static final long STRING_DOMAIN = 0xa54ff53a5f1d36f1L;

    private final boolean signatureBindingEnabled;
    private final long expectedSignerFold;
    private final long[] salts;
    private final long validRuntimeMaterial;
    private final BuildProtectionContext protectionContext;

    private VmKeyConfig(boolean signatureBindingEnabled,
                        long expectedSignerFold,
                        long[] salts,
                        BuildProtectionContext protectionContext) {
        this.signatureBindingEnabled = signatureBindingEnabled;
        this.expectedSignerFold = expectedSignerFold;
        this.salts = salts;
        this.protectionContext = protectionContext;
        this.validRuntimeMaterial = deriveBindingKey(
                signatureBindingEnabled ? expectedSignerFold : DISABLED_FOLD);
    }

    public static @NotNull VmKeyConfig create(@NotNull InstructionRewriter rewriter,
                                               long expectedSignerFold) {
        final BuildProtectionContext context;
        if (rewriter instanceof RandomInstructionRewriter) {
            context = ((RandomInstructionRewriter) rewriter).getProtectionContext();
        } else {
            context = BuildProtectionContext.fromLong(0x243f6a8885a308d3L);
        }
        return forContext(context, expectedSignerFold);
    }

    static @NotNull VmKeyConfig forBuildSeed(long buildSeed, long expectedSignerFold) {
        return forContext(BuildProtectionContext.fromLong(buildSeed), expectedSignerFold);
    }

    static @NotNull VmKeyConfig forContext(@NotNull BuildProtectionContext context,
                                            long expectedSignerFold) {
        final long[] salts = new long[4];
        for (int i = 0; i < salts.length; i++) {
            salts[i] = context.deriveLong("vm-signer-salt-v2",
                    Long.toUnsignedString(expectedSignerFold) + ":" + i);
        }
        return new VmKeyConfig(expectedSignerFold != 0, expectedSignerFold, salts, context);
    }

    public boolean isSignatureBindingEnabled() {
        return signatureBindingEnabled;
    }

    public long getExpectedSignerFold() {
        return expectedSignerFold;
    }

    public long getSalt(int index) {
        return salts[index];
    }

    public long getValidRuntimeMaterial() {
        return validRuntimeMaterial;
    }

    byte @NotNull [] getAeadRootKey() {
        final ByteBuffer bytes = ByteBuffer.allocate(salts.length * Long.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN);
        for (long salt : salts) bytes.putLong(salt);
        return bytes.array();
    }

    public long methodTag64(@NotNull String identity) {
        return protectionContext.deriveLong("vm-method-tag-v2", identity);
    }

    public long siteCookie(@NotNull String identity) {
        return protectionContext.deriveLong("vm-integrity-site-v2", identity);
    }

    public int blockKey(@NotNull String identity, int blockIndex) {
        return protectionContext.deriveInt("vm-legacy-block-key-v2",
                identity + ":" + blockIndex);
    }

    public byte @NotNull [] nonce(@NotNull String domain,
                                   @NotNull String identity) {
        return protectionContext.deriveBytes("vm-nonce/" + domain,
                identity.getBytes(StandardCharsets.UTF_8), VmAead.NONCE_BYTES);
    }

    public @NotNull String nativeSymbol(@NotNull String identity) {
        final byte[] value = protectionContext.deriveBytes("jni-native-symbol-v2",
                identity.getBytes(StandardCharsets.UTF_8), 12);
        final StringBuilder symbol = new StringBuilder("wxm_");
        for (byte b : value) symbol.append(String.format("%02x", b & 0xff));
        Arrays.fill(value, (byte) 0);
        return symbol.toString();
    }

    public @NotNull BuildProtectionContext getProtectionContext() {
        return protectionContext;
    }

    long deriveRuntimeMaterial(long runtimeSignerFold) {
        return deriveBindingKey(runtimeSignerFold);
    }

    long getParseFailureMaterial() {
        return deriveBindingKey(FAILURE_FOLD);
    }

    private long deriveBindingKey(long signerFold) {
        long value = mix64(signerFold ^ salts[0]);
        value = mix64(value + salts[1]);
        value ^= Long.rotateLeft(salts[2], 17);
        value = mix64(value + salts[3]);
        return value != 0 ? value : ZERO_KEY_FALLBACK;
    }

    public @NotNull InstructionStream instructionStream(int methodSeed, int methodTag) {
        return instructionStream(methodSeed, methodTag, validRuntimeMaterial);
    }

    @NotNull InstructionStream instructionStream(int methodSeed,
                                                  int methodTag,
                                                  long runtimeMaterial) {
        final long pair = Integer.toUnsignedLong(methodSeed)
                | (Integer.toUnsignedLong(methodTag) << 32);
        final long mixed = mix64(runtimeMaterial ^ pair ^ METHOD_DOMAIN);
        final int state = methodSeed
                ^ (int) mixed
                ^ Integer.rotateLeft(methodTag, 7)
                ^ 0xa341316c;
        final int extra = (int) (mixed >>> 32)
                ^ methodTag
                ^ Integer.rotateLeft(methodSeed, 13)
                ^ 0xc8013ea4;
        return new InstructionStream(state, extra);
    }

    public void cryptMetadata(byte[] data, long nonce) {
        cryptMetadata(data, nonce, validRuntimeMaterial);
    }

    void cryptMetadata(byte[] data, long nonce, long runtimeMaterial) {
        long state = mix64(runtimeMaterial ^ nonce ^ STRING_DOMAIN);
        for (int i = 0; i < data.length; i++) {
            if ((i & 7) == 0) {
                state = mix64(state + MIX_GAMMA + (i >>> 3));
            }
            data[i] ^= (byte) (state >>> ((i & 7) * 8));
        }
    }

    public static int methodTag(@NotNull String identity) {
        int hash = 0x811c9dc5;
        for (byte value : identity.getBytes(StandardCharsets.UTF_8)) {
            hash ^= value & 0xff;
            hash *= 0x01000193;
        }
        return hash;
    }

    static long mix64(long value) {
        value = (value ^ (value >>> 30)) * 0xbf58476d1ce4e5b9L;
        value = (value ^ (value >>> 27)) * 0x94d049bb133111ebL;
        return value ^ (value >>> 31);
    }

    public static final class InstructionStream {
        private int state;
        private int extra;

        private InstructionStream(int state, int extra) {
            this.state = state;
            this.extra = extra;
        }

        public int nextMask() {
            state = state * 1664525 + 1013904223;
            extra = extra * 747796405 + 0xac564b05;
            return ((state >>> 16) ^ (extra >>> 16)) & 0xffff;
        }
    }
}
