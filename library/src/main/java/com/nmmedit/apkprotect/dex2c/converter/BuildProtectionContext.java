package com.nmmedit.apkprotect.dex2c.converter;

import org.jetbrains.annotations.NotNull;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * One 256-bit protection context per build. Every randomized emitter consumes
 * a domain-separated deterministic stream from this context, so a build is
 * reproducible when a test seed is supplied while production builds retain the
 * full entropy of {@link SecureRandom}.
 */
public final class BuildProtectionContext {
    public static final int SEED_BYTES = 32;
    private static final byte[] EXTRACT_SALT =
            "nmmp-build-context-v2".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LONG_SEED_DOMAIN =
            "nmmp-deterministic-long-seed-v2".getBytes(StandardCharsets.US_ASCII);

    private final byte[] seed;
    private final byte[] prk;

    private BuildProtectionContext(byte[] seed) {
        if (seed.length != SEED_BYTES) {
            throw new IllegalArgumentException("Build seed must contain exactly 32 bytes");
        }
        this.seed = seed.clone();
        this.prk = hmac(EXTRACT_SALT, this.seed);
    }

    public static @NotNull BuildProtectionContext random() {
        final byte[] seed = new byte[SEED_BYTES];
        new SecureRandom().nextBytes(seed);
        return new BuildProtectionContext(seed);
    }

    public static @NotNull BuildProtectionContext fromSeed(byte @NotNull [] seed) {
        return new BuildProtectionContext(seed);
    }

    /** Compatibility entry point for deterministic unit tests and old callers. */
    public static @NotNull BuildProtectionContext fromLong(long seed) {
        try {
            final MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(LONG_SEED_DOMAIN);
            sha256.update(ByteBuffer.allocate(Long.BYTES)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putLong(seed)
                    .array());
            return new BuildProtectionContext(sha256.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    public byte @NotNull [] deriveBytes(@NotNull String domain, int length) {
        return deriveBytes(domain, new byte[0], length);
    }

    /** HKDF-expand style domain separation backed by HMAC-SHA-256. */
    public byte @NotNull [] deriveBytes(@NotNull String domain,
                                         byte @NotNull [] info,
                                         int length) {
        if (length < 0 || length > 255 * 32) {
            throw new IllegalArgumentException("Derived length is outside HKDF bounds: " + length);
        }
        final byte[] domainBytes = domain.getBytes(StandardCharsets.UTF_8);
        final byte[] output = new byte[length];
        byte[] previous = new byte[0];
        int written = 0;
        int counter = 1;
        while (written < length) {
            final byte[] input = new byte[previous.length + domainBytes.length + 1 + info.length + 1];
            int offset = 0;
            System.arraycopy(previous, 0, input, offset, previous.length);
            offset += previous.length;
            System.arraycopy(domainBytes, 0, input, offset, domainBytes.length);
            offset += domainBytes.length;
            input[offset++] = 0;
            System.arraycopy(info, 0, input, offset, info.length);
            offset += info.length;
            input[offset] = (byte) counter++;
            final byte[] block = hmac(prk, input);
            final int count = Math.min(block.length, length - written);
            System.arraycopy(block, 0, output, written, count);
            written += count;
            Arrays.fill(previous, (byte) 0);
            previous = block;
            Arrays.fill(input, (byte) 0);
        }
        Arrays.fill(previous, (byte) 0);
        return output;
    }

    public long deriveLong(@NotNull String domain, @NotNull String identity) {
        final byte[] value = deriveBytes(domain,
                identity.getBytes(StandardCharsets.UTF_8), Long.BYTES);
        final long result = ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN).getLong();
        Arrays.fill(value, (byte) 0);
        return result;
    }

    public int deriveInt(@NotNull String domain, @NotNull String identity) {
        final byte[] value = deriveBytes(domain,
                identity.getBytes(StandardCharsets.UTF_8), Integer.BYTES);
        final int result = ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN).getInt();
        Arrays.fill(value, (byte) 0);
        return result;
    }

    public @NotNull DeterministicStream stream(@NotNull String domain) {
        return stream(domain, new byte[0]);
    }

    public @NotNull DeterministicStream stream(@NotNull String domain,
                                                byte @NotNull [] info) {
        return new DeterministicStream(deriveBytes(domain, info, 32));
    }

    public <T> void shuffle(@NotNull List<T> values, @NotNull String domain) {
        final DeterministicStream stream = stream(domain);
        for (int i = values.size() - 1; i > 0; i--) {
            final int j = stream.nextInt(i + 1);
            final T value = values.get(i);
            values.set(i, values.get(j));
            values.set(j, value);
        }
        stream.destroy();
    }

    /** A non-secret identifier suitable for audit correlation, never the seed. */
    public @NotNull String fingerprint() {
        final byte[] value = deriveBytes("build-fingerprint", 8);
        final StringBuilder out = new StringBuilder(value.length * 2);
        for (byte b : value) out.append(String.format("%02x", b & 0xff));
        Arrays.fill(value, (byte) 0);
        return out.toString();
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    public static final class DeterministicStream {
        private final byte[] key;
        private long counter;
        private byte[] block = new byte[0];
        private int blockOffset;

        private DeterministicStream(byte[] key) {
            this.key = key;
        }

        public void nextBytes(byte @NotNull [] output) {
            int offset = 0;
            while (offset < output.length) {
                if (blockOffset == block.length) refill();
                final int count = Math.min(block.length - blockOffset, output.length - offset);
                System.arraycopy(block, blockOffset, output, offset, count);
                blockOffset += count;
                offset += count;
            }
        }

        public int nextInt() {
            final byte[] bytes = new byte[Integer.BYTES];
            nextBytes(bytes);
            final int value = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
            Arrays.fill(bytes, (byte) 0);
            return value;
        }

        public long nextLong() {
            final byte[] bytes = new byte[Long.BYTES];
            nextBytes(bytes);
            final long value = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getLong();
            Arrays.fill(bytes, (byte) 0);
            return value;
        }

        public int nextInt(int bound) {
            if (bound <= 0) throw new IllegalArgumentException("bound must be positive");
            final long range = 1L << 32;
            final long limit = range - range % bound;
            long candidate;
            do {
                candidate = Integer.toUnsignedLong(nextInt());
            } while (candidate >= limit);
            return (int) (candidate % bound);
        }

        public void destroy() {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(block, (byte) 0);
            counter = 0;
            blockOffset = 0;
        }

        private void refill() {
            Arrays.fill(block, (byte) 0);
            final byte[] input = ByteBuffer.allocate(Long.BYTES)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putLong(counter++)
                    .array();
            block = hmac(key, input);
            Arrays.fill(input, (byte) 0);
            blockOffset = 0;
        }
    }
}
