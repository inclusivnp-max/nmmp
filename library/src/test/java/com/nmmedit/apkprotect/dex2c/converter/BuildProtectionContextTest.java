package com.nmmedit.apkprotect.dex2c.converter;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class BuildProtectionContextTest {
    @Test
    public void sameSeedAndDomainAreReproducible() {
        final byte[] seed = new byte[BuildProtectionContext.SEED_BYTES];
        for (int i = 0; i < seed.length; i++) seed[i] = (byte) (i * 7 + 3);
        final BuildProtectionContext first = BuildProtectionContext.fromSeed(seed);
        final BuildProtectionContext second = BuildProtectionContext.fromSeed(seed);

        assertArrayEquals(first.deriveBytes("opcode", 96), second.deriveBytes("opcode", 96));
        assertEquals(first.deriveLong("method", "Lx;->a()V"),
                second.deriveLong("method", "Lx;->a()V"));
        assertEquals(first.fingerprint(), second.fingerprint());
    }

    @Test
    public void domainsAndAllSeedBytesAffectOutput() {
        final byte[] firstSeed = new byte[BuildProtectionContext.SEED_BYTES];
        final byte[] secondSeed = firstSeed.clone();
        secondSeed[31] = 1;
        final BuildProtectionContext first = BuildProtectionContext.fromSeed(firstSeed);
        final BuildProtectionContext second = BuildProtectionContext.fromSeed(secondSeed);

        assertFalse(Arrays.equals(first.deriveBytes("opcode", 32),
                first.deriveBytes("jni", 32)));
        assertFalse(Arrays.equals(first.deriveBytes("opcode", 32),
                second.deriveBytes("opcode", 32)));
    }

    @Test
    public void deterministicStreamProducesUnbiasedRangeAndStableShuffle() {
        final BuildProtectionContext context = BuildProtectionContext.fromLong(0x123456789abcdef0L);
        final BuildProtectionContext.DeterministicStream stream = context.stream("range-test");
        final boolean[] seen = new boolean[17];
        for (int i = 0; i < 10_000; i++) {
            final int value = stream.nextInt(seen.length);
            assertTrue(value >= 0 && value < seen.length);
            seen[value] = true;
        }
        stream.destroy();
        for (boolean value : seen) assertTrue(value);

        final List<Integer> first = new ArrayList<>();
        final List<Integer> second = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            first.add(i);
            second.add(i);
        }
        context.shuffle(first, "registration-order");
        BuildProtectionContext.fromLong(0x123456789abcdef0L)
                .shuffle(second, "registration-order");
        assertEquals(first, second);
        assertNotEquals(List.copyOf(java.util.stream.IntStream.range(0, 100)
                .boxed().toList()), first);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsShortSeed() {
        BuildProtectionContext.fromSeed(new byte[31]);
    }
}
