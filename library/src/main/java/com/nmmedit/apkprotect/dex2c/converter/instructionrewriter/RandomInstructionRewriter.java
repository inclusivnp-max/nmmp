package com.nmmedit.apkprotect.dex2c.converter.instructionrewriter;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import org.jetbrains.annotations.NotNull;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Random;

/**
 * Shuffles the VM opcode numbering per build so the interpreter's
 * opcode -> handler mapping differs every time.
 * <p>
 * Fixes over the original:
 * - a single seeded RNG instead of {@code new Random()} inside the loop
 *   (reproducible builds + unbiased distribution);
 * - a proper Fisher-Yates shuffle;
 * - the seed is exposed as a build key that later stages (e.g. bytecode
 *   encryption) can bind to.
 * <p>
 * Invariants preserved from the original:
 * - NOP stays at slot 0 (alignment / padding nops are 0x0000);
 * - originally-unused opcode slots stay null;
 * - the permutation is a bijection over the real (non-odex, non-NOP) opcodes,
 *   so {@link InstructionRewriter#generateConfig} still emits a consistent VM.
 */
public class RandomInstructionRewriter extends InstructionRewriter {
    private final List<Opcode> opcodeList = new ArrayList<>(256);
    private final EnumMap<Opcode, Integer> opcodeMap = new EnumMap<>(Opcode.class);
    private final long seed;

    public RandomInstructionRewriter() {
        this(new SecureRandom().nextLong());
    }

    public RandomInstructionRewriter(long seed) {
        //虚拟机使用39版本的opcode,所以这里需要使用同样版本
        super(Opcodes.forDexVersion(39));
        this.seed = seed;
        final Random random = new Random(seed);

        // Build the default layout, and collect the shuffle pool together with
        // the slots those opcodes may occupy (every real, non-NOP opcode).
        final List<Opcode> pool = new ArrayList<>();
        final List<Integer> targetSlots = new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            final Opcode opcode = opcodes.getOpcodeByValue(i);
            opcodeList.add(opcode);
            if (opcode != null && opcode != Opcode.NOP) {//只处理dex指令,忽略odex
                pool.add(opcode);
                targetSlots.add(i);
            }
        }

        // Fisher-Yates on the pool with one seeded RNG: unbiased and reproducible.
        for (int i = pool.size() - 1; i > 0; i--) {
            final int j = random.nextInt(i + 1);
            Collections.swap(pool, i, j);
        }

        // Place the shuffled opcodes back onto the same set of real slots.
        for (int k = 0; k < targetSlots.size(); k++) {
            opcodeList.set(targetSlots.get(k), pool.get(k));
        }

        for (int i = 0; i < opcodeList.size(); i++) {
            final Opcode opcode = opcodeList.get(i);
            if (opcode != null) opcodeMap.put(opcode, i);
        }
    }

    /**
     * Per-build seed of the opcode permutation. Deterministic: the same seed
     * reproduces the same VM, and it can key later hardening stages.
     */
    public long getSeed() {
        return seed;
    }

    @Override
    public int replaceOpcode(Opcode opcode) {
        return opcodeMap.get(opcode);
    }

    @NotNull
    @Override
    protected List<Opcode> getOpcodeList() {
        return opcodeList;
    }
}
