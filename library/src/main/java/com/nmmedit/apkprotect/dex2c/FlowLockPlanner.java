package com.nmmedit.apkprotect.dex2c;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.iface.Annotation;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public final class FlowLockPlanner {
    private static final Set<Opcode> UNSUPPORTED = Set.of(
            Opcode.PACKED_SWITCH,
            Opcode.SPARSE_SWITCH,
            Opcode.FILL_ARRAY_DATA,
            Opcode.PACKED_SWITCH_PAYLOAD,
            Opcode.SPARSE_SWITCH_PAYLOAD,
            Opcode.ARRAY_PAYLOAD,
            Opcode.MONITOR_ENTER,
            Opcode.MONITOR_EXIT,
            Opcode.INVOKE_CUSTOM,
            Opcode.INVOKE_CUSTOM_RANGE,
            Opcode.INVOKE_POLYMORPHIC,
            Opcode.INVOKE_POLYMORPHIC_RANGE,
            Opcode.CONST_METHOD_HANDLE,
            Opcode.CONST_METHOD_TYPE
    );

    private FlowLockPlanner() {
    }

    public static boolean isMarked(@NotNull Method method, String annotationType) {
        if (annotationType == null) return false;
        for (Annotation annotation : method.getAnnotations()) {
            if (annotationType.equals(annotation.getType())) return true;
        }
        return false;
    }

    public static final int DEFAULT_CHUNK_WORDS = 16;

    public static boolean canUseLinearBlocks(@NotNull Method method) {
        final MethodImplementation implementation = method.getImplementation();
        if (implementation == null) return false;
        if (implementation.getTryBlocks().iterator().hasNext()) return false;
        for (Instruction instruction : implementation.getInstructions()) {
            final Opcode opcode = instruction.getOpcode();
            if (opcode.format.isPayloadFormat
                    || opcode == Opcode.PACKED_SWITCH
                    || opcode == Opcode.SPARSE_SWITCH
                    || opcode == Opcode.FILL_ARRAY_DATA) {
                return false;
            }
        }
        return true;
    }

    /**
     * Windows of about {@code chunkWords} code units, always aligned to
     * instruction boundaries. Splitting mid-instruction leaves FETCH() reading
     * the still-encrypted next block and the interpreter spins.
     */
    public static @NotNull Plan createLinearPlan(@NotNull Method method, int chunkWords) {
        final MethodImplementation implementation = method.getImplementation();
        if (implementation == null) {
            throw new IllegalArgumentException("empty implementation");
        }
        final int chunk = Math.max(1, chunkWords);
        final ArrayList<Integer> starts = new ArrayList<>();
        starts.add(0);
        int address = 0;
        int blockStart = 0;
        for (Instruction instruction : implementation.getInstructions()) {
            final int width = instruction.getCodeUnits();
            if (address > blockStart && (address - blockStart) >= chunk) {
                starts.add(address);
                blockStart = address;
            }
            address += width;
        }
        if (address == 0) {
            throw new IllegalArgumentException("empty implementation");
        }
        starts.add(address);
        return new Plan(starts.stream().mapToInt(Integer::intValue).toArray(), address);
    }

    public static @NotNull Plan createPlan(@NotNull Method method, @NotNull String dexFileName) {
        final MethodImplementation implementation = method.getImplementation();
        if (implementation == null) {
            throw invalid(dexFileName, method, "method has no implementation");
        }
        final List<Entry> instructions = new ArrayList<>();
        final TreeSet<Integer> boundaries = new TreeSet<>();
        boundaries.add(0);
        int address = 0;
        for (Instruction instruction : implementation.getInstructions()) {
            final Opcode opcode = instruction.getOpcode();
            final String opcodeName = opcode.name();
            if (UNSUPPORTED.contains(opcode)
                    || opcodeName.contains("QUICK")
                    || opcodeName.contains("VOLATILE")
                    || opcodeName.contains("NO_BARRIER")) {
                throw invalid(dexFileName, method,
                        "unsupported opcode " + opcodeName + " at code unit " + address);
            }
            final int width = instruction.getCodeUnits();
            instructions.add(new Entry(address, width, opcode, instruction));
            address += width;
        }
        if (address == 0) {
            throw invalid(dexFileName, method, "empty implementation");
        }

        final TreeSet<Integer> instructionAddresses = new TreeSet<>();
        for (Entry entry : instructions) instructionAddresses.add(entry.address);
        instructionAddresses.add(address);

        for (TryBlock<? extends ExceptionHandler> tryBlock : implementation.getTryBlocks()) {
            final int start = tryBlock.getStartCodeAddress();
            final int end = start + tryBlock.getCodeUnitCount();
            if (!instructionAddresses.contains(start) || !instructionAddresses.contains(end) || start >= end) {
                throw invalid(dexFileName, method,
                        "invalid try range " + start + ".." + end);
            }
            boundaries.add(start);
            boundaries.add(end);
            for (ExceptionHandler handler : tryBlock.getExceptionHandlers()) {
                final int target = handler.getHandlerCodeAddress();
                if (!instructionAddresses.contains(target) || target == address) {
                    throw invalid(dexFileName, method,
                            "invalid exception handler target " + target);
                }
                boundaries.add(target);
            }
        }

        for (Entry entry : instructions) {
            final int next = entry.address + entry.width;
            final String name = entry.opcode.name();
            if (entry.opcode.format.isPayloadFormat) {
                throw invalid(dexFileName, method,
                        "payload opcode " + name + " at code unit " + entry.address);
            }
            if (name.startsWith("IF_") || name.startsWith("GOTO")) {
                if (!(entry.value instanceof OffsetInstruction offsetInstruction)) {
                    throw invalid(dexFileName, method, "branch without an offset at code unit " + entry.address);
                }
                final int target = entry.address + offsetInstruction.getCodeOffset();
                if (!instructionAddresses.contains(target) || target == address) {
                    throw invalid(dexFileName, method,
                            "invalid branch target " + target + " at code unit " + entry.address);
                }
                boundaries.add(target);
                if (name.startsWith("IF_") && next < address) boundaries.add(next);
            } else if (isTerminal(name) && next < address) {
                boundaries.add(next);
            }
        }
        boundaries.add(address);

        final int[] starts = boundaries.stream().mapToInt(Integer::intValue).toArray();
        return new Plan(starts, address);
    }

    private static boolean isTerminal(String opcodeName) {
        return opcodeName.startsWith("RETURN") || "THROW".equals(opcodeName);
    }

    private static IllegalArgumentException invalid(String dexFileName, Method method, String reason) {
        return new IllegalArgumentException("FlowLock rejected " + dexFileName + ": "
                + method.getDefiningClass() + "->" + method.getName() + "("
                + String.join("", method.getParameterTypes()) + ")" + method.getReturnType()
                + ": " + reason);
    }

    private record Entry(int address, int width, Opcode opcode, Instruction value) {
    }

    public record Plan(int[] starts, int instructionCount) {
        public int blockCount() {
            return starts.length - 1;
        }
    }
}
