package com.nmmedit.apkprotect.dex2c;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.AnnotationVisibility;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.immutable.ImmutableAnnotation;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableExceptionHandler;
import com.android.tools.smali.dexlib2.immutable.ImmutableTryBlock;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10t;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21t;
import org.junit.Test;

import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class FlowLockPlannerTest {
    private static final String MARKER = "Lclient/wex/annotations/WexFlowLock;";

    @Test
    public void buildsBlocksForConditionalAndGotoEdges() {
        final ImmutableMethod method = method(List.of(
                new ImmutableInstruction21t(Opcode.IF_EQZ, 0, 3),
                new ImmutableInstruction10t(Opcode.GOTO, 1),
                new ImmutableInstruction11x(Opcode.RETURN, 0)
        ));

        final FlowLockPlanner.Plan plan = FlowLockPlanner.createPlan(method, "classes.dex");

        assertArrayEquals(new int[]{0, 2, 3, 4}, plan.starts());
    }

    @Test
    public void rejectsMonitorInstructionsWithMethodIdentity() {
        final ImmutableMethod method = method(List.of(
                new ImmutableInstruction11x(Opcode.MONITOR_ENTER, 0),
                new ImmutableInstruction10x(Opcode.RETURN_VOID)
        ));

        final IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> FlowLockPlanner.createPlan(method, "classes7.dex"));

        assertTrue(error.getMessage().contains("classes7.dex: Ltest/Example;->guard()V"));
        assertTrue(error.getMessage().contains("MONITOR_ENTER"));
    }

    @Test
    public void linearPlanAlignsToInstructionBoundaries() {
        final java.util.ArrayList<com.android.tools.smali.dexlib2.iface.instruction.Instruction> insns =
                new java.util.ArrayList<>();
        for (int i = 0; i < 20; i++) {
            insns.add(new ImmutableInstruction10x(Opcode.NOP));
        }
        insns.add(new ImmutableInstruction21t(Opcode.IF_EQZ, 0, 1));
        insns.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
        final ImmutableMethod method = new ImmutableMethod(
                "Ltest/Example;",
                "plain",
                List.of(),
                "V",
                AccessFlags.PRIVATE.getValue(),
                Set.of(),
                null,
                new ImmutableMethodImplementation(1, insns, List.of(), List.of()));

        final FlowLockPlanner.Plan plan = FlowLockPlanner.createLinearPlan(method, 16);

        assertArrayEquals(new int[]{0, 16, 23}, plan.starts());
        for (int start : plan.starts()) {
            org.junit.Assert.assertTrue(start == 23 || start == 0 || start == 16 || start == 22);
        }
        org.junit.Assert.assertEquals(0, plan.starts()[0]);
        org.junit.Assert.assertEquals(23, plan.starts()[plan.starts().length - 1]);
    }

    @Test
    public void detectsConfiguredMarker() {
        assertTrue(FlowLockPlanner.isMarked(method(List.of(
                new ImmutableInstruction10x(Opcode.RETURN_VOID)
        )), MARKER));
    }

    @Test
    public void alignsFlowBlocksToTryRangeAndHandlerBoundaries() {
        final ImmutableMethod method = new ImmutableMethod(
                "Ltest/Example;",
                "guarded",
                List.of(),
                "V",
                AccessFlags.PRIVATE.getValue(),
                Set.of(new ImmutableAnnotation(AnnotationVisibility.RUNTIME, MARKER, Set.of())),
                null,
                new ImmutableMethodImplementation(
                        1,
                        List.of(
                                new ImmutableInstruction10x(Opcode.NOP),
                                new ImmutableInstruction11x(Opcode.MOVE_EXCEPTION, 0),
                                new ImmutableInstruction10x(Opcode.RETURN_VOID)),
                        List.of(new ImmutableTryBlock(
                                0,
                                1,
                                List.of(new ImmutableExceptionHandler("Ljava/lang/Exception;", 1)))),
                        List.of()));

        final FlowLockPlanner.Plan plan = FlowLockPlanner.createPlan(method, "classes.dex");

        assertArrayEquals(new int[]{0, 1, 3}, plan.starts());
    }

    private static ImmutableMethod method(List<com.android.tools.smali.dexlib2.iface.instruction.Instruction> instructions) {
        return new ImmutableMethod(
                "Ltest/Example;",
                "guard",
                List.of(),
                "V",
                AccessFlags.PRIVATE.getValue(),
                Set.of(new ImmutableAnnotation(AnnotationVisibility.RUNTIME, MARKER, Set.of())),
                null,
                new ImmutableMethodImplementation(1, instructions, List.of(), List.of()));
    }
}
