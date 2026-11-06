package com.nmmedit.apkprotect.dex2c;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import org.junit.Test;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class DexStringEncryptorTest {
    private static final String REGISTER_CLASS = "client/wex/internal/NativeBridge";
    private static final long BUILD_SEED = 0x1020304050607080L;

    @Test
    public void meshCipherRoundTripsUnicodeAndVariesByOccurrenceAndBuild() {
        final DexStringEncryptor encryptor = new DexStringEncryptor(BUILD_SEED, REGISTER_CLASS);
        final long methodTag = 0x1122334455667788L;
        final String plain = "ASCII / Привет / 😀 / \u0000";
        final String first = encryptor.encrypt(plain, methodTag, 0);
        final String second = encryptor.encrypt(plain, methodTag, 1);
        final String otherBuild = new DexStringEncryptor(
                BUILD_SEED ^ 0x55aa55aa55aa55aaL, REGISTER_CLASS)
                .encrypt(plain, methodTag, 0);

        assertNotEquals(plain, first);
        assertNotEquals(first, second);
        assertNotEquals(first, otherBuild);
        assertEquals(plain, encryptor.decryptForTest(first, methodTag, 0));
        assertEquals(plain, encryptor.decryptForTest(second, methodTag, 1));

        final char[] tampered = first.toCharArray();
        tampered[Math.max(1, tampered.length / 2)] ^= 1;
        assertThrows(SecurityException.class,
                () -> encryptor.decryptForTest(new String(tampered), methodTag, 0));
    }

    @Test
    public void rewritesLowRegisterLiteralToSelectedMeshEndpoint() {
        final DexStringEncryptor encryptor = new DexStringEncryptor(BUILD_SEED, REGISTER_CLASS);
        final Method original = stringMethod(1, 0, "plain-secret");
        final Method rewritten = encryptor.rewrite(original);
        final List<? extends Instruction> instructions = instructions(rewritten);

        assertEquals(List.of(
                        Opcode.CONST_STRING_JUMBO,
                        Opcode.INVOKE_STATIC,
                        Opcode.MOVE_RESULT_OBJECT,
                        Opcode.RETURN_OBJECT),
                instructions.stream().map(Instruction::getOpcode).toList());
        assertEncryptedLiteralAndEndpoint(encryptor, original, instructions, "plain-secret");
    }

    @Test
    public void usesInvokeRangeForHighStringRegister() {
        final DexStringEncryptor encryptor = new DexStringEncryptor(BUILD_SEED, REGISTER_CLASS);
        final Method original = stringMethod(21, 20, "high-register-secret");
        final Method rewritten = encryptor.rewrite(original);
        final List<? extends Instruction> instructions = instructions(rewritten);

        assertEquals(Opcode.CONST_STRING_JUMBO, instructions.get(0).getOpcode());
        assertEquals(Opcode.INVOKE_STATIC_RANGE, instructions.get(1).getOpcode());
        assertEncryptedLiteralAndEndpoint(
                encryptor, original, instructions, "high-register-secret");
    }

    @Test
    public void selectorUsesEveryEndpointAndNamesChangePerBuild() {
        final DexStringEncryptor encryptor = new DexStringEncryptor(BUILD_SEED, REGISTER_CLASS);
        final Set<String> used = new HashSet<>();
        for (int i = 0; i < 8192; i++) {
            used.add(encryptor.endpointFor(0x100000000L + i, i & 7).identity());
        }

        assertEquals(StringDecryptorClassDef.ENDPOINT_COUNT, used.size());
        assertNotEquals(
                StringDecryptorClassDef.decoderTypes(REGISTER_CLASS, BUILD_SEED),
                StringDecryptorClassDef.decoderTypes(REGISTER_CLASS, BUILD_SEED + 1));
    }

    @Test
    public void generatedDecoderMeshWritesAndReadsAsDexWithoutSharedCore() throws Exception {
        final File dex = File.createTempFile("nmmp-string-decoder-mesh-", ".dex");
        try {
            final DexPool pool = new DexPool(Opcodes.getDefault());
            for (ClassDef classDef : StringDecryptorClassDef.createAll(
                    REGISTER_CLASS, BUILD_SEED)) {
                pool.internClass(classDef);
            }
            pool.writeTo(new FileDataStore(dex));

            final DexBackedDexFile parsed = DexBackedDexFile.fromInputStream(
                    Opcodes.getDefault(),
                    new BufferedInputStream(new FileInputStream(dex)));
            int methodCount = 0;
            final Set<List<Opcode>> loopShapes = new HashSet<>();
            assertEquals(StringDecryptorClassDef.CLASS_COUNT, parsed.getClasses().size());
            for (ClassDef helperClass : parsed.getClasses()) {
                int methodsInClass = 0;
                for (Method decoder : helperClass.getMethods()) {
                    methodsInClass++;
                    methodCount++;
                    final List<Opcode> opcodes = instructions(decoder).stream()
                            .map(Instruction::getOpcode)
                            .toList();
                    loopShapes.add(opcodes);
                    assertTrue(opcodes.contains(Opcode.XOR_INT_2ADDR));
                    assertTrue(opcodes.contains(Opcode.NEW_INSTANCE));
                    assertTrue(opcodes.contains(Opcode.RETURN_OBJECT));
                    for (Instruction instruction : instructions(decoder)) {
                        if (!(instruction instanceof ReferenceInstruction)) continue;
                        final var reference = ((ReferenceInstruction) instruction).getReference();
                        if (reference instanceof MethodReference) {
                            assertFalse(((MethodReference) reference).getDefiningClass()
                                    .startsWith("L" + REGISTER_CLASS + "$x"));
                        }
                    }
                }
                assertEquals(StringDecryptorClassDef.METHODS_PER_CLASS, methodsInClass);
            }
            assertEquals(StringDecryptorClassDef.ENDPOINT_COUNT, methodCount);
            assertEquals("four independent transition bytecode variants", 4, loopShapes.size());
        } finally {
            assertTrue(dex.delete() || !dex.exists());
        }
    }

    private static ImmutableMethod stringMethod(int registerCount, int register, String value) {
        return new ImmutableMethod(
                "Ltest/Strings;",
                "value",
                List.of(),
                "Ljava/lang/String;",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                Set.of(),
                null,
                new ImmutableMethodImplementation(
                        registerCount,
                        List.of(
                                new ImmutableInstruction21c(
                                        Opcode.CONST_STRING,
                                        register,
                                        new ImmutableStringReference(value)),
                                new ImmutableInstruction11x(Opcode.RETURN_OBJECT, register)),
                        List.of(),
                        List.of()));
    }

    private static List<? extends Instruction> instructions(Method method) {
        final ArrayList<Instruction> result = new ArrayList<>();
        method.getImplementation().getInstructions().forEach(result::add);
        return result;
    }

    private static void assertEncryptedLiteralAndEndpoint(
            DexStringEncryptor encryptor,
            Method original,
            List<? extends Instruction> instructions,
            String plain) {
        final long methodTag = DexStringEncryptor.methodTag(original);
        final String encrypted = ((StringReference)
                ((ReferenceInstruction) instructions.get(0)).getReference()).getString();
        assertNotEquals(plain, encrypted);
        assertEquals(plain, encryptor.decryptForTest(encrypted, methodTag, 0));

        final MethodReference decoder = (MethodReference)
                ((ReferenceInstruction) instructions.get(1)).getReference();
        final StringDecryptorClassDef.Endpoint endpoint = encryptor.endpointFor(methodTag, 0);
        assertEquals(endpoint.type, decoder.getDefiningClass());
        assertEquals(endpoint.methodName, decoder.getName());
        assertFalse(encrypted.contains(plain));
    }
}
