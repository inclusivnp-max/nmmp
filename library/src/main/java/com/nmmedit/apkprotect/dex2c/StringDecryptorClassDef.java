package com.nmmedit.apkprotect.dex2c;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction12x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21s;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22b;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22s;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction23x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Generates a build-specific decoder mesh instead of one globally hookable method.
 * Every endpoint owns its bytecode loop and cipher constants; there is no shared
 * Java decode core for an instrumentation tool to intercept once.
 */
public final class StringDecryptorClassDef {
    public static final int CLASS_COUNT = 32;
    public static final int METHODS_PER_CLASS = 4;
    public static final int ENDPOINT_COUNT = CLASS_COUNT * METHODS_PER_CLASS;

    private static final long DEFAULT_SEED = 0x535452494e47564dL;
    private static final long CLASS_DOMAIN = 0x434c4153535f4d58L;
    private static final long METHOD_DOMAIN = 0x4d4554484f445f4dL;
    private static final long ENDPOINT_DOMAIN = 0x454e44504f494e54L;

    private StringDecryptorClassDef() {
    }

    public static @NotNull List<ClassDef> createAll(@NotNull String registerNativesClassName) {
        return createAll(registerNativesClassName, DEFAULT_SEED);
    }

    public static @NotNull List<ClassDef> createAll(@NotNull String registerNativesClassName,
                                                     long buildSeed) {
        final ArrayList<ClassDef> result = new ArrayList<>(CLASS_COUNT);
        for (int classIndex = 0; classIndex < CLASS_COUNT; classIndex++) {
            final String type = typeForClass(registerNativesClassName, buildSeed, classIndex);
            final ArrayList<ImmutableMethod> methods = new ArrayList<>(METHODS_PER_CLASS);
            for (int methodIndex = 0; methodIndex < METHODS_PER_CLASS; methodIndex++) {
                final Endpoint endpoint = endpointAt(
                        registerNativesClassName,
                        buildSeed,
                        classIndex * METHODS_PER_CLASS + methodIndex);
                methods.add(decoderMethod(endpoint));
            }
            result.add(new ImmutableClassDef(
                    type,
                    AccessFlags.PUBLIC.getValue()
                            | AccessFlags.FINAL.getValue()
                            | AccessFlags.SYNTHETIC.getValue(),
                    "Ljava/lang/Object;",
                    Collections.emptyList(),
                    null,
                    Collections.emptySet(),
                    Collections.emptyList(),
                    methods));
        }
        return result;
    }

    static @NotNull Endpoint endpointFor(@NotNull String registerNativesClassName,
                                          long buildSeed,
                                          long methodTag,
                                          int occurrence) {
        final long selected = mix64(buildSeed
                ^ methodTag
                ^ (0x9e3779b97f4a7c15L * (occurrence + 1L))
                ^ 0x53454c4543544f52L);
        return endpointAt(registerNativesClassName, buildSeed, (int) selected & (ENDPOINT_COUNT - 1));
    }

    static @NotNull Set<String> decoderTypes(@NotNull String registerNativesClassName,
                                              long buildSeed) {
        final HashSet<String> result = new HashSet<>(CLASS_COUNT);
        for (int i = 0; i < CLASS_COUNT; i++) {
            result.add(typeForClass(registerNativesClassName, buildSeed, i));
        }
        return result;
    }

    static @NotNull Endpoint endpointAt(@NotNull String registerNativesClassName,
                                         long buildSeed,
                                         int endpointIndex) {
        if (endpointIndex < 0 || endpointIndex >= ENDPOINT_COUNT) {
            throw new IllegalArgumentException("endpoint index out of range: " + endpointIndex);
        }
        final int classIndex = endpointIndex / METHODS_PER_CLASS;
        final int methodIndex = endpointIndex % METHODS_PER_CLASS;
        final long endpointSeed = mix64(buildSeed
                ^ ENDPOINT_DOMAIN
                ^ (0xd6e8feb86659fd93L * (endpointIndex + 1L)));
        return new Endpoint(
                endpointIndex,
                typeForClass(registerNativesClassName, buildSeed, classIndex),
                methodNameFor(buildSeed, endpointIndex, methodIndex),
                endpointSeed,
                derive16(endpointSeed, 0x4845414445524d4cL),
                nontrivialOdd(derive16(endpointSeed, 0x4d554c5449504c59L)),
                derive16(endpointSeed, 0x494e4352454d454eL) | 1,
                (int) mix64(endpointSeed ^ 0x56415249414e5453L) & 3,
                derive16(endpointSeed, 0x434845434b534545L),
                nontrivialOdd(derive16(endpointSeed, 0x434845434b4d554cL)),
                derive16(endpointSeed, 0x5441475f4d41534bL));
    }

    private static @NotNull String typeForClass(@NotNull String registerNativesClassName,
                                                 long buildSeed,
                                                 int classIndex) {
        final String base = normalizeClassName(registerNativesClassName);
        final int token = (int) mix64(buildSeed ^ CLASS_DOMAIN
                ^ (0x94d049bb133111ebL * (classIndex + 1L)));
        return String.format(Locale.ROOT, "L%s$x%08x_%s;",
                base, token, Integer.toString(classIndex, 36));
    }

    private static @NotNull String methodNameFor(long buildSeed,
                                                  int endpointIndex,
                                                  int methodIndex) {
        final int token = (int) mix64(buildSeed ^ METHOD_DOMAIN
                ^ (0xbf58476d1ce4e5b9L * (endpointIndex + 1L)));
        return String.format(Locale.ROOT, "a%08x%s", token, Integer.toString(methodIndex, 36));
    }

    private static @NotNull String normalizeClassName(@NotNull String className) {
        String name = className;
        if (name.startsWith("L")) name = name.substring(1);
        if (name.endsWith(";")) name = name.substring(0, name.length() - 1);
        return name;
    }

    private static ImmutableMethod decoderMethod(Endpoint endpoint) {
        return new ImmutableMethod(
                endpoint.type,
                endpoint.methodName,
                Collections.singletonList(new ImmutableMethodParameter(
                        "Ljava/lang/String;", Collections.emptySet(), null)),
                "Ljava/lang/String;",
                AccessFlags.PUBLIC.getValue()
                        | AccessFlags.STATIC.getValue()
                        | AccessFlags.SYNTHETIC.getValue(),
                Collections.emptySet(),
                Collections.emptySet(),
                decoderImplementation(endpoint));
    }

    private static MutableMethodImplementation decoderImplementation(Endpoint endpoint) {
        final int headerMask = (short) endpoint.headerMask;
        final int multiplier = (short) endpoint.multiplier;
        final int increment = (short) endpoint.increment;
        final int checkSeed = (short) endpoint.checkSeed;
        final int checkMultiplier = (short) endpoint.checkMultiplier;
        final int tagMask = (short) endpoint.tagMask;

        // v0=char[], v1=rolling state/result, v2=index, v3=tag index,
        // v4=temp, p0/v5=rolling integrity checksum after toCharArray().
        final MutableMethodImplementation impl = new MutableMethodImplementation(6);
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_VIRTUAL, 1, 5, 0, 0, 0, 0,
                new ImmutableMethodReference(
                        "Ljava/lang/String;", "toCharArray",
                        Collections.emptyList(), "[C")));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        impl.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 0));
        impl.addInstruction(new BuilderInstruction23x(Opcode.AGET_CHAR, 1, 0, 2));
        impl.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 4, headerMask));
        impl.addInstruction(new BuilderInstruction12x(Opcode.XOR_INT_2ADDR, 1, 4));
        impl.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 1));
        impl.addInstruction(new BuilderInstruction12x(Opcode.ARRAY_LENGTH, 3, 0));
        impl.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 3, 3, -1));
        impl.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 5, checkSeed));
        impl.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        addStateTransition(impl, endpoint.variant, multiplier, increment);
        impl.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_CHAR, 1, 1));
        impl.addInstruction(new BuilderInstruction23x(Opcode.AGET_CHAR, 4, 0, 2));
        impl.addInstruction(new BuilderInstruction12x(Opcode.XOR_INT_2ADDR, 4, 1));
        impl.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_CHAR, 4, 4));
        impl.addInstruction(new BuilderInstruction23x(Opcode.APUT_CHAR, 4, 0, 2));
        impl.addInstruction(new BuilderInstruction22s(
                Opcode.MUL_INT_LIT16, 5, 5, checkMultiplier));
        impl.addInstruction(new BuilderInstruction12x(Opcode.ADD_INT_2ADDR, 5, 4));
        impl.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_CHAR, 5, 5));
        impl.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 2, 1));
        impl.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        impl.addInstruction(new BuilderInstruction23x(Opcode.AGET_CHAR, 4, 0, 3));
        impl.addInstruction(new BuilderInstruction22s(Opcode.XOR_INT_LIT16, 4, 4, tagMask));
        // xor-int/lit16 sign-extends masks >= 0x8000. Normalize back to the
        // unsigned UTF-16 domain before comparing with the rolling checksum.
        impl.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_CHAR, 4, 4));
        // Empty plaintext skips the loop, so the const/16 checksum seed can
        // still be sign-extended here. Canonicalize both comparison operands.
        impl.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_CHAR, 5, 5));
        impl.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        impl.addInstruction(new BuilderInstruction21c(
                Opcode.NEW_INSTANCE, 1, new ImmutableTypeReference("Ljava/lang/SecurityException;")));
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_DIRECT, 1, 1, 0, 0, 0, 0,
                new ImmutableMethodReference(
                        "Ljava/lang/SecurityException;", "<init>",
                        Collections.emptyList(), "V")));
        impl.addInstruction(new BuilderInstruction11x(Opcode.THROW, 1));
        impl.addInstruction(new BuilderInstruction21c(
                Opcode.NEW_INSTANCE, 1, new ImmutableTypeReference("Ljava/lang/String;")));
        impl.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 3, 3, -1));
        impl.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 4, 1));
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_DIRECT, 4, 1, 0, 4, 3, 0,
                new ImmutableMethodReference(
                        "Ljava/lang/String;", "<init>",
                        List.of("[C", "I", "I"), "V")));
        impl.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));

        final Label loop = impl.newLabelForIndex(10);
        final Label end = impl.newLabelForIndex(23);
        final Label valid = impl.newLabelForIndex(31);
        impl.replaceInstruction(10, new BuilderInstruction22t(Opcode.IF_GE, 2, 3, end));
        impl.replaceInstruction(22, new BuilderInstruction10t(Opcode.GOTO, loop));
        impl.replaceInstruction(27, new BuilderInstruction22t(Opcode.IF_EQ, 4, 5, valid));
        return impl;
    }

    private static void addStateTransition(MutableMethodImplementation impl,
                                           int variant,
                                           int multiplier,
                                           int increment) {
        switch (variant) {
            case 0:
                impl.addInstruction(new BuilderInstruction22s(
                        Opcode.MUL_INT_LIT16, 1, 1, multiplier));
                impl.addInstruction(new BuilderInstruction22s(
                        Opcode.ADD_INT_LIT16, 1, 1, increment));
                break;
            case 1:
                impl.addInstruction(new BuilderInstruction22s(
                        Opcode.ADD_INT_LIT16, 1, 1, increment));
                impl.addInstruction(new BuilderInstruction22s(
                        Opcode.MUL_INT_LIT16, 1, 1, multiplier));
                break;
            case 2:
                impl.addInstruction(new BuilderInstruction22s(
                        Opcode.MUL_INT_LIT16, 1, 1, multiplier));
                impl.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, 1, 1, increment));
                break;
            case 3:
                impl.addInstruction(new BuilderInstruction22s(
                        Opcode.XOR_INT_LIT16, 1, 1, increment));
                impl.addInstruction(new BuilderInstruction22s(
                        Opcode.MUL_INT_LIT16, 1, 1, multiplier));
                break;
            default:
                throw new IllegalArgumentException("unknown decoder variant: " + variant);
        }
    }

    private static int nontrivialOdd(int value) {
        final int odd = value | 1;
        return odd == 1 ? 0x6255 : odd;
    }

    private static int derive16(long seed, long domain) {
        return (int) mix64(seed ^ domain) & 0xffff;
    }

    static long mix64(long value) {
        value = (value ^ (value >>> 30)) * 0xbf58476d1ce4e5b9L;
        value = (value ^ (value >>> 27)) * 0x94d049bb133111ebL;
        return value ^ (value >>> 31);
    }

    static final class Endpoint {
        final int index;
        final String type;
        final String methodName;
        final long cipherSeed;
        final int headerMask;
        final int multiplier;
        final int increment;
        final int variant;
        final int checkSeed;
        final int checkMultiplier;
        final int tagMask;

        Endpoint(int index,
                 String type,
                 String methodName,
                 long cipherSeed,
                 int headerMask,
                 int multiplier,
                 int increment,
                 int variant,
                 int checkSeed,
                 int checkMultiplier,
                 int tagMask) {
            this.index = index;
            this.type = type;
            this.methodName = methodName;
            this.cipherSeed = cipherSeed;
            this.headerMask = headerMask;
            this.multiplier = multiplier;
            this.increment = increment;
            this.variant = variant;
            this.checkSeed = checkSeed;
            this.checkMultiplier = checkMultiplier;
            this.tagMask = tagMask;
        }

        ImmutableMethodReference methodReference() {
            return new ImmutableMethodReference(
                    type,
                    methodName,
                    Collections.singletonList("Ljava/lang/String;"),
                    "Ljava/lang/String;");
        }

        String identity() {
            return type + "->" + methodName + "(Ljava/lang/String;)Ljava/lang/String;";
        }
    }
}
