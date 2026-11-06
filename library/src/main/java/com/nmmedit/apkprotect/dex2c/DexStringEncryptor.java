package com.nmmedit.apkprotect.dex2c;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.BuilderInstruction;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction3rc;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Set;

/**
 * Replaces executable string literals with per-occurrence ciphertext and routes
 * each call site through one endpoint in a build-specific decoder mesh.
 */
public final class DexStringEncryptor {
    private final long buildSeed;
    private final String registerNativesClassName;
    private final Set<String> decoderTypes;

    public DexStringEncryptor(long buildSeed, @NotNull String registerNativesClassName) {
        this.buildSeed = buildSeed;
        this.registerNativesClassName = registerNativesClassName;
        this.decoderTypes = StringDecryptorClassDef.decoderTypes(
                registerNativesClassName, buildSeed);
    }

    public @NotNull ClassDef rewriteClass(@NotNull ClassDef classDef) {
        if (decoderTypes.contains(classDef.getType())) return classDef;
        final ArrayList<Method> methods = new ArrayList<>();
        for (Method method : classDef.getMethods()) methods.add(rewrite(method));
        return new ImmutableClassDef(
                classDef.getType(),
                classDef.getAccessFlags(),
                classDef.getSuperclass(),
                classDef.getInterfaces(),
                classDef.getSourceFile(),
                classDef.getAnnotations(),
                classDef.getFields(),
                methods);
    }

    public @NotNull Method rewrite(@NotNull Method method) {
        final MethodImplementation implementation = method.getImplementation();
        if (implementation == null || decoderTypes.contains(method.getDefiningClass())) return method;

        boolean hasLiteral = false;
        for (var instruction : implementation.getInstructions()) {
            if (instruction.getOpcode() == Opcode.CONST_STRING
                    || instruction.getOpcode() == Opcode.CONST_STRING_JUMBO) {
                hasLiteral = true;
                break;
            }
        }
        if (!hasLiteral) return method;

        final MutableMethodImplementation mutable = new MutableMethodImplementation(implementation);
        final long methodTag = methodTag(method);
        int index = 0;
        int occurrence = 0;
        while (index < mutable.getInstructions().size()) {
            final BuilderInstruction instruction = mutable.getInstructions().get(index);
            final Opcode opcode = instruction.getOpcode();
            if (opcode != Opcode.CONST_STRING && opcode != Opcode.CONST_STRING_JUMBO) {
                index++;
                continue;
            }

            final int register = ((OneRegisterInstruction) instruction).getRegisterA();
            final String plain = ((StringReference)
                    ((ReferenceInstruction) instruction).getReference()).getString();
            final StringDecryptorClassDef.Endpoint endpoint = endpointFor(methodTag, occurrence);
            final String encrypted = encrypt(plain, methodTag, occurrence, endpoint);
            mutable.replaceInstruction(index, new BuilderInstruction31c(
                    Opcode.CONST_STRING_JUMBO,
                    register,
                    new ImmutableStringReference(encrypted)));

            if (register <= 15) {
                mutable.addInstruction(index + 1, new BuilderInstruction35c(
                        Opcode.INVOKE_STATIC,
                        1,
                        register, 0, 0, 0, 0,
                        endpoint.methodReference()));
            } else {
                mutable.addInstruction(index + 1, new BuilderInstruction3rc(
                        Opcode.INVOKE_STATIC_RANGE,
                        register,
                        1,
                        endpoint.methodReference()));
            }
            mutable.addInstruction(index + 2,
                    new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, register));
            occurrence++;
            index += 3;
        }

        return new ImmutableMethod(
                method.getDefiningClass(),
                method.getName(),
                method.getParameters(),
                method.getReturnType(),
                method.getAccessFlags(),
                method.getAnnotations(),
                method.getHiddenApiRestrictions(),
                mutable);
    }

    public @NotNull String encrypt(@NotNull String plain, long methodTag, int occurrence) {
        return encrypt(plain, methodTag, occurrence, endpointFor(methodTag, occurrence));
    }

    @NotNull String decryptForTest(@NotNull String encrypted, long methodTag, int occurrence) {
        if (encrypted.length() < 2) throw new IllegalArgumentException("truncated encrypted string");
        final StringDecryptorClassDef.Endpoint endpoint = endpointFor(methodTag, occurrence);
        final char[] chars = encrypted.toCharArray();
        int state = chars[0] ^ endpoint.headerMask;
        int checksum = endpoint.checkSeed;
        final int tagIndex = chars.length - 1;
        for (int i = 1; i < tagIndex; i++) {
            state = nextState(state, endpoint);
            chars[i] = (char) (chars[i] ^ state);
            checksum = nextChecksum(checksum, chars[i], endpoint);
        }
        if ((chars[tagIndex] ^ endpoint.tagMask) != checksum) {
            throw new SecurityException("ciphertext integrity mismatch");
        }
        return new String(chars, 1, tagIndex - 1);
    }

    StringDecryptorClassDef.Endpoint endpointFor(long methodTag, int occurrence) {
        return StringDecryptorClassDef.endpointFor(
                registerNativesClassName,
                buildSeed,
                methodTag,
                occurrence);
    }

    private @NotNull String encrypt(@NotNull String plain,
                                    long methodTag,
                                    int occurrence,
                                    StringDecryptorClassDef.Endpoint endpoint) {
        final long mixed = StringDecryptorClassDef.mix64(endpoint.cipherSeed
                ^ methodTag
                ^ (0x9e3779b97f4a7c15L * (occurrence + 1L))
                ^ Integer.toUnsignedLong(plain.hashCode()));
        int state = (int) mixed & 0xffff;
        final char[] encrypted = new char[plain.length() + 2];
        encrypted[0] = (char) (state ^ endpoint.headerMask);
        int checksum = endpoint.checkSeed;
        for (int i = 0; i < plain.length(); i++) {
            state = nextState(state, endpoint);
            encrypted[i + 1] = (char) (plain.charAt(i) ^ state);
            checksum = nextChecksum(checksum, plain.charAt(i), endpoint);
        }
        encrypted[encrypted.length - 1] = (char) (checksum ^ endpoint.tagMask);
        return new String(encrypted);
    }

    private static int nextChecksum(int checksum,
                                    int plainChar,
                                    StringDecryptorClassDef.Endpoint endpoint) {
        return (checksum * endpoint.checkMultiplier + plainChar) & 0xffff;
    }

    private static int nextState(int state, StringDecryptorClassDef.Endpoint endpoint) {
        switch (endpoint.variant) {
            case 0:
                state = state * endpoint.multiplier + endpoint.increment;
                break;
            case 1:
                state = (state + endpoint.increment) * endpoint.multiplier;
                break;
            case 2:
                state = (state * endpoint.multiplier) ^ endpoint.increment;
                break;
            case 3:
                state = (state ^ endpoint.increment) * endpoint.multiplier;
                break;
            default:
                throw new IllegalArgumentException("unknown decoder variant: " + endpoint.variant);
        }
        return state & 0xffff;
    }

    static long methodTag(Method method) {
        long hash = 0xcbf29ce484222325L;
        final String identity = method.getDefiningClass() + "->" + method.getName()
                + "(" + String.join("", method.getParameterTypes()) + ")" + method.getReturnType();
        for (int i = 0; i < identity.length(); i++) {
            hash ^= identity.charAt(i);
            hash *= 0x100000001b3L;
        }
        return hash;
    }
}
