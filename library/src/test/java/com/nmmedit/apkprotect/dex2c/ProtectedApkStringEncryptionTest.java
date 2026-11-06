package com.nmmedit.apkprotect.dex2c;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/** Optional end-to-end verifier enabled with NMMP_VERIFY_APK. */
public class ProtectedApkStringEncryptionTest {
    private static final String DECODER_TYPE_PREFIX = "Lclient/wex/internal/NativeBridge$x";
    private static final String LEGACY_DECODER_TYPE = "Lclient/wex/internal/NativeBridge$S;";

    @Test
    public void everyExecutableLiteralUsesDistributedDecoderMesh() throws Exception {
        final String apkPath = System.getenv("NMMP_VERIFY_APK");
        if (apkPath == null || apkPath.isBlank()) return;

        final File apk = new File(apkPath);
        assertTrue("missing APK: " + apk, apk.isFile());
        final LinkedHashMap<String, DexBackedDexFile> dexFiles = new LinkedHashMap<>();

        try (ZipFile zip = new ZipFile(apk)) {
            final List<? extends ZipEntry> dexEntries = zip.stream()
                    .filter(entry -> entry.getName().matches("classes(\\d+)?\\.dex"))
                    .sorted(Comparator.comparing(ZipEntry::getName))
                    .toList();
            for (ZipEntry entry : dexEntries) {
                dexFiles.put(entry.getName(), DexBackedDexFile.fromInputStream(
                        Opcodes.getDefault(),
                        new ByteArrayInputStream(zip.getInputStream(entry).readAllBytes())));
            }
        }

        final Set<String> decoderClasses = new HashSet<>();
        final Set<String> decoderEndpoints = new HashSet<>();
        int legacyDecoderClasses = 0;
        for (DexBackedDexFile dex : dexFiles.values()) {
            for (ClassDef classDef : dex.getClasses()) {
                if (LEGACY_DECODER_TYPE.equals(classDef.getType())) legacyDecoderClasses++;
                if (!classDef.getType().startsWith(DECODER_TYPE_PREFIX)) continue;
                decoderClasses.add(classDef.getType());
                for (Method method : classDef.getMethods()) {
                    if (isDecoderMethod(method)) decoderEndpoints.add(methodIdentity(method));
                }
            }
        }

        assertEquals("legacy single decoder must be absent", 0, legacyDecoderClasses);
        assertEquals(StringDecryptorClassDef.CLASS_COUNT, decoderClasses.size());
        assertEquals(StringDecryptorClassDef.ENDPOINT_COUNT, decoderEndpoints.size());

        int literalCount = 0;
        final Map<String, Integer> endpointUsage = new HashMap<>();
        for (Map.Entry<String, DexBackedDexFile> dexEntry : dexFiles.entrySet()) {
            for (ClassDef classDef : dexEntry.getValue().getClasses()) {
                for (Method method : classDef.getMethods()) {
                    if (method.getImplementation() == null) continue;
                    final ArrayList<Instruction> instructions = new ArrayList<>();
                    method.getImplementation().getInstructions().forEach(instructions::add);
                    for (int i = 0; i < instructions.size(); i++) {
                        final Opcode opcode = instructions.get(i).getOpcode();
                        if (opcode != Opcode.CONST_STRING
                                && opcode != Opcode.CONST_STRING_JUMBO) continue;
                        literalCount++;
                        final String location = identity(dexEntry.getKey(), method);
                        assertTrue(location + " has a trailing unprotected literal",
                                i + 2 < instructions.size());

                        final String encrypted = ((StringReference) ((ReferenceInstruction)
                                instructions.get(i)).getReference()).getString();
                        final Instruction invoke = instructions.get(i + 1);
                        assertTrue(location + " does not call a mesh decoder",
                                invoke.getOpcode() == Opcode.INVOKE_STATIC
                                        || invoke.getOpcode() == Opcode.INVOKE_STATIC_RANGE);
                        final MethodReference decoder = (MethodReference)
                                ((ReferenceInstruction) invoke).getReference();
                        final String endpoint = methodIdentity(decoder);
                        assertTrue(location + " targets an unknown decoder " + endpoint,
                                decoderEndpoints.contains(endpoint));
                        endpointUsage.merge(endpoint, 1, Integer::sum);
                        assertEquals(location, Opcode.MOVE_RESULT_OBJECT,
                                instructions.get(i + 2).getOpcode());
                        assertTrue(location + " has truncated ciphertext", encrypted.length() >= 2);
                    }
                }
            }
        }

        assertTrue("no executable string literals found", literalCount > 1000);
        assertEquals("every generated endpoint must be exercised",
                StringDecryptorClassDef.ENDPOINT_COUNT, endpointUsage.size());
        final int minUsage = endpointUsage.values().stream().min(Integer::compareTo).orElseThrow();
        final int maxUsage = endpointUsage.values().stream().max(Integer::compareTo).orElseThrow();

        final String result = "APK=" + apk.getAbsolutePath() + "\n"
                + "DEX_FILES=" + dexFiles.size() + "\n"
                + "ENCRYPTED_CONST_STRING=" + literalCount + "\n"
                + "UNPROTECTED_CONST_STRING=0\n"
                + "LEGACY_SINGLE_DECODER=0\n"
                + "DECODER_CLASSES=" + decoderClasses.size() + "\n"
                + "DECODER_ENDPOINTS=" + decoderEndpoints.size() + "\n"
                + "USED_DECODER_ENDPOINTS=" + endpointUsage.size() + "\n"
                + "MIN_ENDPOINT_USES=" + minUsage + "\n"
                + "MAX_ENDPOINT_USES=" + maxUsage + "\n";
        final String reportPath = System.getenv("NMMP_VERIFY_REPORT");
        if (reportPath != null && !reportPath.isBlank()) {
            Files.writeString(new File(reportPath).toPath(), result, StandardCharsets.UTF_8);
        }
        System.out.print(result);
    }

    private static boolean isDecoderMethod(Method method) {
        if (method.getImplementation() == null) return false;
        if (!"Ljava/lang/String;".equals(method.getReturnType())) return false;
        if (method.getParameterTypes().size() != 1
                || !"Ljava/lang/String;".contentEquals(method.getParameterTypes().get(0))) return false;
        boolean hasCharLoad = false;
        boolean hasReturn = false;
        for (Instruction instruction : method.getImplementation().getInstructions()) {
            hasCharLoad |= instruction.getOpcode() == Opcode.AGET_CHAR;
            hasReturn |= instruction.getOpcode() == Opcode.RETURN_OBJECT;
        }
        return hasCharLoad && hasReturn;
    }

    private static String methodIdentity(MethodReference method) {
        return method.getDefiningClass() + "->" + method.getName()
                + "(" + String.join("", method.getParameterTypes()) + ")"
                + method.getReturnType();
    }

    private static String identity(String dexName, Method method) {
        return dexName + ": " + method.getDefiningClass() + "->" + method.getName();
    }
}
