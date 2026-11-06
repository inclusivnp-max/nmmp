package com.nmmedit.apkprotect.dex2c.converter;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VmTemplateHardeningTest {
    @Test
    public void signatureTemplateIsFailClosedWithoutExpectedFoldConstant() throws Exception {
        final String source = zipEntry("vm/SigCheck.cpp");

        assertFalse(source.contains("EXPECTED_SIG_FOLD"));
        assertFalse(source.contains("vm_sig_delta"));
        assertFalse(source.contains("Fail-open"));
        assertFalse(source.contains("0xDEADBEEFCAFEBABEULL"));
        assertTrue(source.contains("derive_binding_key(FAILURE_FOLD)"));
        assertTrue(source.contains("derive_binding_key(DISABLED_FOLD)"));
        assertTrue(source.contains("0x6a09e667f3bcc909ULL"));
        assertTrue(source.contains("0xbb67ae8584caa73bULL"));
        assertTrue(source.contains("0xd6e8feb86659fd93ULL"));
        assertTrue(source.contains("0xbf58476d1ce4e5b9ULL"));
        assertTrue(source.contains("SIG_STATUS_PARSE_FAILED"));
        assertTrue(source.contains("7u /*SIGENABLED*/"));
        assertTrue(source.contains("find_base_apk_from_self"));
        assertTrue(source.contains("apk_from_dladdr"));
        assertTrue(source.contains("apk_from_native_lib"));
        assertTrue(source.contains("sc_pread(fd, buf, 22, eocd_off)"));
        assertFalse(source.contains("sc_pread(fd, buf, 24, eocd_off)"));
    }

    @Test
    public void integrityTemplatesNeverHashOnTheJniCallerThread() throws Exception {
        final String generated = zipEntry("GeneratedIntegrity.c");
        final String nativeElf = zipEntry("vm/Integrity.cpp");
        final String dex = zipEntry("vm/DexIntegrity.cpp");

        assertTrue(generated.contains("pthread_create"));
        assertTrue(nativeElf.contains("pthread_create"));
        assertTrue(dex.contains("pthread_create"));
        assertFalse(functionTail(generated, "u8 nmmp_integrity_delta(void)")
                .contains("vm_verify_module("));
        assertFalse(functionTail(nativeElf, "u8 vm_integrity_delta(void)")
                .contains("vm_verify_module("));
        assertFalse(functionTail(dex, "u8 vm_dex_integrity_delta(void)")
                .contains("hash_dex_entry("));
    }

    @Test
    public void vmTemplateUsesAuthenticatedPerMethodBlobs() throws Exception {
        final String header = zipEntry("vm/include/vm.h");
        final String interpreter = zipEntry("vm/InterpC-portable.cpp");
        final String crypto = zipEntry("vm/Crypto.cpp");

        assertTrue(header.contains("#define vm_aead_open WX_API_0"));
        assertTrue(header.contains("u8 contextTag;"));
        assertTrue(header.contains("u8 siteMaterial;"));
        assertTrue(header.contains("const u8 integrityDelta;"));
        assertTrue(interpreter.contains("vm_aead_open(dst, src"));
        assertFalse(interpreter.contains("vm_stream_init"));
        assertFalse(interpreter.contains("void vm_decode_bytes"));
        assertTrue(crypto.contains("ChaCha20") || crypto.contains("chacha_block"));
        assertTrue(crypto.contains("HmacSha256"));
        assertTrue(crypto.contains("constant_time_equal_16"));
        assertTrue(crypto.contains("vm_integrity_delta()"));
        assertTrue(crypto.contains("vm_dex_integrity_delta()"));
    }

    @Test
    public void distributedIntegrityCoversGeneratedNativeAndDex() throws Exception {
        final String generated = zipEntry("GeneratedIntegrity.c");
        final String dex = zipEntry("vm/DexIntegrity.cpp");
        final String rootCmake = zipEntry("CMakeLists.txt");
        final String vmCmake = zipEntry("vm/CMakeLists.txt");

        assertTrue(generated.contains("nmmp_integrity_delta"));
        assertTrue(generated.contains("vm_verify_module"));
        assertTrue(dex.contains("EXPECTED_DEX_COUNT"));
        assertTrue(dex.contains("hash_deflated"));
        assertTrue(dex.contains("vm_dex_integrity_delta"));
        assertTrue(rootCmake.contains("-Wl,-z,relro"));
        assertTrue(rootCmake.contains("-Wl,-z,now"));
        assertTrue(rootCmake.contains("--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map"));
        assertTrue(vmCmake.contains("-fstack-protector-strong"));
        assertTrue(vmCmake.contains("-D_FORTIFY_SOURCE=2"));
        assertTrue(vmCmake.contains("target_link_libraries(${LIBNMMVM_NAME} log dl z)"));
    }

    @Test
    public void runtimeGuardDoesNotTreatAnEmulatorAsRuntimeTampering() throws Exception {
        final String source = zipEntry("vm/Guard.cpp");
        final int start = source.indexOf("bool rt_tamper_detected()");
        final int end = source.indexOf("\n}\n", start);

        assertTrue(start >= 0);
        assertTrue(end > start);
        final String detector = source.substring(start, end);
        assertTrue(detector.contains("audit_address_space()"));
        assertTrue(detector.contains("audit_thread_names()"));
        assertTrue(detector.contains("vm_integrity_delta()"));
        assertFalse(detector.contains("check_emulator_devices()"));
        assertFalse(detector.contains("check_hypervisor_timing()"));
        assertTrue(source.contains("if (rt_tamper_detected())"));
    }

    private static String zipEntry(String wanted) throws IOException {
        final InputStream resource = VmTemplateHardeningTest.class.getResourceAsStream("/vmsrc.zip");
        if (resource == null) throw new IOException("missing /vmsrc.zip");
        try (ZipInputStream zip = new ZipInputStream(resource)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (!wanted.equals(entry.getName())) continue;
                final ByteArrayOutputStream out = new ByteArrayOutputStream();
                zip.transferTo(out);
                return out.toString(StandardCharsets.UTF_8);
            }
        }
        throw new IOException("missing zip entry: " + wanted);
    }

    private static String functionTail(String source, String signature) {
        final int start = source.lastIndexOf(signature);
        assertTrue("missing function: " + signature, start >= 0);
        return source.substring(start);
    }
}
