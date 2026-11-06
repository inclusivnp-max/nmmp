package com.nmmedit.apkprotect.dex2c.converter.structs;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import org.junit.Test;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class RegisterNativesUtilClassDefTest {

    @Test
    public void nativeRegistrationMethodsKeepIntegerClassIndexInSerializedDex() throws Exception {
        final String type = "Lclient/wex/internal/NativeBridge;";
        final String methodName = "classes2_part1Init0";
        final File dexFile = File.createTempFile("nmmp-native-bridge-", ".dex");
        final Opcodes opcodes = Opcodes.forApi(28);
        final DexPool pool = new DexPool(opcodes);
        pool.internClass(new RegisterNativesUtilClassDef(
                type, List.of(methodName), "nmmp"));
        pool.writeTo(new FileDataStore(dexFile));

        final DexBackedDexFile dex = DexBackedDexFile.fromInputStream(
                opcodes,
                new BufferedInputStream(new FileInputStream(dexFile)));
        ClassDef bridge = null;
        for (ClassDef classDef : dex.getClasses()) {
            if (type.equals(classDef.getType())) {
                bridge = classDef;
                break;
            }
        }
        assertNotNull(bridge);

        Method init = null;
        for (Method method : bridge.getMethods()) {
            if (methodName.equals(method.getName())) {
                init = method;
                break;
            }
        }
        assertNotNull(init);
        assertEquals(List.of("I"), init.getParameterTypes());
        assertEquals("V", init.getReturnType());
        assertEquals(true, dexFile.delete() || !dexFile.exists());
    }
}
