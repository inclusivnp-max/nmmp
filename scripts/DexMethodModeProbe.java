import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.InputStream;
import java.util.Comparator;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class DexMethodModeProbe {
    private static final int ACC_NATIVE = 0x100;

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("usage: DexMethodModeProbe APK CLASS_DESCRIPTOR METHOD_NAME");
            System.exit(64);
        }
        File apk = new File(args[0]);
        String wantedClass = args[1];
        String wantedMethod = args[2];
        try (ZipFile zip = new ZipFile(apk)) {
            List<? extends ZipEntry> dexEntries = zip.stream()
                    .filter(e -> e.getName().matches("classes(?:[0-9]+)?\\.dex"))
                    .sorted(Comparator.comparing(ZipEntry::getName))
                    .toList();
            for (ZipEntry entry : dexEntries) {
                try (InputStream raw = zip.getInputStream(entry);
                     BufferedInputStream input = new BufferedInputStream(raw)) {
                    DexBackedDexFile dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), input);
                    for (ClassDef classDef : dex.getClasses()) {
                        if (!wantedClass.equals(classDef.getType())) continue;
                        for (Method method : classDef.getMethods()) {
                            if (!wantedMethod.equals(method.getName())) continue;
                            boolean nativeMethod = (method.getAccessFlags() & ACC_NATIVE) != 0;
                            String mode = nativeMethod ? "native" : "dex-code";
                            System.out.printf(
                                    "FOUND apk=%s dex=%s class=%s method=%s mode=%s%n",
                                    apk.getName(), entry.getName(), wantedClass, wantedMethod, mode);
                            System.exit(nativeMethod ? 2 : 0);
                        }
                        System.out.printf("MISSING apk=%s class=%s method=%s%n",
                                apk.getName(), wantedClass, wantedMethod);
                        System.exit(3);
                    }
                }
            }
        }
        System.out.printf("MISSING apk=%s class=%s%n", apk.getName(), wantedClass);
        System.exit(4);
    }
}
