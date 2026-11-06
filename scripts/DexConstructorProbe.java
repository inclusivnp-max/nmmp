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

public final class DexConstructorProbe {
    private static final int ACC_PUBLIC = 0x1;

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: DexConstructorProbe APK CLASS_DESCRIPTOR");
            System.exit(64);
        }
        File apk = new File(args[0]);
        String wanted = args[1];
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
                        if (!wanted.equals(classDef.getType())) continue;
                        for (Method method : classDef.getMethods()) {
                            if ("<init>".equals(method.getName())
                                    && method.getParameterTypes().isEmpty()
                                    && "V".equals(method.getReturnType())
                                    && (method.getAccessFlags() & ACC_PUBLIC) != 0) {
                                System.out.printf(
                                        "FOUND apk=%s dex=%s class=%s constructor=public-non-arg%n",
                                        apk.getName(), entry.getName(), wanted);
                                System.exit(0);
                            }
                        }
                        System.out.printf(
                                "FOUND apk=%s dex=%s class=%s constructor=<missing-public-non-arg>%n",
                                apk.getName(), entry.getName(), wanted);
                        System.exit(2);
                    }
                }
            }
        }
        System.out.printf("MISSING apk=%s class=%s%n", apk.getName(), wanted);
        System.exit(3);
    }
}
