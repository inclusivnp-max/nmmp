import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.Annotation;
import com.android.tools.smali.dexlib2.iface.AnnotationElement;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.value.ArrayEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.EncodedValue;
import com.android.tools.smali.dexlib2.iface.value.StringEncodedValue;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class DexSignatureProbe {
    private static final String SIGNATURE = "Ldalvik/annotation/Signature;";

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: DexSignatureProbe APK CLASS_DESCRIPTOR");
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
                        List<String> parts = new ArrayList<>();
                        for (Annotation annotation : classDef.getAnnotations()) {
                            if (!SIGNATURE.equals(annotation.getType())) continue;
                            for (AnnotationElement element : annotation.getElements()) {
                                EncodedValue value = element.getValue();
                                if (value instanceof ArrayEncodedValue array) {
                                    for (EncodedValue item : array.getValue()) {
                                        if (item instanceof StringEncodedValue string) {
                                            parts.add(string.getValue());
                                        }
                                    }
                                }
                            }
                        }
                        String signature = String.join("", parts);
                        System.out.printf("FOUND apk=%s dex=%s class=%s signature=%s%n",
                                apk.getName(), entry.getName(), wanted,
                                signature.isEmpty() ? "<missing>" : signature);
                        System.exit(signature.isEmpty() ? 2 : 0);
                    }
                }
            }
        }
        System.out.printf("MISSING apk=%s class=%s%n", apk.getName(), wanted);
        System.exit(3);
    }
}
