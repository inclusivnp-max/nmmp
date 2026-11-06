package com.nmmedit.apkprotect;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedClassDef;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.mcal.apkparser.xml.ManifestParser;
import com.mcal.apkparser.zip.ZipEntry;
import com.mcal.apkparser.zip.ZipFile;
import com.mcal.apkparser.zip.ZipOutputStream;
import com.nmmedit.apkprotect.data.Prefs;
import com.nmmedit.apkprotect.dex2c.Dex2c;
import com.nmmedit.apkprotect.dex2c.DexConfig;
import com.nmmedit.apkprotect.dex2c.DexStringEncryptor;
import com.nmmedit.apkprotect.dex2c.GlobalDexConfig;
import com.nmmedit.apkprotect.dex2c.StringDecryptorClassDef;
import com.nmmedit.apkprotect.dex2c.converter.ClassAnalyzer;
import com.nmmedit.apkprotect.dex2c.converter.instructionrewriter.InstructionRewriter;
import com.nmmedit.apkprotect.dex2c.converter.instructionrewriter.RandomInstructionRewriter;
import com.nmmedit.apkprotect.dex2c.converter.structs.RegisterNativesUtilClassDef;
import com.nmmedit.apkprotect.dex2c.filters.ClassAndMethodFilter;
import com.nmmedit.apkprotect.log.VmpLogger;
import com.nmmedit.apkprotect.util.ApkUtils;
import com.nmmedit.apkprotect.util.CmakeUtils;
import com.nmmedit.apkprotect.util.ElfAntiObjdumpPatcher;
import com.nmmedit.apkprotect.util.FileHelper;
import com.nmmedit.apkprotect.util.ManifestConfuser;
import com.nmmedit.apkprotect.util.ZipHelper;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApkProtect {

    public static final String ANDROID_MANIFEST_XML = "AndroidManifest.xml";
    public static final String ANDROID_APP_APPLICATION = "android.app.Application";
    @Nullable
    public static VmpLogger vmpLogger;
    private final ApkFolders apkFolders;
    private final InstructionRewriter instructionRewriter;
    private final ClassAndMethodFilter filter;
    private final ClassAnalyzer classAnalyzer;

    private ApkProtect(ApkFolders apkFolders,
                       InstructionRewriter instructionRewriter,
                       ClassAndMethodFilter filter,
                       ClassAnalyzer classAnalyzer
    ) {
        this.apkFolders = apkFolders;

        this.instructionRewriter = instructionRewriter;

        this.filter = filter;
        this.classAnalyzer = classAnalyzer;

    }

    //根据apk里文件得到abi，如果没有本地库则返回所有
    private static @NotNull List<String> getAbis(File apk) throws IOException {
        final Pattern pattern = Pattern.compile("lib/(.*)/.*\\.so");
        Set<String> abis = new HashSet<>();
        try (ZipFile zipFile = new ZipFile(apk)) {
            final Enumeration<? extends ZipEntry> entries = zipFile.getEntries();
            while (entries.hasMoreElements()) {
                final ZipEntry entry = entries.nextElement();
                final Matcher matcher = pattern.matcher(entry.getName());
                if (matcher.matches()) {
                    abis.add(matcher.group(1));
                }
            }
            //不支持armeabi，可能还要删除mips相关
            abis.remove("armeabi");
            abis.remove("mips");
            abis.remove("mips64");
            if (abis.isEmpty()) {
                //默认只生成armeabi-v7a
                ArrayList<String> abi = new ArrayList<>();
                if (Prefs.isArm()) {
                    abi.add("armeabi-v7a");
                }
                if (Prefs.isArm64()) {
                    abi.add("arm64-v8a");
                }

                if (Prefs.isX86()) {
                    abi.add("x86");
                }

                if (Prefs.isX64()) {
                    abi.add("x86_64");
                }
                return abi;
            }
        }
        return new ArrayList<>(abis);
    }

    private static @NotNull List<File> getClassesFiles(File apkFile, File zipExtractDir) throws IOException {
        List<File> files = ApkUtils.extractFiles(apkFile, "classes(\\d+)*\\.dex", zipExtractDir);
        //根据classes索引大小排序
        files.sort((file, t1) -> {
            final String numb = file.getName().replace("classes", "").replace(".dex", "");
            final String numb2 = t1.getName().replace("classes", "").replace(".dex", "");
            int n, n2;
            if (numb.isEmpty()) {
                n = 0;
            } else {
                n = Integer.parseInt(numb);
            }
            if (numb2.isEmpty()) {
                n2 = 0;
            } else {
                n2 = Integer.parseInt(numb2);
            }
            return n - n2;
        });
        return files;
    }

    private static @NotNull File dexWriteToFile(DexPool dexPool, int index, @NotNull File dexOutDir) throws IOException {
        if (!dexOutDir.exists()) dexOutDir.mkdirs();

        File outDexFile;
        if (index == 0) {
            outDexFile = new File(dexOutDir, "classes.dex");
        } else {
            outDexFile = new File(dexOutDir, String.format("classes%d.dex", index + 1));
        }
        dexPool.writeTo(new FileDataStore(outDexFile));

        return outDexFile;
    }

    private static List<String> getApplicationClassesFromMainDex(@NotNull GlobalDexConfig globalConfig, String applicationClass) throws IOException {
        final List<String> mainDexClassList = new ArrayList<>();
        String tmpType = classDotNameToType(applicationClass);
        mainDexClassList.add(tmpType);
        for (DexConfig config : globalConfig.getConfigs()) {
            DexBackedDexFile dexFile = DexBackedDexFile.fromInputStream(
                    null,
                    new BufferedInputStream(new FileInputStream(config.getShellDexFile())));
            final Set<? extends DexBackedClassDef> classes = dexFile.getClasses();
            ClassDef classDef;
            while (true) {
                classDef = getClassDefFromType(classes, tmpType);
                if (classDef == null) {
                    break;
                }
                if (classDotNameToType(ANDROID_APP_APPLICATION).equals(classDef.getSuperclass())) {
                    return mainDexClassList;
                }
                tmpType = classDef.getSuperclass();
                mainDexClassList.add(tmpType);
            }
        }
        return mainDexClassList;
    }

    private static @Nullable ClassDef getClassDefFromType(@NotNull Set<? extends ClassDef> classDefSet, String type) {
        for (ClassDef classDef : classDefSet) {
            if (classDef.getType().equals(type)) {
                return classDef;
            }
        }
        return null;
    }

    /**
     * 给处理过的class注入静态初始化方法,同时dex适当拆分防止dex索引异常
     * 不缓存写好的dexpool,每次切换dexpool时马上把失效的dexpool写入文件,减小内存占用
     *
     * @param globalConfig
     * @param mainClassSet
     * @param maxPoolSize
     * @param dexOutDir
     * @return
     * @throws IOException
     */
    public static @NotNull ArrayList<File> injectInstructionAndWriteToFile(@NotNull GlobalDexConfig globalConfig,
                                                                           Set<String> mainClassSet,
                                                                           int maxPoolSize,
                                                                           File dexOutDir
    ) throws IOException {

        final ArrayList<File> dexFiles = new ArrayList<>();
        final List<DexConfig> configs = globalConfig.getConfigs();
        final Opcodes outputOpcodes = outputOpcodes(configs);
        DexPool lastDexPool = new DexPool(outputOpcodes);
        //第一个dex为main dex
        //提前处理主dex里的类
        for (DexConfig config : configs) {

            DexBackedDexFile dexNativeFile = DexBackedDexFile.fromInputStream(
                    null,
                    new BufferedInputStream(new FileInputStream(config.getShellDexFile())));

            for (ClassDef classDef : dexNativeFile.getClasses()) {
                if (mainClassSet.contains(classDef.getType())) {
                    //可能保留的类太多,导超出致dex引用,又没再接收返回的dex而导致丢失class
                    Dex2c.injectCallRegisterNativeInsns(
                            config, lastDexPool, mainClassSet, maxPoolSize, outputOpcodes);
                }
            }
        }

        for (int i = 0; i < configs.size(); i++) {
            DexConfig config = configs.get(i);
            final List<DexPool> retPools = Dex2c.injectCallRegisterNativeInsns(
                    config, lastDexPool, mainClassSet, maxPoolSize, outputOpcodes);
            if (retPools.isEmpty()) {
                final VmpLogger logger = vmpLogger;
                if (logger != null) {
                    logger.error("Dex inject instruction error");
                } else {
                    throw new RuntimeException("Dex inject instruction error");
                }
            }
            if (retPools.size() > 1) {
                for (int k = 0; k < retPools.size() - 1; k++) {
                    final int size = dexFiles.size();
                    final File file = dexWriteToFile(retPools.get(k), size, dexOutDir);
                    dexFiles.add(file);
                }

                lastDexPool = retPools.get(retPools.size() - 1);
                if (i == configs.size() - 1) {
                    final int size = dexFiles.size();
                    final File file = dexWriteToFile(lastDexPool, size, dexOutDir);
                    dexFiles.add(file);
                }
            } else {
                final int size = dexFiles.size();
                final File file = dexWriteToFile(retPools.get(0), size, dexOutDir);
                dexFiles.add(file);


                lastDexPool = new DexPool(outputOpcodes);
            }
        }

        return dexFiles;
    }

    private static @NotNull Opcodes outputOpcodes(@NotNull List<DexConfig> configs)
            throws IOException {
        int highestApi = Opcodes.getDefault().api;
        for (DexConfig config : configs) {
            final DexBackedDexFile dexFile = DexBackedDexFile.fromInputStream(
                    null,
                    new BufferedInputStream(new FileInputStream(config.getShellDexFile())));
            highestApi = Math.max(highestApi, dexFile.getOpcodes().api);
        }
        return Opcodes.forApi(highestApi);
    }

    private static @NotNull byte[] hardenPackagedNativeLibrary(@NotNull ZipFile zipFile,
                                                                @NotNull ZipEntry entry,
                                                                @NotNull File workDir)
            throws IOException {
        final Path hardeningDir = new File(workDir, "input-native-hardening").toPath();
        Files.createDirectories(hardeningDir);
        final Path temporary = Files.createTempFile(hardeningDir, "nmmp-lib-", ".so");
        try {
            try (InputStream input = zipFile.getInputStream(entry)) {
                Files.copy(input, temporary, StandardCopyOption.REPLACE_EXISTING);
            }
            final ElfAntiObjdumpPatcher.Result result =
                    ElfAntiObjdumpPatcher.patch(temporary.toFile());
            final String message = String.format(
                    "ELF anti-objdump (packaged): %s, sections preserved %d, executable flags cleared %d",
                    entry.getName(), result.originalSectionCount(), result.modifiedSectionCount());
            if (vmpLogger != null) {
                vmpLogger.info(message);
            } else {
                System.out.println(message);
            }
            return Files.readAllBytes(temporary);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    /**
     * 复制dex里所有类到新的dex里
     *
     * @param oldDexFile 原dex
     * @param newDex     目标dex
     */
    public static void copyDex(@NotNull DexFile oldDexFile,
                               @NotNull DexPool newDex) {
        for (ClassDef classDef : oldDexFile.getClasses()) {
            newDex.internClass(classDef);
        }
    }

    //在主dex里增加NativeUtil类
    //返回处理后的dex文件
    public static @NotNull File internNativeUtilClassDef(@NotNull File mainDex,
                                                         @NotNull GlobalDexConfig globalConfig,
                                                         @NotNull String libName) throws IOException {
        return internNativeUtilClassDef(
                mainDex, globalConfig, libName, 0x535452494e47564dL);
    }

    public static @NotNull File internNativeUtilClassDef(@NotNull File mainDex,
                                                         @NotNull GlobalDexConfig globalConfig,
                                                         @NotNull String libName,
                                                         long stringSeed) throws IOException {


        DexBackedDexFile mainDexFile = DexBackedDexFile.fromInputStream(
                null,
                new BufferedInputStream(new FileInputStream(mainDex)));

        DexPool newDex = new DexPool(mainDexFile.getOpcodes());


        copyDex(mainDexFile, newDex);

        final ArrayList<String> nativeMethodNames = new ArrayList<>();
        for (DexConfig config : globalConfig.getConfigs()) {
            nativeMethodNames.add(config.getRegisterNativesMethodName());
        }


        final String registerClassName = globalConfig.getConfigs().get(0).getRegisterNativesClassName();
        final DexStringEncryptor stringEncryptor = new DexStringEncryptor(
                stringSeed, registerClassName);
        newDex.internClass(stringEncryptor.rewriteClass(
                new RegisterNativesUtilClassDef("L" + registerClassName + ";",
                        nativeMethodNames, libName)));
        for (ClassDef decoderClass : StringDecryptorClassDef.createAll(
                registerClassName, stringSeed)) {
            newDex.internClass(decoderClass);
        }

        final File injectLoadLib = new File(mainDex.getParent(), "injectLoadLib");
        if (!injectLoadLib.exists()) injectLoadLib.mkdirs();

        final File newFile = new File(injectLoadLib, mainDex.getName());
        newDex.writeTo(new FileDataStore(newFile));

        return newFile;
    }

    @Contract(pure = true)
    private static @NotNull String classDotNameToType(@NotNull String classDotName) {
        return "L" + classDotName.replace('.', '/') + ";";
    }

    public static void printProgress(int percent, String message) {
        final int barWidth = 25;
        int filled = (percent * barWidth) / 100;
        StringBuilder bar = new StringBuilder();
        for (int i = 0; i < barWidth; i++) {
            if (i < filled) bar.append("=");
            else if (i == filled) bar.append(">");
            else bar.append(" ");
        }
        System.out.print(String.format("\r\033[K[%s] %3d%%  %s", bar.toString(), percent, message));
        System.out.flush();
    }

    public void run() throws IOException {
        final File apkFile = apkFolders.getInApk();
        final File zipExtractDir = apkFolders.getZipExtractTempDir();

        try {
            final VmpLogger logger = vmpLogger;
            printProgress(10, "Reading input APK & AndroidManifest.xml...");
            byte[] manifestBytes = ZipHelper.getZipFileContent(apkFile, ANDROID_MANIFEST_XML);
            if (manifestBytes == null) {
                if (logger != null) {
                    logger.warning("Not is apk");
                } else {
                    throw new RuntimeException("Not is apk");
                }
            }
            final long manifestSeed = instructionRewriter instanceof RandomInstructionRewriter
                    ? ((RandomInstructionRewriter) instructionRewriter).getSeed()
                    : 0x4d414e4946455354L;
            final ManifestConfuser.Result manifestResult =
                    ManifestConfuser.confuseDetailed(manifestBytes, manifestSeed);
            manifestBytes = manifestResult.data();
            System.out.printf(Locale.ROOT,
                    "%nManifestConfuser: strings %d -> %d (+%d decoys, %d namespace aliases), "
                            + "attributes shuffled %d across %d elements, line markers rewritten %d%n",
                    manifestResult.originalStrings(), manifestResult.outputStrings(),
                    manifestResult.decoyStrings(), manifestResult.namespaceAliases(),
                    manifestResult.shuffledAttributes(), manifestResult.shuffledElements(),
                    manifestResult.rewrittenLineNumbers());

            printProgress(20, "Generating hardened C++ VM sources...");
            CmakeUtils.generateCSources(apkFolders.getDex2cSrcDir(), instructionRewriter);

            printProgress(30, "Unpacking and analyzing DEX classes...");
            List<File> files = getClassesFiles(apkFile, zipExtractDir);
            if (files.isEmpty()) {
                if (logger != null) {
                    logger.warning("No classes.dex");
                } else {
                    throw new RuntimeException("No classes.dex");
                }
            }
            final ManifestParser parser = new ManifestParser(manifestBytes);
            final String minSdkVersion = parser.getMinSdkVersion();
            int minSdk = 21;
            if (minSdkVersion != null && !minSdkVersion.isEmpty()) {
                minSdk = Integer.parseInt(minSdkVersion);
            }
            classAnalyzer.setMinSdk(minSdk);

            if (minSdk < 23) {
                //todo 加载android5的sdk,以保证能正确分析一些有问题的代码
            }

            for (File file : files) {
                classAnalyzer.loadDexFile(file);
            }

            printProgress(40, "Translating DEX bytecode to C++ & FlowLock splitting...");
            final GlobalDexConfig globalConfig = Dex2c.handleAllDex(files,
                    filter,
                    instructionRewriter,
                    classAnalyzer,
                    apkFolders.getCodeGeneratedDir());

            final Set<String> mainDexClassTypeSet = new HashSet<>();

            printProgress(50, "Injecting JNI native registration callers...");
            final ArrayList<File> outDexFiles = injectInstructionAndWriteToFile(
                    globalConfig,
                    mainDexClassTypeSet,
                    60000,
                    apkFolders.getTempDexDir());

            File mainDex = outDexFiles.get(0);

            final File newManDex = internNativeUtilClassDef(
                    mainDex,
                    globalConfig,
                    Prefs.getNmmpName(),
                    manifestSeed);
            outDexFiles.set(0, newManDex);

            // DEX hashes must cover the exact files that will be packaged.  The
            // native util class is injected before compiling the VM so there is
            // no circular dependency between DEX bytes and native libraries.
            CmakeUtils.writeDexIntegrityConfig(
                    apkFolders.getDex2cSrcDir(), outDexFiles);

            final List<String> abis = getAbis(apkFile);

            printProgress(60, "Compiling native C++ libraries for target ABIs...");
            final Map<String, Map<File, File>> nativeLibs = BuildNativeLib.generateNativeLibs(apkFolders.getOutRootDir(), abis);

            printProgress(80, "Repackaging protected DEX & native libs into APK...");
            final File outputApk = apkFolders.getOutputApk();
            if (outputApk.exists()) {
                outputApk.delete();
            }

            try (ZipFile zipFile = new ZipFile(apkFile)) {
                try (ZipOutputStream zos = new ZipOutputStream(outputApk)) {
                    //add AndroidManifest.xml
                    zos.putNextEntry(ANDROID_MANIFEST_XML);
                    zos.write(manifestBytes);
                    zos.closeEntry();

                    //add classesX.dex
                    for (File file : outDexFiles) {
                        zos.putNextEntry(file.getName());
                        zos.write(FileHelper.readBytes(file));
                        zos.closeEntry();
                    }

                    //add native libs
                    final Set<String> generatedNativeEntries = new HashSet<>();
                    for (Map.Entry<String, Map<File, File>> entry : nativeLibs.entrySet()) {
                        final String abi = entry.getKey();
                        for (File file : entry.getValue().values()) {
                            final String entryName = "lib/" + abi + "/" + file.getName();
                            generatedNativeEntries.add(entryName);
                            zos.putNextEntry(entryName);
                            zos.write(FileHelper.readBytes(file));
                            zos.closeEntry();
                        }
                    }

                    final Pattern regex = Pattern.compile(
                            "classes(\\d)*\\.dex" +
//                                    "|META-INF/.*\\.(RSA|DSA|EC|SF|MF)" +
                                    "|AndroidManifest\\.xml");
                    final Enumeration<ZipEntry> enumeration = zipFile.getEntries();
                    while (enumeration.hasMoreElements()) {
                        final ZipEntry ze = enumeration.nextElement();
                        final String entryName = ze.getName();
                        if (regex.matcher(entryName).matches()) {
                            continue;
                        }
                        if (generatedNativeEntries.contains(entryName)) {
                            continue;
                        }
                        if (entryName.matches("lib/[^/]+/[^/]+\\.so")) {
                            zos.putNextEntry(entryName);
                            zos.write(hardenPackagedNativeLibrary(
                                    zipFile, ze, apkFolders.getOutRootDir()));
                            zos.closeEntry();
                            continue;
                        }
                        zos.copyZipEntry(ze, zipFile);
                    }
                }
            }
        } finally {
            //删除解压缓存目录
            FileHelper.deleteFile(zipExtractDir);
        }
    }

    public static class Builder {
        private final ApkFolders apkFolders;
        private InstructionRewriter instructionRewriter;
        private ClassAndMethodFilter filter;
        private ClassAnalyzer classAnalyzer;


        public Builder(ApkFolders apkFolders) {
            this.apkFolders = apkFolders;
        }

        public Builder setInstructionRewriter(InstructionRewriter instructionRewriter) {
            this.instructionRewriter = instructionRewriter;
            return this;
        }


        public Builder setFilter(ClassAndMethodFilter filter) {
            this.filter = filter;
            return this;
        }

        public Builder setClassAnalyzer(ClassAnalyzer classAnalyzer) {
            this.classAnalyzer = classAnalyzer;
            return this;
        }

        public ApkProtect build() {
            final VmpLogger logger = vmpLogger;
            if (instructionRewriter == null) {
                if (logger != null) {
                    logger.warning("instructionRewriter == null");
                } else {
                    throw new RuntimeException("instructionRewriter == null");
                }
            }
            if (classAnalyzer == null) {
                if (logger != null) {
                    logger.warning("classAnalyzer == null");
                } else {
                    throw new RuntimeException("classAnalyzer == null");
                }
            }
            return new ApkProtect(apkFolders, instructionRewriter, filter, classAnalyzer);
        }

        public void setLogger(@NotNull VmpLogger logger) {
            vmpLogger = logger;
        }
    }
}
