package com.nmmedit.apkprotect.dex2c;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.util.MethodUtil;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.google.common.collect.HashMultimap;
import com.nmmedit.apkprotect.data.Prefs;
import com.nmmedit.apkprotect.dex2c.converter.ClassAnalyzer;
import com.nmmedit.apkprotect.dex2c.converter.JniCodeGenerator;
import com.nmmedit.apkprotect.dex2c.converter.instructionrewriter.InstructionRewriter;
import com.nmmedit.apkprotect.dex2c.converter.instructionrewriter.RandomInstructionRewriter;
import com.nmmedit.apkprotect.dex2c.converter.structs.MethodConverter;
import com.nmmedit.apkprotect.dex2c.converter.structs.MyClassDef;
import com.nmmedit.apkprotect.dex2c.converter.structs.RegisterNativesCallerClassDef;
import com.nmmedit.apkprotect.dex2c.filters.ClassAndMethodFilter;
import com.nmmedit.apkprotect.util.Pair;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class Dex2c {

    public static final String LANDROID_APP_APPLICATION = "Landroid/app/Application;";
    private static final int STRING_ENCRYPTION_DEX_HEADROOM = 60000;

    private Dex2c() {
    }

    /**
     * 处理多个dex文件
     *
     * @param dexFiles dex文件列表
     * @param outDir   生成c文件等输出目录
     * @return 输出结果配置
     * @throws IOException
     */
    public static @NotNull GlobalDexConfig handleAllDex(@NotNull List<File> dexFiles,
                                                        @NotNull ClassAndMethodFilter filter,
                                                        @NotNull InstructionRewriter instructionRewriter,
                                                        @NotNull ClassAnalyzer classAnalyzer,
                                                        @NotNull File outDir) throws IOException {
        if (!outDir.exists()) outDir.mkdirs();
        final GlobalDexConfig globalConfig = new GlobalDexConfig(outDir);

        for (File file : partitionDexFiles(dexFiles, outDir, STRING_ENCRYPTION_DEX_HEADROOM)) {
            final DexConfig config = handleDex(file, filter, classAnalyzer, instructionRewriter, outDir);

            //不需要给外部
            config.setShellMethods(null);

            globalConfig.addDexConfig(config);
        }
        globalConfig.generateJniInitCode();
        return globalConfig;
    }

    /**
     * Leaves headroom for the decoder reference and the extra encrypted string IDs.
     * Large input DEX files are split only at class boundaries; the later packaging
     * stage is already multidex-aware and merges/splits these shell chunks again.
     */
    private static @NotNull List<File> partitionDexFiles(@NotNull List<File> dexFiles,
                                                          @NotNull File outDir,
                                                          int maxPoolSize) throws IOException {
        final ArrayList<File> result = new ArrayList<>();
        final File chunkDir = new File(outDir, ".string-dex-chunks");

        for (File dexFile : dexFiles) {
            final DexBackedDexFile dex = DexBackedDexFile.fromInputStream(
                    null,
                    new BufferedInputStream(new FileInputStream(dexFile)));
            final Opcodes inputOpcodes = dex.getOpcodes();
            final ArrayList<ClassDef> chunk = new ArrayList<>();
            DexPool probe = new DexPool(inputOpcodes);
            int part = 0;

            for (ClassDef classDef : dex.getClasses()) {
                probe.internClass(classDef);
                if (probe.hasOverflowed(maxPoolSize) && !chunk.isEmpty()) {
                    if (!chunkDir.exists() && !chunkDir.mkdirs()) {
                        throw new IOException("Cannot create DEX chunk directory: " + chunkDir);
                    }
                    result.add(writeDexChunk(
                            chunk, chunkDir, dexFile.getName(), ++part, inputOpcodes));
                    chunk.clear();
                    probe = new DexPool(inputOpcodes);
                    probe.internClass(classDef);
                }
                chunk.add(classDef);
            }

            if (part == 0) {
                result.add(dexFile);
            } else if (!chunk.isEmpty()) {
                result.add(writeDexChunk(
                        chunk, chunkDir, dexFile.getName(), ++part, inputOpcodes));
            }
        }
        return result;
    }

    private static @NotNull File writeDexChunk(@NotNull List<ClassDef> classes,
                                                @NotNull File chunkDir,
                                                @NotNull String originalName,
                                                int part,
                                                @NotNull Opcodes opcodes) throws IOException {
        final int extension = originalName.lastIndexOf('.');
        final String baseName = extension < 0 ? originalName : originalName.substring(0, extension);
        final File output = new File(chunkDir, baseName + "_part" + part + ".dex");
        final DexPool pool = new DexPool(opcodes);
        for (ClassDef classDef : classes) pool.internClass(classDef);
        pool.writeTo(new FileDataStore(output));
        return output;
    }

    /**
     * 处理单个dex文件
     */
    public static @NotNull DexConfig handleDex(@NotNull File dexFile,
                                               @NotNull ClassAndMethodFilter filter,
                                               @NotNull ClassAnalyzer classAnalyzer,
                                               @NotNull InstructionRewriter instructionRewriter,
                                               @NotNull File outDir) throws IOException {
        return handleDex(new BufferedInputStream(new FileInputStream(dexFile)),
                dexFile.getName(),
                filter,
                classAnalyzer,
                instructionRewriter,
                outDir);
    }

    public static @NotNull DexConfig handleModuleDex(@NotNull File dexFile,
                                                     @NotNull ClassAndMethodFilter filter,
                                                     @NotNull ClassAnalyzer classAnalyzer,
                                                     @NotNull InstructionRewriter instructionRewriter,
                                                     @NotNull File outDir) throws IOException {
        final GlobalDexConfig globalDexConfig = new GlobalDexConfig(outDir);
        final DexConfig dexConfig = handleDex(dexFile, filter, classAnalyzer, instructionRewriter, outDir);
        globalDexConfig.addDexConfig(dexConfig);

        globalDexConfig.generateJniInitCode();
        return dexConfig;
    }

    /**
     * 处理单个dex流
     */
    public static @NotNull DexConfig handleDex(@NotNull InputStream dex,
                                               @NotNull String dexFileName,
                                               @NotNull ClassAndMethodFilter filter,
                                               @NotNull ClassAnalyzer classAnalyzer,
                                               @NotNull InstructionRewriter instructionRewriter,
                                               @NotNull File outDir) throws IOException {
        if (!outDir.exists()) outDir.mkdirs();
        DexConfig config = splitDex(
                dex, dexFileName, filter, classAnalyzer, instructionRewriter, outDir);


        final DexBackedDexFile nativeImplDexFile = DexBackedDexFile.fromInputStream(null,
                new BufferedInputStream(new FileInputStream(config.getImplDexFile())));

        //根据符号dex生成c代码
        try (FileWriter nativeCodeWriter = new FileWriter(config.getNativeFunctionsFile());
             FileWriter resolverWriter = new FileWriter(config.getResolverFile());
        ) {
            JniCodeGenerator codeGenerator = new JniCodeGenerator(nativeImplDexFile,
                    classAnalyzer,
                    instructionRewriter,
                    filter.getFlowLockAnnotationType());

            codeGenerator.generate(
                    config,
                    resolverWriter,
                    nativeCodeWriter
            );
            config.setResult(codeGenerator);
        }

        return config;
    }

    //分割dex产生两个dex,一个为壳dex,一个为实现dex,壳dex将会打包进apk,实现dex会被转换为c代码
    private static @NotNull DexConfig splitDex(@NotNull InputStream dex,
                                               @NotNull String dexFileName,
                                               @NotNull ClassAndMethodFilter filter,
                                               @NotNull ClassAnalyzer classAnalyzer,
                                               @NotNull InstructionRewriter instructionRewriter,
                                               @NotNull File outDir) throws IOException {
        DexBackedDexFile originDexFile = DexBackedDexFile.fromInputStream(
                null,
                dex);

        //把方法变为本地方法,用它替换掉原本的dex
        DexPool shellDexPool = new DexPool(originDexFile.getOpcodes());

        DexPool nativeImplDexPool = new DexPool(originDexFile.getOpcodes());

        final String flowLockAnnotationType = filter.getFlowLockAnnotationType();
        final MethodConverter methodConverter = new MethodConverter(classAnalyzer, flowLockAnnotationType);
        final long stringSeed = instructionRewriter instanceof RandomInstructionRewriter
                ? ((RandomInstructionRewriter) instructionRewriter).getSeed()
                : 0x535452494e47564dL;
        final DexStringEncryptor stringEncryptor = new DexStringEncryptor(
                stringSeed,
                Prefs.getRegisterNativesClassName());

        HashMultimap<String, List<? extends Method>> shellMethods = HashMultimap.create();

        for (final ClassDef classDef : originDexFile.getClasses()) {
            if (classDef.getType().equals(flowLockAnnotationType)) {
                continue;
            }
            final boolean acceptedClass = filter.acceptClass(classDef);
            if (acceptedClass) {
                final ArrayList<Method> shellDirectMethods = new ArrayList<>();
                final ArrayList<Method> shellVirtualMethods = new ArrayList<>();

                final ArrayList<Method> implDirectMethods = new ArrayList<>();
                final ArrayList<Method> implVirtualMethods = new ArrayList<>();
                boolean flowLockedClass = false;

                // 处理所有需要转换的方法
                for (Method method : classDef.getMethods()) {
                    final boolean flowLocked = FlowLockPlanner.isMarked(method, flowLockAnnotationType);
                    flowLockedClass |= flowLocked;
                    final boolean acceptedMethod = filter.acceptMethod(method);
                    final boolean unsupportedInterfaceMember = isUnconvertibleInterfaceMember(classDef, method);
                    if (flowLocked && !acceptedMethod) {
                        throw flowLockRejected(dexFileName, method, "method is excluded by protection rules");
                    }
                    if (flowLocked && unsupportedInterfaceMember) {
                        throw flowLockRejected(dexFileName, method, "interface default methods are not supported");
                    }
                    if (acceptedMethod
                        // 有直接调用jna方法的指令,则不能进行native化
                        // 感觉很少会发生,默认就把这个判断注释掉了,谁需要再去掉注释
//                            && !classAnalyzer.hasCallJnaMethod(method)
                        && !unsupportedInterfaceMember
                    ) {
                        if (flowLocked) {
                            FlowLockPlanner.createPlan(method, dexFileName);
                        }
                        final Pair<List<? extends Method>, Method> pair = methodConverter.convert(method);
                        // 转换后可能出现变为多个方法
                        final ArrayList<Method> encryptedShellMethods = new ArrayList<>(pair.first.size());
                        for (Method shellMethod : pair.first) {
                            encryptedShellMethods.add(stringEncryptor.rewrite(shellMethod));
                        }
                        addMethods(shellDirectMethods, shellVirtualMethods, encryptedShellMethods);

                        //记录当前类，所有需要被修改的方法
                        shellMethods.put(classDef.getType(), encryptedShellMethods);

                        //只有一个具体实现
                        addMethod(implDirectMethods, implVirtualMethods, pair.second);
                    } else {
                        //不需要进行处理
                        addMethod(shellDirectMethods, shellVirtualMethods, stringEncryptor.rewrite(method));
                    }
                }

                //把需要转换的方法设为native
                shellDexPool.internClass(new MyClassDef(
                        classDef, shellDirectMethods, shellVirtualMethods, flowLockedClass));
                //收集所有需要转换的方法生成新dex
                nativeImplDexPool.internClass(new MyClassDef(classDef, implDirectMethods, implVirtualMethods));
            } else {
                final ArrayList<Method> encryptedMethods = new ArrayList<>();
                for (Method method : classDef.getMethods()) {
                    if (FlowLockPlanner.isMarked(method, flowLockAnnotationType)) {
                        throw flowLockRejected(dexFileName, method, "class is excluded by protection rules");
                    }
                    encryptedMethods.add(stringEncryptor.rewrite(method));
                }
                // Classes excluded from native conversion still receive runtime string
                // encryption; their class/member identities remain unchanged.
                shellDexPool.internClass(new ImmutableClassDef(
                        classDef.getType(),
                        classDef.getAccessFlags(),
                        classDef.getSuperclass(),
                        classDef.getInterfaces(),
                        classDef.getSourceFile(),
                        classDef.getAnnotations(),
                        classDef.getFields(),
                        encryptedMethods));
            }
        }
        DexConfig config = new DexConfig(outDir, dexFileName);

        config.setShellMethods(shellMethods);

        //写入需要运行的dex
        shellDexPool.writeTo(new FileDataStore(config.getShellDexFile()));
        //写入符号dex
        nativeImplDexPool.writeTo(new FileDataStore(config.getImplDexFile()));
        return config;
    }

    private static IllegalArgumentException flowLockRejected(String dexFileName, Method method, String reason) {
        return new IllegalArgumentException("FlowLock rejected " + dexFileName + ": "
                + method.getDefiningClass() + "->" + method.getName() + "("
                + String.join("", method.getParameterTypes()) + ")" + method.getReturnType()
                + ": " + reason);
    }

    /**
     * True for a non-static, non-private, non-abstract instance method declared directly on an
     * interface — i.e. any Kotlin/Java8+ interface default method with a real body (`interface
     * Foo { fun bar() = Unit }`, or a property with a custom getter like `val x: Boolean get() =
     * false`). This is the ONLY shape of interface member that {@link MethodConverter} cannot
     * safely native-convert on this project's target ART versions, and the failure mode is nasty
     * enough to warrant excluding it outright rather than trying to route around it:
     *
     * - splitMethod()'s usual path just ORs AccessFlags.NATIVE onto the method's EXISTING flags
     *   and drops its code_item. That leaves a public, non-abstract, native (no-code) interface
     *   member — a shape the ART dex-file-verifier rejects ("Interface method ... is not public
     *   and abstract"), confirmed via dexdump against a real protected build.
     * - generateMethod()'s wrapper (private+native shell method, tiny real stub left on the
     *   original public method) — normally the safe fallback for a virtual-method JNI-lookup
     *   collision — does NOT fix this either: dexdump on the same build flags the private+native
     *   shell too ("Interface virtual method ... is not public"), i.e. this specific ART build
     *   doesn't accept a non-static instance native method on an interface AT ALL, private or
     *   not.
     * Either shape breaks class *linking* for every class overriding the method, not just calls
     * to it — the first such implementor touched at runtime throws NoClassDefFoundError even
     * though the class and its bytecode are both still physically present in the dex (diagnosed
     * against WEX's ChatTransport interface and its GlobalChatTransport implementor). There's no
     * safe way to native-convert this shape without also making it static (which needs an
     * explicit receiver parameter and touches call-site codegen this tool doesn't currently do),
     * so the pragmatic, zero-risk fix is: leave these methods completely untouched. They're
     * invariably trivial one-liners (constant getters, no-ops) with nothing worth hiding anyway.
     */
    private static boolean isUnconvertibleInterfaceMember(@NotNull ClassDef classDef, @NotNull Method method) {
        if (!AccessFlags.INTERFACE.isSet(classDef.getAccessFlags())) return false;
        final int flags = method.getAccessFlags();
        return !AccessFlags.STATIC.isSet(flags)
                && !AccessFlags.PRIVATE.isSet(flags)
                && !AccessFlags.ABSTRACT.isSet(flags);
    }

    private static void addMethods(List<Method> directMethods,
                                   List<Method> virtualMethods,
                                   @NotNull List<? extends Method> methods) {
        for (Method method : methods) {
            addMethod(directMethods, virtualMethods, method);
        }
    }

    private static void addMethod(List<Method> directMethods,
                                  List<Method> virtualMethods,
                                  Method method) {
        if (MethodUtil.isDirect(method)) {
            directMethods.add(method);
        } else {
            virtualMethods.add(method);
        }
    }

    //在处理过的class的static{}块最前面添加注册本地方法代码,如果不存在static{}块则新增<clinit>方法
    public static @NotNull List<DexPool> injectCallRegisterNativeInsns(@NotNull DexConfig config,
                                                                       DexPool lastDexPool,
                                                                       Set<String> mainClassSet,
                                                                       int maxPoolSize,
                                                                       @NotNull Opcodes outputOpcodes) throws IOException {

        DexBackedDexFile dexNativeFile = DexBackedDexFile.fromInputStream(
                null,
                new BufferedInputStream(new FileInputStream(config.getShellDexFile())));

        List<DexPool> dexPools = new ArrayList<>();
        dexPools.add(lastDexPool);


        for (ClassDef classDef : dexNativeFile.getClasses()) {
            if (mainClassSet.contains(classDef.getType())) {//提前处理过的class,不用再处理
                continue;
            }
            internClass(config, lastDexPool, classDef);

            if (lastDexPool.hasOverflowed(maxPoolSize)) {
                lastDexPool = new DexPool(outputOpcodes);
                dexPools.add(lastDexPool);
            }
        }
        return dexPools;
    }

    private static void internClass(@NotNull DexConfig config, DexPool dexPool, @NotNull ClassDef classDef) {
        final Set<String> classes = config.getHandledNativeClasses();
        final String type = classDef.getType();
        final String className = type.substring(1, type.length() - 1);
        if (classes.contains(className)) {
            final RegisterNativesCallerClassDef nativeClassDef = new RegisterNativesCallerClassDef(
                    classDef,
                    config.getOffsetFromClassName(className),
                    "L" + config.getRegisterNativesClassName() + ";",
                    config.getRegisterNativesMethodName());
            dexPool.internClass(nativeClassDef);
        } else {
            dexPool.internClass(classDef);
        }
    }
}
