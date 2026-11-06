package com.nmmedit.apkprotect.dex2c.converter;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedClassDef;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedMethod;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.util.MethodUtil;
import com.google.common.collect.HashMultimap;
import com.nmmedit.apkprotect.data.Prefs;
import com.nmmedit.apkprotect.dex2c.DexConfig;
import com.nmmedit.apkprotect.dex2c.FlowLockPlanner;
import com.nmmedit.apkprotect.dex2c.converter.instructionrewriter.InstructionRewriter;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.Writer;
import java.util.*;


/**
 * 根据dex把所有方法的字节码和异常表提取出来生成jni函数
 */

public class JniCodeGenerator {
    // 不能再设为false,不然无法正确加载本地库,而且按标准的jni函数名可能会有命名冲突问题
    // 所以只保留注册本地函数这种方式
    // todo 再改改jni函数名生成方式应该可以把bridge这类方法也native化
    private final boolean isRegisterNative = true;

    private final HashMultimap<String, MyMethod> handledNativeMethods = HashMultimap.create();

    private final Map<String, Integer> nativeMethodOffsets = new HashMap<>();
    private final ResolverCodeGenerator resolverCodeGenerator;
    private final InstructionRewriter instructionRewriter;
    private final DexBackedDexFile dexFile;
    private final String flowLockAnnotationType;
    private final VmKeyConfig vmKeyConfig;

    public JniCodeGenerator(@NotNull DexBackedDexFile dexFile,
                            @NotNull ClassAnalyzer analyzer,
                            @NotNull InstructionRewriter instructionRewriter,
                            String flowLockAnnotationType) {
        this.dexFile = dexFile;
        this.vmKeyConfig = VmKeyConfig.create(instructionRewriter, Prefs.getExpectedSigFold());

//      根据dex里字符串常量,类型常量等生成符号解析代码,给vm提供符号信息
        resolverCodeGenerator = new ResolverCodeGenerator(dexFile, analyzer, vmKeyConfig);

        this.instructionRewriter = instructionRewriter;
        this.flowLockAnnotationType = flowLockAnnotationType;

        instructionRewriter.loadReferences(resolverCodeGenerator.getReferences(), analyzer);

    }

    @Contract(pure = true)
    public static @NotNull String getJNIType(@NotNull String type) {
        return switch (type) {
            case "Z" -> "jboolean";
            case "B" -> "jbyte";
            case "S" -> "jshort";
            case "C" -> "jchar";
            case "I" -> "jint";
            case "F" -> "jfloat";
            case "J" -> "jlong";
            case "D" -> "jdouble";
//            case "Ljava/lang/String;" -> "jstring";
            case "V" -> "void";
            default -> "jobject";
        };
    }

    public void addMethod(@NotNull Method method, Writer writer) throws IOException {
        final MethodImplementation implementation = method.getImplementation();
        if (implementation == null) {
            return;
        }

        final boolean isStatic = AccessFlags.STATIC.isSet(method.getAccessFlags());

        final String classType = method.getDefiningClass();

        final String methodName = method.getName();
        final int registerCount = implementation.getRegisterCount();
        final List<? extends CharSequence> parameterTypes = method.getParameterTypes();
        final int parameterRegisterCount = MethodUtil.getParameterRegisterCount(parameterTypes, isStatic);
        final String returnType = method.getReturnType();
        final String methodIdentity = methodIdentity(
                classType, methodName, parameterTypes, returnType);
        final String nativeFunctionName = vmKeyConfig.nativeSymbol(methodIdentity);


        String clazzName = classType.substring(1, classType.length() - 1);

        handledNativeMethods.put(clazzName, new MyMethod(clazzName, methodName, parameterTypes, returnType));

        writer.write(String.format("%s %s %s(JNIEnv *env, %s ",
                isRegisterNative ? "static" : "JNIEXPORT",
                getJNIType(returnType),
                nativeFunctionName,
                isStatic ? "jclass jcls" : "jobject thiz")
        );

//        --------jni函数定义及参数赋值-------

        //如果寄存器数量比较小直接使用栈上内存,不自己分配和释放
        boolean useStack = registerCount <= 8;

        //寄存器初始化
        StringBuilder regsAssign;
        StringBuilder regFlagsAssign;
        if (useStack) {
            regsAssign = new StringBuilder(String.format(
                    "    regptr_t regs[%d];\n", registerCount));
            //直接赋值数组元素值为0,初始化寄存器及其状态,不调用memset
            //好处是和后面赋值参数及参数类型时,编译器可以优化无用赋值

            for (int i = 0; i < registerCount; i++) {
                regsAssign.append(String.format("    regs[%d] = 0;\n", i));
            }
            regFlagsAssign = new StringBuilder(String.format(
                    "    u1 reg_flags[%d];\n", registerCount));

            for (int i = 0; i < registerCount; i++) {
                regFlagsAssign.append(String.format("    reg_flags[%d] = 0;\n", i));
            }
        } else {
            //一次同时分配寄存器及它的状态所需内存
            regsAssign = new StringBuilder(String.format(
                    "    regptr_t *regs = (regptr_t *) calloc(%d, sizeof(regptr_t) + sizeof(u1));\n",
                    registerCount));

            //寄存器后面部分是寄存器状态数组,和寄存器数量一一对应
            regFlagsAssign = new StringBuilder(
                    String.format("    u1 *reg_flags = ((u1 *) regs) + (%d * sizeof(regptr_t));\n", registerCount));
        }
        int paramRegStart = registerCount - parameterRegisterCount;
        if (!isStatic) {
            regsAssign.append(String.format("    regs[%d] = (regptr_t) thiz;\n", paramRegStart));
            //对象寄存器需要标识出来
            regFlagsAssign.append(String.format("    reg_flags[%d] = 1;\n", paramRegStart));

            paramRegStart++;
        }
        StringBuilder params = new StringBuilder();
        for (int i = 0, size = parameterTypes.size(); i < size; i++) {
            String type = parameterTypes.get(i).toString();
            String jniType = getJNIType(type);
            final int argNum = isStatic ? i : i + 1;
            params.append(jniType)
                    .append(" p")
                    .append(argNum);
            if (type.startsWith("[") || type.startsWith("L")) {//对象类型
                regsAssign.append(String.format("    regs[%d] = (regptr_t) p%d;\n", paramRegStart, argNum));

                regFlagsAssign.append(String.format("    reg_flags[%d] = 1;\n", paramRegStart));

                paramRegStart++;
            } else if (type.equals("F")) {
                regsAssign.append(String.format("    SET_REGISTER_FLOAT(%d, p%d);\n", paramRegStart++, argNum));
            } else if (type.equals("D")) {
                regsAssign.append(String.format("    SET_REGISTER_DOUBLE(%d, p%d);\n", paramRegStart++, argNum));
                paramRegStart++;
            } else if (type.equals("J")) {
                regsAssign.append(String.format("    SET_REGISTER_WIDE(%d, p%d);\n", paramRegStart++, argNum));
                paramRegStart++;
            } else {
                regsAssign.append(String.format("    regs[%d] = p%d;\n", paramRegStart++, argNum));
            }
            if (i < size - 1) {//最后不用加,
                params.append(", ");
            }
        }
        if (!params.isEmpty()) {
            writer.append(", ").append(params.toString());
        }
        writer.append(") {\n");
        writer.append(regsAssign);
        writer.append("\n");

        writer.append(regFlagsAssign);
        writer.append("\n");
//        -----------结束----------------

        final byte[] instructionData = instructionRewriter.rewriteInstructions(implementation);
        final int dataLength = instructionData.length;
        final int insnWords = dataLength / 2;
        final boolean annotated = FlowLockPlanner.isMarked(method, flowLockAnnotationType);
        final boolean useFlow = annotated;
        final FlowLockPlanner.Plan flowPlan = annotated
                ? FlowLockPlanner.createPlan(method, "implementation DEX")
                : null;
        final long methodTag = vmKeyConfig.methodTag64(methodIdentity);
        final long methodSite = vmKeyConfig.siteCookie(methodIdentity);
        VmAead.Sealed instructionBlob = null;
        final ArrayList<FlowBlob> flowBlobs = new ArrayList<>();
        final byte[] encryptedInstructions;
        if (useFlow) {
            encryptedInstructions = new byte[dataLength];
            for (int i = 0; i < flowPlan.blockCount(); i++) {
                final int startWords = flowPlan.starts()[i];
                final int sizeWords = flowPlan.starts()[i + 1] - startWords;
                final int startBytes = startWords * 2;
                final int sizeBytes = sizeWords * 2;
                final String blockIdentity = methodIdentity + "#flow:" + i;
                final long blockTag = vmKeyConfig.methodTag64(blockIdentity);
                final long blockSite = vmKeyConfig.siteCookie(blockIdentity);
                final byte[] nonce = vmKeyConfig.nonce("flow-block", blockIdentity);
                final byte[] plainBlock = Arrays.copyOfRange(
                        instructionData, startBytes, startBytes + sizeBytes);
                final VmAead.Sealed sealed = VmAead.seal(vmKeyConfig, plainBlock,
                        VmAead.DOMAIN_FLOW_BLOCK, blockTag, nonce, blockSite);
                final byte[] ciphertext = sealed.ciphertext();
                System.arraycopy(ciphertext, 0, encryptedInstructions, startBytes, ciphertext.length);
                Arrays.fill(plainBlock, (byte) 0);
                Arrays.fill(ciphertext, (byte) 0);
                flowBlobs.add(new FlowBlob(startWords, sizeWords, blockTag, blockSite, sealed));
            }
        } else {
            final byte[] nonce = vmKeyConfig.nonce("instructions", methodIdentity);
            instructionBlob = VmAead.seal(vmKeyConfig, instructionData,
                    VmAead.DOMAIN_INSTRUCTIONS, methodTag, nonce, methodSite);
            encryptedInstructions = instructionBlob.ciphertext();
        }

        writeByteArray(writer, "insns_enc", encryptedInstructions, true);
        if (useFlow) {
            writer.append("    static const vmFlowBlock flow_blocks[] = {\n");
            for (FlowBlob block : flowBlobs) {
                writer.append(String.format(
                        "        {%d, %d, 0x%016xULL, 0x%016xULL, %s, %s},\n",
                        block.startWords, block.sizeWords, block.contextTag, block.siteMaterial,
                        byteInitializer(block.sealed.nonce()),
                        byteInitializer(block.sealed.tag())));
            }
            writer.append("    };\n");
            writer.append(String.format(
                    "    static const vmFlow flow = {insns_enc, flow_blocks, %d};\n",
                    flowPlan.blockCount()));
        } else {
            writeByteArray(writer, "insns_nonce", instructionBlob.nonce(), true);
            writeByteArray(writer, "insns_tag", instructionBlob.tag(), true);
        }

        final boolean insnsUseStack = insnWords <= 2048;
        if (insnsUseStack) {
            writer.append(String.format("    u2 insns[%d]%s;\n", insnWords, useFlow ? " = {0}" : ""));
        } else if (useFlow) {
            writer.append(String.format("    u2 *insns = (u2 *) calloc(%d, sizeof(u2));\n", insnWords));
        } else {
            writer.append(String.format("    u2 *insns = (u2 *) malloc(%d * sizeof(u2));\n", insnWords));
        }
        writer.append("    const u8 method_integrity = nmmp_integrity_delta();\n");
        if (useFlow) {
            writer.append("    const bool insns_ok = true;\n");
        } else {
            writer.append(String.format(
                    "    const bool insns_ok = vm_aead_open((u1 *) insns, insns_enc, %d, " +
                            "insns_nonce, insns_tag, 0x%08xu, 0x%016xULL, " +
                            "0x%016xULL ^ method_integrity);\n",
                    dataLength, VmAead.DOMAIN_INSTRUCTIONS, methodTag, methodSite));
        }


        final byte[] tries = instructionRewriter.handleTries(implementation);
        StringBuilder triesBuilder = new StringBuilder();
        if (tries.length == 0) {
            triesBuilder.append("    u1 *tries = NULL;\n");
            triesBuilder.append("    const bool tries_ok = true;\n");
        } else {
            final String triesIdentity = methodIdentity + "#tries";
            final long triesTag = vmKeyConfig.methodTag64(triesIdentity);
            final long triesSite = vmKeyConfig.siteCookie(triesIdentity);
            final VmAead.Sealed sealedTries = VmAead.seal(vmKeyConfig, tries,
                    VmAead.DOMAIN_TRIES, triesTag,
                    vmKeyConfig.nonce("tries", triesIdentity), triesSite);
            appendByteArray(triesBuilder, "tries_enc", sealedTries.ciphertext(), true);
            appendByteArray(triesBuilder, "tries_nonce", sealedTries.nonce(), true);
            appendByteArray(triesBuilder, "tries_tag", sealedTries.tag(), true);
            triesBuilder.append(String.format("    u1 tries[%d];\n", tries.length));
            triesBuilder.append(String.format(
                    "    const bool tries_ok = vm_aead_open(tries, tries_enc, %d, " +
                            "tries_nonce, tries_tag, 0x%08xu, 0x%016xULL, " +
                            "0x%016xULL ^ method_integrity);\n",
                    tries.length, VmAead.DOMAIN_TRIES, triesTag, triesSite));
        }
        writer.write(triesBuilder.toString());


        //调用解释器
        writer.write(String.format("\n" +
                        "    const vmCode code = {\n" +
                        "            .insns=insns,\n" +
                        "            .insnsSize=%d,\n" +
                        "            .returnType='%c',\n" +
                        "            .regs=regs,\n" +
                        "            .reg_flags=reg_flags,\n" +
                        "            .triesHandlers=tries,\n" +
                        "            .flow=%s,\n" +
                        "            .integrityDelta=method_integrity\n" +
                        "    };\n" +
                        "\n" +
                        "    jvalue value = {0};\n" +
                        "    if (insns_ok && tries_ok) {\n" +
                        "        value = vmInterpret(env, &code, &dvmResolver);\n" +
                        "    }\n"
                , dataLength / 2, returnType.charAt(0), useFlow ? "&flow" : "NULL"));
        writer.write(String.format("    vm_secure_wipe(insns, %d * sizeof(u2));\n", insnWords));
        writer.write(String.format("    vm_secure_wipe(regs, %d * sizeof(regptr_t));\n", registerCount));
        writer.write(String.format("    vm_secure_wipe(reg_flags, %d * sizeof(u1));\n", registerCount));
        if (tries.length > 0) {
            writer.write(String.format("    vm_secure_wipe(tries, %d);\n", tries.length));
        }
        //不使用栈需要释放内存
        if (!useStack) {
            writer.write("    free(regs);\n");
        }
        //解密缓冲若在堆上分配也需要释放
        if (!insnsUseStack) {
            writer.write("    free(insns);\n");
        }

        //根据返回类型处理jvalue
        if (!returnType.equals("V")) {
            char typeCh = returnType.charAt(0);
            writer.append(
                    String.format("    return value.%s;\n", Character.toLowerCase(typeCh == '[' ? 'L' : typeCh))
            );
        }
        writer.append("}\n\n");
    }

    public Set<String> getHandledNativeClasses() {
        return handledNativeMethods.keySet();
    }

    //必须在产生代码后调用才有效果
    public Map<String, Integer> getNativeMethodOffsets() {
        return nativeMethodOffsets;
    }

    public void generate(@NotNull DexConfig config, Writer resolverWriter, @NotNull Writer codeWriter) throws IOException {
        resolverCodeGenerator.generate(resolverWriter);

        codeWriter.write(String.format("\n" +
                        "#include <stdio.h>\n" +
                        "#include <string.h>\n" +
                        "#include <malloc.h>\n" +
                        "#include <jni.h>\n" +
                        "#include \"vm.h\"\n" +
                        "extern u8 nmmp_integrity_delta(void);\n" +
                        "#include \"%s\"\n" +
                        "\n" +
                        "#ifdef __cplusplus\n" +
                        "extern \"C\" {\n" +
                        "#endif\n" +
                        "\n" +
                        "\n" +
                        "#define SET_REGISTER_FLOAT(_idx, _val)      (*((float*) &regs[(_idx)]) = (_val))\n" +
                        "\n" +
                        "\n" +
                        "#define SET_REGISTER_WIDE(_idx, _val)       (regs[(_idx)] =(s8) (_val));\n" +
                        "\n" +
                        "#define SET_REGISTER_DOUBLE(_idx, _val)     (*((double*) &regs[(_idx)]) = (_val));\n" +
                        "\n\n" +
                        "__attribute__((noinline)) static void vm_secure_wipe(void *ptr, size_t size) {\n" +
                        "    volatile u1 *p = (volatile u1 *) ptr;\n" +
                        "    while (size-- != 0) *p++ = 0;\n" +
                        "}\n" +
                        "\n"
                , config.getResolverFile().getName()));

        for (DexBackedClassDef classDef : dexFile.getClasses()) {
            for (DexBackedMethod method : classDef.getMethods()) {
                addMethod(method, codeWriter);
            }
        }

        generateNativeMethodCode(config, codeWriter);

        codeWriter.write(String.format("void %s(JNIEnv *env) {\n", config.getHeaderFileAndSetupFunc().setupFunctionName));

        codeWriter.write("\n    //符号解析器初始化\n");
        codeWriter.write("    resolver_init(env);\n\n");

        if (isRegisterNative) {
            codeWriter.write("    //注册\n");

            final String funName = vmKeyConfig.nativeSymbol(methodIdentity(
                    "L" + config.getRegisterNativesClassName() + ";",
                    config.getRegisterNativesMethodName(), Collections.singletonList("I"), "V"));
            codeWriter.write(String.format(
                    "    jclass clazz = (*env)->FindClass(env, \"%s\");\n" +
                            "    static const JNINativeMethod nativeMethod = {\n" +
                            "        .name=\"%s\",\n" +
                            "        .signature=\"(I)V\",\n" +
                            "        .fnPtr=%s\n" +
                            "    };\n" +
                            "   (*env)->RegisterNatives(env, clazz, &nativeMethod, 1);\n" +
                            "\n" +
                            "   (*env)->DeleteLocalRef(env, clazz);\n" +
                            "\n"
                    , config.getRegisterNativesClassName(),
                    config.getRegisterNativesMethodName(), funName));
        }
        codeWriter.write("}\n");

        codeWriter.write(
                "\n\n#ifdef __cplusplus\n" +
                        "}\n" +
                        "#endif\n\n");
    }

    //生成本地方法注册代码,同时返回类名和方法数组索引等
    private void generateNativeMethodCode(DexConfig config, Writer writer) throws IOException {
        if (!isRegisterNative) {
            return;
        }
        //记录类名之下所有方法起始位置及数量用于生成注册代码
        LinkedHashMap<String, Ranger> methodRanger = new LinkedHashMap<>();

        final long fnMask = vmKeyConfig.getProtectionContext().deriveLong(
                "jni-pointer-mask-v2", config.getDexName());
        writer.write("\n" +
                "#include <stdint.h>\n" +
                "typedef struct{\n" +
                "    u4 nameIdx;\n" +
                "    u4 sigIdx;\n" +
                "    void *fnPtr;\n" +
                "} MyNativeMethod;\n");
        writer.write(String.format("static const uintptr_t gFnMask = (uintptr_t) 0x%016xULL;\n", fnMask));

        int methodIdx = 0;
        writer.write("static MyNativeMethod gNativeMethods[] = {\n");
        final References references = resolverCodeGenerator.getReferences();
        final ArrayList<String> classes = new ArrayList<>(handledNativeMethods.keySet());
        Collections.sort(classes);
        vmKeyConfig.getProtectionContext().shuffle(
                classes, "jni-class-order-v2/" + config.getDexName());
        for (String clazz : classes) {

            int startIdx = methodIdx;
            final ArrayList<MyMethod> methods = new ArrayList<>(handledNativeMethods.get(clazz));
            methods.sort(Comparator.comparing(MyMethod::identity));
            vmKeyConfig.getProtectionContext().shuffle(methods,
                    "jni-method-order-v2/" + config.getDexName() + "/" + clazz);
            for (MyMethod method : methods) {
                int nameIdx = references.getStringItemIndex(method.name);
                int sigIdx = references.getStringItemIndex(MyMethodUtil.getMethodSignature(method.parameterTypes, method.returnType));
                String jniFunName = vmKeyConfig.nativeSymbol(method.identity());
                writer.write(String.format(
                        "    {%d, %d, (void *) %s},\n",
                        nameIdx, sigIdx, jniFunName
                ));
                methodIdx++;
            }
            methodRanger.put(clazz, new Ranger(startIdx, methodIdx - startIdx));
        }

        writer.write("};\n");
        writer.write("//ends native method\n");

        //根据索引生成注册需要的结构体
        writer.write(
                "\n" +
                        "typedef struct {\n" +
                        "    u4 classIdx;\n" +
                        "    u4 offset;\n" +
                        "    u4 count;\n" +
                        "} NativeMethodData;\n");

        writer.write("static const NativeMethodData gNativeRegisterData[] = {\n");
        int dataOff = 0;
        for (Map.Entry<String, Ranger> entry : methodRanger.entrySet()) {
            Ranger ranger = entry.getValue();
            final String className = entry.getKey();
            int classIdx = references.getClassNameItemIndex(className);
            writer.write(String.format("    {.classIdx = %d, .offset = %d, .count = %d},\n", classIdx, ranger.start, ranger.count));
            nativeMethodOffsets.put(className, dataOff++);
        }
        writer.write("};\n\n");

        //当前dex下所有处理过的class对应的本地方法注册
        final String funName = vmKeyConfig.nativeSymbol(methodIdentity(
                "L" + config.getRegisterNativesClassName() + ";",
                config.getRegisterNativesMethodName(), Collections.singletonList("I"), "V"));
        writer.write(String.format(
                "static void %s(JNIEnv *env, jclass jcls, jint dataIdx){\n" +
                        "#define MAX_METHOD 8\n" +
                        "    JNINativeMethod methodBuf[MAX_METHOD];\n" +
                        "\n" +
                        "    static int encoded = 0;\n" +
                        "    if (!encoded) {\n" +
                        "        for (u4 i = 0; i < (u4) (sizeof(gNativeMethods) / sizeof(gNativeMethods[0])); i++) {\n" +
                        "            gNativeMethods[i].fnPtr = (void *) ((uintptr_t) gNativeMethods[i].fnPtr ^ gFnMask);\n" +
                        "        }\n" +
                        "        encoded = 1;\n" +
                        "    }\n" +
                        "\n" +
                        "    JNINativeMethod *methods;\n" +
                        "    const NativeMethodData data = gNativeRegisterData[(u4) dataIdx];\n" +
                        "    if (data.count > MAX_METHOD) {\n" +
                        "        methods = (JNINativeMethod *) malloc(sizeof(JNINativeMethod) * data.count);\n" +
                        "    } else {\n" +
                        "        //方法数比较小直接使用栈内存,减少内存分配和释放\n" +
                        "        methods = methodBuf;\n" +
                        "    }\n" +
                        "\n" +
                        "    jclass clazz = (*env)->FindClass(env, STRING_BY_CLASS_ID(data.classIdx));\n" +
                        "    if (clazz == NULL) {\n" +
                        "        return;\n" +
                        "    }\n" +
                        "    for (int midx = 0; midx < data.count; ++midx) {\n" +
                        "        MyNativeMethod myNativeMethod = gNativeMethods[data.offset + midx];\n" +
                        "\n" +
                        "        JNINativeMethod *method = methods + midx;\n" +
                        "        method->name = STRING_BY_ID(myNativeMethod.nameIdx);\n" +
                        "        method->signature = STRING_BY_ID(myNativeMethod.sigIdx);\n" +
                        "        method->fnPtr = (void *) ((uintptr_t) myNativeMethod.fnPtr ^ gFnMask);\n" +
                        "    }\n" +
                        "\n" +
                        "    (*env)->RegisterNatives(env, clazz, methods, data.count);\n" +
                        "\n" +
                        "    (*env)->DeleteLocalRef(env, clazz);\n" +
                        "\n" +
                        "    //不相等表示使用malloc申请的内存需要释放\n" +
                        "    if (methods != methodBuf)free(methods);\n" +
                        "}\n\n"
                , funName)
        );
    }

    private static @NotNull String methodIdentity(@NotNull String classType,
                                                   @NotNull String methodName,
                                                   @NotNull List<? extends CharSequence> parameterTypes,
                                                   @NotNull String returnType) {
        return classType + "->" + methodName
                + MyMethodUtil.getMethodSignature(parameterTypes, returnType);
    }

    private static void writeByteArray(@NotNull Writer writer,
                                       @NotNull String name,
                                       byte @NotNull [] data,
                                       boolean constant) throws IOException {
        final StringBuilder output = new StringBuilder();
        appendByteArray(output, name, data, constant);
        writer.write(output.toString());
    }

    private static void appendByteArray(@NotNull StringBuilder output,
                                        @NotNull String name,
                                        byte @NotNull [] data,
                                        boolean constant) {
        output.append("    static ");
        if (constant) output.append("const ");
        output.append("u1 ").append(name).append('[').append(data.length).append("] = {");
        for (int i = 0; i < data.length; i++) {
            if ((i & 15) == 0) output.append("\n        ");
            output.append(String.format("0x%02x, ", data[i] & 0xff));
        }
        output.append("\n    };\n");
    }

    private static @NotNull String byteInitializer(byte @NotNull [] data) {
        final StringBuilder output = new StringBuilder("{");
        for (int i = 0; i < data.length; i++) {
            if (i != 0) output.append(", ");
            output.append(String.format("0x%02x", data[i] & 0xff));
        }
        return output.append('}').toString();
    }

    private static final class FlowBlob {
        private final int startWords;
        private final int sizeWords;
        private final long contextTag;
        private final long siteMaterial;
        private final VmAead.Sealed sealed;

        private FlowBlob(int startWords, int sizeWords,
                         long contextTag, long siteMaterial,
                         VmAead.Sealed sealed) {
            this.startWords = startWords;
            this.sizeWords = sizeWords;
            this.contextTag = contextTag;
            this.siteMaterial = siteMaterial;
            this.sealed = sealed;
        }
    }

    private static class MyMethod {
        final String className;
        final String name;
        final List<? extends CharSequence> parameterTypes;

        final String returnType;

        MyMethod(String className, String name, List<? extends CharSequence> parameterTypes, String returnType) {
            this.className = className;
            this.name = name;
            this.parameterTypes = parameterTypes;
            this.returnType = returnType;
        }

        private @NotNull String identity() {
            return methodIdentity("L" + className + ";", name, parameterTypes, returnType);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            MyMethod myMethod = (MyMethod) o;

            if (!className.equals(myMethod.className)) return false;
            if (!name.equals(myMethod.name)) return false;
            if (!parameterTypes.equals(myMethod.parameterTypes)) return false;
            return returnType.equals(myMethod.returnType);
        }

        @Override
        public int hashCode() {
            int result = className.hashCode();
            result = 31 * result + name.hashCode();
            result = 31 * result + parameterTypes.hashCode();
            result = 31 * result + returnType.hashCode();
            return result;
        }
    }

    private static class Ranger {
        final int start;
        final int count;

        Ranger(int start, int count) {
            this.start = start;
            this.count = count;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Ranger ranger = (Ranger) o;

            if (start != ranger.start) return false;
            return count == ranger.count;
        }

        @Override
        public int hashCode() {
            int result = start;
            result = 31 * result + count;
            return result;
        }
    }
}
