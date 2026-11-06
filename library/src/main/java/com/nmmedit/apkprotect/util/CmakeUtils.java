package com.nmmedit.apkprotect.util;

import com.nmmedit.apkprotect.data.Prefs;
import com.nmmedit.apkprotect.dex2c.converter.BuildProtectionContext;
import com.nmmedit.apkprotect.dex2c.converter.VmKeyConfig;
import com.nmmedit.apkprotect.dex2c.converter.instructionrewriter.InstructionRewriter;
import com.nmmedit.apkprotect.dex2c.converter.instructionrewriter.RandomInstructionRewriter;
import com.nmmedit.apkprotect.sign.ApkVerifyCodeGenerator;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class CmakeUtils {

    //根据指令重写规则,重新生成新的opcode
    public static void writeOpcodeHeaderFile(File source, @NotNull InstructionRewriter instructionRewriter) throws IOException {
        final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(
                new FileInputStream(source), StandardCharsets.UTF_8));

        final String collect = bufferedReader.lines().collect(Collectors.joining("\n"));
        final Pattern opcodePattern = Pattern.compile(
                "enum Opcode \\{.*?};",
                Pattern.MULTILINE | Pattern.DOTALL);
        final StringWriter opcodeContent = new StringWriter();
        final StringWriter gotoTableContent = new StringWriter();
        instructionRewriter.generateConfig(opcodeContent, gotoTableContent);
        String headerContent = opcodePattern
                .matcher(collect)
                .replaceAll(String.format("enum Opcode {\n%s};\n", opcodeContent.toString()));

        //根据opcode生成goto表
        final Pattern patternGotoTable = Pattern.compile(
                "_name\\[kNumPackedOpcodes] = \\{.*?};",
                Pattern.MULTILINE | Pattern.DOTALL);
        headerContent = patternGotoTable
                .matcher(headerContent)
                .replaceAll(String.format("_name[kNumPackedOpcodes] = {        \\\\\n%s};\n", gotoTableContent));

        try (FileWriter fileWriter = new FileWriter(source)) {
            fileWriter.write(headerContent);
        }
        System.out.println("   [1] opcode randomizer     opcode map + handler table regenerated");
    }

    //读取证书信息,并把公钥写入签名验证文件里,运行时对apk进行签名校验
    private static void writeApkVerifierFile(String packageName, File source, ApkVerifyCodeGenerator apkVerifyCodeGenerator) throws IOException {
        if (apkVerifyCodeGenerator == null) {
            return;
        }
        final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(
                new FileInputStream(source), StandardCharsets.UTF_8));

        final String lines = bufferedReader.lines().collect(Collectors.joining("\n"));
        String dataPlaceHolder = "#define publicKeyPlaceHolder";

        String content = lines.replaceAll(dataPlaceHolder, dataPlaceHolder + apkVerifyCodeGenerator.generate());
        content = content.replaceAll("(#define PACKAGE_NAME) .*\n", "$1 \"" + packageName + "\"\n");

        try (FileWriter fileWriter = new FileWriter(source)) {
            fileWriter.write(content);
        }
    }

    public static void writeCmakeFile(File cmakeTemp, String libNmmpName, String libVmName, String cxxFlags) throws IOException {
        final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(
                new FileInputStream(cmakeTemp), StandardCharsets.UTF_8));

        String lines = bufferedReader.lines().collect(Collectors.joining("\n"));
        //定位cmake里的语句,防止替换错误
        String libNameFormat = "set\\(LIBNAME_PLACEHOLDER \"%s\"\\)";

        //替换原本libname
        lines = lines.replaceAll(String.format(libNameFormat, "nmmp"), String.format(libNameFormat, libNmmpName));

        libNameFormat = "set\\(LIBNMMVM_NAME \"%s\" CACHE INTERNAL \"lib %s name\"\\)";
        lines = lines.replaceAll(String.format(libNameFormat, "nmmvm", "nmmvm"), String.format(libNameFormat, libVmName, libVmName));

        //额外FLAGS
        lines = lines.replaceAll("-fvisibility=hidden", "-fvisibility=hidden " + cxxFlags);

        FileHelper.writeToFile(cmakeTemp, lines);
        System.out.println("   [6] branding              lib" + libNmmpName + " / lib" + libVmName);
    }


    public static void generateCSources(File srcDir, InstructionRewriter instructionRewriter) throws IOException {
        final File vmsrcFile = new File(FileUtils.getHomePath(), "tools/vmsrc.zip");
        vmsrcFile.getParentFile().mkdirs();
        try (InputStream inputStream = CmakeUtils.class.getResourceAsStream("/vmsrc.zip")) {
            if (inputStream == null) {
                throw new FileNotFoundException("Bundled /vmsrc.zip not found");
            }
            try (FileOutputStream outputStream = new FileOutputStream(vmsrcFile)) {
                FileHelper.copyStream(inputStream, outputStream);
            }
        }
        final List<File> cSources = ApkUtils.extractFiles(vmsrcFile, ".*", srcDir);
        final VmKeyConfig vmKeyConfig = VmKeyConfig.create(
                instructionRewriter, Prefs.getExpectedSigFold());

        //处理指令及apk验证,生成新的c文件
        for (File source : cSources) {
            if (source.getName().endsWith("DexOpcodes.h")) {
                //根据指令重写规则重新生成DexOpcodes.h文件
                writeOpcodeHeaderFile(source, instructionRewriter);
            } else if (source.getName().equals("CMakeLists.txt")) {
                //处理cmake里配置的本地库名
                writeCmakeFile(source, Prefs.getNmmpName(), Prefs.getVmName(), Prefs.getCxxFlags());
            } else if (source.getName().endsWith("vm.h")) {
                writePublicApiNames(source, mutationSeed(instructionRewriter));
                writeRandomResolver(source, mutationSeed(instructionRewriter));
            } else if (source.getName().endsWith("JNIWrapper.h")) {
                writeRandomJNIWrapper(source, mutationSeed(instructionRewriter));
            } else if (source.getName().endsWith("GlobalCache.h")) {
                writePublicApiNames(source, mutationSeed(instructionRewriter));
            } else if (source.getName().equals("Guard.cpp")) {
                mutateGuard(source, mutationSeed(instructionRewriter));
            } else if (source.getName().equals("SigCheck.cpp")) {
                //注入分片build salt；预期签名fingerprint本身不再写入native代码
                writeSigConfig(source, vmKeyConfig);
            } else if (source.getName().equals("InterpC-portable.cpp")) {
                //每次构建注入不同的handler变异常量, 破坏开源handler的字节指纹
                mutateHandlers(source, mutationSeed(instructionRewriter));
            } else if (source.getName().equals("GeneratedIntegrity.c")) {
                mutateGeneratedIntegrity(source, mutationSeed(instructionRewriter));
            }
        }
        System.out.println("   [7] build context         fingerprint "
                + protectionContext(instructionRewriter).fingerprint());
    }

    private static void writeSigConfig(File source, VmKeyConfig config) throws IOException {
        String content = FileHelper.readFile(source, StandardCharsets.UTF_8);
        content = replaceRequired(content, "7u /*SIGENABLED*/",
                config.isSignatureBindingEnabled() ? "1u /*SIGENABLED*/" : "0u /*SIGENABLED*/", source);
        for (int i = 0; i < 4; i++) {
            final long salt = config.getSalt(i);
            content = replaceRequired(content,
                    String.format("0x%08xu /*SIGS%dL*/", 0x13579bdfL + i, i),
                    String.format("0x%08xu /*SIGS%dL*/", salt & 0xffffffffL, i), source);
            content = replaceRequired(content,
                    String.format("0x%08xu /*SIGS%dH*/", 0x2468ace0L + i, i),
                    String.format("0x%08xu /*SIGS%dH*/", (salt >>> 32) & 0xffffffffL, i), source);
        }
        FileHelper.writeToFile(source, content);
    }

    private static String replaceRequired(String content,
                                          String placeholder,
                                          String replacement,
                                          File source) throws IOException {
        if (!content.contains(placeholder)) {
            throw new IOException("Placeholder '" + placeholder + "' not found in " + source);
        }
        return content.replace(placeholder, replacement);
    }

    //每构建唯一的种子: 绑定到opcode置换种子, 保证可复现
    private static long mutationSeed(InstructionRewriter rewriter) {
        return protectionContext(rewriter).deriveLong(
                "native-template-mutation-v2", "cmake-sources");
    }

    private static @NotNull BuildProtectionContext protectionContext(
            InstructionRewriter rewriter) {
        if (rewriter instanceof RandomInstructionRewriter) {
            return ((RandomInstructionRewriter) rewriter).getProtectionContext();
        }
        return BuildProtectionContext.fromLong(0x9E3779B97F4A7C15L);
    }

    private static void mutateGuard(File source, long seed) throws IOException {
        final String[] mapThreadSigs = {
                "frida", "linjector", "gadget", "gum-js", "re.frida", "pool-frida", "pool-spawn"
        };
        final String[] cpuinfoSigs = {
                "Goldfish", "ranchu", "QEMU", "vbox", "Hypervisor"
        };
        final String[] cmdlineSigs = {
                "qemu=1", "androidboot.hardware=goldfish",
                "androidboot.hardware=ranchu", "vboxsf"
        };
        final String[] emulatorPaths = {
                "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/goldfish_sync",
                "/dev/socket/qemud",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/system/lib64/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace", "/system/bin/qemu-props",
                "/dev/vboxguest", "/dev/vboxuser",
                "/dev/socket/genyd", "/dev/socket/baseband_genyd",
                "/system/bin/genymotion-vbox-sf",
                "/sys/module/qemu_trace", "/sys/module/vboxguest",
                "/dev/ttyS0"
        };

        final int key = 1 + new Random(seed ^ 0x47554152444CL).nextInt(255);

        final StringBuilder sigsBlock = new StringBuilder("// WEX_SIGS_BEGIN\n");
        sigsBlock.append("// Per-build encoded runtime indicators.\n");
        for (int i = 0; i < mapThreadSigs.length; i++) {
            appendEncodedArray(sigsBlock, "S" + i, mapThreadSigs[i], key);
        }
        for (int i = 0; i < cpuinfoSigs.length; i++) {
            appendEncodedArray(sigsBlock, "SC" + i, cpuinfoSigs[i], key);
        }
        for (int i = 0; i < cmdlineSigs.length; i++) {
            appendEncodedArray(sigsBlock, "SD" + i, cmdlineSigs[i], key);
        }
        sigsBlock.append("// WEX_SIGS_END");

        final StringBuilder epathsBlock = new StringBuilder("// WEX_EPATHS_BEGIN\n");
        epathsBlock.append("// Per-build encoded emulator device paths.\n");
        for (int i = 0; i < emulatorPaths.length; i++) {
            appendEncodedArray(epathsBlock, "EP" + i, emulatorPaths[i], key);
        }
        epathsBlock.append("// WEX_EPATHS_END");

        String content = FileHelper.readFile(source, StandardCharsets.UTF_8);

        final Pattern sigsPattern = Pattern.compile(
                "// WEX_SIGS_BEGIN.*?// WEX_SIGS_END", Pattern.MULTILINE | Pattern.DOTALL);
        Matcher m = sigsPattern.matcher(content);
        if (!m.find()) throw new IOException("Guard WEX_SIGS block not found in " + source);
        content = m.replaceFirst(Matcher.quoteReplacement(sigsBlock.toString()));

        final Pattern epathsPattern = Pattern.compile(
                "// WEX_EPATHS_BEGIN.*?// WEX_EPATHS_END", Pattern.MULTILINE | Pattern.DOTALL);
        m = epathsPattern.matcher(content);
        if (!m.find()) throw new IOException("Guard WEX_EPATHS block not found in " + source);
        content = m.replaceFirst(Matcher.quoteReplacement(epathsBlock.toString()));

        content = content.replace("0xA5u /*WXSIGKEY*/", String.format("0x%02Xu /*WXSIGKEY*/", key));
        FileHelper.writeToFile(source, content);
    }

    private static void appendEncodedArray(StringBuilder sb, String name, String str, int key) {
        sb.append("const u1 ").append(name).append("[] = {");
        final byte[] bytes = str.getBytes(StandardCharsets.US_ASCII);
        for (int j = 0; j < bytes.length; j++) {
            if (j != 0) sb.append(", ");
            sb.append(String.format("0x%02x", (bytes[j] & 0xff) ^ key));
        }
        sb.append("};\n");
    }

    private static void writePublicApiNames(File source, long seed) throws IOException {
        String lines = FileHelper.readFile(source, StandardCharsets.UTF_8);
        for (int i = 0; i < 6; i++) {
            final Random random = new Random(seed ^ 0x57584150494CL ^ (0x9E3779B97F4A7C15L * i));
            final String name = String.format("wx_%012x", random.nextLong() & 0xffffffffffffL);
            lines = lines.replace("WX_API_" + i, name);
        }
        if (lines.contains("WX_API_")) {
            throw new IOException("Unresolved public API placeholder in " + source);
        }
        FileHelper.writeToFile(source, lines);
    }

    //把HANDLE_OPCODE宏里的变异常量占位符替换为本次构建的随机常量
    private static void mutateHandlers(File source, long seed) throws IOException {
        final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(
                new FileInputStream(source), StandardCharsets.UTF_8));
        String lines = bufferedReader.lines().collect(Collectors.joining("\n"));
        final Random rnd = new Random(seed);
        final long a = (rnd.nextInt() | 1) & 0xffffffffL; //奇数乘子, 更好混合
        final long b = rnd.nextInt() & 0xffffffffL;
        lines = lines.replace("0xA5A5A5A5u /*WXMA*/", String.format("0x%08xu /*WXMA*/", a));
        lines = lines.replace("0x5A5A5A5Bu /*WXMB*/", String.format("0x%08xu /*WXMB*/", b));
        FileHelper.writeToFile(source, lines);
    }

    private static void mutateGeneratedIntegrity(File source, long seed) throws IOException {
        String content = FileHelper.readFile(source, StandardCharsets.UTF_8);
        final long value = new Random(seed ^ 0x524f4f54494e5447L).nextInt() & 0xffffffffL;
        content = replaceRequired(content,
                "0x6d2b79f5u /*WXROOTSCHED*/",
                String.format("0x%08xu /*WXROOTSCHED*/", value), source);
        FileHelper.writeToFile(source, content);
    }

    private static void writeRandomResolver(File source, long seed) throws IOException {
        final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(
                new FileInputStream(source), StandardCharsets.UTF_8));
        String lines = bufferedReader.lines().collect(Collectors.joining("\n"));
        final Pattern p = Pattern.compile("typedef struct \\{([^}]*?)} vmResolver;", Pattern.MULTILINE | Pattern.DOTALL);
        final Matcher matcherResolver = p.matcher(lines);
        if (matcherResolver.find()) {
            final String body = matcherResolver.group(1);
            //match function pointer
            final Pattern funcPattern = Pattern.compile("([^();]* \\**\\(\\*[a-zA-z0-9]*\\)\\([^();]*\\);)", Pattern.MULTILINE | Pattern.DOTALL);
            final ArrayList<String> funcs = new ArrayList<>();
            final Matcher matcher = funcPattern.matcher(body);
            while (matcher.find()) {
                funcs.add(matcher.group(1));
            }


            try (FileWriter fileWriter = new FileWriter(source)) {
                final String doc = matcherResolver.replaceAll("typedef struct {\n" +
                        randomList(funcs, seed ^ 0x5245534f4c564552L) +
                        "} vmResolver;");
                fileWriter.write(doc);
            }
        }
    }

    private static void writeRandomJNIWrapper(File file, long seed) throws IOException {
        final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(
                new FileInputStream(file), StandardCharsets.UTF_8));
        String lines = bufferedReader.lines().collect(Collectors.joining("\n"));
        final Pattern p = Pattern.compile("typedef struct \\{([^}]*?)} JNIWrapper;", Pattern.MULTILINE | Pattern.DOTALL);
        final Matcher matcherWrapper = p.matcher(lines);
        if (matcherWrapper.find()) {
            final String body = matcherWrapper.group(1);
            //match function pointer
            final Pattern funcPattern = Pattern.compile("([^();]* \\**\\(\\*[a-zA-z0-9]*\\)\\([^();]*\\);)", Pattern.MULTILINE | Pattern.DOTALL);
            final ArrayList<String> funcs = new ArrayList<>();
            final Matcher matcher = funcPattern.matcher(body);
            while (matcher.find()) {
                funcs.add(matcher.group(1));
            }
            try (FileWriter fileWriter = new FileWriter(file)) {
                final String doc = matcherWrapper.replaceAll("typedef struct {\n" +
                        randomList(funcs, seed ^ 0x4a4e495752415050L) +
                        "} JNIWrapper;");
                fileWriter.write(doc);
            }
        }
    }

    private static @NotNull String randomList(@NotNull List<String> list, long seed) {
        final StringBuilder sb = new StringBuilder();
        final Random random = new Random(seed);
        while (!list.isEmpty()) {
            final int idx = random.nextInt(list.size());
            sb.append(list.get(idx));
            sb.append('\n');
            list.remove(idx);
        }
        return sb.toString();
    }

    /** Injects SHA-256 values of the final shell DEX files before native compilation. */
    public static void writeDexIntegrityConfig(@NotNull File srcDir,
                                               @NotNull List<File> dexFiles) throws IOException {
        final File source = new File(srcDir, "vm/DexIntegrity.cpp");
        if (!source.isFile()) {
            throw new FileNotFoundException("Dex integrity template not found: " + source);
        }
        final ArrayList<File> ordered = new ArrayList<>(dexFiles);
        ordered.sort(Comparator.comparing(CmakeUtils::dexIndex));
        final StringBuilder block = new StringBuilder("// WEX_DEX_HASHES_BEGIN\n");
        block.append("static const ExpectedDex EXPECTED_DEX[] = {\n");
        for (File dex : ordered) {
            final byte[] digest = sha256(dex);
            block.append("        {\"").append(dex.getName()).append("\", {");
            for (int i = 0; i < digest.length; i++) {
                if (i != 0) block.append(", ");
                block.append(String.format("0x%02x", digest[i] & 0xff));
            }
            block.append("}},\n");
        }
        if (ordered.isEmpty()) block.append("        {nullptr, {0}},\n");
        block.append("};\n");
        block.append("static const volatile size_t EXPECTED_DEX_COUNT = ")
                .append(ordered.size()).append("; /*WEX_DEX_COUNT*/\n");
        block.append("// WEX_DEX_HASHES_END");

        final String content = FileHelper.readFile(source, StandardCharsets.UTF_8);
        final Pattern pattern = Pattern.compile(
                "// WEX_DEX_HASHES_BEGIN.*?// WEX_DEX_HASHES_END",
                Pattern.MULTILINE | Pattern.DOTALL);
        final Matcher matcher = pattern.matcher(content);
        if (!matcher.find()) {
            throw new IOException("DEX integrity placeholder block not found in " + source);
        }
        FileHelper.writeToFile(source,
                matcher.replaceFirst(Matcher.quoteReplacement(block.toString())));
        System.out.println("   [8] DEX integrity         SHA-256 entries " + ordered.size());
    }

    private static int dexIndex(File dex) {
        final String name = dex.getName();
        if ("classes.dex".equals(name)) return 1;
        final String number = name.replace("classes", "").replace(".dex", "");
        try {
            return Integer.parseInt(number);
        } catch (NumberFormatException ignored) {
            return Integer.MAX_VALUE;
        }
    }

    private static byte[] sha256(File file) throws IOException {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = Files.newInputStream(file.toPath())) {
                final byte[] buffer = new byte[64 * 1024];
                int count;
                while ((count = input.read(buffer)) >= 0) {
                    if (count != 0) digest.update(buffer, 0, count);
                }
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
}
