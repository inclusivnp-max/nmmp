package com.nmmedit.apkprotect.dex2c.filters;

import com.google.common.collect.HashMultimap;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * class * extends android.app.Activity
 * class * implements java.io.Serializable
 * class my.package.AClass
 * class my.package.* { *; }
 * class * extends java.util.ArrayList {
 * if*;
 * }
 * class A {
 * }
 * class B extends A {
 * }
 * class C extends B {
 * }
 * The rule 'class * extends A' only match B
 */
public class SimpleRules {
    private final HashMultimap<ClassRule, MethodRule> convertRules = HashMultimap.create();
    private final List<String> keepClassRegexes = new ArrayList<>();
    private Set<MethodRule> methodRules;
    private String flowLockAnnotationType;

    public SimpleRules() {
    }

    @Contract(pure = true)
    private static @NotNull String classNameToType(@NotNull String className) {
        return "L" + className.replace('.', '/') + ";";
    }

    @NotNull
    private static String toRegex(@NotNull String s) {
        final StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                c = s.charAt(++i);
                appendRegexLiteral(sb, c);
                continue;
            }
            if (c == '*') {
                sb.append(".*");
            } else {
                appendRegexLiteral(sb, c);
            }
        }
        return sb.toString();
    }

    private static void appendRegexLiteral(@NotNull StringBuilder sb, char c) {
        if ("\\.[]{}()+-^$|?".indexOf(c) >= 0) {
            sb.append('\\');
        }
        sb.append(c);
    }

    public void parse(Reader ruleReader) throws IOException {
        try (BufferedReader reader = new BufferedReader(ruleReader)) {
            ClassRule classRule = null;
            final ArrayList<String> methodNameList = new ArrayList<>();
            boolean methodParsing = false;
            int lineNumb = 0;
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) {
                    lineNumb++;
                    continue;
                }
                if (line.startsWith("keep class") || line.startsWith("!class")) {
                    if (methodParsing) {
                        throw new RemoteException("Error rule " + lineNumb + ": " + line);
                    }
                    final String rest = line.startsWith("keep class")
                            ? line.substring("keep class".length()).trim()
                            : line.substring("!class".length()).trim();
                    String className = rest;
                    final int brace = rest.indexOf('{');
                    if (brace != -1) {
                        className = rest.substring(0, brace).trim();
                    }
                    if (className.isEmpty()) {
                        throw new RemoteException("Error rule " + lineNumb + ": " + line);
                    }
                    keepClassRegexes.add(toRegex(classNameToType(className.split(" +")[0])));
                    lineNumb++;
                    continue;
                }
                if (line.startsWith("flowlock-annotation")) {
                    if (methodParsing) {
                        throw new RemoteException("Error rule " + lineNumb + ": " + line);
                    }
                    final String[] split = line.split(" +");
                    if (split.length != 2 || flowLockAnnotationType != null || split[1].contains("*")) {
                        throw new RemoteException("Error rule " + lineNumb + ": " + line);
                    }
                    flowLockAnnotationType = split[1].startsWith("L") && split[1].endsWith(";")
                            ? split[1]
                            : classNameToType(split[1]);
                } else if (line.startsWith("class")) {
                    final String[] split = line.split(" +");
                    final int length = split.length;
                    if (length < 2) {
                        throw new RemoteException("Error rule " + lineNumb + ": " + line);
                    }
                    String className = split[1];
                    String supperName = "";
                    String interfaceName = "";
                    if (length >= 4) {
                        if ("extends".equals(split[2])) {//class * extends A
                            supperName = split[3];
                        } else if ("implements".equals(split[2])) {//class * implements I
                            interfaceName = split[3];
                        }
                    }
                    classRule = new ClassRule(className, supperName, interfaceName);
                    int mstart;
                    if ((mstart = line.indexOf('{')) != -1) { // my.pkg.A { methodA;methodB;}
                        int mend;
                        if ((mend = line.indexOf('}')) != -1) {
                            final String[] methodNames = line.substring(mstart + 1, mend).trim().split(";");
                            if (methodNames.length == 0) {
                                throw new RemoteException("Error rule " + lineNumb + ": " + line);
                            }
                            for (String name : methodNames) {
                                convertRules.put(classRule, new MethodRule(name));
                            }
                        } else {
                            methodNameList.clear();
                            methodParsing = true;
                        }
                    } else {
                        //any methods
                        convertRules.put(classRule, new MethodRule("*"));
                    }
                } else if (methodParsing) {
                    // my.pkg.A {
                    //   methodA;
                    //   methodB;
                    // }
                    if (line.indexOf('}') != -1) {
                        if (methodNameList.isEmpty()) {
                            throw new RemoteException("Error rule " + lineNumb + ": " + line);
                        }
                        for (String methodName : methodNameList) {
                            if ("".equals(methodName)) {
                                continue;
                            }
                            convertRules.put(classRule, new MethodRule(methodName));
                        }
                        methodParsing = false;
                    } else {
                        methodNameList.add(line.replace(";", ""));
                    }
                } else {
                    throw new RemoteException("Error rule " + lineNumb + ": " + line);
                }

                lineNumb++;
            }
        }
    }

    public boolean matchClass(@NotNull String classType, @Nullable String supperType, @NotNull List<String> ifacTypes) {
        for (String keep : keepClassRegexes) {
            if (classType.matches(keep)) {
                methodRules = null;
                return false;
            }
        }
        for (ClassRule rule : convertRules.keySet()) {
            final String typeRegex = toRegex(classNameToType(rule.className));
            if (classType.matches(typeRegex)) {// match classType
                if (!"".equals(rule.supperName)) {//supper name not empty
                    if (supperType != null) {
                        final String type = classNameToType(rule.supperName);
                        if (supperType.equals(type)) {
                            methodRules = convertRules.get(rule);
                            return true;
                        }
                    }
                    continue;
                }
                if (!"".equals(rule.interfaceName)) {//interface name not empty
                    for (String iface : ifacTypes) {
                        if (iface.equals(classNameToType(rule.interfaceName))) {
                            methodRules = convertRules.get(rule);
                            return true;
                        }
                    }
                    continue;
                }
                methodRules = convertRules.get(rule);
                return true;
            }
        }
        methodRules = null;
        return false;
    }

    public boolean matchMethod(String methodName) {
        if (methodRules == null || methodName == null) {
            return false;
        }
        for (MethodRule methodRule : methodRules) {
            if (methodName.matches(toRegex(methodRule.methodName))) {
                return true;
            }
        }
        return false;
    }

    public String getFlowLockAnnotationType() {
        return flowLockAnnotationType;
    }

    private static class ClassRule {
        @NotNull
        private final String className;
        //supper class
        @NotNull
        private final String supperName;
        //interface
        @NotNull
        private final String interfaceName;

        public ClassRule(@NotNull String className) {
            this(className, "", "");
        }

        public ClassRule(@NotNull String className, @NotNull String supperName, @NotNull String interfaceName) {
            this.className = className;
            this.supperName = supperName;
            this.interfaceName = interfaceName;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            ClassRule classRule = (ClassRule) o;

            if (!className.equals(classRule.className)) return false;
            if (!supperName.equals(classRule.supperName)) return false;
            return interfaceName.equals(classRule.interfaceName);
        }

        @Override
        public int hashCode() {
            int result = className.hashCode();
            result = 31 * result + supperName.hashCode();
            result = 31 * result + interfaceName.hashCode();
            return result;
        }
    }

    private static class MethodRule {
        @NotNull
        private final String methodName;
        // args ?
        // private final List<String> args;

        public MethodRule(@NotNull String methodName) {
            this.methodName = methodName;
        }
    }
}
