package com.nmmedit.apkprotect.dex2c.filters;

import com.nmmedit.apkprotect.deobfus.MappingReader;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SimpleRulesTest {
    @Test
    public void readsFlowLockAnnotationFromRulesFile() throws Exception {
        final SimpleRules rules = new SimpleRules();
        rules.parse(new StringReader(
                "flowlock-annotation client.wex.annotations.WexFlowLock\n"
                        + "class client.wex.** { *; }\n"));

        assertEquals(
                "Lclient/wex/annotations/WexFlowLock;",
                rules.getFlowLockAnnotationType());
    }

    @Test
    public void keepClassBeatsConvertWildcard() throws Exception {
        final SimpleRules rules = new SimpleRules();
        rules.parse(new StringReader(
                "class client.wex.** { *; }\n"
                        + "keep class client.wex.modules.TdJniLoader\n"
                        + "keep class client.wex.utils.helper.tgkiller.**\n"
                        + "keep class client.wex.security.Guard$*\n"
                        + "keep class client.wex.feature.BotActivity\\$*\n"));

        assertFalse(
                rules.matchClass(
                        "Lclient/wex/modules/TdJniLoader;",
                        "Ljava/lang/Object;",
                        java.util.Collections.emptyList()));
        assertFalse(
                rules.matchClass(
                        "Lclient/wex/utils/helper/tgkiller/mtproto/TdAccount;",
                        "Ljava/lang/Object;",
                        java.util.Collections.emptyList()));
        assertFalse(
                rules.matchClass(
                        "Lclient/wex/security/Guard$CachedState;",
                        "Ljava/lang/Object;",
                        java.util.Collections.emptyList()));
        assertFalse(
                rules.matchClass(
                        "Lclient/wex/feature/BotActivity$Callback;",
                        "Ljava/lang/Object;",
                        java.util.Collections.emptyList()));
        assertTrue(
                rules.matchClass(
                        "Lclient/wex/modules/NativeModuleGate;",
                        "Ljava/lang/Object;",
                        java.util.Collections.emptyList()));
    }

    @Test
    public void mappingConfigPropagatesAndRemapsFlowLockAnnotation() throws Exception {
        final SimpleRules rules = new SimpleRules();
        rules.parse(new StringReader(
                "flowlock-annotation client.wex.annotations.WexFlowLock\n"
                        + "class client.wex.** { *; }\n"));
        final MappingReader mapping = new MappingReader(new ByteArrayInputStream(
                "client.wex.annotations.WexFlowLock -> a.b:\n"
                        .getBytes(StandardCharsets.UTF_8)));

        final ProguardMappingConfig config = new ProguardMappingConfig(null, mapping, rules);

        assertEquals("La/b;", config.getFlowLockAnnotationType());
    }
}
