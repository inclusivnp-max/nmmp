package com.nmmedit.apkprotect.util;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class ManifestConfuserTest {
    private static final int NO_INDEX = 0xffffffff;
    private static final String ANDROID_URI = "http://schemas.android.com/apk/res/android";

    @Test
    public void appliesEveryLayerAndPreservesManifestSemantics() {
        byte[] original = sampleManifest();
        ManifestConfuser.Result result = ManifestConfuser.confuseDetailed(original, 0x12345678L);
        byte[] confused = result.data();

        assertFalse(Arrays.equals(original, confused));
        assertArrayEquals(confused, ManifestConfuser.confuse(original, 0x12345678L));
        assertEquals(12, result.originalStrings());
        assertEquals(result.originalStrings() + result.decoyStrings() + 1,
                result.outputStrings());
        assertTrue(result.decoyStrings() >= 32);
        assertEquals(1, result.namespaceAliases());
        assertEquals(1, result.shuffledElements());
        assertEquals(2, result.shuffledAttributes());
        assertEquals(4, result.rewrittenLineNumbers());
        assertEquals(semanticSnapshot(original), semanticSnapshot(confused));
        assertEquals(ANDROID_URI, namespaceUri(confused));
        assertNotEquals("android", namespacePrefix(confused));
        assertEquals("id", specialAttributeName(confused, 14));
        assertEquals("class", specialAttributeName(confused, 16));
        assertEquals("style", specialAttributeName(confused, 18));
    }

    @Test
    public void seedIsDeterministicAndBuildsArePolymorphic() {
        byte[] original = sampleManifest();
        byte[] first = ManifestConfuser.confuse(original, 7L);
        byte[] repeat = ManifestConfuser.confuse(original, 7L);
        byte[] second = ManifestConfuser.confuse(original, 8L);

        assertArrayEquals(first, repeat);
        assertFalse(Arrays.equals(first, second));
        assertEquals(semanticSnapshot(first), semanticSnapshot(second));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsNonAxmldata() {
        ManifestConfuser.confuse(new byte[]{1, 2, 3, 4}, 1L);
    }

    private static byte[] sampleManifest() {
        String[] strings = {
                "manifest", "label", "id", "com.example.app", "Example", "android",
                ANDROID_URI, "style", "StyleValue", "class", "ClassValue", "Identifier"
        };
        ByteArrayOutputStream poolData = new ByteArrayOutputStream();
        int[] offsets = new int[strings.length];
        for (int i = 0; i < strings.length; i++) {
            offsets[i] = poolData.size();
            byte[] bytes = strings[i].getBytes(StandardCharsets.UTF_8);
            writeLength8(poolData, strings[i].length());
            writeLength8(poolData, bytes.length);
            poolData.writeBytes(bytes);
            poolData.write(0);
        }
        while ((poolData.size() & 3) != 0) poolData.write(0);
        byte[] poolBytes = poolData.toByteArray();
        int poolHeader = 28;
        int poolStringsStart = poolHeader + offsets.length * 4;
        int poolSize = poolStringsStart + poolBytes.length;
        byte[] poolChunk = new byte[poolSize];
        put16(poolChunk, 0, 0x0001);
        put16(poolChunk, 2, poolHeader);
        put32(poolChunk, 4, poolSize);
        put32(poolChunk, 8, strings.length);
        put32(poolChunk, 12, 0);
        put32(poolChunk, 16, 0x100);
        put32(poolChunk, 20, poolStringsStart);
        put32(poolChunk, 24, 0);
        for (int i = 0; i < offsets.length; i++) {
            put32(poolChunk, poolHeader + i * 4, offsets[i]);
        }
        System.arraycopy(poolBytes, 0, poolChunk, poolStringsStart, poolBytes.length);

        byte[] resourceMap = new byte[20];
        put16(resourceMap, 0, 0x0180);
        put16(resourceMap, 2, 8);
        put32(resourceMap, 4, resourceMap.length);
        put32(resourceMap, 8, 0);
        put32(resourceMap, 12, 0x01010001);
        put32(resourceMap, 16, 0x010100d0);

        byte[] startNamespace = namespaceChunk(0x0100, 1, 5, 6);

        byte[] start = new byte[36 + 3 * 20];
        put16(start, 0, 0x0102);
        put16(start, 2, 16);
        put32(start, 4, start.length);
        put32(start, 8, 2);
        put32(start, 12, NO_INDEX);
        put32(start, 16, NO_INDEX);
        put32(start, 20, 0);
        put16(start, 24, 20);
        put16(start, 26, 20);
        put16(start, 28, 3);
        put16(start, 30, 1);
        put16(start, 32, 2);
        put16(start, 34, 3);
        putAttribute(start, 36, 6, 2, 11);
        putAttribute(start, 56, NO_INDEX, 9, 10);
        putAttribute(start, 76, NO_INDEX, 7, 8);

        byte[] end = new byte[24];
        put16(end, 0, 0x0103);
        put16(end, 2, 16);
        put32(end, 4, end.length);
        put32(end, 8, 3);
        put32(end, 12, NO_INDEX);
        put32(end, 16, NO_INDEX);
        put32(end, 20, 0);

        byte[] endNamespace = namespaceChunk(0x0101, 4, 5, 6);
        byte[][] chunks = {poolChunk, resourceMap, startNamespace, start, end, endNamespace};
        int bodySize = Arrays.stream(chunks).mapToInt(chunk -> chunk.length).sum();
        byte[] result = new byte[8 + bodySize];
        put16(result, 0, 0x0003);
        put16(result, 2, 8);
        put32(result, 4, result.length);
        int cursor = 8;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, result, cursor, chunk.length);
            cursor += chunk.length;
        }
        return result;
    }

    private static byte[] namespaceChunk(int type, int line, int prefix, int uri) {
        byte[] chunk = new byte[24];
        put16(chunk, 0, type);
        put16(chunk, 2, 16);
        put32(chunk, 4, chunk.length);
        put32(chunk, 8, line);
        put32(chunk, 12, NO_INDEX);
        put32(chunk, 16, prefix);
        put32(chunk, 20, uri);
        return chunk;
    }

    private static void putAttribute(byte[] data, int offset, int namespace, int name, int value) {
        put32(data, offset, namespace);
        put32(data, offset + 4, name);
        put32(data, offset + 8, value);
        put16(data, offset + 12, 8);
        data[offset + 14] = 0;
        data[offset + 15] = 3;
        put32(data, offset + 16, value);
    }

    private static String semanticSnapshot(byte[] data) {
        String[] strings = strings(data);
        TreeMap<String, String> attributes = new TreeMap<>();
        TreeMap<String, String> resources = new TreeMap<>();
        String element = "";
        String uri = "";
        String specials = "";
        for (int offset = 8; offset < data.length; ) {
            int type = get16(data, offset);
            int header = get16(data, offset + 2);
            int size = get32(data, offset + 4);
            if (type == 0x0180) {
                int count = (size - header) / 4;
                for (int i = 0; i < count; i++) {
                    resources.put(strings[i], Integer.toUnsignedString(get32(data,
                            offset + header + i * 4), 16));
                }
            } else if (type == 0x0100) {
                uri = stringAt(strings, get32(data, offset + 20));
            } else if (type == 0x0102) {
                element = stringAt(strings, get32(data, offset + 20));
                int ext = offset + 16;
                int attributeStart = get16(data, ext + 8);
                int attributeSize = get16(data, ext + 10);
                int attributeCount = get16(data, ext + 12);
                int attrs = ext + attributeStart;
                for (int i = 0; i < attributeCount; i++) {
                    int attr = attrs + i * attributeSize;
                    String name = stringAt(strings, get32(data, attr + 4));
                    String raw = stringAt(strings, get32(data, attr + 8));
                    String typed = (data[attr + 15] & 0xff) == 3
                            ? stringAt(strings, get32(data, attr + 16))
                            : Integer.toUnsignedString(get32(data, attr + 16), 16);
                    attributes.put(name, raw + "/" + typed);
                }
                specials = specialAttributeName(data, 14) + "/"
                        + specialAttributeName(data, 16) + "/"
                        + specialAttributeName(data, 18);
            }
            offset += size;
        }
        return element + "|" + uri + "|" + attributes + "|" + resources + "|" + specials;
    }

    private static String namespacePrefix(byte[] data) {
        String[] strings = strings(data);
        return stringAt(strings, indexAt(data, 0x0100, 16));
    }

    private static String namespaceUri(byte[] data) {
        String[] strings = strings(data);
        return stringAt(strings, indexAt(data, 0x0100, 20));
    }

    private static String specialAttributeName(byte[] data, int relativeSpecialOffset) {
        String[] strings = strings(data);
        for (int offset = 8; offset < data.length; ) {
            int size = get32(data, offset + 4);
            if (get16(data, offset) == 0x0102) {
                int ext = offset + 16;
                int oneBased = get16(data, ext + relativeSpecialOffset);
                if (oneBased == 0) return "";
                int attrs = ext + get16(data, ext + 8);
                int attrSize = get16(data, ext + 10);
                return stringAt(strings, get32(data, attrs + (oneBased - 1) * attrSize + 4));
            }
            offset += size;
        }
        return "";
    }

    private static String[] strings(byte[] data) {
        for (int offset = 8; offset < data.length; ) {
            int type = get16(data, offset);
            int size = get32(data, offset + 4);
            if (type == 0x0001) {
                int header = get16(data, offset + 2);
                int count = get32(data, offset + 8);
                boolean utf8 = (get32(data, offset + 16) & 0x100) != 0;
                int stringsStart = offset + get32(data, offset + 20);
                String[] result = new String[count];
                for (int i = 0; i < count; i++) {
                    int stringOffset = stringsStart + get32(data, offset + header + i * 4);
                    result[i] = decodeString(data, stringOffset, utf8);
                }
                return result;
            }
            offset += size;
        }
        throw new AssertionError("missing string pool");
    }

    private static String decodeString(byte[] data, int offset, boolean utf8) {
        if (utf8) {
            int[] first = readLength8(data, offset);
            int[] second = readLength8(data, first[1]);
            return new String(data, second[1], second[0], StandardCharsets.UTF_8);
        }
        int first = get16(data, offset);
        int length;
        int cursor;
        if ((first & 0x8000) == 0) {
            length = first;
            cursor = offset + 2;
        } else {
            length = ((first & 0x7fff) << 16) | get16(data, offset + 2);
            cursor = offset + 4;
        }
        return new String(data, cursor, length * 2, StandardCharsets.UTF_16LE);
    }

    private static int[] readLength8(byte[] data, int offset) {
        int first = data[offset] & 0xff;
        if ((first & 0x80) == 0) return new int[]{first, offset + 1};
        return new int[]{((first & 0x7f) << 8) | (data[offset + 1] & 0xff), offset + 2};
    }

    private static String stringAt(String[] strings, int index) {
        return index == NO_INDEX ? "" : strings[index];
    }

    private static int indexAt(byte[] data, int type, int relative) {
        for (int offset = 8; offset + 8 <= data.length; ) {
            int size = get32(data, offset + 4);
            if (get16(data, offset) == type) return get32(data, offset + relative);
            offset += size;
        }
        return -1;
    }

    private static void writeLength8(ByteArrayOutputStream output, int value) {
        if (value <= 0x7f) {
            output.write(value);
        } else {
            output.write((value >>> 8) | 0x80);
            output.write(value & 0xff);
        }
    }

    private static int get32(byte[] data, int offset) {
        return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16) | ((data[offset + 3] & 0xff) << 24);
    }

    private static int get16(byte[] data, int offset) {
        return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8);
    }

    private static void put16(byte[] data, int offset, int value) {
        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >>> 8);
    }

    private static void put32(byte[] data, int offset, int value) {
        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >>> 8);
        data[offset + 2] = (byte) (value >>> 16);
        data[offset + 3] = (byte) (value >>> 24);
    }
}
