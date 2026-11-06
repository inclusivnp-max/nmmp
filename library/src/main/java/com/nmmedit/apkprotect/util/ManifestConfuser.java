package com.nmmedit.apkprotect.util;

import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Produces a non-canonical but PackageManager-compatible compiled AndroidManifest.xml.
 *
 * <p>The manifest itself cannot be encrypted because Android must parse it before any
 * application code runs. Instead this transform permutes the string pool and attributes,
 * injects unreachable pool entries, aliases namespace prefixes, and perturbs diagnostic
 * line markers while preserving all semantic string/resource references.</p>
 */
public final class ManifestConfuser {
    private static final int RES_STRING_POOL_TYPE = 0x0001;
    private static final int RES_XML_TYPE = 0x0003;
    private static final int RES_XML_RESOURCE_MAP_TYPE = 0x0180;
    private static final int RES_XML_START_NAMESPACE_TYPE = 0x0100;
    private static final int RES_XML_END_NAMESPACE_TYPE = 0x0101;
    private static final int RES_XML_START_ELEMENT_TYPE = 0x0102;
    private static final int RES_XML_END_ELEMENT_TYPE = 0x0103;
    private static final int RES_XML_CDATA_TYPE = 0x0104;
    private static final int NO_INDEX = 0xffffffff;
    private static final int TYPE_STRING = 0x03;
    private static final int SORTED_FLAG = 0x00000001;
    private static final int UTF8_FLAG = 0x00000100;
    private static final long POOL_DOMAIN = 0x4d414e4946455354L;
    private static final long DECOY_DOMAIN = 0x535452494e47504fL;
    private static final long ATTRIBUTE_DOMAIN = 0x4154545249425554L;
    private static final long LINE_DOMAIN = 0x4c494e454e554d42L;
    private static final int MIN_DECOYS = 32;
    private static final int DECOY_VARIANCE = 17;

    private ManifestConfuser() {
    }

    public record Result(byte[] data, int originalStrings, int outputStrings,
                         int decoyStrings, int namespaceAliases,
                         int shuffledElements, int shuffledAttributes,
                         int rewrittenLineNumbers) {
    }

    public static @NotNull byte[] confuse(byte @NotNull [] manifest, long seed) {
        return confuseDetailed(manifest, seed).data();
    }

    public static @NotNull Result confuseDetailed(byte @NotNull [] manifest, long seed) {
        byte[] output = manifest.clone();
        List<Chunk> originalChunks = chunks(output);
        Chunk originalPool = findPool(originalChunks);
        PoolInfo originalInfo = parsePool(output, originalPool);

        int decoyCount = 0;
        int aliasCount = 0;
        int outputStringCount = originalInfo.stringCount;
        Map<Integer, Integer> aliasLogicalIndexes = Map.of();
        int[] remap;

        // Styled strings are not expected in compiled manifests. Leave such a pool intact
        // rather than risking reassociation of style records; node-level confusion is safe.
        if (originalInfo.styleCount == 0) {
            Set<Integer> namespaceUris = collectNamespaceUris(output, originalChunks,
                    originalInfo.stringCount);
            Random poolRandom = new Random(seed ^ POOL_DOMAIN);
            decoyCount = MIN_DECOYS + poolRandom.nextInt(DECOY_VARIANCE);

            List<byte[]> entries = extractStringEntries(output, originalPool, originalInfo);
            LinkedHashMap<Integer, Integer> mutableAliases = new LinkedHashMap<>();
            int aliasOrdinal = 0;
            for (int uri : namespaceUris) {
                int logicalIndex = entries.size();
                String alias = opaqueName(seed ^ POOL_DOMAIN, aliasOrdinal++, "p");
                entries.add(encodeString(alias, originalInfo.utf8()));
                mutableAliases.put(uri, logicalIndex);
            }
            aliasLogicalIndexes = mutableAliases;
            aliasCount = mutableAliases.size();

            for (int i = 0; i < decoyCount; i++) {
                entries.add(encodeString(opaqueName(seed ^ DECOY_DOMAIN, i, "x"),
                        originalInfo.utf8()));
            }

            outputStringCount = entries.size();
            int resourceCount = resourceMapCount(originalChunks, originalInfo.stringCount);
            List<Integer> order = shuffledOrder(outputStringCount, resourceCount, poolRandom);
            remap = remap(order);

            byte[] rebuiltPool = rebuildPool(output, originalPool, originalInfo, entries, order);
            output = replacePool(output, originalPool, rebuiltPool);
            List<Chunk> rebuiltChunks = chunks(output);
            PoolInfo rebuiltInfo = parsePool(output, findPool(rebuiltChunks));
            if (rebuiltInfo.stringCount != outputStringCount) {
                throw invalid("rebuilt string count mismatch");
            }
            rewriteReferences(output, rebuiltChunks, remap, originalInfo.stringCount);
            rewriteNamespacePrefixes(output, rebuiltChunks, aliasLogicalIndexes, remap);
        }

        List<Chunk> finalChunks = chunks(output);
        ShuffleStats shuffleStats = shuffleAttributes(output, finalChunks, seed);
        int lineCount = rewriteLineNumbers(output, finalChunks, seed);
        // Parse the final layout once more so malformed chunk arithmetic never reaches output.
        parsePool(output, findPool(chunks(output)));

        return new Result(output, originalInfo.stringCount, outputStringCount,
                decoyCount, aliasCount, shuffleStats.elements, shuffleStats.attributes,
                lineCount);
    }

    private static Chunk findPool(List<Chunk> chunks) {
        Chunk pool = null;
        for (Chunk chunk : chunks) {
            if (chunk.type != RES_STRING_POOL_TYPE) continue;
            if (pool != null) throw invalid("multiple string pools");
            pool = chunk;
        }
        if (pool == null) throw invalid("missing string pool");
        return pool;
    }

    private static Set<Integer> collectNamespaceUris(byte[] data, List<Chunk> chunks,
                                                      int stringCount) {
        LinkedHashSet<Integer> uris = new LinkedHashSet<>();
        for (Chunk chunk : chunks) {
            if (chunk.type != RES_XML_START_NAMESPACE_TYPE) continue;
            int uri = get32(data, chunk.offset + 20);
            if (uri == NO_INDEX) continue;
            if (uri < 0 || uri >= stringCount) throw invalid("namespace URI outside pool");
            uris.add(uri);
        }
        return uris;
    }

    private static List<byte[]> extractStringEntries(byte[] data, Chunk pool, PoolInfo info) {
        int dataStart = pool.offset + info.stringsStart;
        int dataEnd = info.stylesStart == 0 ? pool.offset + pool.size
                : pool.offset + info.stylesStart;
        ArrayList<byte[]> entries = new ArrayList<>(info.stringCount);
        for (int offset : info.offsets) {
            int start = dataStart + offset;
            if (start < dataStart || start >= dataEnd) throw invalid("string offset outside pool");
            int length = encodedStringLength(data, start, dataEnd, info.utf8());
            entries.add(Arrays.copyOfRange(data, start, start + length));
        }
        return entries;
    }

    private static int encodedStringLength(byte[] data, int start, int end, boolean utf8) {
        int cursor = start;
        if (utf8) {
            Length utf16Length = readLength8(data, cursor, end);
            Length byteLength = readLength8(data, utf16Length.next, end);
            cursor = byteLength.next;
            if ((long) cursor + byteLength.value + 1L > end) throw invalid("truncated UTF-8 string");
            if (data[cursor + byteLength.value] != 0) throw invalid("unterminated UTF-8 string");
            return cursor + byteLength.value + 1 - start;
        }
        Length utf16Length = readLength16(data, cursor, end);
        cursor = utf16Length.next;
        long terminator = (long) cursor + (long) utf16Length.value * 2L;
        if (terminator + 2L > end) throw invalid("truncated UTF-16 string");
        if (data[(int) terminator] != 0 || data[(int) terminator + 1] != 0) {
            throw invalid("unterminated UTF-16 string");
        }
        return (int) terminator + 2 - start;
    }

    private static Length readLength8(byte[] data, int offset, int end) {
        if (offset >= end) throw invalid("truncated UTF-8 length");
        int first = data[offset] & 0xff;
        if ((first & 0x80) == 0) return new Length(first, offset + 1);
        if (offset + 1 >= end) throw invalid("truncated UTF-8 length");
        return new Length(((first & 0x7f) << 8) | (data[offset + 1] & 0xff), offset + 2);
    }

    private static Length readLength16(byte[] data, int offset, int end) {
        if (offset + 2 > end) throw invalid("truncated UTF-16 length");
        int first = get16(data, offset);
        if ((first & 0x8000) == 0) return new Length(first, offset + 2);
        if (offset + 4 > end) throw invalid("truncated UTF-16 length");
        int value = ((first & 0x7fff) << 16) | get16(data, offset + 2);
        return new Length(value, offset + 4);
    }

    private static byte[] encodeString(String value, boolean utf8) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(value.length() * 2 + 8);
        if (utf8) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            writeLength8(output, value.length());
            writeLength8(output, bytes.length);
            output.writeBytes(bytes);
            output.write(0);
        } else {
            writeLength16(output, value.length());
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                output.write(c & 0xff);
                output.write((c >>> 8) & 0xff);
            }
            output.write(0);
            output.write(0);
        }
        return output.toByteArray();
    }

    private static void writeLength8(ByteArrayOutputStream output, int value) {
        if (value < 0 || value > 0x7fff) throw invalid("generated UTF-8 string too long");
        if (value <= 0x7f) {
            output.write(value);
        } else {
            output.write((value >>> 8) | 0x80);
            output.write(value & 0xff);
        }
    }

    private static void writeLength16(ByteArrayOutputStream output, int value) {
        if (value < 0) throw invalid("negative UTF-16 length");
        if (value <= 0x7fff) {
            output.write(value & 0xff);
            output.write((value >>> 8) & 0xff);
        } else {
            int high = (value >>> 16) | 0x8000;
            output.write(high & 0xff);
            output.write((high >>> 8) & 0xff);
            output.write(value & 0xff);
            output.write((value >>> 8) & 0xff);
        }
    }

    private static String opaqueName(long seed, int ordinal, String prefix) {
        long first = mix64(seed + 0x9e3779b97f4a7c15L * (ordinal + 1L));
        long second = mix64(first ^ 0xd1b54a32d192ed03L);
        return prefix + fixedHex(first) + fixedHex(second);
    }

    private static long mix64(long value) {
        value = (value ^ (value >>> 30)) * 0xbf58476d1ce4e5b9L;
        value = (value ^ (value >>> 27)) * 0x94d049bb133111ebL;
        return value ^ (value >>> 31);
    }

    private static String fixedHex(long value) {
        String hex = Long.toUnsignedString(value, 16);
        return "0".repeat(16 - hex.length()) + hex;
    }

    private static List<Integer> shuffledOrder(int stringCount, int resourceCount, Random random) {
        ArrayList<Integer> order = new ArrayList<>(stringCount);
        for (int i = 0; i < stringCount; i++) order.add(i);
        Collections.shuffle(order.subList(0, resourceCount), random);
        Collections.shuffle(order.subList(resourceCount, order.size()), random);
        if (resourceCount >= 2 && identityAt(order, 0, resourceCount)) {
            Collections.swap(order, 0, 1);
        } else if (stringCount - resourceCount >= 2
                && identityAt(order, resourceCount, stringCount)) {
            Collections.swap(order, resourceCount, resourceCount + 1);
        }
        return order;
    }

    private static boolean identityAt(List<Integer> order, int start, int end) {
        for (int i = start; i < end; i++) if (order.get(i) != i) return false;
        return true;
    }

    private static int[] remap(List<Integer> order) {
        int[] result = new int[order.size()];
        for (int newIndex = 0; newIndex < order.size(); newIndex++) {
            result[order.get(newIndex)] = newIndex;
        }
        return result;
    }

    private static byte[] rebuildPool(byte[] data, Chunk pool, PoolInfo info,
                                      List<byte[]> entries, List<Integer> order) {
        int count = entries.size();
        int stringsStart = align4(info.headerSize + count * 4);
        ByteArrayOutputStream strings = new ByteArrayOutputStream();
        int[] offsets = new int[count];
        for (int newIndex = 0; newIndex < count; newIndex++) {
            offsets[newIndex] = strings.size();
            strings.writeBytes(entries.get(order.get(newIndex)));
        }
        while ((strings.size() & 3) != 0) strings.write(0);

        byte[] stringBytes = strings.toByteArray();
        byte[] rebuilt = new byte[stringsStart + stringBytes.length];
        System.arraycopy(data, pool.offset, rebuilt, 0, info.headerSize);
        put16(rebuilt, 0, RES_STRING_POOL_TYPE);
        put16(rebuilt, 2, info.headerSize);
        put32(rebuilt, 4, rebuilt.length);
        put32(rebuilt, 8, count);
        put32(rebuilt, 12, 0);
        put32(rebuilt, 16, info.flags & ~SORTED_FLAG);
        put32(rebuilt, 20, stringsStart);
        put32(rebuilt, 24, 0);
        for (int i = 0; i < offsets.length; i++) {
            put32(rebuilt, info.headerSize + i * 4, offsets[i]);
        }
        System.arraycopy(stringBytes, 0, rebuilt, stringsStart, stringBytes.length);
        return rebuilt;
    }

    private static byte[] replacePool(byte[] data, Chunk pool, byte[] rebuiltPool) {
        if (get16(data, 0) != RES_XML_TYPE || get32(data, 4) != data.length) {
            throw invalid("missing XML root for pool expansion");
        }
        int delta = rebuiltPool.length - pool.size;
        byte[] output = new byte[data.length + delta];
        System.arraycopy(data, 0, output, 0, pool.offset);
        System.arraycopy(rebuiltPool, 0, output, pool.offset, rebuiltPool.length);
        System.arraycopy(data, pool.offset + pool.size, output, pool.offset + rebuiltPool.length,
                data.length - pool.offset - pool.size);
        put32(output, 4, output.length);
        return output;
    }

    private static void rewriteReferences(byte[] data, List<Chunk> chunks, int[] remap,
                                          int originalStringCount) {
        for (Chunk chunk : chunks) {
            switch (chunk.type) {
                case RES_XML_RESOURCE_MAP_TYPE ->
                        rewriteResourceMap(data, chunk, remap, originalStringCount);
                case RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE -> {
                    remapIndex(data, chunk.offset + 16, remap, originalStringCount);
                    remapIndex(data, chunk.offset + 20, remap, originalStringCount);
                }
                case RES_XML_START_ELEMENT_TYPE ->
                        rewriteStartElementReferences(data, chunk, remap, originalStringCount);
                case RES_XML_END_ELEMENT_TYPE -> {
                    remapIndex(data, chunk.offset + 16, remap, originalStringCount);
                    remapIndex(data, chunk.offset + 20, remap, originalStringCount);
                }
                case RES_XML_CDATA_TYPE ->
                        remapIndex(data, chunk.offset + 16, remap, originalStringCount);
                default -> {
                }
            }
        }
    }

    private static void rewriteNamespacePrefixes(byte[] data, List<Chunk> chunks,
                                                  Map<Integer, Integer> aliases,
                                                  int[] remap) {
        if (aliases.isEmpty()) return;
        LinkedHashMap<Integer, Integer> finalAliases = new LinkedHashMap<>();
        for (Map.Entry<Integer, Integer> entry : aliases.entrySet()) {
            finalAliases.put(remap[entry.getKey()], remap[entry.getValue()]);
        }
        for (Chunk chunk : chunks) {
            if (chunk.type != RES_XML_START_NAMESPACE_TYPE
                    && chunk.type != RES_XML_END_NAMESPACE_TYPE) continue;
            int uri = get32(data, chunk.offset + 20);
            Integer alias = finalAliases.get(uri);
            if (alias != null) put32(data, chunk.offset + 16, alias);
        }
    }

    private static void rewriteResourceMap(byte[] data, Chunk chunk, int[] remap,
                                           int originalStringCount) {
        int count = (chunk.size - chunk.headerSize) / 4;
        if (count > originalStringCount) throw invalid("resource map exceeds string pool");
        int[] ids = new int[count];
        for (int oldIndex = 0; oldIndex < count; oldIndex++) {
            int newIndex = remap[oldIndex];
            if (newIndex < 0 || newIndex >= count) throw invalid("resource string escaped map prefix");
            ids[newIndex] = get32(data, chunk.offset + chunk.headerSize + oldIndex * 4);
        }
        for (int i = 0; i < count; i++) {
            put32(data, chunk.offset + chunk.headerSize + i * 4, ids[i]);
        }
    }

    private static int resourceMapCount(List<Chunk> chunks, int stringCount) {
        int count = 0;
        for (Chunk chunk : chunks) {
            if (chunk.type != RES_XML_RESOURCE_MAP_TYPE) continue;
            int current = (chunk.size - chunk.headerSize) / 4;
            if (current > stringCount) throw invalid("resource map exceeds string pool");
            count = Math.max(count, current);
        }
        return count;
    }

    private static void rewriteStartElementReferences(byte[] data, Chunk chunk, int[] remap,
                                                       int originalStringCount) {
        remapIndex(data, chunk.offset + 16, remap, originalStringCount);
        remapIndex(data, chunk.offset + 20, remap, originalStringCount);
        AttributeBlock block = attributeBlock(data, chunk);
        for (int i = 0; i < block.count; i++) {
            int attr = block.offset + i * block.size;
            remapIndex(data, attr, remap, originalStringCount);
            remapIndex(data, attr + 4, remap, originalStringCount);
            remapIndex(data, attr + 8, remap, originalStringCount);
            if ((data[attr + 15] & 0xff) == TYPE_STRING) {
                remapIndex(data, attr + 16, remap, originalStringCount);
            }
        }
    }

    private static ShuffleStats shuffleAttributes(byte[] data, List<Chunk> chunks, long seed) {
        Random random = new Random(seed ^ ATTRIBUTE_DOMAIN);
        int[] resourceIds = resourceIdsByStringIndex(data, chunks);
        int changedElements = 0;
        int changedAttributes = 0;
        for (Chunk chunk : chunks) {
            if (chunk.type != RES_XML_START_ELEMENT_TYPE) continue;
            AttributeBlock block = attributeBlock(data, chunk);
            if (block.count < 2) continue;

            // Framework TypedArray lookup expects resource-backed attributes to retain
            // aapt2's resource-ID ordering. Only permute opaque (resource ID 0) records;
            // they are resolved by name and can safely trade positions with each other.
            ArrayList<Integer> positions = new ArrayList<>();
            for (int i = 0; i < block.count; i++) {
                int nameIndex = get32(data, block.offset + i * block.size + 4);
                if (nameIndex < 0 || nameIndex >= resourceIds.length) {
                    throw invalid("attribute name outside final string pool");
                }
                if (resourceIds[nameIndex] == 0) positions.add(i);
            }
            if (positions.size() < 2) continue;

            ArrayList<Integer> sources = new ArrayList<>(positions);
            Collections.shuffle(sources, random);
            if (sources.equals(positions)) Collections.swap(sources, 0, 1);

            byte[] original = Arrays.copyOfRange(data, block.offset,
                    block.offset + block.count * block.size);
            int[] oldToNew = new int[block.count];
            for (int i = 0; i < block.count; i++) oldToNew[i] = i;
            for (int i = 0; i < positions.size(); i++) {
                int newIndex = positions.get(i);
                int oldIndex = sources.get(i);
                oldToNew[oldIndex] = newIndex;
                System.arraycopy(original, oldIndex * block.size, data,
                        block.offset + newIndex * block.size, block.size);
            }

            int ext = chunk.offset + 16;
            rewriteSpecialAttributeIndex(data, ext + 14, block.count, oldToNew);
            rewriteSpecialAttributeIndex(data, ext + 16, block.count, oldToNew);
            rewriteSpecialAttributeIndex(data, ext + 18, block.count, oldToNew);
            changedElements++;
            changedAttributes += positions.size();
        }
        return new ShuffleStats(changedElements, changedAttributes);
    }

    private static int[] resourceIdsByStringIndex(byte[] data, List<Chunk> chunks) {
        PoolInfo info = parsePool(data, findPool(chunks));
        int[] resourceIds = new int[info.stringCount];
        for (Chunk chunk : chunks) {
            if (chunk.type != RES_XML_RESOURCE_MAP_TYPE) continue;
            int count = (chunk.size - chunk.headerSize) / 4;
            if (count > resourceIds.length) throw invalid("resource map exceeds final string pool");
            for (int i = 0; i < count; i++) {
                resourceIds[i] = get32(data, chunk.offset + chunk.headerSize + i * 4);
            }
        }
        return resourceIds;
    }

    private static AttributeBlock attributeBlock(byte[] data, Chunk chunk) {
        int ext = chunk.offset + 16;
        int attrStart = get16(data, ext + 8);
        int attrSize = get16(data, ext + 10);
        int attrCount = get16(data, ext + 12);
        if (attrStart < 20 || attrSize < 20) throw invalid("invalid attribute layout");
        int attrs = ext + attrStart;
        long end = (long) attrs + (long) attrCount * attrSize;
        if (attrs < ext || end > chunk.offset + chunk.size) {
            throw invalid("attributes outside element");
        }
        return new AttributeBlock(attrs, attrSize, attrCount);
    }

    private static void rewriteSpecialAttributeIndex(byte[] data, int offset, int count,
                                                     int[] oldToNew) {
        int oldOneBased = get16(data, offset);
        if (oldOneBased == 0) return;
        if (oldOneBased > count) throw invalid("special attribute index outside element");
        put16(data, offset, oldToNew[oldOneBased - 1] + 1);
    }

    private static int rewriteLineNumbers(byte[] data, List<Chunk> chunks, long seed) {
        Random random = new Random(seed ^ LINE_DOMAIN);
        int count = 0;
        for (Chunk chunk : chunks) {
            switch (chunk.type) {
                case RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE,
                        RES_XML_START_ELEMENT_TYPE, RES_XML_END_ELEMENT_TYPE,
                        RES_XML_CDATA_TYPE -> {
                    put32(data, chunk.offset + 8, 1 + random.nextInt(0xffff));
                    count++;
                }
                default -> {
                }
            }
        }
        return count;
    }

    private static void remapIndex(byte[] data, int offset, int[] remap,
                                   int originalStringCount) {
        int value = get32(data, offset);
        if (value == NO_INDEX) return;
        if (value < 0 || value >= originalStringCount) throw invalid("string index outside pool");
        put32(data, offset, remap[value]);
    }

    private static PoolInfo parsePool(byte[] data, Chunk chunk) {
        if (chunk.headerSize < 28) throw invalid("invalid string pool header");
        int count = get32(data, chunk.offset + 8);
        int styleCount = get32(data, chunk.offset + 12);
        int flags = get32(data, chunk.offset + 16);
        int stringsStart = get32(data, chunk.offset + 20);
        int stylesStart = get32(data, chunk.offset + 24);
        if (count < 0 || styleCount < 0 || stringsStart < chunk.headerSize
                || stringsStart >= chunk.size) throw invalid("invalid string pool bounds");
        if (stylesStart != 0 && (stylesStart < stringsStart || stylesStart > chunk.size)) {
            throw invalid("invalid style pool bounds");
        }
        int offsetsStart = chunk.offset + chunk.headerSize;
        if ((long) offsetsStart + (long) (count + styleCount) * 4L
                > chunk.offset + chunk.size) throw invalid("string offsets outside chunk");
        int[] offsets = new int[count];
        for (int i = 0; i < count; i++) offsets[i] = get32(data, offsetsStart + i * 4);
        return new PoolInfo(chunk.headerSize, count, styleCount, flags,
                stringsStart, stylesStart, offsets);
    }

    private static List<Chunk> chunks(byte[] data) {
        if (data.length < 8) throw invalid("truncated AXML");
        ArrayList<Chunk> result = new ArrayList<>();
        int rootType = get16(data, 0);
        int rootHeader = get16(data, 2);
        int rootSize = get32(data, 4);
        if (rootType == RES_XML_TYPE) {
            if (rootHeader < 8 || rootSize != data.length) throw invalid("invalid XML root chunk");
            return childChunks(data, rootHeader, rootSize, result);
        }
        return childChunks(data, 0, data.length, result);
    }

    private static List<Chunk> childChunks(byte[] data, int start, int end,
                                           ArrayList<Chunk> result) {
        int offset = start;
        while (offset < end) {
            if (data.length - offset < 8) throw invalid("truncated chunk header");
            int type = get16(data, offset);
            int headerSize = get16(data, offset + 2);
            int size = get32(data, offset + 4);
            if (headerSize < 8 || size < headerSize || offset + size > end) {
                throw invalid("invalid chunk bounds");
            }
            result.add(new Chunk(offset, type, headerSize, size));
            offset += size;
        }
        if (offset != end) throw invalid("chunk boundary mismatch");
        return result;
    }

    private static int align4(int value) {
        return (value + 3) & ~3;
    }

    private static int get16(byte[] data, int offset) {
        if (offset < 0 || offset + 2 > data.length) throw invalid("truncated uint16");
        return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8);
    }

    private static int get32(byte[] data, int offset) {
        if (offset < 0 || offset + 4 > data.length) throw invalid("truncated uint32");
        return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16) | ((data[offset + 3] & 0xff) << 24);
    }

    private static void put16(byte[] data, int offset, int value) {
        if (offset < 0 || offset + 2 > data.length) throw invalid("truncated uint16 write");
        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >>> 8);
    }

    private static void put32(byte[] data, int offset, int value) {
        if (offset < 0 || offset + 4 > data.length) throw invalid("truncated uint32 write");
        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >>> 8);
        data[offset + 2] = (byte) (value >>> 16);
        data[offset + 3] = (byte) (value >>> 24);
    }

    private static IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException("Invalid AndroidManifest.xml: " + message);
    }

    private record Chunk(int offset, int type, int headerSize, int size) {
    }

    private record PoolInfo(int headerSize, int stringCount, int styleCount, int flags,
                            int stringsStart, int stylesStart, int[] offsets) {
        boolean utf8() {
            return (flags & UTF8_FLAG) != 0;
        }
    }

    private record Length(int value, int next) {
    }

    private record AttributeBlock(int offset, int size, int count) {
    }

    private record ShuffleStats(int elements, int attributes) {
    }
}
