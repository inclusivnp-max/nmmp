package com.nmmedit.apkprotect.util;

import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class ElfIntegrityPatcher {
    private static final int PT_LOAD = 1;
    private static final int PT_DYNAMIC = 2;
    private static final int PF_X = 1;
    private static final long DT_NULL = 0;
    private static final long DT_TEXTREL = 22;
    private static final long DT_FLAGS = 30;
    private static final long DF_TEXTREL = 4;
    private static final byte[] PLACEHOLDER = {
            0x71, 0x3c, (byte) 0xa9, 0x52, (byte) 0xe6, 0x18, 0x4d, (byte) 0xbf,
            (byte) 0x90, 0x27, 0x65, (byte) 0xda, 0x43, (byte) 0xbc, 0x0f, (byte) 0x81,
            0x5e, (byte) 0xd4, 0x39, (byte) 0xa7, (byte) 0xc2, 0x68, (byte) 0xf1, 0x0b,
            (byte) 0x96, 0x54, 0x2d, (byte) 0xe3, 0x7a, (byte) 0xc8, 0x11, 0x6f
    };

    private ElfIntegrityPatcher() {
    }

    public static @NotNull byte[] patch(@NotNull File elf) throws IOException {
        final byte[] data = Files.readAllBytes(elf.toPath());
        if (data.length < 64 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
            throw new IOException("Not an ELF file: " + elf);
        }
        if (data[5] != 1) {
            throw new IOException("Only little-endian ELF is supported: " + elf);
        }

        final ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        final boolean elf64 = data[4] == 2;
        if (!elf64 && data[4] != 1) throw new IOException("Unsupported ELF class: " + data[4]);

        final long phoff = elf64 ? buf.getLong(32) : u32(buf, 28);
        final int phentsize = Short.toUnsignedInt(buf.getShort(elf64 ? 54 : 42));
        final int phnum = Short.toUnsignedInt(buf.getShort(elf64 ? 56 : 44));
        final int minimumPhdr = elf64 ? 56 : 32;
        if (phentsize < minimumPhdr || phnum == 0 || phoff < 0 || phoff + (long) phentsize * phnum > data.length) {
            throw new IOException("Invalid ELF program headers: " + elf);
        }

        final List<Segment> executable = new ArrayList<>();
        final List<Segment> dynamic = new ArrayList<>();
        for (int i = 0; i < phnum; i++) {
            final int off = Math.toIntExact(phoff + (long) i * phentsize);
            final int type = buf.getInt(off);
            final int flags = elf64 ? buf.getInt(off + 4) : buf.getInt(off + 24);
            final long fileOffset = elf64 ? buf.getLong(off + 8) : u32(buf, off + 4);
            final long fileSize = elf64 ? buf.getLong(off + 32) : u32(buf, off + 16);
            checkRange(fileOffset, fileSize, data.length, elf);
            final Segment segment = new Segment(fileOffset, fileSize);
            if (type == PT_LOAD && (flags & PF_X) != 0 && fileSize != 0) executable.add(segment);
            if (type == PT_DYNAMIC && fileSize != 0) dynamic.add(segment);
        }
        if (executable.isEmpty()) throw new IOException("No executable PT_LOAD segment: " + elf);
        rejectTextRelocations(buf, dynamic, elf64, elf);

        final int placeholder = findUnique(data, PLACEHOLDER);
        for (Segment segment : executable) {
            if (placeholder >= segment.offset && placeholder < segment.offset + segment.size) {
                throw new IOException("Integrity placeholder is inside executable segment: " + elf);
            }
        }

        try {
            final MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (Segment segment : executable) {
                sha.update(data, Math.toIntExact(segment.offset), Math.toIntExact(segment.size));
            }
            final byte[] digest = sha.digest();
            System.arraycopy(digest, 0, data, placeholder, digest.length);
            Files.write(elf.toPath(), data);
            return digest;
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    private static void rejectTextRelocations(ByteBuffer buf, List<Segment> dynamic,
                                              boolean elf64, File elf) throws IOException {
        final int entrySize = elf64 ? 16 : 8;
        for (Segment segment : dynamic) {
            for (long p = segment.offset; p + entrySize <= segment.offset + segment.size; p += entrySize) {
                final int off = Math.toIntExact(p);
                final long tag = elf64 ? buf.getLong(off) : u32(buf, off);
                final long value = elf64 ? buf.getLong(off + 8) : u32(buf, off + 4);
                if (tag == DT_NULL) break;
                if (tag == DT_TEXTREL || (tag == DT_FLAGS && (value & DF_TEXTREL) != 0)) {
                    throw new IOException("ELF contains text relocations: " + elf);
                }
            }
        }
    }

    private static int findUnique(byte[] data, byte[] needle) throws IOException {
        int found = -1;
        for (int i = 0; i <= data.length - needle.length; i++) {
            if (!matches(data, i, needle)) continue;
            if (found >= 0) throw new IOException("Multiple integrity placeholders found");
            found = i;
        }
        if (found < 0) throw new IOException("Integrity placeholder not found");
        return found;
    }

    private static boolean matches(byte[] data, int offset, byte[] needle) {
        return Arrays.equals(data, offset, offset + needle.length, needle, 0, needle.length);
    }

    private static long u32(ByteBuffer buf, int offset) {
        return Integer.toUnsignedLong(buf.getInt(offset));
    }

    private static void checkRange(long offset, long size, int fileSize, File elf) throws IOException {
        if (offset < 0 || size < 0 || offset > fileSize || size > fileSize - offset) {
            throw new IOException("Invalid ELF segment range: " + elf);
        }
    }

    private record Segment(long offset, long size) {
    }
}
