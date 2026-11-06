package com.nmmedit.apkprotect.util;

import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class ElfAntiObjdumpPatcherTest {
    private static final int RUNTIME_END = 0x200;
    private static final int STRING_TABLE_OFFSET = 0x220;
    private static final int COMMENT_OFFSET = 0x260;
    private static final int SECTION_TABLE_OFFSET = 0x300;
    private static final byte[] SECTION_NAMES =
            "\0.text\0.comment\0.shstrtab\0".getBytes(StandardCharsets.US_ASCII);

    @Test
    public void hardensElf64WithoutChangingRuntimePayload() throws Exception {
        verifyFixture(true);
    }

    @Test
    public void hardensElf32WithoutChangingRuntimePayload() throws Exception {
        verifyFixture(false);
    }

    @Test
    public void rejectsTruncatedSectionTable() throws Exception {
        final byte[] fixture = fixture(true);
        final ByteBuffer header = ByteBuffer.wrap(fixture).order(ByteOrder.LITTLE_ENDIAN);
        header.putLong(40, fixture.length - 16L);
        final Path file = Files.createTempFile("nmmp-corrupt-elf-", ".so");
        try {
            Files.write(file, fixture);
            assertThrows(IOException.class,
                    () -> ElfAntiObjdumpPatcher.patch(file.toFile()));
        } finally {
            Files.deleteIfExists(file);
        }
    }

    @Test
    public void hardensExternalElfWhenRequested() throws Exception {
        final String externalPath = System.getenv("NMMP_VERIFY_ANTI_OBJDUMP_SO");
        if (externalPath == null || externalPath.isBlank()) return;

        final Path source = Path.of(externalPath);
        assertTrue("missing external ELF: " + source, Files.isRegularFile(source));
        final Path copy = Files.createTempFile("nmmp-real-sectionless-", ".so");
        try {
            Files.copy(source, copy, StandardCopyOption.REPLACE_EXISTING);
            final byte[] original = Files.readAllBytes(copy);
            final ElfAntiObjdumpPatcher.Result result =
                    ElfAntiObjdumpPatcher.patch(copy.toFile());
            final byte[] hardened = Files.readAllBytes(copy);
            final boolean elf64 = hardened[4] == 2;
            final ByteBuffer originalHeader =
                    ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);
            final long originalSectionOffset = elf64
                    ? originalHeader.getLong(40)
                    : Integer.toUnsignedLong(originalHeader.getInt(32));
            final ByteBuffer header = ByteBuffer.wrap(hardened).order(ByteOrder.LITTLE_ENDIAN);
            assertFalse(result.alreadyHardened());
            assertTrue(result.originalSectionCount() > 0);
            assertTrue(result.modifiedSectionCount() > 0);
            assertEquals(originalSectionOffset, elf64 ? header.getLong(40)
                    : Integer.toUnsignedLong(header.getInt(32)));
            assertEquals(result.originalSectionCount(),
                    Short.toUnsignedInt(header.getShort(elf64 ? 60 : 48)));
            assertProgramRangesPreserved(original, hardened, elf64);

            final String report = "INPUT=" + source.toAbsolutePath() + "\n"
                    + "ORIGINAL_SECTIONS=" + result.originalSectionCount() + "\n"
                    + "EXECUTABLE_FLAGS_CLEARED=" + result.modifiedSectionCount() + "\n"
                    + "RUNTIME_RANGES=" + result.runtimeRangeCount() + "\n"
                    + "SECTIONS_PRESERVED=" + result.originalSectionCount() + "\n";
            final String reportPath = System.getenv("NMMP_VERIFY_ANTI_OBJDUMP_REPORT");
            if (reportPath != null && !reportPath.isBlank()) {
                Files.writeString(Path.of(reportPath), report, StandardCharsets.UTF_8);
            }
            System.out.print(report);
        } finally {
            Files.deleteIfExists(copy);
        }
    }

    private static void verifyFixture(boolean elf64) throws Exception {
        final byte[] original = fixture(elf64);
        final Path file = Files.createTempFile(
                elf64 ? "nmmp-elf64-" : "nmmp-elf32-", ".so");
        try {
            Files.write(file, original);
            final ElfAntiObjdumpPatcher.Result result =
                    ElfAntiObjdumpPatcher.patch(file.toFile());
            final byte[] hardened = Files.readAllBytes(file);

            assertFalse(result.alreadyHardened());
            assertEquals(4, result.originalSectionCount());
            assertEquals(1, result.modifiedSectionCount());
            assertEquals(1, result.runtimeRangeCount());
            assertEquals(original.length, hardened.length);

            assertProgramRangesPreserved(original, hardened, elf64);

            final ByteBuffer header = ByteBuffer.wrap(hardened).order(ByteOrder.LITTLE_ENDIAN);
            assertEquals(SECTION_TABLE_OFFSET, elf64 ? header.getLong(40)
                    : Integer.toUnsignedLong(header.getInt(32)));
            assertEquals(elf64 ? 64 : 40,
                    Short.toUnsignedInt(header.getShort(elf64 ? 58 : 46)));
            assertEquals(4, Short.toUnsignedInt(header.getShort(elf64 ? 60 : 48)));
            assertEquals(3, Short.toUnsignedInt(header.getShort(elf64 ? 62 : 50)));

            final int sectionEntrySize = elf64 ? 64 : 40;
            final int flagsOffset = SECTION_TABLE_OFFSET + sectionEntrySize + 8;
            if (elf64) {
                assertEquals(0x2L, header.getLong(flagsOffset));
            } else {
                assertEquals(0x2, header.getInt(flagsOffset));
            }
            final byte[] expected = original.clone();
            final ByteBuffer expectedHeader = ByteBuffer.wrap(expected).order(ByteOrder.LITTLE_ENDIAN);
            if (elf64) {
                expectedHeader.putLong(flagsOffset, 0x2L);
            } else {
                expectedHeader.putInt(flagsOffset, 0x2);
            }
            assertArrayEquals(expected, hardened);

            final byte[] beforeSecondPass = hardened.clone();
            final ElfAntiObjdumpPatcher.Result second =
                    ElfAntiObjdumpPatcher.patch(file.toFile());
            assertTrue(second.alreadyHardened());
            assertEquals(4, second.originalSectionCount());
            assertEquals(0, second.modifiedSectionCount());
            assertArrayEquals(beforeSecondPass, Files.readAllBytes(file));
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static byte[] fixture(boolean elf64) {
        final byte[] data = new byte[0x500];
        final ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        data[0] = 0x7f;
        data[1] = 'E';
        data[2] = 'L';
        data[3] = 'F';
        data[4] = (byte) (elf64 ? 2 : 1);
        data[5] = 1;
        data[6] = 1;

        final int headerSize = elf64 ? 64 : 52;
        final int programEntrySize = elf64 ? 56 : 32;
        final int sectionEntrySize = elf64 ? 64 : 40;
        buffer.putShort(16, (short) 3);
        buffer.putShort(18, (short) (elf64 ? 183 : 40));
        buffer.putInt(20, 1);
        if (elf64) {
            buffer.putLong(32, headerSize);
            buffer.putLong(40, SECTION_TABLE_OFFSET);
            buffer.putShort(52, (short) headerSize);
            buffer.putShort(54, (short) programEntrySize);
            buffer.putShort(56, (short) 1);
            buffer.putShort(58, (short) sectionEntrySize);
            buffer.putShort(60, (short) 4);
            buffer.putShort(62, (short) 3);
        } else {
            buffer.putInt(28, headerSize);
            buffer.putInt(32, SECTION_TABLE_OFFSET);
            buffer.putShort(40, (short) headerSize);
            buffer.putShort(42, (short) programEntrySize);
            buffer.putShort(44, (short) 1);
            buffer.putShort(46, (short) sectionEntrySize);
            buffer.putShort(48, (short) 4);
            buffer.putShort(50, (short) 3);
        }

        writeProgramHeader(buffer, headerSize, elf64);
        Arrays.fill(data, 0x100, 0x120, (byte) 0xa5);
        System.arraycopy(SECTION_NAMES, 0, data,
                STRING_TABLE_OFFSET, SECTION_NAMES.length);
        final byte[] comment = "clang metadata must go".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(comment, 0, data, COMMENT_OFFSET, comment.length);

        writeSection(buffer, SECTION_TABLE_OFFSET + sectionEntrySize,
                elf64, 1, 1, 0x6, 0x100, 0x20);
        writeSection(buffer, SECTION_TABLE_OFFSET + 2 * sectionEntrySize,
                elf64, 7, 1, 0, COMMENT_OFFSET, 24);
        writeSection(buffer, SECTION_TABLE_OFFSET + 3 * sectionEntrySize,
                elf64, 16, 3, 0, STRING_TABLE_OFFSET, SECTION_NAMES.length);
        return data;
    }

    private static void writeProgramHeader(ByteBuffer buffer,
                                           int offset,
                                           boolean elf64) {
        buffer.putInt(offset, 1);
        if (elf64) {
            buffer.putInt(offset + 4, 5);
            buffer.putLong(offset + 8, 0);
            buffer.putLong(offset + 16, 0x10000);
            buffer.putLong(offset + 24, 0x10000);
            buffer.putLong(offset + 32, RUNTIME_END);
            buffer.putLong(offset + 40, RUNTIME_END);
            buffer.putLong(offset + 48, 0x1000);
        } else {
            buffer.putInt(offset + 4, 0);
            buffer.putInt(offset + 8, 0x10000);
            buffer.putInt(offset + 12, 0x10000);
            buffer.putInt(offset + 16, RUNTIME_END);
            buffer.putInt(offset + 20, RUNTIME_END);
            buffer.putInt(offset + 24, 5);
            buffer.putInt(offset + 28, 0x1000);
        }
    }

    private static void writeSection(ByteBuffer buffer,
                                     int offset,
                                     boolean elf64,
                                     int name,
                                     int type,
                                     long flags,
                                     int fileOffset,
                                     int size) {
        buffer.putInt(offset, name);
        buffer.putInt(offset + 4, type);
        if (elf64) {
            buffer.putLong(offset + 8, flags);
            buffer.putLong(offset + 24, fileOffset);
            buffer.putLong(offset + 32, size);
            buffer.putLong(offset + 48, 1);
        } else {
            buffer.putInt(offset + 8, (int) flags);
            buffer.putInt(offset + 16, fileOffset);
            buffer.putInt(offset + 20, size);
            buffer.putInt(offset + 32, 1);
        }
    }

    private static void assertZero(byte[] data, int offset, int size) {
        for (int i = offset; i < offset + size; i++) {
            assertEquals("non-zero byte at 0x" + Integer.toHexString(i), 0, data[i]);
        }
    }

    private static void assertProgramRangesPreserved(byte[] original,
                                                     byte[] hardened,
                                                     boolean elf64) {
        assertEquals(original.length, hardened.length);
        final ByteBuffer header = ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);
        final long tableOffset = elf64 ? header.getLong(32)
                : Integer.toUnsignedLong(header.getInt(28));
        final int entrySize = Short.toUnsignedInt(header.getShort(elf64 ? 54 : 42));
        final int count = Short.toUnsignedInt(header.getShort(elf64 ? 56 : 44));
        for (int i = 0; i < count; i++) {
            final int entry = Math.toIntExact(tableOffset + (long) i * entrySize);
            final long fileOffset = elf64 ? header.getLong(entry + 8)
                    : Integer.toUnsignedLong(header.getInt(entry + 4));
            final long fileSize = elf64 ? header.getLong(entry + 32)
                    : Integer.toUnsignedLong(header.getInt(entry + 16));
            for (long position = fileOffset; position < fileOffset + fileSize; position++) {
                final int offset = Math.toIntExact(position);
                if (isSuppressedHeaderField(offset, elf64)) continue;
                assertEquals("runtime byte changed at 0x" + Long.toHexString(position),
                        original[offset], hardened[offset]);
            }
        }
    }

    private static boolean isSuppressedHeaderField(int offset, boolean elf64) {
        final int sectionCount = elf64 ? 60 : 48;
        return offset >= sectionCount && offset < sectionCount + 4;
    }
}
