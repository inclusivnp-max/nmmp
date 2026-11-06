package com.nmmedit.apkprotect.util;

import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.Set;

/**
 * Disables default section-based disassembly without deleting ELF metadata
 * required by Android native-bridge loaders.
 *
 * <p>The patcher preserves the complete section table, names, dynamic metadata,
 * symbols, relocations and every file-backed program segment. It only clears
 * {@code SHF_EXECINSTR} in section-header flags. LLVM objdump's default
 * {@code -d} path then has no executable section to select, while Android's
 * linker and native-bridge implementations can still locate {@code .dynamic}
 * and related sections.</p>
 */
public final class ElfAntiObjdumpPatcher {
    private static final int ELFCLASS32 = 1;
    private static final int ELFCLASS64 = 2;
    private static final int ELFDATA2LSB = 1;
    private static final int PN_XNUM = 0xffff;
    private static final int SHN_UNDEF = 0;
    private static final int SHN_XINDEX = 0xffff;
    private static final int SHT_NULL = 0;
    private static final int SHT_STRTAB = 3;
    private static final int SHT_NOBITS = 8;
    private static final long SHF_ALLOC = 0x2L;
    private static final long SHF_EXECINSTR = 0x4L;
    private static final byte[] DECOY_NAMES =
            "\0.shstrtab\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private ElfAntiObjdumpPatcher() {
    }

    public static @NotNull Result patch(@NotNull File elf) throws IOException {
        final Path path = elf.toPath();
        final byte[] data = Files.readAllBytes(path);
        validateMagic(data, elf);

        final int elfClass = Byte.toUnsignedInt(data[4]);
        final boolean elf64;
        final int minimumHeader;
        final int minimumProgramHeader;
        final int minimumSectionHeader;
        if (elfClass == ELFCLASS64) {
            elf64 = true;
            minimumHeader = 64;
            minimumProgramHeader = 56;
            minimumSectionHeader = 64;
        } else if (elfClass == ELFCLASS32) {
            elf64 = false;
            minimumHeader = 52;
            minimumProgramHeader = 32;
            minimumSectionHeader = 40;
        } else {
            throw new IOException("Unsupported ELF class " + elfClass + ": " + elf);
        }
        if (data.length < minimumHeader) {
            throw new IOException("Truncated ELF header: " + elf);
        }
        if (Byte.toUnsignedInt(data[5]) != ELFDATA2LSB) {
            throw new IOException("Only little-endian ELF is supported: " + elf);
        }

        final ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        final int sectionOffsetField = elf64 ? 40 : 32;
        final int sectionEntrySizeField = elf64 ? 58 : 46;
        final int sectionCountField = elf64 ? 60 : 48;
        final int sectionStringIndexField = elf64 ? 62 : 50;
        final long sectionOffset = elf64
                ? buffer.getLong(sectionOffsetField)
                : u32(buffer, sectionOffsetField);
        final int sectionEntrySize = Short.toUnsignedInt(
                buffer.getShort(sectionEntrySizeField));
        final int rawSectionCount = Short.toUnsignedInt(buffer.getShort(sectionCountField));
        final int rawStringIndex = Short.toUnsignedInt(
                buffer.getShort(sectionStringIndexField));

        if (sectionOffset == 0 && rawSectionCount == 0) {
            throw new IOException("Sectionless ELF has no metadata carrier for decoy table: " + elf);
        }
        if (sectionOffset <= 0 || sectionEntrySize < minimumSectionHeader) {
            throw new IOException("Invalid ELF section table: " + elf);
        }
        checkRange(sectionOffset, sectionEntrySize, data.length, "section table", elf);

        final int sectionCount;
        if (rawSectionCount == 0) {
            final long extendedCount = elf64
                    ? buffer.getLong(Math.toIntExact(sectionOffset) + 32)
                    : u32(buffer, Math.toIntExact(sectionOffset) + 20);
            sectionCount = checkedCount(extendedCount, "extended section count", elf);
        } else {
            sectionCount = rawSectionCount;
        }
        final long sectionTableSize = multiply(sectionEntrySize, sectionCount,
                "section table", elf);
        checkRange(sectionOffset, sectionTableSize, data.length, "section table", elf);

        final int sectionStringIndex;
        if (rawStringIndex == SHN_XINDEX) {
            final long extendedIndex = u32(buffer,
                    Math.toIntExact(sectionOffset) + (elf64 ? 40 : 24));
            sectionStringIndex = checkedIndex(extendedIndex, sectionCount,
                    "extended section string index", elf);
        } else {
            sectionStringIndex = rawStringIndex;
            if (sectionStringIndex != SHN_UNDEF && sectionStringIndex >= sectionCount) {
                throw new IOException("Section string index is out of range: " + elf);
            }
        }

        final List<FileRange> runtimeRanges = readProgramRanges(
                buffer, data.length, elf64, sectionOffset, sectionEntrySize,
                sectionCount, minimumProgramHeader, elf);
        final List<Section> sections = readSections(
                buffer, data.length, elf64, sectionOffset,
                sectionEntrySize, sectionCount, elf);

        if (isDecoyTable(data, sections, sectionStringIndex)) {
            throw new IOException("Legacy decoy-section ELF cannot be made loader-safe; "
                    + "rebuild from an unprotected input: " + elf);
        }

        if (sectionStringIndex != SHN_UNDEF) {
            final Section strings = sections.get(sectionStringIndex);
            if (strings.type == SHT_NOBITS) {
                throw new IOException("Section string table has no file data: " + elf);
            }
            checkRange(strings.offset, strings.size, data.length,
                    "section string table", elf);
        }

        final ByteBuffer output = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        int modifiedSections = 0;
        for (int index = 0; index < sections.size(); index++) {
            final Section section = sections.get(index);
            if ((section.flags & SHF_EXECINSTR) == 0) continue;
            final int flagsOffset = Math.toIntExact(
                    sectionOffset + (long) index * sectionEntrySize + 8L);
            if (elf64) {
                output.putLong(flagsOffset, section.flags & ~SHF_EXECINSTR);
            } else {
                output.putInt(flagsOffset, (int) (section.flags & ~SHF_EXECINSTR));
            }
            modifiedSections++;
        }

        if (modifiedSections == 0) {
            return new Result(true, sectionCount, 0, runtimeRanges.size());
        }

        writeAtomically(path, data);
        return new Result(false, sectionCount, modifiedSections, runtimeRanges.size());
    }

    private static void validateMagic(byte[] data, File elf) throws IOException {
        if (data.length < 6 || data[0] != 0x7f || data[1] != 'E'
                || data[2] != 'L' || data[3] != 'F') {
            throw new IOException("Not an ELF file: " + elf);
        }
    }

    private static List<FileRange> readProgramRanges(ByteBuffer buffer,
                                                     int fileSize,
                                                     boolean elf64,
                                                     long sectionOffset,
                                                     int sectionEntrySize,
                                                     int sectionCount,
                                                     int minimumEntrySize,
                                                     File elf) throws IOException {
        final long programOffset = elf64 ? buffer.getLong(32) : u32(buffer, 28);
        final int programEntrySize = Short.toUnsignedInt(buffer.getShort(elf64 ? 54 : 42));
        final int rawProgramCount = Short.toUnsignedInt(buffer.getShort(elf64 ? 56 : 44));
        if (programOffset <= 0 || programEntrySize < minimumEntrySize) {
            throw new IOException("Invalid ELF program headers: " + elf);
        }

        final int programCount;
        if (rawProgramCount == PN_XNUM) {
            if (sectionCount == 0) {
                throw new IOException("Missing section zero for extended program count: " + elf);
            }
            final long extendedCount = u32(buffer,
                    Math.toIntExact(sectionOffset) + (elf64 ? 44 : 28));
            programCount = checkedCount(extendedCount, "extended program count", elf);
        } else {
            programCount = rawProgramCount;
        }
        if (programCount == 0) {
            throw new IOException("ELF has no program headers: " + elf);
        }
        final long tableSize = multiply(programEntrySize, programCount,
                "program table", elf);
        checkRange(programOffset, tableSize, fileSize, "program table", elf);

        final ArrayList<FileRange> ranges = new ArrayList<>(programCount);
        for (int i = 0; i < programCount; i++) {
            final int offset = Math.toIntExact(programOffset + (long) i * programEntrySize);
            final long fileOffset = elf64 ? buffer.getLong(offset + 8) : u32(buffer, offset + 4);
            final long rangeSize = elf64 ? buffer.getLong(offset + 32) : u32(buffer, offset + 16);
            checkRange(fileOffset, rangeSize, fileSize, "program segment", elf);
            if (rangeSize != 0) ranges.add(new FileRange(fileOffset, rangeSize));
        }
        return ranges;
    }

    private static List<Section> readSections(ByteBuffer buffer,
                                              int fileSize,
                                              boolean elf64,
                                              long tableOffset,
                                              int entrySize,
                                              int count,
                                              File elf) throws IOException {
        final ArrayList<Section> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            final int offset = Math.toIntExact(tableOffset + (long) i * entrySize);
            final int nameOffset = buffer.getInt(offset);
            final int type = buffer.getInt(offset + 4);
            final long flags = elf64 ? buffer.getLong(offset + 8) : u32(buffer, offset + 8);
            final long fileOffset = elf64 ? buffer.getLong(offset + 24) : u32(buffer, offset + 16);
            final long size = elf64 ? buffer.getLong(offset + 32) : u32(buffer, offset + 20);
            if (type != SHT_NOBITS) {
                checkRange(fileOffset, size, fileSize, "section", elf);
            }
            result.add(new Section(nameOffset, type, flags, fileOffset, size));
        }
        return result;
    }

    private static boolean isDecoyTable(byte[] data,
                                        List<Section> sections,
                                        int stringIndex) {
        if (sections.size() != 2 || stringIndex != 1) return false;
        final Section zero = sections.get(0);
        final Section strings = sections.get(1);
        if (zero.nameOffset != 0 || zero.type != SHT_NULL
                || zero.flags != 0 || zero.offset != 0 || zero.size != 0) {
            return false;
        }
        if (strings.nameOffset != 1 || strings.type != SHT_STRTAB
                || strings.flags != 0 || strings.size != DECOY_NAMES.length
                || strings.offset < 0
                || strings.offset > data.length - DECOY_NAMES.length) {
            return false;
        }
        return Arrays.equals(data,
                Math.toIntExact(strings.offset),
                Math.toIntExact(strings.offset + strings.size),
                DECOY_NAMES, 0, DECOY_NAMES.length);
    }

    private static long chooseDecoyStringOffset(List<Section> sections,
                                                 int stringIndex,
                                                 long tableOffset,
                                                 int entrySize,
                                                 long tableSize,
                                                 List<FileRange> runtimeRanges,
                                                 File elf) throws IOException {
        if (stringIndex != SHN_UNDEF) {
            final Section strings = sections.get(stringIndex);
            if (strings.type != SHT_NOBITS
                    && strings.size >= DECOY_NAMES.length
                    && isOutsideRuntime(strings.offset, DECOY_NAMES.length, runtimeRanges)) {
                return strings.offset;
            }
        }

        final long tail = tableOffset + 2L * entrySize;
        if (tableSize >= 2L * entrySize + DECOY_NAMES.length
                && isOutsideRuntime(tail, DECOY_NAMES.length, runtimeRanges)) {
            return tail;
        }
        throw new IOException("No safe metadata range for ELF decoy names: " + elf);
    }

    private static void writeDecoyStringSection(ByteBuffer output,
                                                 int offset,
                                                 boolean elf64,
                                                 long stringOffset) {
        output.putInt(offset, 1);
        output.putInt(offset + 4, SHT_STRTAB);
        if (elf64) {
            output.putLong(offset + 8, 0L);
            output.putLong(offset + 16, 0L);
            output.putLong(offset + 24, stringOffset);
            output.putLong(offset + 32, DECOY_NAMES.length);
            output.putInt(offset + 40, 0);
            output.putInt(offset + 44, 0);
            output.putLong(offset + 48, 1L);
            output.putLong(offset + 56, 0L);
        } else {
            output.putInt(offset + 8, 0);
            output.putInt(offset + 12, 0);
            output.putInt(offset + 16, Math.toIntExact(stringOffset));
            output.putInt(offset + 20, DECOY_NAMES.length);
            output.putInt(offset + 24, 0);
            output.putInt(offset + 28, 0);
            output.putInt(offset + 32, 1);
            output.putInt(offset + 36, 0);
        }
    }

    private static void addSafeRange(BitSet wipe,
                                     long offset,
                                     long size,
                                     List<FileRange> runtimeRanges,
                                     int fileSize) {
        if (size == 0) return;
        final FileRange candidate = new FileRange(offset, size);
        for (FileRange runtime : runtimeRanges) {
            if (candidate.overlaps(runtime)) return;
        }
        wipe.set(Math.toIntExact(offset), Math.toIntExact(offset + size));
    }

    private static boolean isOutsideRuntime(long offset,
                                            long size,
                                            List<FileRange> runtimeRanges) {
        final FileRange candidate = new FileRange(offset, size);
        for (FileRange runtime : runtimeRanges) {
            if (candidate.overlaps(runtime)) return false;
        }
        return true;
    }

    private static int checkedCount(long value, String what, File elf) throws IOException {
        if (value <= 0 || value > 1_000_000L) {
            throw new IOException("Invalid " + what + " " + value + ": " + elf);
        }
        return (int) value;
    }

    private static int checkedIndex(long value, int count,
                                    String what, File elf) throws IOException {
        if (value < 0 || value >= count) {
            throw new IOException("Invalid " + what + " " + value + ": " + elf);
        }
        return (int) value;
    }

    private static long multiply(long left, long right,
                                 String what, File elf) throws IOException {
        try {
            return Math.multiplyExact(left, right);
        } catch (ArithmeticException e) {
            throw new IOException("Overflow in " + what + ": " + elf, e);
        }
    }

    private static long u32(ByteBuffer buffer, int offset) {
        return Integer.toUnsignedLong(buffer.getInt(offset));
    }

    private static void checkRange(long offset, long size, int fileSize,
                                   String what, File elf) throws IOException {
        if (offset < 0 || size < 0 || offset > fileSize || size > fileSize - offset) {
            throw new IOException("Invalid " + what + " range: " + elf);
        }
    }

    private static void writeAtomically(Path target, byte[] data) throws IOException {
        final Path absolute = target.toAbsolutePath();
        final Path parent = absolute.getParent();
        final Set<PosixFilePermission> permissions;
        try {
            permissions = Files.getPosixFilePermissions(absolute);
        } catch (UnsupportedOperationException e) {
            // Windows and other non-POSIX file systems retain their own ACLs.
            returnWriteAtomicallyWithoutPosix(absolute, parent, data);
            return;
        }

        final Path temporary = Files.createTempFile(parent, ".nmmp-sectionless-", ".tmp");
        try {
            Files.write(temporary, data);
            Files.setPosixFilePermissions(temporary, permissions);
            moveReplacing(temporary, absolute);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void returnWriteAtomicallyWithoutPosix(Path target,
                                                           Path parent,
                                                           byte[] data) throws IOException {
        final Path temporary = Files.createTempFile(parent, ".nmmp-sectionless-", ".tmp");
        try {
            Files.write(temporary, data);
            moveReplacing(temporary, target);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void moveReplacing(Path source, Path target) throws IOException {
        try {
            Files.move(source, target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    public record Result(boolean alreadyHardened,
                         int originalSectionCount,
                         int modifiedSectionCount,
                         int runtimeRangeCount) {
    }

    private record Section(int nameOffset, int type, long flags, long offset, long size) {
    }

    private record FileRange(long offset, long size) {
        private boolean overlaps(FileRange other) {
            return offset < other.offset + other.size
                    && other.offset < offset + size;
        }
    }
}
