#!/usr/bin/env python3
"""Ensure resources.arsc is STORED (uncompressed) for Android R+ install.

Fast path: every entry except resources.arsc is copied byte-for-byte
(raw compressed data, no re-compression). Only resources.arsc is
decompressed and re-inserted with ZIP_STORED, then the central
directory is rebuilt with corrected offsets.
"""
import struct
import sys
import zipfile
import zlib

LOCAL_SIG = 0x04034B50
CENTRAL_SIG = 0x02014B50
EOCD_SIG = 0x06054B50
FLAG_DESCRIPTOR = 0x0008

MUST_STORE = {"resources.arsc"}


def dos_time(dt):
    y, m, d, h, mi, s = dt
    return (h << 11) | (mi << 5) | (s >> 1), ((y - 1980) << 9) | (m << 5) | d


def fix_apk(src: str, dst: str) -> None:
    with zipfile.ZipFile(src, "r") as zin:
        entries = zin.infolist()

        with open(src, "rb") as fin, open(dst, "wb") as fout:
            new_entries = []
            for info in entries:
                name = info.filename
                fn = name.encode("utf-8")

                fin.seek(info.header_offset)
                local_head = fin.read(30)
                local_nlen, local_elen = struct.unpack("<HH", local_head[26:30])
                fin.read(local_nlen)
                local_extra = fin.read(local_elen)

                dost, dosd = dos_time(info.date_time)

                if name in MUST_STORE:
                    data = zin.read(name)
                    crc = zlib.crc32(data)
                    csize = usize = len(data)
                    method = zipfile.ZIP_STORED
                else:
                    data = fin.read(info.compress_size)
                    crc = info.CRC
                    csize = info.compress_size
                    usize = info.file_size
                    method = info.compress_type

                header = struct.pack(
                    "<IHHHHHIIIHH",
                    LOCAL_SIG, 20, info.flag_bits & ~FLAG_DESCRIPTOR,
                    method, dost, dosd, crc, csize, usize, len(fn), len(local_extra),
                )
                offset = fout.tell()
                fout.write(header)
                fout.write(fn)
                fout.write(local_extra)
                fout.write(data)

                new_entries.append((info, offset, fn, crc, csize, usize, method, dost, dosd))

            cd_offset = fout.tell()
            cd_size = 0
            for info, offset, fn, crc, csize, usize, method, dost, dosd in new_entries:
                comment = (info.comment or "").encode("utf-8")
                central = struct.pack(
                    "<IHHHHHHIIIHHHHHII",
                    CENTRAL_SIG,
                    (info.create_system << 8) | info.create_version,
                    20,
                    info.flag_bits & ~FLAG_DESCRIPTOR,
                    method, dost, dosd,
                    crc, csize, usize,
                    len(fn), len(info.extra or b""), len(comment),
                    0, info.internal_attr, info.external_attr,
                    offset,
                )
                fout.write(central)
                fout.write(fn)
                fout.write(info.extra or b"")
                fout.write(comment)
                cd_size += len(central) + len(fn) + len(info.extra or b"") + len(comment)

            eocd = struct.pack(
                "<IHHHHIIH",
                EOCD_SIG, 0, 0, len(new_entries), len(new_entries),
                cd_size, cd_offset, 0,
            )
            fout.write(eocd)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.apk> <output.apk>", file=sys.stderr)
        sys.exit(1)
    fix_apk(sys.argv[1], sys.argv[2])