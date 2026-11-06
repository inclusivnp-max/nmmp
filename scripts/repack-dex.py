#!/usr/bin/env python3
"""Replace dex files in APK while preserving original compression for other entries."""
import glob
import os
import shutil
import sys
import zipfile

STORED = zipfile.ZIP_STORED
DEFLATED = zipfile.ZIP_DEFLATED
MUST_STORE = {"resources.arsc"}


def repack(apk_in: str, dex_dir: str, apk_out: str) -> None:
    dex_files = sorted(glob.glob(os.path.join(dex_dir, "classes*.dex")))
    if not dex_files:
        raise SystemExit(f"No dex files in {dex_dir}")

    new_dex = {os.path.basename(p): p for p in dex_files}

    with zipfile.ZipFile(apk_in, "r") as zin:
        entries = [i for i in zin.infolist() if not i.filename.endswith(".dex")]
        payload = {i.filename: zin.read(i.filename) for i in entries}

    with zipfile.ZipFile(apk_out, "w") as zout:
        for info in entries:
            name = info.filename
            out = zipfile.ZipInfo(name)
            if name in MUST_STORE or info.compress_type == STORED:
                out.compress_type = STORED
            else:
                out.compress_type = DEFLATED
            zout.writestr(out, payload[name])
        for name, path in sorted(new_dex.items()):
            zout.write(path, name)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <input.apk> <dex_dir> <output.apk>", file=sys.stderr)
        sys.exit(1)
    repack(sys.argv[1], sys.argv[2], sys.argv[3])