#!/usr/bin/env bash
# Install the protected WEX APK AND force AOT compilation.
#
# WHY: a freshly sideloaded (adb install) APK is left at dexopt status=verify —
# ART runs the whole app through the interpreter (+ on-the-fly JIT). On a
# layout-heavy screen like the chat that means ~30% janky frames and the "lags
# especially when the keyboard opens" behaviour. Play Store applies the baseline
# profile at install; a sideload does not, and bg-dexopt only kicks in later
# (overnight, on charge). Forcing `compile -m speed` gives full AOT immediately.
# Measured on Pixel 9 Pro XL: janky 7.8%->1.6%, 90th pct 26ms->12ms.
set -euo pipefail
APK="${1:-/home/zapahtravki/AndroidStudioProjects/WEX/app/release/wex-protected.apk}"
PKG="client.wex"
echo ">> installing $APK"
adb install -r -d "$APK"
echo ">> forcing full AOT (speed) — takes ~20s"
adb shell cmd package compile -m speed -f "$PKG"
echo -n ">> dexopt status now: "
adb shell dumpsys package dexopt 2>/dev/null | sed -n "/\[$PKG\]/,/status=/p" | grep -o 'status=[a-z-]*' | head -1
echo ">> done. Launch the app and test the chat."
