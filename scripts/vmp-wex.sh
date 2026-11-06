#!/usr/bin/env bash
set -euo pipefail

INPUT_APK="${1:-/home/zapahtravki/AndroidStudioProjects/WEX/app/release/app-release.apk}"
OUTPUT_APK="${2:-/home/zapahtravki/AndroidStudioProjects/WEX/app/release/wexclient.org.apk}"
NMMP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# D8 repack breaks nmmp dex2c on multi-dex release builds; ProtectCli already
# fixes resources.arsc + zipalign + signs the output APK.
rm -rf "$(dirname "$OUTPUT_APK")/dex2c" "$(dirname "$OUTPUT_APK")/.cxx" "$(dirname "$OUTPUT_APK")/obj" 2>/dev/null || true
cd "$NMMP_DIR"
./gradlew --offline --console=plain :composeApp:protectApk -PinputApk="$INPUT_APK" -PoutputApk="$OUTPUT_APK"

echo "Done: $OUTPUT_APK"
