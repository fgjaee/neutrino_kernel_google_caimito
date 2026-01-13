#!/bin/bash
set -euo pipefail

OUT_DIR=${1:-out}
IMAGE_PATH="$OUT_DIR/arch/arm64/boot/Image.lz4"

if [ ! -f "$IMAGE_PATH" ]; then
  echo "❌ Missing kernel image: $IMAGE_PATH" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "❌ curl is required to download AnyKernel3." >&2
  exit 1
fi

if ! command -v unzip >/dev/null 2>&1; then
  echo "❌ unzip is required to extract AnyKernel3." >&2
  exit 1
fi

WORKDIR=$(mktemp -d)
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

AK_ZIP="$WORKDIR/AnyKernel3.zip"
AK_URL="https://github.com/osm0sis/AnyKernel3/archive/refs/heads/master.zip"

echo "⬇️  Downloading AnyKernel3..."
curl -L "$AK_URL" -o "$AK_ZIP"

unzip -q "$AK_ZIP" -d "$WORKDIR"
AK_DIR=$(find "$WORKDIR" -maxdepth 1 -type d -name "AnyKernel3-*" | head -n 1)

if [ -z "$AK_DIR" ]; then
  echo "❌ Unable to locate AnyKernel3 contents after unzip." >&2
  exit 1
fi

cp scripts/anykernel3/anykernel.sh "$AK_DIR/anykernel.sh"
cp "$IMAGE_PATH" "$AK_DIR/Image.lz4"

# Remove placeholders from AnyKernel3 directories to make it flash-ready
echo "🧹 Cleaning AnyKernel3 placeholders..."
rm -f "$AK_DIR/Image"* "$AK_DIR/zImage"* "$AK_DIR/dtb"* "$AK_DIR/dtbo.img"
rm -rf "$AK_DIR/modules/"*
rm -rf "$AK_DIR/patch/"*
rm -rf "$AK_DIR/ramdisk/"*
# Ensure directories exist only if we are using them (currently we are not)
# mkdir -p "$AK_DIR/modules" "$AK_DIR/patch" "$AK_DIR/ramdisk"
rm -rf "$AK_DIR/modules" "$AK_DIR/patch" "$AK_DIR/ramdisk"

cp scripts/anykernel3/anykernel.sh "$AK_DIR/anykernel.sh"
cp "$IMAGE_PATH" "$AK_DIR/Image.lz4"

# Remove irrelevant README
rm -f "$AK_DIR/README.md"

# Replace 32-bit tools with 64-bit tools from Magisk APK (Critical for Pixel 9/Android 15)
echo "⬇️  Downloading Magisk to extract 64-bit tools..."
MAGISK_APK="$WORKDIR/Magisk.apk"
curl -L -o "$MAGISK_APK" "https://github.com/topjohnwu/Magisk/releases/download/v27.0/Magisk-v27.0.apk"

echo "📦 Extracting 64-bit busybox and magiskboot..."
# Extract libbusybox.so -> busybox
unzip -p "$MAGISK_APK" "lib/arm64-v8a/libbusybox.so" > "$AK_DIR/tools/busybox"
# Extract libmagiskboot.so -> magiskboot
unzip -p "$MAGISK_APK" "lib/arm64-v8a/libmagiskboot.so" > "$AK_DIR/tools/magiskboot"
# Also update magiskpolicy if it exists, as it's often used
if unzip -l "$MAGISK_APK" | grep -q "libmagiskpolicy.so"; then
    unzip -p "$MAGISK_APK" "lib/arm64-v8a/libmagiskpolicy.so" > "$AK_DIR/tools/magiskpolicy"
    chmod 755 "$AK_DIR/tools/magiskpolicy"
fi

# Fix permissions for tools (critical for busybox)
echo "🔧 Fixing permissions..."
chmod -R 755 "$AK_DIR/tools"
chmod 755 "$AK_DIR/anykernel.sh"

ZIP_NAME="AnyKernel3-zumapro.zip"
( cd "$AK_DIR" && zip -r9 "$WORKDIR/$ZIP_NAME" ./* -x .git .gitignore ./*.zip )

mv "$WORKDIR/$ZIP_NAME" .

echo "✅ Created $ZIP_NAME"
