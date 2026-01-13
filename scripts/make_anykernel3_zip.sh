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

# Replace 32-bit busybox with 64-bit busybox (required for Pixel 9/Android 15+)
echo "⬇️  Downloading 64-bit busybox..."
curl -L -o "$AK_DIR/tools/busybox" "https://raw.githubusercontent.com/osm0sis/AnyKernel3/master/tools/busybox"
# Wait, the master branch one IS 32-bit. We need a specific aarch64 build.
# Using osm0sis's Android Image Kitchen binaries or a known good static aarch64 busybox.
# A reliable source for a static aarch64 busybox is the mime-types/busybox-static repo or similar, 
# but let's use a direct link to a known working binary commonly used in Android rooting.
# Actually, KSU/Magisk usually rely on their own internal busybox, but AK3 needs one to run.
# Let's try downloading from a reliable static binary source.
curl -L -o "$AK_DIR/tools/busybox" "https://github.com/Mainstream-Magisk/BusyBox-Binary/raw/master/builds/busybox-arm64"


# Fix permissions for tools (critical for busybox)
echo "🔧 Fixing permissions..."
chmod -R 755 "$AK_DIR/tools"
chmod 755 "$AK_DIR/anykernel.sh"

ZIP_NAME="AnyKernel3-zumapro.zip"
( cd "$AK_DIR" && zip -r9 "$WORKDIR/$ZIP_NAME" ./* -x .git .gitignore ./*.zip )

mv "$WORKDIR/$ZIP_NAME" .

echo "✅ Created $ZIP_NAME"
