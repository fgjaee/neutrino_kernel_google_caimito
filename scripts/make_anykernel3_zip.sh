#!/bin/bash
set -euo pipefail

OUT_DIR=${1:-out}
# We now expect the repacked image, not just Image.lz4
IMAGE_PATH="vendor_kernel_boot-repacked.img"

if [ ! -f "$IMAGE_PATH" ]; then
  echo "❌ Missing repacked image: $IMAGE_PATH" >&2
  exit 1
fi

# Removed unzip check to allow running in restricted envs (python3 fallback or CI has it)


WORKDIR=$(mktemp -d)
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

AK_ZIP="$WORKDIR/AnyKernel3.zip"
AK_URL="https://github.com/osm0sis/AnyKernel3/archive/refs/heads/master.zip"

echo "⬇️  Downloading AnyKernel3..."
curl -L "$AK_URL" -o "$AK_ZIP"

python3 -c "import zipfile, sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])"  "$AK_ZIP" "$WORKDIR"
ls -la "$WORKDIR"
AK_DIR=$(find "$WORKDIR" -maxdepth 1 -type d -name "AnyKernel3-*" | head -n 1)

if [ -z "$AK_DIR" ]; then
  echo "❌ Unable to locate AnyKernel3 contents after unzip." >&2
  exit 1
fi

cp scripts/anykernel3/anykernel.sh "$AK_DIR/anykernel.sh"

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
# Copy valid image as vendor_kernel_boot.img for AK3 to flash
cp "$IMAGE_PATH" "$AK_DIR/vendor_kernel_boot.img"

# Remove irrelevant README
rm -f "$AK_DIR/README.md"

# Replace 32-bit tools with 64-bit tools from Magisk APK (Critical for Pixel 9/Android 15)
echo "⬇️  Downloading Magisk to extract 64-bit tools..."
MAGISK_APK="$WORKDIR/Magisk.apk"
curl -L -o "$MAGISK_APK" "https://github.com/topjohnwu/Magisk/releases/download/v27.0/Magisk-v27.0.apk"

echo "📦 Extracting 64-bit busybox and magiskboot..."
# Extract libbusybox.so -> busybox
# Extract 64-bit tools using python
python3 -c "import zipfile, sys; z=zipfile.ZipFile(sys.argv[1]); open(sys.argv[2], 'wb').write(z.read('lib/arm64-v8a/libbusybox.so'));" "$MAGISK_APK" "$AK_DIR/tools/busybox"
python3 -c "import zipfile, sys; z=zipfile.ZipFile(sys.argv[1]); open(sys.argv[2], 'wb').write(z.read('lib/arm64-v8a/libmagiskboot.so'));" "$MAGISK_APK" "$AK_DIR/tools/magiskboot"

# Check and extract magiskpolicy
if python3 -c "import zipfile, sys; exit(0 if 'lib/arm64-v8a/libmagiskpolicy.so' in zipfile.ZipFile(sys.argv[1]).namelist() else 1)" "$MAGISK_APK"; then
    python3 -c "import zipfile, sys; z=zipfile.ZipFile(sys.argv[1]); open(sys.argv[2], 'wb').write(z.read('lib/arm64-v8a/libmagiskpolicy.so'));" "$MAGISK_APK" "$AK_DIR/tools/magiskpolicy"
    chmod 755 "$AK_DIR/tools/magiskpolicy"
fi

# Fix permissions for tools (critical for busybox)
echo "🔧 Fixing permissions..."
chmod -R 755 "$AK_DIR/tools"
chmod 755 "$AK_DIR/anykernel.sh"

ZIP_NAME="AnyKernel3-zumapro.zip"
( cd "$AK_DIR" && python3 -c "import zipfile, sys, os; z=zipfile.ZipFile(sys.argv[1], 'w', zipfile.ZIP_DEFLATED); [z.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), '.')) for root, dirs, files in os.walk('.') for file in files if not file.endswith('.zip') and '.git' not in root]" "$WORKDIR/$ZIP_NAME" )

mv "$WORKDIR/$ZIP_NAME" .

echo "✅ Created $ZIP_NAME"
