#!/bin/bash
set -euo pipefail

# Scripts to repack vendor_kernel_boot.img with a new kernel image
# Usage: ./scripts/repack_vendor_kernel_boot.sh <path_to_stock_vendor_kernel_boot.img> [path_to_kernel_image]

STOCK_IMG="${1:-}"
KERNEL_IMG="${2:-out/arch/arm64/boot/Image.lz4}"
OUTPUT_IMG="vendor_kernel_boot-repacked.img"

if [ -z "$STOCK_IMG" ]; then
    echo "Usage: $0 <path_to_stock_vendor_kernel_boot.img> [path_to_kernel_image]"
    echo "Example: $0 stock_vendor_kernel_boot.img"
    exit 1
fi

if [ ! -f "$STOCK_IMG" ]; then
    echo "❌ Stock image not found: $STOCK_IMG"
    exit 1
fi

if [ ! -f "$KERNEL_IMG" ]; then
    echo "❌ Kernel image not found: $KERNEL_IMG"
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "❌ curl is required." >&2
    exit 1
fi

if ! command -v unzip >/dev/null 2>&1; then
    echo "❌ unzip is required." >&2
    exit 1
fi

WORKDIR=$(mktemp -d)
cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "🔧 Preparing tools..."

# Reuse logic to get 64-bit magiskboot from Magisk APK
MAGISKBOOT="$WORKDIR/magiskboot"
MAGISK_APK="$WORKDIR/Magisk.apk"
MAGISK_URL="https://github.com/topjohnwu/Magisk/releases/download/v27.0/Magisk-v27.0.apk"

echo "⬇️  Downloading Magisk to extract magiskboot..."
curl -L -o "$MAGISK_APK" "$MAGISK_URL"

echo "📦 Extracting magiskboot..."
unzip -p "$MAGISK_APK" "lib/arm64-v8a/libmagiskboot.so" > "$MAGISKBOOT"
chmod 755 "$MAGISKBOOT"

echo "📂 Unpacking stock image..."
cp "$STOCK_IMG" "$WORKDIR/vendor_kernel_boot.img"
cd "$WORKDIR"
./magiskboot unpack vendor_kernel_boot.img

if [ ! -f "kernel" ]; then
    echo "❌ Failed to unpack kernel from image. Is this a valid vendor_kernel_boot.img?"
    exit 1
fi

echo "🔄 Replacing kernel..."
cp "$KERNEL_IMG" kernel

echo "📦 Repacking image..."
./magiskboot repack vendor_kernel_boot.img

if [ ! -f "new-boot.img" ]; then
    echo "❌ Repack failed."
    exit 1
fi

mv new-boot.img "$OLDPWD/$OUTPUT_IMG"
cd "$OLDPWD"

echo "✅ Repacked image created: $OUTPUT_IMG"
echo "   Flash with: fastboot flash vendor_kernel_boot $OUTPUT_IMG"
