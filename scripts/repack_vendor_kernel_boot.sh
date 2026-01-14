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


# Script updated to use local python logic, no external tools needed except python3



echo "🔄 Repacking image using custom script..."
python3 scripts/manage_vendor_kernel_boot.py repack "$STOCK_IMG" "$KERNEL_IMG" "$OUTPUT_IMG"

if [ ! -f "$OUTPUT_IMG" ]; then
    echo "❌ Repack failed."
    exit 1
fi

echo "✅ Done." # Moved by script

echo "✅ Repacked image created: $OUTPUT_IMG"
echo "   Flash with: fastboot flash vendor_kernel_boot $OUTPUT_IMG"
