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

ZIP_NAME="AnyKernel3-zumapro.zip"
( cd "$AK_DIR" && zip -r9 "$WORKDIR/$ZIP_NAME" ./* -x .git .gitignore ./*.zip )

mv "$WORKDIR/$ZIP_NAME" .

echo "✅ Created $ZIP_NAME"
