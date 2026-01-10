#!/bin/bash
set -e

CLANG_VER="r487747c"
CLANG_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/master/clang-${CLANG_VER}.tar.gz"

INSTALL_DIR="$(pwd)/toolchain/clang-${CLANG_VER}"

echo "🔧 Preparing to install Android Clang Toolchain ($CLANG_VER)..."

if [ -d "$INSTALL_DIR/bin" ]; then
    echo "✅ Toolchain already exists at: $INSTALL_DIR"
    echo "   You can proceed to build."
    exit 0
fi

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "⬇️  Downloading toolchain (this may take a while)..."
# Try curl, fall back to wget
if command -v curl &> /dev/null; then
    curl -L "$CLANG_URL" | tar -xz
elif command -v wget &> /dev/null; then
    wget -O - "$CLANG_URL" | tar -xz
else
    echo "❌ Error: Neither 'curl' nor 'wget' found. Please install one of them."
    exit 1
fi

echo ""
echo "✅ Toolchain installed successfully at: $INSTALL_DIR"
echo "👉 Run the following command to add it to your PATH (or use build_kernel.sh which will find it):"
echo "   export PATH=$INSTALL_DIR/bin:\$PATH"
