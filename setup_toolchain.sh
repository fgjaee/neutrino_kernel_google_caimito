#!/bin/bash
set -e

CLANG_VER="r487747c"
# Try android14-release branch first (most likely to have it)
CLANG_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/android14-release/clang-${CLANG_VER}.tar.gz"
INSTALL_DIR="$(pwd)/toolchain/clang-${CLANG_VER}"


echo "⬇️  Downloading toolchain from: $CLANG_URL"

# Create directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Download with curl, failing on HTTP errors (-f)
if command -v curl &> /dev/null; then
    curl -f -L "$CLANG_URL" | tar -xz || {
        echo "⚠️  Primary URL failed. Trying 'master' branch fallback..."
        rm -rf * # Clear partial files
        FALLBACK_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/master/clang-${CLANG_VER}.tar.gz"
        curl -f -L "$FALLBACK_URL" | tar -xz
    }
elif command -v wget &> /dev/null; then
    wget -O - "$CLANG_URL" | tar -xz
else
    echo "❌ Error: Neither 'curl' nor 'wget' found."
    exit 1
fi

echo ""
echo "✅ Toolchain installed successfully at: $INSTALL_DIR"
echo "👉 Run the following command to add it to your PATH (or use build_kernel.sh which will find it):"
echo "   export PATH=$INSTALL_DIR/bin:\$PATH"
