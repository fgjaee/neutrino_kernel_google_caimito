#!/bin/bash
set -e

# Configuration
export ARCH=arm64
export SUBARCH=arm64
export O=out
export DEFCONFIG=neutrino_defconfig

# 1. Check for compiler
CLANG_VER="r487747c"
LOCAL_CLANG="$(pwd)/toolchain/clang-${CLANG_VER}/bin"

if [ -d "$LOCAL_CLANG" ]; then
    export PATH="$LOCAL_CLANG:$PATH"
    echo "ℹ️  Using local toolchain: $LOCAL_CLANG"
fi

if ! command -v clang &> /dev/null; then
    echo "❌ Error: 'clang' compiler not found."
    echo "   Please run './setup_toolchain.sh' to download it automatically."
    exit 1
fi

echo "✅ Found compiler: $(clang --version | head -n 1)"

# 2. Check for defconfig
if [ ! -f "arch/arm64/configs/$DEFCONFIG" ]; then
    echo "❌ Error: Defconfig '$DEFCONFIG' not found!"
    exit 1
fi

# 3. Prepare Environment
rm -rf "$O"
mkdir -p "$O"
export KBUILD_BUILD_USER="Neutrino"
export KBUILD_BUILD_HOST="GitHub-Runner"

# 4. Configure
echo "🛠️  Configuring kernel with $DEFCONFIG..."
make O=$O LLVM=1 LLVM_IAS=1 $DEFCONFIG
if ! grep -q "^CONFIG_MODULES=y$" "$O/.config"; then
    echo "🔧 Enabling CONFIG_MODULES..."
    scripts/config --file "$O/.config" --enable MODULES
    make O=$O LLVM=1 LLVM_IAS=1 olddefconfig
fi

# 5. Build Kernel Image
echo "🚀 Building Kernel Image..."
make O=$O LLVM=1 LLVM_IAS=1 -j$(nproc) Image.lz4

# 6. Build Google Modules (REQUIRED for DTBs on Pixel 9)
echo "🚀 Building Google Modules & DTBs..."
# We try to build modules in the adjacent folder if it exists, or in-tree
if [ -d "../google-modules" ]; then
    MODULES_DIR=$(realpath ../google-modules)
    echo "ℹ️  Found external modules at: $MODULES_DIR"

    # Build SoC modules, then build DTBs from the main tree.
    make O=$O LLVM=1 LLVM_IAS=1 \
         -j$(nproc) \
         M=$MODULES_DIR/soc \
         KERNEL_SRC=$(pwd) \
         modules
    make O=$O LLVM=1 LLVM_IAS=1 -j$(nproc) dtbs
else
    echo "⚠️  ../google-modules not found. Attempting to build DTBs in-tree..."
    # Fallback: try to build dtbs from main tree just in case
    make O=$O LLVM=1 LLVM_IAS=1 -j$(nproc) dtbs || echo "⚠️  DTB Build failed or no DTBs found."
fi

echo ""
echo "✅ Build process finished."
