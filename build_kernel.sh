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

# 3. Prepare Environment (Fixes the loop!)
mkdir -p $O
export KBUILD_BUILD_USER="Neutrino"
export KBUILD_BUILD_HOST="GitHub-Runner"

# 4. Clean and Configure (skip mrproper on fresh builds)
if [ -f "$O/.config" ]; then
    echo "🧹 Cleaning previous builds..."
    make O=$O mrproper
else
    echo "ℹ️  Fresh build - skipping cleanup"
fi

echo "🛠️  Configuring kernel with $DEFCONFIG..."
make O=$O LLVM=1 LLVM_IAS=1 $DEFCONFIG

# 5. Build (modules disabled - testing if google-modules causes loop)
echo "🚀 Building kernel (Image.lz4, dtbs only - modules skipped)..."
make O=$O LLVM=1 LLVM_IAS=1 -j$(nproc) Image.lz4 dtbs

echo ""
echo "✅ Build completed successfully!"
echo "   Kernel Image: $O/arch/arm64/boot/Image.lz4"
echo "   DTBs:         $O/arch/arm64/boot/dts/google/"
