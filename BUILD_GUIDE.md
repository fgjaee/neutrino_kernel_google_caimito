# Kernel Build Guide (Final Build)

This guide will help you build the **Custom Kernel (Pixel 9 Pro Fold)** with **SukiSU Ultra** integration.

## 📋 Prerequisites
*   Linux environment (Ubuntu/Debian recommended)
*   Basic build tools (`make`, `git`, `curl` or `wget`)
*   ~2GB-5GB free space for toolchain and build artifacts

## ☁️ Option 1: Build with GitHub Actions (Recommended)
You can compile this kernel entirely in the cloud without setting up a local toolchain:

1.  **Push** this repository to GitHub.
2.  Go to the **Actions** tab in your repository.
3.  Select **"Build Custom Kernel"**.
4.  Click **Run workflow**.

Once complete, the `Image.lz4` and `dtbs` will be available in the **Artifacts** section of the workflow run.

## 💻 Option 2: Local Build
If you prefer building locally:

### 1. Setup Toolchain
We need the official Android Clang toolchain (`r487747c`) to compile this kernel correctly. 

I have created a script to handle this automatically:

```bash
./setup_toolchain.sh
```

*This will download the toolchain to a `toolchain/` directory inside your project folder.*

## 🚀 Step 2: Build the Kernel
Once the toolchain is set up, run the build helper script:

```bash
./build_kernel.sh
```

This script will:
1.  Detect the downloaded toolchain.
2.  Configure the kernel using `custom_defconfig` (which includes all our Stealth/SukiSU patches).
3.  Build the kernel image and device trees.
4.  Output the results to the `out/` directory.

## 📂 Step 3: Locate Output
After a successful build, your files will be in:

*   **Kernel Image**: `out/arch/arm64/boot/Image.lz4` (Target for `vendor_kernel_boot`)
*   **DTBs**: `out/arch/arm64/boot/dts/google/*.dtb`

## 📲 ​📲 Step 4: Flashing (Pixel 9 Pro Fold)
​WARNING: This device requires updating BOTH the boot and vendor_kernel_boot partitions to boot a custom kernel.
​Generate AnyKernel3 Zip:
Use the provided workflow or script to create an AnyKernel3 zip. This zip is configured to:
​Flash Image.lz4 to the boot partition (The Kernel).
​Flash dtb files to the vendor_kernel_boot partition (The Device Tree).
​Flash in Recovery:
adb sideload AnyKernel3-Custom.zip
(Or flash via Kernel Flasher / FKM app if rooted).
​Note: Do NOT attempt to flash only one partition. The Kernel and DTBs must match version-for-version.