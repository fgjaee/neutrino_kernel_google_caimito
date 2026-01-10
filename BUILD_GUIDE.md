# Kernel Build Guide (Build Triggered)

This guide will help you build the **Neutrino Kernel (Pixel 9 Pro Fold)** with **SukiSU Ultra** integration.

## 📋 Prerequisites
*   Linux environment (Ubuntu/Debian recommended)
*   Basic build tools (`make`, `git`, `curl` or `wget`)
*   ~2GB-5GB free space for toolchain and build artifacts

## ☁️ Option 1: Build with GitHub Actions (Recommended)
You can compile this kernel entirely in the cloud without setting up a local toolchain:

1.  **Push** this repository to GitHub.
2.  Go to the **Actions** tab in your repository.
3.  Select **"Build Neutrino Kernel"**.
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
2.  Configure the kernel using `neutrino_defconfig` (which includes all our Stealth/SukiSU patches).
3.  Build the kernel image and device trees.
4.  Output the results to the `out/` directory.

## 📂 Step 3: Locate Output
After a successful build, your files will be in:

*   **Kernel Image**: `out/arch/arm64/boot/Image.lz4` (Target for `vendor_kernel_boot`)
*   **DTBs**: `out/arch/arm64/boot/dts/google/*.dtb`

## 📲 Step 4: Flashing (Pixel 9 Pro Fold)
**WARNING**: This kernel targets the `vendor_kernel_boot` partition.

1.  **Repack**: You cannot flash `Image.lz4` directly. You must repack it into a `vendor_kernel_boot.img`.
    *   Use **AnyKernel3** (configure for `vendor_kernel_boot`).
    *   OR use `magiskboot` / `mkbootimg` if you are comfortable with manual repacking.
2.  **Flash**:
    ```bash
    fastboot flash vendor_kernel_boot vendor_kernel_boot-new.img
    ```

> **Note**: Do NOT flash to `boot` partition. The Pixel 9 series (Caimito) uses `init_boot` for ramdisk and `vendor_kernel_boot` for the kernel.
