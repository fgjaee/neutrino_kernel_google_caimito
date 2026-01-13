---
description: Repack the compiled kernel into a flashable AnyKernel3 zip
---

# Repack Kernel

This workflow creates a flashable AnyKernel3 zip file containing the compiled `Image.lz4` kernel.

## Prerequisites
- A successful kernel build (`out/arch/arm64/boot/Image.lz4` exists).

## Steps

1. **Verify Image**
   Ensure the kernel image exists.
   ```bash
   ls -lh out/arch/arm64/boot/Image.lz4
   ```

2. **Run Repack Script**
   // turbo
   Run the project's repack script which downloads AnyKernel3 and packages the kernel.
   ```bash
   chmod +x scripts/make_anykernel3_zip.sh
   ./scripts/make_anykernel3_zip.sh
   ```

3. **Verify Output**
   Check for the generated zip file.
   ```bash
   ls -lh AnyKernel3-zumapro.zip
   ```

4. **Flashing Instructions**
   - **Flash via App:** Copy `AnyKernel3-zumapro.zip` to your phone and flash with **Kernel Flasher** or **FKM**.
   - **Flash via ADB:** `adb sideload AnyKernel3-zumapro.zip` (in recovery).
