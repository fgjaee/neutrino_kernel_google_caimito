# Neutrino Kernel for Pixel 9 Pro Fold (Caimito)

[![Build Kernel](https://github.com/fgjaee/neutrino_kernel_google_caimito/actions/workflows/build_kernel.yml/badge.svg)](https://github.com/fgjaee/neutrino_kernel_google_caimito/actions/workflows/build_kernel.yml)

A custom kernel for the **Google Pixel 9 Pro Fold** (codename: caimito) with integrated root solution and maximum stealth features.

## ✨ Features

### 🔓 Root Solution
| Feature | Status | Description |
|---------|--------|-------------|
| **KernelSU-Next** | ✅ Enabled | Next-generation kernel-level root |
| **SukiSU-Ultra (SUSFS)** | ✅ Full Stealth | Complete SUSFS integration with all hiding features |

### 🛡️ SUSFS Stealth Configuration
All SUSFS features are enabled for maximum root hiding:

- `CONFIG_KSU_SUSFS` - Main SUSFS support
- `CONFIG_KSU_SUSFS_SUS_PATH` - Hide specific file paths
- `CONFIG_KSU_SUSFS_SUS_MOUNT` - Hide suspicious mount points
- `CONFIG_KSU_SUSFS_SUS_KSTAT` - Hide file statistics
- `CONFIG_KSU_SUSFS_SUS_MAP` - Hide memory mappings
- `CONFIG_KSU_SUSFS_SPOOF_UNAME` - Spoof kernel version info
- `CONFIG_KSU_SUSFS_ENABLE_LOG` - Enable logging
- `CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS` - Hide kernel symbols
- `CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG` - Spoof boot parameters
- `CONFIG_KSU_SUSFS_OPEN_REDIRECT` - Redirect file opens

### 🔒 Security & Protection
| Feature | Status | Description |
|---------|--------|-------------|
| **Baseband Guard** | ✅ Enabled | Anti-format protection for critical partitions |
| **Re-Kernel** | ✅ Enabled | Enhanced process management |
| **HymoFS** | ✅ Enabled | Kernel-level path manipulation |
| **Mountify (Nuke EXT4)** | ✅ Enabled | Mount point hiding |

### 🔧 Stealth Hardening
These kernel options are **disabled** to prevent root detection:

- `CONFIG_IKCONFIG_PROC` - Disabled (hides kernel config)
- `CONFIG_FTRACE` - Disabled (hides tracing)
- `CONFIG_PROFILING` - Disabled (hides profiling)

### 🌐 VPN & Hotspot Hiding

**TTL Modification** (for hotspot hiding):
- `CONFIG_IP_NF_TARGET_TTL=y` - IPv4 TTL modification
- `CONFIG_IP6_NF_TARGET_HL=y` - IPv6 Hop Limit modification

**VPN Interface Hiding** (via SUSFS):
Use the SukiSU Manager to add these paths to the SUSFS hide list:
```
/dev/tun
/dev/net/tun
/sys/class/net/tun*
/proc/net/dev (filter tun entries)
```

**Hotspot TTL Fix** (after boot):
```bash
# Set TTL to 64 (same as phone) to hide tethering
iptables -t mangle -A POSTROUTING -o rmnet+ -j TTL --ttl-set 64
ip6tables -t mangle -A POSTROUTING -o rmnet+ -j HL --hl-set 64
```

## 📱 Device Compatibility

| Property | Value |
|----------|-------|
| Device | Google Pixel 9 Pro Fold |
| Codename | caimito |
| Kernel Version | 6.1.159 |
| Android Version | Android 15 |
| Architecture | arm64 |

## 🚀 Building

### Option 1: GitHub Actions (Recommended)
1. Fork this repository
2. Go to **Actions** tab
3. Click **"Run workflow"**
4. Download artifacts when complete

### Option 2: Local Build
```bash
# Setup toolchain
./setup_toolchain.sh

# Build kernel
./build_kernel.sh
```

### Option 3: Create AnyKernel3 Zip (Script)
To generate a flashable `AnyKernel3-zumapro.zip` automatically:
```bash
./scripts/make_anykernel3_zip.sh
```

### Option 4: Create AnyKernel3 Zip (Manual / Replace Placeholders)
If you need to manually create the zip (e.g., updating a generic AnyKernel3 zip):
1. Download [AnyKernel3](https://github.com/osm0sis/AnyKernel3).
2. **Replace Placeholder Image**: Copy `out/arch/arm64/boot/Image.lz4` to the root of the AnyKernel3 folder.
3. **Replace Placeholder Script**: Copy `scripts/anykernel3/anykernel.sh` to the AnyKernel3 folder (replacing the default `anykernel.sh`).
4. **Clear Placeholders**: Delete the contents of the `modules`, `patch`, and `ramdisk` folders (unless you have specific files to add).
5. Zip the contents recursively (excluding `.git` and gitignore).

### Option 5: Repack Vendor Kernel Boot Image (Script)
If you prefer to flash a raw disk image instead of using AnyKernel3:
1. Obtain your stock `vendor_kernel_boot.img` (extract from factory image).
2. Run the repack script:
   ```bash
   ./scripts/repack_vendor_kernel_boot.sh /path/to/stock_vendor_kernel_boot.img
   ```
3. The script will generate `vendor_kernel_boot-repacked.img`.

## 📦 Output Files

After building:
- `out/arch/arm64/boot/Image.lz4` - Kernel image
- `out/arch/arm64/boot/dts/google/*.dtb` - Device tree blobs

## ⚠️ Flashing Instructions

### Method 1: AnyKernel3 Zip (Recommended)
1. Transfer `AnyKernel3-zumapro.zip` to your device.
2. Flash using a Kernel Manager (e.g., FKM, EXKM) or KernelSU/APatch App (if supported).
   - **Note**: Requires root or a custom recovery.

### Method 2: Manual Fastboot Flash
> **CRITICAL**: Flash to `vendor_kernel_boot`, NOT `boot.img`!

```bash
# Extract vendor_kernel_boot from factory image
# Replace Image.lz4 in the extracted partition
# Repack and flash:
fastboot flash vendor_kernel_boot vendor_kernel_boot.img
```

## 📄 License

This kernel is based on the Android Common Kernel and is licensed under the GPL-2.0 license.

## 🙏 Credits

- **KernelSU-Next** - Kernel root solution
- **SukiSU-Ultra** - SUSFS stealth features
- **Baseband Guard** - Partition protection
- **Re-Kernel** - Process management
- **HymoFS** - Path manipulation
- **Mountify** - Mount hiding
