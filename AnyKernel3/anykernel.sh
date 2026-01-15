### AnyKernel3 Ramdisk Mod Script
## osm0sis @ xda-developers

### AnyKernel setup
# global properties
properties() { '
kernel.string=Neutrino Kernel (zumapro)
do.devicecheck=1
do.modules=0
do.systemless=1
do.cleanup=1
do.cleanuponabort=0
device.name1=zumapro
device.name2=caimito
device.name3=comet
device.name4=google-comet
supported.versions=
supported.patchlevels=
supported.vendorpatchlevels=
'; } # end properties


### AnyKernel install
# -------------------------------------------------
# PART 1: Flash the Kernel (boot partition)
# -------------------------------------------------
BLOCK=/dev/block/by-name/boot;
IS_SLOT_DEVICE=1;
RAMDISK_COMPRESSION=auto;
PATCH_VBMETA_FLAG=auto;

# Import the tools
. tools/ak3-core.sh;

# Split the phone's boot.img, INSERT your Image.lz4, and repack
split_boot;
flash_boot;

# -------------------------------------------------
# PART 2: Flash the DTBs (vendor_kernel_boot partition)
# -------------------------------------------------
# Reset logic for the next partition
reset_ak;

BLOCK=/dev/block/by-name/vendor_kernel_boot;
IS_SLOT_DEVICE=1;
RAMDISK_COMPRESSION=auto;
PATCH_VBMETA_FLAG=auto;

# Split the vendor_boot, replace the DTB, and repack
split_boot;
flash_boot;
