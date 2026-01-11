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
supported.versions=
supported.patchlevels=
supported.vendorpatchlevels=
'; } # end properties


### vendor_kernel_boot shell variables
BLOCK=/dev/block/bootdevice/by-name/vendor_kernel_boot;
IS_SLOT_DEVICE=1;
RAMDISK_COMPRESSION=auto;
PATCH_VBMETA_FLAG=auto;

# import functions/variables and setup patching - see for reference (DO NOT REMOVE)
. tools/ak3-core.sh;

# reset for vendor_kernel_boot patching
reset_ak;

# vendor_kernel_boot install
split_boot; # skip unpack/repack ramdisk
flash_boot;
## end vendor_kernel_boot install
