#!/sbin/sh
# AnyKernel3 Ramdisk Mod Script
# Adapted for Google Comet / Caimito builds

## AnyKernel setup
# shellcheck disable=SC2034
kernelstring="Google Comet / Caimito"
do.devicecheck=1
do.modules=0
do.cleanup=1
do.cleanuponabort=1

# Device checks
# shellcheck disable=SC2034
device.name1=comet
# shellcheck disable=SC2034
device.name2=caimito

# Flash settings
# shellcheck disable=SC2034
block=auto
# shellcheck disable=SC2034
is_slot_device=auto
# shellcheck disable=SC2034
patch_vbmeta_flag=auto
# shellcheck disable=SC2034
repack_ramdisk=auto

# Boot image settings
# shellcheck disable=SC2034
kernel=Image
# shellcheck disable=SC2034
ramdisk_compression=auto

. tools/ak3-core.sh

split_boot
flash_boot
