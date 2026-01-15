# Baseband Guard Makefile - Simplified for in-tree build

bbg-objs += baseband_guard.o
bbg-objs += tracing/tracing.o

ccflags-y += -I$(srctree)/security/baseband-guard -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h

obj-$(CONFIG_BBG) += bbg.o

# Hardcoded version info
ccflags-y += -DBBG_VERSION=\"kometra1n\"
ccflags-y += -DBBG_REPO=\"https://github.com/vc-teahouse/Baseband-guard\"
