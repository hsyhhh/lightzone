ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
ccflags-y := -I$(src)/arch/arm64
ccflags-y += -I$(src)
obj-m := lightzone.o
lightzone-y :=  arch/arm64/lzarm.o arch/arm64/lzcpu.o\
				arch/arm64/npt.o arch/arm64/pt.o\
				arch/arm64/lzentry.o arch/arm64/lzvec.o\
				arch/arm64/sanitize.o arch/arm64/copied.o\
				arch/arm64/paravirt.o arch/arm64/lowvisor.o\
				arch/arm64/nohammer.o main.o lzuapi.o

else
# normal makefile
LZDIR ?= $(PWD)/../..
KDIR ?= $(LZDIR)/kbuild
MDIR ?= $(LZDIR)/rootfs
NVKDIR ?= $(LZDIR)/board/Linux_for_Tegra/source/public/kernel/kbuild
NVMDIR ?= $(LZDIR)/board/Linux_for_Tegra/rootfs
NVTOOLS ?= $(LZDIR)/board/toolchain/bin/aarch64-buildroot-linux-gnu-

default:
	python lzsym.py emu
	$(MAKE) EXTRA_CFLAGS+=-D__KVM_VHE_HYPERVISOR__\
		EXTRA_AFLAGS+=-D__KVM_VHE_HYPERVISOR__\
		EXTRA_CFLAGS+=-DRUN_ON_VHE_HOST\
		EXTRA_AFLAGS+=-DRUN_ON_VHE_HOST\
		EXTRA_CFLAGS+=-DLAZY_VHE_LOWVISOR_OPT\
		EXTRA_AFLAGS+=-DLAZY_VHE_LOWVISOR_OPT\
		-C $(KDIR) M=$$PWD ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules

tge:
	python lzsym.py emu
	$(MAKE) EXTRA_CFLAGS+=-D__KVM_VHE_HYPERVISOR__\
		EXTRA_AFLAGS+=-D__KVM_VHE_HYPERVISOR__\
		EXTRA_CFLAGS+=-DRUN_ON_VHE_HOST\
		EXTRA_AFLAGS+=-DRUN_ON_VHE_HOST\
		EXTRA_CFLAGS+=-DLAZY_VHE_LOWVISOR_OPT\
		EXTRA_AFLAGS+=-DLAZY_VHE_LOWVISOR_OPT\
		EXTRA_CFLAGS+=-DTGE_OPT_EL2 EXTRA_AFLAGS+=-DTGE_OPT_EL2\
		-C $(KDIR) M=$$PWD ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules

install:
	sudo mount -t ext4 $(LZDIR)/ubuntu.img $(LZDIR)/rootfs/
	sudo $(MAKE) -C $(KDIR) M=$$PWD INSTALL_MOD_PATH=$(MDIR)\
			ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules_install
	sudo umount $(LZDIR)/rootfs

v:
	python lzsym.py emu
	$(MAKE) -C $(KDIR) M=$$PWD ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules

installv:
	sudo mount -t ext4 $(LZDIR)/ubuntu-nested.img $(LZDIR)/rootfs/
	sudo $(MAKE) -C $(KDIR) M=$$PWD INSTALL_MOD_PATH=$(MDIR)\
			ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules_install
	sudo umount $(LZDIR)/rootfs

nvd:
	python lzsym.py board
	$(MAKE) EXTRA_CFLAGS+=-D__KVM_VHE_HYPERVISOR__\
		EXTRA_AFLAGS+=-D__KVM_VHE_HYPERVISOR__\
		EXTRA_CFLAGS+=-DRUN_ON_VHE_HOST\
		EXTRA_AFLAGS+=-DRUN_ON_VHE_HOST\
		EXTRA_CFLAGS+=-DLAZY_VHE_LOWVISOR_OPT\
		EXTRA_AFLAGS+=-DLAZY_VHE_LOWVISOR_OPT\
		EXTRA_CFLAGS+=-DNVIDIA_BOARD EXTRA_AFLAGS+=-DNVIDIA_BOARD\
		-C $(NVKDIR) M=$$PWD ARCH=arm64 CROSS_COMPILE=$(NVTOOLS) modules

nvdtge:
	python lzsym.py board
	$(MAKE) EXTRA_CFLAGS+=-D__KVM_VHE_HYPERVISOR__\
		EXTRA_AFLAGS+=-D__KVM_VHE_HYPERVISOR__\
		EXTRA_CFLAGS+=-DRUN_ON_VHE_HOST\
		EXTRA_AFLAGS+=-DRUN_ON_VHE_HOST\
		EXTRA_CFLAGS+=-DLAZY_VHE_LOWVISOR_OPT\
		EXTRA_AFLAGS+=-DLAZY_VHE_LOWVISOR_OPT\
		EXTRA_CFLAGS+=-DNVIDIA_BOARD EXTRA_AFLAGS+=-DNVIDIA_BOARD\
		EXTRA_CFLAGS+=-DTGE_OPT_EL2 EXTRA_AFLAGS+=-DTGE_OPT_EL2\
		-C $(NVKDIR) M=$$PWD ARCH=arm64 CROSS_COMPILE=$(NVTOOLS) modules

installnvd:
	sudo $(MAKE) -C $(NVKDIR) M=$$PWD INSTALL_MOD_PATH=$(NVMDIR)\
			ARCH=arm64 CROSS_COMPILE=$(NVTOOLS) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$$PWD ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- clean

endif