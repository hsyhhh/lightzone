LZDIR ?= $(PWD)/../..
CROSS_=aarch64-linux-gnu-
# OBJDUMP=objdump
OBJDUMP=${CROSS_}objdump
# GCC=${CROSS_}gcc
GCC=gcc
CFLAGS = -g -fPIC -O3 -Wno-implicit-function-declaration -fno-stack-protector -march=armv8.2-a

ASM_SRC	= $(sort $(wildcard *.S))
C_SRC = $(sort $(wildcard *.c))
OBJ = $(patsubst %.S,%.o,$(ASM_SRC)) $(patsubst %.c,%.o,$(C_SRC))

default: copy

v: copyv

insarm: clean lib install

dump:
	${OBJDUMP} -d liblz.so > liblz.txt

lib: $(OBJ)
	${GCC} -shared $(OBJ) -o liblz.so

%.o: %.S
	${GCC} $(CFLAGS) -c $<

%.o: %.c
	${GCC} $(CFLAGS) -c $<

install:
	sudo cp liblz.so /usr/lib
	sudo cp liblz.h /usr/include

copy:
	sudo mount -t ext4 $(LZDIR)/ubuntu.img $(LZDIR)/rootfs/
	sudo mkdir -p $(LZDIR)/rootfs/home/lz/liblz
	sudo cp -r * $(LZDIR)/rootfs/home/lz/liblz
	sudo chmod 777 $(LZDIR)/rootfs/home/lz/liblz
	sleep 4
	sudo umount $(LZDIR)/rootfs

copyv:
	sudo mount -t ext4 $(LZDIR)/ubuntu-nested.img $(LZDIR)/rootfs/
	sudo mkdir -p $(LZDIR)/rootfs/home/lz/liblz
	sudo cp -r * $(LZDIR)/rootfs/home/lz/liblz
	sudo chmod 777 $(LZDIR)/rootfs/home/lz/liblz
	sleep 4
	sudo umount $(LZDIR)/rootfs

umount:
	sudo umount $(LZDIR)/rootfs

clean:
	sudo rm *.o *.so


