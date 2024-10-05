#!/bin/bash

sudo qemu-system-aarch64 -enable-kvm -s -m 1024M\
        -smp 4 -cpu host -machine virt,gic_version=2 -machine type=virt\
        -kernel kbuild/arch/arm64/boot/Image -append "kpti=0 nokaslr console=ttyAMA0 root=/dev/vda rw net.ifnames=0" -nographic\
        -drive if=none,file=ubuntu-nested.img,id=hd0,format=raw -device virtio-blk-device,drive=hd0\
	# -netdev tap,id=mynet0,ifname=tap0,script=no,downscript=no\
	# -device e1000,netdev=mynet0,mac=AA:FC:00:00:00:01

#-netdev tap,id=net0,ifname=tap0,script=no,downscript=no -device virtio-net-device,netdev=net0,mac=52:55:00:d1:55:01