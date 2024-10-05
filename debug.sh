#!/bin/bash

qemu-system-aarch64 -s -m 8192M\
        -smp 6 -cpu max -machine virt,gic_version=2 -machine virtualization=true -machine type=virt\
        -kernel kbuild/arch/arm64/boot/Image -append "kpti=0 nokaslr console=ttyAMA0 root=/dev/vda rw net.ifnames=0" -nographic\
        -drive if=none,file=ubuntu.img,id=hd0,format=raw -device virtio-blk-device,drive=hd0\
	-netdev tap,id=mynet0,ifname=tap0,script=no,downscript=no\
	-device e1000,netdev=mynet0,mac=AA:FC:00:00:00:01
