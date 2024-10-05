## Build a customized kernel

We build our kernel based on [Jetson Linux 35.2.1](https://developer.nvidia.com/embedded/jetson-linux-r3521).
Refer to the [official site](https://docs.nvidia.com/jetson/archives/r35.2.1/DeveloperGuide/text/SD/Kernel/KernelCustomization.html).

```shell
# In this dir, first download the toolchain and the Linux source

wget 
wget https://developer.nvidia.com/downloads/public-sourcestbz2

# Extract the toolchain in this folder through GUI, call it toolchain/

# Extract the kernel
tar -xjf public_sources.tbz2
cd Linux_for_Tegra/source/public
tar -xjf kernel_src.tbz2

# Build the kernel
cd kernel
mkdir kbuild
export CROSS_COMPILE_AARCH64_PATH=<toolchain-path>
export CROSS_COMPILE_AARCH64=<toolchain-path>/bin/aarch64-buildroot-linux-gnu-
cd ..
./nvbuild.sh -o $PWD/kernel/kbuild

echo ${CROSS_COMPILE_AARCH64}
cd kernel/kernel-5.10
sudo make O=../kbuild ARCH=arm64 modules_install CROSS_COMPILE=${CROSS_COMPILE_AARCH64} INSTALL_MOD_PATH=../../../../../Linux_for_Tegra/rootfs
cd ../..

sudo rm ../../../Linux_for_Tegra/rootfs/usr/lib/modules/5.10.104-tegra/kernel/drivers/gpu/nvgpu/nvgpu.ko
sudo cp kernel/kbuild/drivers/gpu/nvgpu/nvgpu.ko ../../../Linux_for_Tegra/rootfs/usr/lib/modules/5.10.104-tegra/kernel/drivers/gpu/nvgpu/

sudo rm -rf ../../../Linux_for_Tegra/kernel/dtb/
sudo cp -R kernel/kbuild/arch/arm64/boot/dts/nvidia/ ../../../Linux_for_Tegra/kernel/dtb/

sudo rm ../../../Linux_for_Tegra/kernel/Image
sudo cp kernel/kbuild/arch/arm64/boot/Image ../../../Linux_for_Tegra/kernel/Image

cd ../../../Linux_for_Tegra/
# cd rootfs/
# sudo tar --owner root --group root -cjf kernel_supplements.tbz2 lib/modules
# Linux_for_Tegra/kernel/kernel_supplements.tbz2
# cd ..

sudo ./apply_binaries.sh

# Refer to 1-boot-linux.md to program the binaries
```

## Port LightZone to the customized kernel version

```shell
# Apply the patch in lzsrc/lzpatch
# Rebuild the customized kernel like the last step
# Before ./apply_binaries.sh, enter lzko, make nvd, make installnvd
# Apply bin and program the device
# Open the device, and add `nokaslr` boot argument to /boot/extlinu/extlinux.conf
# Reboot the device
```

## Install LightZone in the customized kernel

## Run the basic unit tests on board