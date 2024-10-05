# LightZone Testing Env

Before going on, we need the toolchain to compile and build the software.
There are so many dependencies, therefore I will not list them.
Luckily, all can be downloaded on `Ubuntu 22.04 LTS`.

We are on the base directory of LightZone's environment.

### 1. Build the Linux kernel
```sh
cd linux
make O=../kbuild defconfig ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
cp ../kconfig ../kbuild/.config
make O=../kbuild ARCH=arm64 Image modules scripts_gdb -j10 CROSS_COMPILE=aarch64-linux-gnu-
cd ..

# config gdb
# in gedit /home/$(USER)/.config/gdb/gdbinit
# optionally, add this line
#       add-auto-load-safe-path $(YOUR_WORKING_DIR)/linux/scripts/gdb/vmlinux-gdb.py
```

### 2. Build the root file system and initialize
```sh
wget http://cdimage.ubuntu.com/ubuntu-base/releases/20.04/release/ubuntu-base-20.04.5-base-arm64.tar.gz

mkdir rootfs
# 128GB, if larger disks are needed, check https://superuser.com/questions/693158/can-i-expand-the-size-of-a-file-based-disk-image
dd if=/dev/zero of=ubuntu.img bs=1M count=131072 oflag=direct
mkfs.ext4 ubuntu.img
sudo mount -t ext4 ubuntu.img rootfs/
sudo tar -xzf ubuntu-base-20.04.5-base-arm64.tar.gz -C rootfs/

sudo cp /usr/bin/qemu-aarch64-static rootfs/usr/bin/
sudo cp /etc/resolv.conf rootfs/etc/resolv.conf
sudo mount -t proc /proc rootfs/proc
sudo mount -t sysfs /sys rootfs/sys
sudo mount -o bind /dev rootfs/dev
sudo mount -o bind /dev/pts rootfs/dev/pts

cd linux
sudo make O=../kbuild ARCH=arm64 modules_install CROSS_COMPILE=aarch64-linux-gnu- INSTALL_MOD_PATH=../rootfs
cd ..

sudo chroot rootfs

# in the rootfs to pre-install useful tools
# if we want to add binaries, they should be cross-compiled
apt-get update
apt-get install sudo vim bash-completion -y
apt-get install net-tools ethtool ifupdown network-manager iputils-ping nano -y
apt-get install rsyslog resolvconf udev -y
apt-get install systemd kmod gcc gdb make -y
adduser lz
adduser lz sudo
echo "lzvm" >/etc/hostname
echo "127.0.0.1 localhost" >/etc/hosts
echo "127.0.0.1 lzvm">>/etc/hosts
dpkg-reconfigure resolvconf
dpkg-reconfigure tzdata
exit
# out of the rootfs

sudo umount rootfs/proc
sudo umount rootfs/sys
sudo umount rootfs/dev/pts
sudo umount rootfs/dev
sudo umount rootfs
```

### 3. Run QEMU
```sh
# terminal
./debug.sh
```
We integrate the debugging process of the kernel and the modules into VSCode.
However, we need to install the VSCode C/C++ extension first.
```sh
# vscode
# go to 'Run and Debug'
# click the GUI buttons
```

### 4. Cross-compile a kernel module
```sh
# in lzsrc/helloko
# compile and install
make
make install

# clean
make clean
```

### 5. Debug both the kernel and loaded modules with GDB
Refer to the example in `lzsrc/helloko` and `.vscode/launch.json`.

```sh
# in the debug console, -exec lx-symbols lzsrc/lzko/, or the kernel module
```

### 6. LightZone application-liblz interface
```c
lzerr_t lz_enter(bool slat);
int lz_alloc(void);
void lz_free(int lz);
int lz_mprotect(unsigned long addr, size_t len, int lz);
void lz_perm_rw(int lz, bool enable);
```

### 7. LightZone liblz-lzko interface (TBD)
```c
// fd

// ioctl
```
For **liblz**, there are several key steps in the following APIs.

- `lz_init`
- `lz_alloc`
- `lz_free`
- `lz_mprotect`
- `lz_set_perm`

It also needs to play as a shim for Linux system calls.

- General operations needs synergy of the API and kernel module.
- Some special Linux syscalls are completely handled in kernel module.

### 8. LightZone guest-lzko interface (TBD)

### 9. Establish QEMU Debug Environment

Refer to the file `debug-env.md`.