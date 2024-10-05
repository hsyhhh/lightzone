## 1. Establish NAT network in QEMU

### Create a tap device in the host

First, create a tap device and set up NAT routing traffic out of the tap device in the host. **Note that the code below uses `ens3` as the internet-facing interface. `ens3` may be different on different host machines. Need to revise!** Use ifconfig to get the name of the name of your active net device.

```
sudo ip tuntap add tap0 mode tap
sudo ip addr add 172.16.0.1/24 dev tap0
sudo ip link set tap0 up
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i tap0 -o ens3 -j ACCEPT
```

### Do some changes in rootfs

```
sudo mount -t ext4 ubuntu.img rootfs/
sudo mount -t proc /proc rootfs/proc
sudo mount -t sysfs /sys rootfs/sys
sudo mount -o bind /dev rootfs/dev
sudo mount -o bind /dev/pts rootfs/dev/pts

sudo chroot rootfs

echo -e 'source-directory /etc/network/interfaces.d\n\nauto lo\niface lo inet loopback\n' > /etc/network/interfaces
echo -en "127.0.0.1\tlocalhost\n" | sudo tee /etc/hosts
echo "nameserver 8.8.8.8" > /etc/resolv.conf
apt-get install openssh-server binutils make -y

exit

sudo umount rootfs/proc
sudo umount rootfs/sys
sudo umount rootfs/dev/pts
sudo umount rootfs/dev
sudo umount rootfs
```

### In the Guest

After booting, bring up networking within the QEMU guest:
```
# network init
sudo bash -c "echo 'nameserver 8.8.8.8' > /etc/resolv.conf"
sudo ip addr add 172.16.0.2/24 dev eth0
sudo ip link set eth0 up
sudo ip route add default via 172.16.0.1 dev eth0
```
Now we can connect to the Internet in QEMU guest machine.

## 2. liblz usage

To debug liblz, we need to compile and install liblz in QEMU guest machine. 

Before we start QEMU, copy liblz files to rootfs:

```
# under lzsrc/liblz
make copy
```

In QEMU guest machine, compile and install liblz:

```
# under /home/lz/liblz in the guest
make clean
make
```

**Note that we must execute `make clean`**, otherwise gdb might not work when we want to step into liblz source code.

## 3. Debug user app in QEMU

Now we can connect to the Internet in QEMU guest machine (also SSH connection between host and guest).

After we start QEMU (We can start more CPU cores when doing this step), use VSCode SSH to connect to the guest machine (lz@172.16.0.2). Install VSCode C/C++ extension in QEMU guest machine. 

Assume VSCode opens folder `/home/lz`, and we want to debug `/home/lz/test.c`. First compile `test.c`:
```
gcc -g test.c -llz
```

Create file `.vscode/launch.json` under the current working dir. The content can be:
```
{
	"version": "0.2.0",
	"configurations": [
		{
			"name": "(gdb) launch",
			"type": "cppdbg",
			"request": "launch",
			"program": "${workspaceFolder}/a.out",
			"args": [],
			"stopAtEntry": false,
			"cwd": "${fileDirname}",
			"environment": [],
			"externalConsole": false,
			"MIMode": "gdb",
			"setupCommands": []
		}
	]
}
```

Just change `a.out` to debug other programs. Now we can debug in VSCode happily.

## 4. Debug QEMU/KVM in QEMU

First, build `ubuntu-nested.img` in the host. Similar to `ubuntu.img`, Create `ubuntu-nested.img` for kvm in qemu.

```
# 20GB
dd if=/dev/zero of=ubuntu-nested.img bs=1M count=20480 oflag=direct
mkfs.ext4 ubuntu-nested.img
sudo mount -t ext4 ubuntu-nested.img rootfs/
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

apt-get update
apt-get install sudo vim bash-completion net-tools ethtool ifupdown network-manager iputils-ping nano rsyslog resolvconf udev systemd kmod gcc gdb git make openssh-server binutils -y
adduser lz
adduser lz sudo
echo "lzvm" >/etc/hostname
echo "127.0.0.1 localhost" >/etc/hosts
echo "127.0.0.1 lzvm">>/etc/hosts
dpkg-reconfigure resolvconf
dpkg-reconfigure tzdata
exit

sudo umount rootfs/proc
sudo umount rootfs/sys
sudo umount rootfs/dev/pts
sudo umount rootfs/dev
sudo umount rootfs
```

Second, copy files to `ubuntu.img`:
```
sudo mount -t ext4 ubuntu.img rootfs/

cd rootfs/home/lz
git clone https://gitee.com/monikerzju/lightzone510.git

# copy ubuntu-nested.img to QEMU
cp ubuntu-nested.img rootfs/home/lz/lightzone510

sudo umount rootfs
```

After start QEMU (use more memory (4096M) and more cores) and establish network in QEMU, using VSCode to connect to QEMU, and execute:
```
sudo apt install qemu-system-aarch64 qemu-efi bridge-utils cpu-checker libvirt-clients libvirt-daemon qemu qemu-kvm gdb-multiarch -y

# check kvm enabled or not
kvm-ok

# the following process may need one day
cd /home/lz/lightzone510/linux
make O=../kbuild defconfig ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
cp ../kconfig ../kbuild/.config
make O=../kbuild ARCH=arm64 Image modules scripts_gdb -j10 CROSS_COMPILE=aarch64-linux-gnu-
cd ..

mkdir rootfs
sudo mount -t ext4 ubuntu-nested.img rootfs/
sudo mount -t proc /proc rootfs/proc
sudo mount -t sysfs /sys rootfs/sys
sudo mount -o bind /dev rootfs/dev
sudo mount -o bind /dev/pts rootfs/dev/pts

cd linux
sudo make O=../kbuild ARCH=arm64 modules_install CROSS_COMPILE=aarch64-linux-gnu- INSTALL_MOD_PATH=../rootfs
cd ..

sudo umount rootfs/proc
sudo umount rootfs/sys
sudo umount rootfs/dev/pts
sudo umount rootfs/dev
sudo umount rootfs
```

Finally, start QEMU/KVM in QEMU:

```
./debug-nested.sh
```

We can use the same `launch.json` to debug QEMU/KVM in QEMU.