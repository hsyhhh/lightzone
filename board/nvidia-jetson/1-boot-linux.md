# 如何在 Jetson AGX Xavier 上启动 Linux 和 KVM

基本参考 [NV官网](https://docs.nvidia.com/jetson/archives/r35.2.1/DeveloperGuide/text/IN/QuickStart.html) 即可

## 1. 准备定制版 kernel 和 rootfs

```shell
wget https://developer.nvidia.com/downloads/jetson-linux-r3521-aarch64tbz2
wget https://developer.nvidia.com/downloads/linux-sample-root-filesystem-r3521aarch64tbz2
tar xf Jetson_Linux_R35.2.1_aarch64.tbz2
sudo tar xpf Tegra_Linux_Sample-Root-Filesystem_R35.2.1_aarch64.tbz2 -C Linux_for_Tegra/rootfs/
cd Linux_for_Tegra/
sudo ./apply_binaries.sh
sudo ./tools/l4t_flash_prerequisites.sh
```

## 2. 正确连接板子和主机

usb3.0 type-c 数据线, usb3.0 连接主机, 另一端连接板子 **靠近电源键** 的 type-c 接口

连接电源线

根据官网指示操作按键:

1. 长按recover
2. 短按一下poweron键 (中间的按键)
3. 松开recover

## 3. 将 rootfs flash 到板载存储 (eMMC) 上

```shell
sudo ./flash.sh jetson-agx-xavier-devkit internal
```

HDMI 线连接板子和显示器, flash 完成后会自动重启



