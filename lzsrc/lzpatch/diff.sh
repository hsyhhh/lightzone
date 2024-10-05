#! /bin/sh

git diff --no-index ../../linux-5.10.104-stable ../../linux-5.10.104 > kernel.patch
sed 's,../../linux-5.10.104-stable/,,' kernel.patch > tmp.patch
sed 's,../../linux-5.10.104/,,' tmp.patch > kernel.patch
sed 's,static void update_vmid,void update_vmid,' kernel.patch > tmp.patch
mv tmp.patch kernel.patch

