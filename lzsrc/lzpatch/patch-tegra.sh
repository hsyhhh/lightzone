#! /bin/sh

cd ../../board/Linux_for_Tegra/source/public/kernel/kernel-5.10
git apply --reject ../../../../../../lzsrc/lzpatch/kernel.patch