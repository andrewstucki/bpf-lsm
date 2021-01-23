#!/usr/bin/env bash

# Run this on a fedora 33 machine to build a new kernel
# that has BPF enabled as an LSM, this script needs to
# be run as root

dnf install fedpkg fedora-packager rpmdevtools ncurses-devel pesign grubby make -y
fedpkg clone -a kernel
cd kernel && git checkout origin/f33
echo 'CONFIG_LSM="yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf"' > configs/fedora/generic/CONFIG_LSM
echo 'CONFIG_LSM="yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf"' > configs/fedora/debug/CONFIG_LSM
sed -i '/buildid \.local/s/^# /%/g' kernel.spec
dnf builddep kernel.spec
git checkout -b lsm-bpf
./build_configs.sh
fedpkg --release f33 local
