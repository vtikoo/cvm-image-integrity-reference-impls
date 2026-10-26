#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
install -d -m 700 /var/tmp/canonical-build
exec > >(tee /var/tmp/canonical-build/install.log) 2>&1
missing=()
for spec in 'git:git' 'go:golang-go' 'qemu-img:qemu-utils' \
    'sgdisk:gdisk' 'veritysetup:cryptsetup-bin' 'pkg-config:pkg-config' \
    'gcc:build-essential' 'make:build-essential' 'objcopy:binutils' \
    'unmkinitramfs:initramfs-tools-core' 'modprobe:kmod' 'cpio:cpio' \
    'sbsign:sbsigntool' 'sbverify:sbsigntool' 'sbattach:sbsigntool' 'openssl:openssl'; do
    command -v "${spec%%:*}" >/dev/null || missing+=("${spec#*:}")
done
if ! pkg-config --exists libudev; then
    missing+=(libudev-dev)
fi
if ((${#missing[@]})); then
    apt-get update -qq
    apt-get install -y --no-install-recommends "${missing[@]}"
fi
modprobe nbd max_part=16
go version
qemu-img --version | head -n 1
veritysetup --version
dpkg-query -W git golang-go qemu-utils gdisk cryptsetup-bin libudev-dev binutils initramfs-tools-core \
    > /var/tmp/canonical-build/tool-packages.txt
bash -n "$0"
echo HELPER_TOOLS_READY
