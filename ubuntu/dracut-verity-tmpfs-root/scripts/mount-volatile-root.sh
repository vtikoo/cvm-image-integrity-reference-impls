#!/bin/bash
set -euo pipefail
trap 'echo "CVM_VOLATILE_ROOT_FAILED line=$LINENO command=$BASH_COMMAND" >&2' ERR
root=${1:?Expected root mountpoint}
[[ "$root" = /* && "$root" != / ]]
base=/run/cvm-overlay
test ! -e "$base"
test "$(findmnt -n -o FSTYPE --mountpoint "$root")" = ext4
findmnt -rn -S /dev/mapper/root -o TARGET | grep -Fx "$root"
findmnt -n -o OPTIONS --mountpoint "$root" | grep -Eq '(^|,)ro(,|$)'
mount -t tmpfs -o mode=0755 tmpfs "$base" --mkdir
mkdir -m 755 "$base/lower" "$base/upper" "$base/work"
# PID 1 makes the parent shared, which forbids moving the original root mount.
mount --bind "$root" "$base/lower"
umount "$root"
mount -t overlay -o "lowerdir=$base/lower,upperdir=$base/upper,workdir=$base/work" overlay "$root"
# Keep systemd's original-root identity without hiding the backing mounts.
ln -s /dev/mapper/root /run/systemd/volatile-root
/usr/local/libexec/cvm-check-root "$root"
