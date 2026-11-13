#!/bin/bash
set -euo pipefail
trap 'echo "CVM_ROOT_POLICY_FAILED line=$LINENO" >&2' ERR
root=${1:?Expected root mountpoint}
test "$(findmnt -n -o FSTYPE --mountpoint "$root")" = overlay
findmnt -n -o OPTIONS --mountpoint "$root" | grep -Eq '(^|,)rw(,|$)'
options=$(findmnt -n -o OPTIONS --mountpoint "$root")
upper=$(printf '%s\n' "$options" | tr ',' '\n' | sed -n 's/^upperdir=//p')
work=$(printf '%s\n' "$options" | tr ',' '\n' | sed -n 's/^workdir=//p')
test -n "$upper"
test -n "$work"
test "$(findmnt -n -o FSTYPE -T "$upper")" = tmpfs
test "$(findmnt -n -o FSTYPE -T "$work")" = tmpfs
upper_mount=$(findmnt -n -o TARGET -T "$upper")
work_mount=$(findmnt -n -o TARGET -T "$work")
test "$upper_mount" = "$work_mount"
findmnt -rn -S /dev/mapper/root -o FSTYPE,OPTIONS | grep -Eq '^ext4 (ro,|[^ ]*,ro(,|$))'
dmsetup table root | awk '$3 == "verity" { found=1 } END { exit !found }'
dmsetup status root | awk '$3 == "verity" && $4 == "V" { found=1 } END { exit !found }'
swap=$(swapon --noheadings --show=NAME)
test -z "$swap"
echo CVM_ROOT_POLICY_PASSED
