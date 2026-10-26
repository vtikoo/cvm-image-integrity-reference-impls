#!/bin/bash
set -euo pipefail
cloud-init status --wait --long
systemctl is-active walinuxagent
test -c /dev/tpmrm0
python3 -c 'import glob,pathlib; paths=glob.glob("/sys/firmware/efi/efivars/SecureBoot-*"); assert len(paths)==1 and pathlib.Path(paths[0]).read_bytes()[4]==1'
if ! mountpoint -q /boot/efi; then
    esp=$(lsblk -rpn -o PATH,LABEL | awk '$2=="UEFI" {print $1}')
    test -b "$esp"
    mount -o ro "$esp" /boot/efi
fi
test ! -e /canonical-volatile-reference
test ! -e /var/tmp/canonical-smoke-reference
test ! -e /var/tmp/canonical-reference-evidence.json
grep -q canonical-tmpfs-reference-v1 /etc/canonical-tmpfs-reference/source.json
test "$(findmnt -n -o FSTYPE /)" = overlay
test "$(findmnt -n -o FSTYPE -T /run/mnt/writable-tmp/upper)" = tmpfs
root=$(lsblk -rpn -o PATH,PARTLABEL | awk '$2=="cloudimg-rootfs" { print $1 }')
hash=$(lsblk -rpn -o PATH,PARTLABEL | awk '$2=="cloudimg-rootfs-verity" { print $1 }')
test -b "$root" && test -b "$hash"
roothash=$(python3 -c 'import json; print(json.load(open("/boot/efi/EFI/ubuntu/manifest.json"))["partitions"][0]["root_hash"])')
test "$roothash" = "${POC_EXPECTED_ROOT_HASH:?The offline expected root hash is required}"
veritysetup verify "$root" "$hash" "$roothash"
actual_hash=$(dmsetup table --target verity | awk '{if ($1 ~ /:$/) print $13; else print $12}')
test "$actual_hash" = "$roothash"
test "$(sha256sum /boot/efi/EFI/ubuntu/kernel.efi-6.8.0-1068-azure-fde | cut -d ' ' -f1)" = "${POC_EXPECTED_UKI_HASH:-b45c0d1e10c7b3b6fbf5f4884fa30acacf8f3ab16035d591bec100fe206c755a}"
echo '=== post-reboot evidence ==='
cat /proc/sys/kernel/random/boot_id
cat /proc/cmdline
for path in / /run/mnt/cloudimg-rootfs /run/mnt/writable-tmp; do
    findmnt -n -o TARGET,SOURCE,FSTYPE,OPTIONS -T "$path"
done
dmsetup status
dmsetup table --target verity
sha256sum /boot/efi/EFI/ubuntu/kernel.efi-6.8.0-1068-azure-fde
df -B1 /run/mnt/writable-tmp
df -i /run/mnt/writable-tmp
grep -E 'Shmem:|MemAvailable:|SwapTotal:|SwapFree:' /proc/meminfo
systemctl --failed --no-pager
python3 - <<'PY'
import json
import pathlib
import subprocess

assert not pathlib.Path('/canonical-volatile-reference').exists()
assert not pathlib.Path('/var/tmp/canonical-smoke-reference').exists()
assert not pathlib.Path('/var/tmp/canonical-reference-evidence.json').exists()
result = dict(boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              volatile_marker_absent=True, smoke_workload_absent=True,
              first_boot_evidence_absent=True, full_lower_verification_passed=True,
              verity_status=subprocess.check_output(['dmsetup', 'status', '--target', 'verity'], text=True).strip())
pathlib.Path('/var/tmp/canonical-reboot-evidence.json').write_text(json.dumps(result, indent=2) + '\n')
PY
echo VOLATILE_REBOOT_AND_UNCHANGED_LOWER_PASSED
