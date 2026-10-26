#!/usr/bin/env bash
set -euo pipefail
mode=${1:?Specify write or reset}
trap 'echo "GUEST_CHECK_FAILED line=$LINENO status=$?"' ERR
echo "BOOT_ID=$(cat /proc/sys/kernel/random/boot_id)"
echo "MACHINE_ID=$(cat /etc/machine-id)"
for pubkey in /etc/ssh/ssh_host_*_key.pub; do
    test -f "$pubkey"
    ssh-keygen -lf "$pubkey"
done
cat /proc/cmdline
test "$(findmnt -nr -o FSTYPE /)" = overlay
findmnt -nr -o OPTIONS / | grep -Eq '(^|,)rw(,|$)'
test "$(findmnt -nr -o FSTYPE -T /etc)" = overlay
test "$(findmnt -nr -o FSTYPE -T /var)" = overlay
test "$(blockdev --getro /dev/mapper/root)" -eq 1
veritysetup status root
dmsetup table root
findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS
test "$(wc -l < /proc/swaps)" -eq 1
df -B1 /
df -i /
grep -E 'MemTotal|MemAvailable|Shmem' /proc/meminfo
systemctl is-active sshd
systemctl is-active waagent
systemctl --failed --no-pager
test "$(systemctl --failed --no-legend --no-pager | wc -l)" -eq 0
ip -brief address
if command -v cloud-init; then
    cloud_status=0
    cloud-init status --format json > /run/verity-repro-cloud-status.json || cloud_status=$?
    cat /run/verity-repro-cloud-status.json
    python3 - "$mode" "$cloud_status" /run/verity-repro-cloud-status.json <<'PY'
import json
import sys

mode, code, path = sys.argv[1:]
with open(path) as stream:
    status = json.load(stream)
assert status["status"] == "done", status
assert not status["errors"], status
warnings = status["recoverable_errors"]
if code == "0":
    assert not warnings, status
else:
    expected = (
        "Unable to find provisioning media, falling back to IMDS metadata. "
        "Be aware that IMDS metadata does not support admin passwords or "
        "custom-data (user-data only)."
    )
    assert mode == "reset" and code == "2", status
    assert status["detail"] == "DataSourceAzure [seed=IMDS]", status
    assert set(warnings) == {"WARNING"}, status
    assert warnings["WARNING"] and all(w == expected for w in warnings["WARNING"]), status
    print("EXPECTED_IMDS_REPROVISION_WARNING: SSH-key/IMDS repro only; no admin password or custom-data")
PY
fi
if test -e /sys/fs/selinux/enforce; then cat /sys/fs/selinux/enforce; else
    echo "SELINUX_DISABLED_IN_BASE"
fi
test "$(cat /etc/verity-repro-modify)" = protected-base-original
test "$(cat /etc/verity-repro-delete)" = protected-base-delete-test
test "$(cat /var/lib/verity-repro/seed)" = protected-var-original
test ! -e /etc/verity-repro-new
test ! -e /var/lib/verity-repro/new
if test "$mode" = reset; then
    echo VOLATILE_REBOOT_RESET_OK
    exit 0
fi
test "$mode" = write
printf '%s\n' volatile-new-file > /etc/verity-repro-new
printf '%s\n' volatile-modification > /etc/verity-repro-modify
rm /etc/verity-repro-delete
printf '%s\n' volatile-var-write > /var/lib/verity-repro/new
test "$(cat /etc/verity-repro-modify)" = volatile-modification
test ! -e /etc/verity-repro-delete
python3 -c 'from pathlib import Path; p=Path("/var/lib/verity-repro/application"); p.write_text("application-write"); assert p.read_text()=="application-write"; p.unlink()'
before=$(awk '/^Shmem:/ {print $2}' /proc/meminfo)
dd if=/dev/zero of=/var/lib/verity-repro/workload bs=1M count=32 status=none
sync
after=$(awk '/^Shmem:/ {print $2}' /proc/meminfo)
echo "SHMEM_KIB_BEFORE=$before SHMEM_KIB_AFTER=$after"
test "$((after-before))" -ge 24576
df -B1 /
df -i /
grep -E 'MemTotal|MemAvailable|Shmem' /proc/meminfo
rm /var/lib/verity-repro/workload
echo VOLATILE_WRITES_AND_RESOURCE_SMOKE_OK
