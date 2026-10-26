#!/bin/bash
set -euo pipefail
cloud-init status --wait --long
systemctl is-active walinuxagent
test -c /dev/tpmrm0
if ! mountpoint -q /boot/efi; then
    esp=$(lsblk -rpn -o PATH,LABEL | awk '$2=="UEFI" {print $1}')
    test -b "$esp"
    mount -o ro "$esp" /boot/efi
    echo 'The guest ESP was mounted read-only for evidence collection.'
fi
python3 - <<'PY'
import glob
import hashlib
import json
import os
import pathlib
import subprocess
import struct
import uuid

def run(*args):
    return subprocess.check_output(args, text=True).strip()

def mount(path):
    return json.loads(run("findmnt", "-J", "-T", str(path), "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"))["filesystems"][0]

def memory():
    return {
        key: int(value.split()[0]) * 1024
        for line in pathlib.Path("/proc/meminfo").read_text().splitlines()
        for key, value in [line.split(":", 1)]
        if key in ("Shmem", "MemAvailable", "SwapTotal", "SwapFree")
    }

def usage(path):
    fs = os.statvfs(path)
    return {
        "used_bytes": (fs.f_blocks - fs.f_bfree) * fs.f_frsize,
        "available_bytes": fs.f_bavail * fs.f_frsize,
        "used_inodes": fs.f_files - fs.f_ffree,
        "available_inodes": fs.f_favail,
        "memory": memory(),
    }

cmdline = pathlib.Path("/proc/cmdline").read_text().strip()
assert "snapd_recovery_mode=cloudimg-rootfs" in cmdline
assert "roothash=" not in cmdline and "systemd.volatile=" not in cmdline
root = mount("/")
assert root["fstype"] == "overlay", root
options = dict(option.split("=", 1) for option in root["options"].split(",") if "=" in option)
assert len(options["lowerdir"].split(":")) == 1
lower = mount(options["lowerdir"])
upper = mount(options["upperdir"])
work = mount(options["workdir"])
assert upper["fstype"] == work["fstype"] == "tmpfs"
assert upper["target"] == work["target"]
assert lower["fstype"] == "ext4"
assert "ro" in lower["options"].split(",")
table = run("dmsetup", "table", lower["source"])
assert table.split()[2] == "verity", table
status = run("dmsetup", "status", lower["source"])
assert status.split()[3] == "V", status
manifest = json.loads(pathlib.Path("/boot/efi/EFI/ubuntu/manifest.json").read_text())
assert len(manifest["partitions"]) == 1
entry = manifest["partitions"][0]
assert entry["read_only"] is True and entry["label"] == "cloudimg-rootfs"
assert entry["root_hash"] == os.environ["POC_EXPECTED_ROOT_HASH"]
assert table.split()[11] == entry["root_hash"]
assert run("swapon", "--show", "--noheadings") == ""
secure_boot = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
assert len(secure_boot) == 1 and pathlib.Path(secure_boot[0]).read_bytes()[4] == 1
uki = pathlib.Path("/boot/efi/EFI/ubuntu/kernel.efi-6.8.0-1068-azure-fde")
uki_hash = hashlib.sha256(uki.read_bytes()).hexdigest()
assert uki_hash == os.environ.get("POC_EXPECTED_UKI_HASH", "b45c0d1e10c7b3b6fbf5f4884fa30acacf8f3ab16035d591bec100fe206c755a")
db_certificates = []
expected_certificate = os.environ.get("POC_EXPECTED_CERT_SHA256")
if expected_certificate:
    data = pathlib.Path("/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f").read_bytes()
    offset = 4
    while offset < len(data):
        kind = uuid.UUID(bytes_le=data[offset:offset + 16])
        size, header, entry_size = struct.unpack_from("<III", data, offset + 16)
        assert size >= 28 + header and entry_size > 16 and offset + size <= len(data)
        entries = data[offset + 28 + header:offset + size]
        assert len(entries) % entry_size == 0
        if str(kind) == "a5c059a1-94e4-4aa7-87b5-ab155c2bf072":
            db_certificates.extend(hashlib.sha256(entries[i + 16:i + entry_size]).hexdigest()
                                   for i in range(0, len(entries), entry_size))
        offset += size
    assert expected_certificate in db_certificates, db_certificates
base = json.loads(pathlib.Path("/etc/canonical-tmpfs-reference/source.json").read_text())
assert base["base_marker"] == "canonical-tmpfs-reference-v1"
marker = pathlib.Path("/canonical-volatile-reference")
assert not marker.exists()
marker.write_text("This uniquely named root write must disappear after reboot.\n")
assert (pathlib.Path(options["upperdir"]) / marker.name).is_file()
before = usage(options["upperdir"])
assert before["available_bytes"] > 256 * 1024 * 1024
assert before["memory"]["MemAvailable"] > 512 * 1024 * 1024
smoke = pathlib.Path("/var/tmp/canonical-smoke-reference")
assert mount(smoke.parent)["fstype"] == "overlay"
smoke.mkdir()
with (smoke / "bulk").open("wb") as file:
    for _ in range(128):
        file.write(bytes(1024 * 1024))
for index in range(2048):
    (smoke / f"small-{index:04d}").write_bytes(b"x" * 1024)
after = usage(options["upperdir"])
evidence = {
    "boot_id": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    "kernel": run("uname", "-r"),
    "cmdline": cmdline,
    "root": root,
    "lower": lower,
    "upper": upper,
    "work": work,
    "verity_table": table,
    "verity_status": status,
    "manifest": manifest,
    "expected_root_hash": os.environ["POC_EXPECTED_ROOT_HASH"],
    "uki_sha256": uki_hash,
    "firmware_db_certificate_sha256": db_certificates,
    "swap": [],
    "smoke": {"bulk_bytes": 128 * 1024 * 1024, "small_file_count": 2048, "small_file_bytes": 1024},
    "before": before,
    "after": after,
    "marker": str(marker),
}
print(json.dumps(evidence, indent=2))
pathlib.Path("/var/tmp/canonical-reference-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
PY
echo '=== live block identities ==='
lsblk -b -o NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,PARTLABEL,PARTUUID,MOUNTPOINTS
echo '=== complete mount evidence ==='
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
echo '=== failed units ==='
systemctl --failed --no-pager
echo '=== manifest/initrd boot evidence ==='
journalctl -b --no-pager -u snap-initramfs-mounts.service
echo REFERENCE_BOOT_AND_SMOKE_PASSED
