#!/bin/bash
set -euo pipefail
test "$#" = 1
root=$(readlink -e "$1")
test "$(findmnt -n -o TARGET -T "$root")" = "$root"
test "$(findmnt -n -o FSTYPE -T "$root")" = ext4
python3 - "$root" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
assert not any(line.startswith("pocadmin:") for line in (root / "etc/passwd").read_text().splitlines())
assert not list((root / "var/lib/cloud/instances").glob("*"))
path = root / "etc/fstab"
lines = []
removed = 0
for line in path.read_text().splitlines():
    fields = line.split()
    if fields and not line.lstrip().startswith("#") and len(fields) >= 4:
        if fields[1] == "/":
            removed += 1
            continue
        if fields[1] == "/boot/efi":
            fields[3] = ",".join([v for v in fields[3].split(",") if v not in ("rw", "ro")] + ["ro"])
            line = "\t".join(fields)
    lines.append(line)
assert removed == 1, f"Expected one original root fstab entry, found {removed}"
path.write_text("\n".join(lines) + "\n")
(root / "etc/machine-id").write_text("")
for path in (root / "etc/ssh").glob("ssh_host_*_key*"):
    path.unlink()
marker = root / "etc/canonical-tmpfs-reference/source.json"
marker.parent.mkdir(exist_ok=True)
marker.write_text(json.dumps({
    "image": "Canonical:ubuntu-22_04-lts:cvm:22.04.202610220",
    "base_marker": "canonical-tmpfs-reference-v1",
    "variant": "custom-initrd-poc-signed-uki",
    "root_policy": "dm-verity lower; automatically generated tmpfs upper",
    "source": "unbooted generalized Marketplace disk; no source VM",
}, indent=2) + "\n")
(root / "etc/cloud/cloud.cfg.d/99-canonical-tmpfs.cfg").write_text(
    'growpart:\n  mode: "off"\nresize_rootfs: false\n')
journal = root / "etc/systemd/journald.conf.d/canonical-tmpfs.conf"
journal.parent.mkdir(exist_ok=True)
journal.write_text("[Journal]\nStorage=volatile\nRuntimeMaxUse=64M\n")
print("UNBOOTED_SOURCE_CUSTOMIZED_OFFLINE_BEFORE_HASHING")
PY
