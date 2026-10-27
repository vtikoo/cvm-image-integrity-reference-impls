#!/bin/bash
set -euo pipefail
source=$(readlink -e "${POC_SOURCE_DISK:-/dev/disk/azure/scsi1/lun0}") || {
    echo 'Source disk does not exist; set POC_SOURCE_DISK for a local build.' >&2
    exit 1
}
test -b "$source" || { echo 'Source must be a block device, not an image file.' >&2; exit 1; }
work=/var/tmp/canonical-build
image="$work/root-working.raw"
out="$work/evidence"
install -d -m 700 "$out" "$work/root" "$work/esp"
exec > >(tee "$work/image-build.log") 2>&1
nbd=
mounted=
cleanup() {
    if test -n "$mounted"; then umount "$mounted"; fi
    if test -e /dev/mapper/canonical-corruption-test; then veritysetup close canonical-corruption-test; fi
    if test -n "$nbd"; then qemu-nbd --disconnect "$nbd"; fi
}
trap cleanup EXIT
trap 'echo "IMAGE_BUILD_FAILED line=$LINENO command=$BASH_COMMAND" >&2' ERR
connect_image() {
    local input=$1 format=${2:-raw}
    test -z "$nbd"
    local candidate
    for candidate in /sys/class/block/nbd*; do
        if test ! -f "$candidate/pid"; then
            nbd="/dev/${candidate##*/}"
            break
        fi
    done
    test -n "$nbd"
    qemu-nbd --connect "$nbd" --format "$format" "$input"
    blockdev --rereadpt "$nbd"
    udevadm settle
}
disconnect_image() {
    qemu-nbd --disconnect "$nbd"
    nbd=
    udevadm settle
}
partition_by_label() {
    local field=$1 label=$2
    lsblk -rpn -o "PATH,$field" "$nbd" | awk -v label="$label" '$2==label { print $1 }'
}
if lsblk -srpn -o PATH "$(findmnt -n -o SOURCE /)" | grep -Fxq "$source"; then
    echo 'Refusing to use the helper boot disk.' >&2
    exit 1
fi
if lsblk -rn -o MOUNTPOINT "$source" | grep -q '[^[:space:]]'; then
    echo 'Refusing to use a mounted source disk.' >&2
    exit 1
fi
test "$(blockdev --getsize64 "$source")" = 32213303296
blockdev --setro "$source"
if test ! -f "$out/manifest.json"; then
if test -e "$image"; then
    test ! -e "$work/canonical-tmpfs.vhd"
    test -f "$work/raw-copy-complete"
    echo 'Resuming the unfinalized disposable working image.'
else
    qemu-img convert -f raw -O raw -S 4k "$source" "$image"
    touch "$work/raw-copy-complete"
fi
connect_image "$image"
root=$(partition_by_label LABEL cloudimg-rootfs)
test -b "$root"
mount "$root" "$work/root"
mounted="$work/root"
if test -n "${POC_OFFLINE_PREPARE_SCRIPT:-}"; then
    bash "$POC_OFFLINE_PREPARE_SCRIPT" "$work/root"
fi
python3 - "$work/root" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for key_type in ("rsa", "ecdsa", "ed25519", "dsa"):
    for suffix in ("", ".pub"):
        (root / f"etc/ssh/ssh_host_{key_type}_key{suffix}").unlink(missing_ok=True)
source = json.loads((root / "etc/canonical-tmpfs-reference/source.json").read_text())
assert source["base_marker"] == "canonical-tmpfs-reference-v1"
assert source["image"] == "Canonical:ubuntu-22_04-lts:cvm:22.04.202610220"
assert not any(
    len(fields := line.split()) >= 2 and fields[1] == "/"
    for line in (root / "etc/fstab").read_text().splitlines()
    if not line.lstrip().startswith("#")
)
assert (root / "etc/machine-id").read_text().strip() in ("", "uninitialized")
assert not any(line.startswith("pocadmin:") for line in (root / "etc/passwd").read_text().splitlines())
assert not list((root / "etc/ssh").glob("ssh_host_*_key"))
assert not list((root / "var/lib/cloud/instances").glob("*"))
print("OFFLINE_GENERALIZATION_VERIFIED")
PY
if test -d "$work/root/var/tmp/canonical-poc-baseline"; then
    rm -rf -- "$work/root/var/tmp/canonical-poc-baseline"
fi
sync
umount "$mounted"
mounted=
disconnect_image
"$work/encrypt-cloud-image-tool" integrity-protect "$image"
fi
connect_image "$image"
root=$(partition_by_label PARTLABEL cloudimg-rootfs)
hash=$(partition_by_label PARTLABEL cloudimg-rootfs-verity)
esp=$(partition_by_label LABEL UEFI)
test -b "$root" && test -b "$hash" && test -b "$esp"
if test -n "${POC_SIGNED_UKI:-}"; then
    test -n "${POC_EXPECTED_UKI_HASH:?Verified custom UKI hash is required}"
    test "$(sha256sum "$POC_SIGNED_UKI" | cut -d ' ' -f1)" = "$POC_EXPECTED_UKI_HASH"
    mount "$esp" "$work/esp"
    mounted="$work/esp"
    install -m 644 "$POC_SIGNED_UKI" "$work/esp/EFI/ubuntu/kernel.efi-6.8.0-1068-azure-fde"
    sync
    umount "$mounted"
    mounted=
fi
mount -o ro "$esp" "$work/esp"
mounted="$work/esp"
if test -f "$out/manifest.json"; then
    cmp "$work/esp/EFI/ubuntu/manifest.json" "$out/manifest.json"
else
    cp "$work/esp/EFI/ubuntu/manifest.json" "$out/manifest.json"
fi
roothash=$(python3 - "$out/manifest.json" <<'PY'
import json
import re
import sys
manifest = json.load(open(sys.argv[1]))
assert len(manifest["partitions"]) == 1
lower = manifest["partitions"][0]
assert lower["label"] == "cloudimg-rootfs" and lower["read_only"] is True
assert set(lower) == {"label", "read_only", "root_hash"}
assert re.fullmatch("[0-9a-f]{64}", lower["root_hash"])
print(lower["root_hash"])
PY
)
printf '%s\n' "$roothash" > "$out/root-hash.txt"
uki="$work/esp/EFI/ubuntu/kernel.efi-6.8.0-1068-azure-fde"
test "$(sha256sum "$uki" | cut -d ' ' -f1)" = "${POC_EXPECTED_UKI_HASH:-b45c0d1e10c7b3b6fbf5f4884fa30acacf8f3ab16035d591bec100fe206c755a}"
sha256sum "$uki" > "$out/uki-after.sha256"
umount "$mounted"
mounted=
sgdisk --verify "$nbd" > "$out/gpt-verification.txt"
sgdisk --print "$nbd" > "$out/partition-table.txt"
sfdisk --json "$image" > "$out/disk-layout.json"
veritysetup dump "$hash" > "$out/verity-superblock.txt"
veritysetup verify "$root" "$hash" "$roothash"
echo OFFLINE_VERITY_VERIFICATION_PASSED
disconnect_image
clone="$work/corruption-test.qcow2"
if test -e "$clone"; then
    qemu-img info -f qcow2 --output=json "$clone" | python3 -c \
        'import json,sys; info=json.load(sys.stdin); assert info["full-backing-filename"] == sys.argv[1]' "$image"
    rm -- "$clone"
fi
qemu-img create -f qcow2 -F raw -b "$image" "$clone"
connect_image "$clone" qcow2
root=$(partition_by_label PARTLABEL cloudimg-rootfs)
hash=$(partition_by_label PARTLABEL cloudimg-rootfs-verity)
python3 - "$root" <<'PY'
import os
import sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    original = os.pread(fd, 1, 4096 * 8)
    assert len(original) == 1
    os.pwrite(fd, bytes([original[0] ^ 0x80]), 4096 * 8)
    os.fsync(fd)
finally:
    os.close(fd)
PY
if veritysetup verify "$root" "$hash" "$roothash" > "$out/corruption-offline.txt" 2>&1; then
    echo 'Corruption incorrectly passed offline verification.' >&2
    exit 1
fi
veritysetup open "$root" canonical-corruption-test "$hash" "$roothash"
if dd if=/dev/mapper/canonical-corruption-test bs=4096 skip=8 count=1 status=none \
    > /dev/null 2> "$out/corruption-read.txt"; then
    echo 'Corruption incorrectly passed a live verified read.' >&2
    exit 1
fi
dmsetup status canonical-corruption-test > "$out/corruption-dm-status.txt"
dmesg | tail -n 30 > "$out/corruption-kernel.txt"
veritysetup close canonical-corruption-test
disconnect_image
rm -- "$clone"
echo CORRUPTION_OFFLINE_AND_LIVE_READ_FAILED_AS_EXPECTED
vhd="$work/canonical-tmpfs.vhd"
test ! -e "$vhd"
qemu-img convert -f raw -O vpc -o subformat=fixed,force_size=on "$image" "$vhd"
qemu-img info -f vpc --output=json "$vhd" > "$out/vhd-info.json"
python3 - "$vhd" "$out/vhd-footer.json" <<'PY'
import json
import os
import struct
import sys
size = os.stat(sys.argv[1]).st_size
with open(sys.argv[1], "rb") as file:
    file.seek(-512, os.SEEK_END)
    footer = bytearray(file.read(512))
assert footer[:8] == b"conectix"
virtual_size = struct.unpack_from(">Q", footer, 48)[0]
disk_type = struct.unpack_from(">I", footer, 60)[0]
checksum = struct.unpack_from(">I", footer, 64)[0]
footer[64:68] = bytes(4)
assert checksum == (~sum(footer) & 0xffffffff)
assert disk_type == 2
assert virtual_size == 32213303296
assert virtual_size % (1024 * 1024) == 0
assert size == virtual_size + 512
record = {"virtual_size": virtual_size, "file_size": size, "disk_type": "fixed", "footer_checksum_valid": True}
open(sys.argv[2], "w").write(json.dumps(record, indent=2) + "\n")
print(json.dumps(record))
PY
echo "ROOT_HASH=$roothash"
cat "$out/manifest.json"
echo
cat "$out/corruption-offline.txt"
cat "$out/corruption-read.txt"
cat "$out/corruption-dm-status.txt"
echo IMAGE_BUILD_AND_NEGATIVE_TESTS_PASSED
