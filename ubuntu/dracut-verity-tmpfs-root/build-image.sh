#!/bin/bash
set -euo pipefail
umask 077
fail() { echo "BUILD_FAILED: $*" >&2; exit 1; }
if (($# != 5)); then
    echo 'Usage: build-image.sh SOURCE.raw PRIVATE_KEY CERTIFICATE.pem RUN_DIRECTORY KERNEL_VERSION' >&2
    exit 2
fi
recipe=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
for tool in python3 losetup lsblk udevadm mount umount rsync sgdisk mkfs.ext4 mkfs.vfat \
    veritysetup e2fsck chroot openssl sbverify sbsign qemu-img modprobe modinfo findmnt git cargo rustc cc; do
    command -v "$tool" >/dev/null || fail "Missing required tool: $tool"
done
ukify=${UKIFY:-/usr/lib/systemd/ukify}
test -x "$ukify" || fail "Missing ukify: $ukify"
test "$(id -u)" = 0 || fail 'An exclusive root-capable Linux builder is required'
source_image=$(readlink -e "$1") || fail 'Missing source image'
key=$(readlink -e "$2") || fail 'Missing signing key'
cert=$(readlink -e "$3") || fail 'Missing certificate'
run=$(realpath -m "$4")
kernel=$5
[[ "$kernel" =~ ^[0-9][a-zA-Z0-9.+_-]*-azure(-fde)?$ ]] || fail 'Expected an explicit Azure kernel version'
test -f "$source_image" || fail 'Source must be a regular raw disk image, not a live device'
test ! -e "$run" || fail 'Run directory already exists'
checkout=$(cd "$recipe/../.." && pwd -P)
case "$run/" in "$checkout/"*) fail 'Run directory must be outside the checkout';; esac
for private_input in "$key" "$cert"; do
    case "$private_input" in "$checkout/"*) fail 'Signing inputs must be outside the checkout';; esac
done
(( (8#$(stat -c %a "$key") & 8#077) == 0 )) || fail 'Private key must have mode 0600 or stricter'
openssl x509 -in "$cert" -checkend 0 -noout
key_pub=$(openssl pkey -in "$key" -pubout -outform DER | sha256sum | cut -d ' ' -f1)
cert_pub=$(openssl x509 -in "$cert" -pubkey -noout |
    openssl pkey -pubin -outform DER | sha256sum | cut -d ' ' -f1)
test "$key_pub" = "$cert_pub" || fail 'Key and certificate do not match'
openssl x509 -in "$cert" -noout -text | grep -Fq 'Public Key Algorithm: rsaEncryption' ||
    fail 'Use an RSA signing certificate for the Azure UEFI db profile'
install -d -m 700 "$run" "$run/evidence" "$run/source-root" "$run/source-boot" "$run/source-esp" "$run/root" "$run/esp"
propagation=$(findmnt -rn -o PROPAGATION -T "$run")
test "$propagation" = private ||
    fail 'Use unshare --mount --propagation private to isolate build mounts'
exec > >(tee "$run/build.log") 2>&1
bash "$recipe/scripts/build-attestation.sh" "$run/attestation-sdk"
src_loop=''
out_loop=''
mounts=()
cleanup() {
    local result=$? i
    trap - EXIT
    for ((i=${#mounts[@]}-1; i>=0; i--)); do
        if ! umount -R "${mounts[i]}"; then echo "Cleanup failed: ${mounts[i]}" >&2; result=1; fi
    done
    if test -n "$out_loop"; then losetup -d "$out_loop" || result=1; fi
    if test -n "$src_loop"; then losetup -d "$src_loop" || result=1; fi
    exit "$result"
}
trap cleanup EXIT
trap 'echo "BUILD_FAILED line=$LINENO command=$BASH_COMMAND" >&2' ERR
mount_tracked() { mount "$@"; mounts+=("${!#}"); }
unmount_last() {
    umount -R "${mounts[-1]}"
    unset 'mounts[-1]'
}
partition() {
    local disk=$1 field=$2 value=$3
    local -a found
    mapfile -t found < <(lsblk -rpn -o "PATH,$field" "$disk" | awk -v value="$value" '$2==value {print $1}')
    ((${#found[@]} == 1)) || fail "Expected one $field=$value partition"
    printf '%s\n' "${found[0]}"
}
image_urn=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["imageUrn"])' "$recipe/inputs.json")
sha256sum "$source_image" > "$run/evidence/source.sha256"
# A VHD footer is not part of a raw image. Refuse rather than misinterpret it.
python3 - "$source_image" <<'PY'
import sys
with open(sys.argv[1], "rb") as stream:
    stream.seek(-512, 2)
    if stream.read(8) == b"conectix":
        raise ValueError("Convert the fixed VHD to raw with qemu-img first")
PY
src_loop=$(losetup --find --show --read-only --partscan "$source_image")
udevadm settle
source_root=$(partition "$src_loop" LABEL cloudimg-rootfs)
source_esp=$(partition "$src_loop" LABEL UEFI)
mount_tracked -o ro,noload "$source_root" "$run/source-root"
mount_tracked -o ro "$source_esp" "$run/source-esp"
lsblk -J -o PATH,PARTLABEL,LABEL,FSTYPE,SIZE,PARTUUID "$src_loop" > "$run/evidence/source-layout.json"
mapfile -t boots < <(lsblk -rpn -o PATH,LABEL "$src_loop" | awk '$2=="BOOT" {print $1}')
((${#boots[@]} <= 1)) || fail 'Ambiguous source boot partitions'
if ((${#boots[@]} == 1)); then
    mount_tracked -o ro,noload "${boots[0]}" "$run/source-boot"
fi
test -d "$run/source-root/lib/modules/$kernel" || fail 'Matching source kernel module tree is missing'
stock="$run/source-esp/EFI/ubuntu/kernel.efi-$kernel"
test -f "$stock" || fail "Expected the source Canonical UKI: $stock"
python3 - "$recipe" "$stock" "$run" <<'PY'
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / "scripts"))
from image_policy import pe_section
pathlib.Path(sys.argv[3], "vmlinuz").write_bytes(pe_section(sys.argv[2], ".linux"))
PY
sha256sum "$stock" "$run/vmlinuz" > "$run/evidence/kernel.sha256"
read -r esp_mib data_mib < <(python3 - "$recipe/inputs.json" <<'PY'
import json, sys
inputs = json.load(open(sys.argv[1]))
print(inputs["espMiB"], inputs["dataMiB"])
PY
)
# SHA-256 at 4 KiB gives 128 digests/block. Include all levels and superblock.
hash_mib=$(( (data_mib + 126) / 127 + 2 ))
truncate -s "$(( (esp_mib + data_mib + hash_mib + 2) * 1024 * 1024 ))" "$run/image.raw"
sgdisk --clear \
    --new="1:2048:+${esp_mib}M" --typecode=1:ef00 --change-name=1:ESP \
    --new="2:0:+${data_mib}M" --typecode=2:8300 --change-name=2:cvm-root \
    --new="3:0:+${hash_mib}M" --typecode=3:8300 --change-name=3:cvm-root-verity "$run/image.raw"
out_loop=$(losetup --find --show --partscan "$run/image.raw")
udevadm settle
data=$(partition "$out_loop" PARTLABEL cvm-root)
hash=$(partition "$out_loop" PARTLABEL cvm-root-verity)
esp=$(partition "$out_loop" PARTLABEL ESP)
mkfs.ext4 -F -L cvm-root "$data"
mkfs.vfat -F 32 -n CVMESP "$esp"
mount_tracked "$data" "$run/root"
rsync -aHAX --numeric-ids --one-file-system "$run/source-root/" "$run/root/"
if ((${#boots[@]} == 1)); then
    rsync -aHAX --numeric-ids "$run/source-boot/" "$run/root/boot/"
fi
python3 "$recipe/scripts/image_policy.py" finalize "$run/root" "$image_urn"
install -D -m 755 "$run/attestation-sdk/azure-guest-attest" "$run/root/usr/local/bin/azure-guest-attest"
install -m 755 "$recipe/attest-guest.py" "$run/root/usr/local/bin/cvm-attest"
install -m 644 "$run/attestation-sdk/build.json" "$run/root/etc/cvm-verity/attestation-sdk.json"
install -D -m 644 "$run/attestation-sdk/LICENSE" "$run/root/usr/share/doc/azure-guest-attest/LICENSE"
cp "$run/attestation-sdk/build.json" "$run/evidence/attestation-sdk.json"
chroot "$run/root" /usr/local/bin/azure-guest-attest --version
chroot "$run/root" /usr/local/bin/cvm-attest --help
# Chroot package operations never receive the signing key or the ESP.
install -D -m 755 "$recipe/scripts/check-root.sh" "$run/root/usr/local/libexec/cvm-check-root"
install -d "$run/root/usr/lib/dracut/modules.d/91cvm-verity"
cp "$recipe/dracut/91cvm-verity/"* "$run/root/usr/lib/dracut/modules.d/91cvm-verity/"
install -m 755 "$recipe/scripts/check-root.sh" "$run/root/usr/lib/dracut/modules.d/91cvm-verity/check-root.sh"
install -m 755 "$recipe/scripts/mount-volatile-root.sh" "$run/root/usr/lib/dracut/modules.d/91cvm-verity/mount-volatile-root.sh"
mount_tracked -t proc proc "$run/root/proc"
mount_tracked --rbind /dev "$run/root/dev"
mount --make-rslave "$run/root/dev"
mount_tracked --rbind /sys "$run/root/sys"
mount --make-rslave "$run/root/sys"
install -d "$run/root/run"
mount_tracked -t tmpfs tmpfs "$run/root/run"
# APT drops privileges; its temporary resolver must remain world-readable.
resolver="$run/root/etc/resolv.conf"
if test -e "$resolver" || test -L "$resolver"; then
    mv "$resolver" "$run/root/run/original-resolv.conf"
fi
install -m 644 /etc/resolv.conf "$resolver"
if test -e "$run/root/usr/sbin/policy-rc.d" || test -L "$run/root/usr/sbin/policy-rc.d"; then
    mv "$run/root/usr/sbin/policy-rc.d" "$run/root/run/original-policy-rc.d"
fi
cat > "$run/root/usr/sbin/policy-rc.d" <<'POLICY'
#!/bin/sh
exit 101
POLICY
chmod 755 "$run/root/usr/sbin/policy-rc.d"
chroot "$run/root" apt-get -o APT::Update::Error-Mode=any update
chroot "$run/root" apt-get install -y --no-install-recommends dracut-core systemd-boot-efi cryptsetup-bin
install -d "$run/root/etc/cvm-verity/dracut-empty"
chroot "$run/root" dpkg-query -W > "$run/evidence/packages.txt"
for name in dm_verity overlay ext4 hv_vmbus hv_storvsc hv_netvsc nvme; do
    modprobe -C /dev/null --dirname "$run/root" --set-version "$kernel" --show-depends "$name"
done > "$run/evidence/module-plan.txt"
while read -r kind file rest; do
    if test "$kind" = builtin; then continue; fi
    test "$kind" = insmod || fail 'Unexpected module dependency format'
    [[ "$(modinfo -F vermagic "$file")" == "$kernel "* ]] || fail "Wrong module version: $file"
    test -n "$(modinfo -F signer "$file")" || fail "Unsigned module: $file"
done < "$run/evidence/module-plan.txt"
chroot "$run/root" dracut --force --no-hostonly --no-hostonly-cmdline \
    --conf /dev/null --confdir /etc/cvm-verity/dracut-empty \
    --add 'systemd systemd-initrd systemd-veritysetup dracut-systemd cvm-verity' \
    --omit 'crypt lvm mdraid resume' \
    --add-drivers 'dm_verity overlay ext4 hv_vmbus hv_storvsc hv_netvsc nvme' \
    --gzip /run/cvm.initrd "$kernel"
chroot "$run/root" lsinitrd /run/cvm.initrd > "$run/evidence/initrd-inventory.txt"
for required in systemd-veritysetup-generator systemd-veritysetup systemd-volatile-root \
    cvm-check-root cvm-mount-volatile-root cvm-verity-root.service \
    initrd-switch-root.service.d/cvm-verity.conf systemd-volatile-root.service.d/cvm-verity.conf; do
    grep -Fq "$required" "$run/evidence/initrd-inventory.txt" || fail "Missing initramfs component: $required"
done
if grep -Eq 'snap-bootstrap|snap-initramfs-mounts' "$run/evidence/initrd-inventory.txt"; then
    fail 'Canonical snap-bootstrap must not participate in the new boot path'
fi
cp "$run/root/run/cvm.initrd" "$run/initrd"
cp "$run/root/usr/lib/systemd/boot/efi/linuxx64.efi.stub" "$run/stub.efi"
cp -L "$run/root/etc/os-release" "$run/os-release"
rm "$run/root/usr/sbin/policy-rc.d"
if test -e "$run/root/run/original-policy-rc.d" || test -L "$run/root/run/original-policy-rc.d"; then
    mv "$run/root/run/original-policy-rc.d" "$run/root/usr/sbin/policy-rc.d"
fi
rm "$resolver"
if test -e "$run/root/run/original-resolv.conf" || test -L "$run/root/run/original-resolv.conf"; then
    mv "$run/root/run/original-resolv.conf" "$resolver"
fi
chroot "$run/root" apt-get clean
truncate -s 0 "$run/root/etc/machine-id"
find "$run/root/etc/ssh" -maxdepth 1 -type f -name 'ssh_host_*_key*' -delete
python3 - "$run" "$recipe" <<'PY'
import hashlib, json, pathlib, sys
run, recipe = map(pathlib.Path, sys.argv[1:])
sdk = json.loads((run / "evidence/attestation-sdk.json").read_text())
installed = json.loads((run / "root/etc/cvm-verity/attestation-sdk.json").read_text())
if installed != sdk:
    raise ValueError("Installed SDK provenance differs from the builder record")
binary = run / "root/usr/local/bin/azure-guest-attest"
if hashlib.sha256(binary.read_bytes()).hexdigest() != sdk["binarySha256"]:
    raise ValueError("Installed native collector differs from the built SDK")
wrapper = (recipe / "attest-guest.py").read_bytes()
if (run / "root/usr/local/bin/cvm-attest").read_bytes() != wrapper:
    raise ValueError("Installed attestation wrapper differs from the recipe")
sdk["wrapperSha256"] = hashlib.sha256(wrapper).hexdigest()
(run / "evidence/attestation-installation.json").write_text(json.dumps(sdk, indent=2) + "\n")
PY
unmount_last # /run
unmount_last # /sys
unmount_last # /dev
unmount_last # /proc
sync
unmount_last # root data: no more writable mounts from this point
e2fsck -fn "$data" > "$run/evidence/fsck.txt" 2>&1
veritysetup format --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
    "$data" "$hash" > "$run/evidence/verity-format.txt"
root_hash=$(sed -n 's/^Root hash:[[:space:]]*//p' "$run/evidence/verity-format.txt")
data_uuid=$(lsblk -dn -o PARTUUID "$data")
hash_uuid=$(lsblk -dn -o PARTUUID "$hash")
python3 "$recipe/scripts/image_policy.py" cmdline "$root_hash" "$data_uuid" "$hash_uuid" > "$run/cmdline"
"$ukify" build --config /dev/null --linux "$run/vmlinuz" --initrd "$run/initrd" \
    --stub "$run/stub.efi" --uname "$kernel" --os-release "@$run/os-release" \
    --cmdline "@$run/cmdline" --no-sign-kernel \
    --secureboot-private-key "$key" --secureboot-certificate "$cert" \
    --output "$run/cvm.efi"
sbverify --cert "$cert" "$run/cvm.efi"
python3 "$recipe/scripts/image_policy.py" check-uki "$run/cvm.efi" "$run/cmdline" "$run/vmlinuz" "$run/initrd"
openssl x509 -in "$cert" -outform DER -out "$run/signer.der"
mount_tracked "$esp" "$run/esp"
install -D -m 644 "$run/cvm.efi" "$run/esp/EFI/BOOT/BOOTX64.EFI"
cmp "$run/cvm.efi" "$run/esp/EFI/BOOT/BOOTX64.EFI"
sync
unmount_last
sgdisk --verify "$run/image.raw" > "$run/evidence/gpt.txt"
lsblk -J -o PATH,PARTLABEL,FSTYPE,SIZE,PARTUUID "$out_loop" > "$run/evidence/output-layout.json"
losetup -d "$out_loop"
out_loop=
qemu-img convert -f raw -O vpc -o subformat=fixed,force_size=on "$run/image.raw" "$run/image.vhd"
qemu-img info -f vpc --output=json "$run/image.vhd" > "$run/evidence/vhd-info.json"
python3 - "$run" "$image_urn" "$kernel" "$root_hash" "$data_uuid" "$hash_uuid" <<'PY'
import json, pathlib, struct, sys
run = pathlib.Path(sys.argv[1])
with (run / "image.vhd").open("rb") as stream:
    stream.seek(-512, 2)
    footer = bytearray(stream.read(512))
size = struct.unpack_from(">Q", footer, 48)[0]
checksum = struct.unpack_from(">I", footer, 64)[0]
footer[64:68] = bytes(4)
if (footer[:8] != b"conectix" or struct.unpack_from(">I", footer, 60)[0] != 2
        or size % (1024 * 1024) or size != (run / "image.raw").stat().st_size
        or (run / "image.vhd").stat().st_size != size + 512
        or checksum != (~sum(footer) & 0xffffffff)):
    raise ValueError("Invalid Azure fixed VHD")
(run / "evidence/build.json").write_text(json.dumps(dict(
    imageUrn=sys.argv[2], kernel=sys.argv[3], rootHash=sys.argv[4],
    dataPartUuid=sys.argv[5], hashPartUuid=sys.argv[6],
    attestationSdk=json.loads((run / "evidence/attestation-installation.json").read_text()),
    diskQualification="NOT_RUN: full verification and corruption tests are optional qualification",
    validation="offline build only; Azure CVM acceptance required",
), indent=2) + "\n")
PY
sha256sum "$run/image.raw" "$run/image.vhd" "$run/cvm.efi" "$run/signer.der" > "$run/evidence/output.sha256"
echo DRACUT_VERITY_IMAGE_BUILD_PASSED
