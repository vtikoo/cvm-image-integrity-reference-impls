#!/bin/bash
set -euo pipefail
umask 077
if (($# != 5)); then
    echo 'Usage: Rebuild-SignedUki.sh STOCK_UKI PRIVATE_KEY CERTIFICATE_PEM OUTPUT_DIRECTORY KERNEL_VERSION' >&2
    exit 2
fi
test "$(id -u)" = 0
for command in objcopy unmkinitramfs modprobe modinfo depmod cpio gzip sbsign sbverify sbattach openssl python3 chroot; do
    command -v "$command" >/dev/null || { echo "Missing required tool: $command" >&2; exit 1; }
done
stock=$(readlink -e "$1")
key=$(readlink -e "$2")
certificate=$(readlink -e "$3")
out=$(readlink -m "$4")
kernel=$5
test "$kernel" = 6.8.0-1068-azure-fde
stock_hash=b45c0d1e10c7b3b6fbf5f4884fa30acacf8f3ab16035d591bec100fe206c755a
test "$(sha256sum "$stock" | cut -d ' ' -f1)" = "$stock_hash"
test ! -e "$out"
if (( (8#$(stat -c %a "$key") & 8#077) != 0 )); then
    echo 'The private signing key must not be accessible to group or other users.' >&2
    exit 1
fi
install -d -m 700 "$out"
key_public=$(openssl pkey -in "$key" -pubout -outform DER | sha256sum | cut -d ' ' -f1)
certificate_public=$(openssl x509 -in "$certificate" -pubkey -noout |
    openssl pkey -pubin -outform DER | sha256sum | cut -d ' ' -f1)
test "$key_public" = "$certificate_public"
openssl x509 -in "$certificate" -checkend 0 -noout
openssl x509 -in "$certificate" -outform DER -out "$out/signer.der"
grep -qx 'CONFIG_RD_GZIP=y' "/boot/config-$kernel"
modules=$(readlink -e "/lib/modules/$kernel")
objcopy --dump-section ".initrd=$out/stock.initrd" "$stock" "$out/inspection-copy.efi"
test "$(sha256sum "$stock" | cut -d ' ' -f1)" = "$stock_hash"
unmkinitramfs "$out/stock.initrd" "$out/unpacked"
main="$out/unpacked/main"
test -d "$main/usr/lib/modules/$kernel"
test "$(readlink -m "$main/lib/modules/$kernel")" = "$main/usr/lib/modules/$kernel"
for name in dm_verity overlay; do
    modprobe -C /dev/null --set-version "$kernel" --show-depends "$name"
done > "$out/module-plan.txt"
while read -r kind file rest; do
    if [[ "$kind" == builtin ]]; then continue; fi
    test "$kind" = insmod
    resolved=$(readlink -e "$file")
    case "$resolved" in
        "$modules"/*) ;;
        *) echo "Dependency outside the matching kernel module tree: $file" >&2; exit 1 ;;
    esac
    [[ "$(modinfo -F vermagic "$resolved")" == "$kernel "* ]]
    test -n "$(modinfo -F signer "$resolved")"
    relative=${resolved#"$modules"/}
    install -D -m 644 "$resolved" "$main/usr/lib/modules/$kernel/$relative"
done < "$out/module-plan.txt"
for metadata in modules.builtin modules.builtin.modinfo modules.order; do
    cp "$modules/$metadata" "$main/usr/lib/modules/$kernel/$metadata"
done
depmod -b "$main" "$kernel"
for name in dm_verity overlay; do
    modprobe -C /dev/null --dirname "$main" --set-version "$kernel" --show-depends "$name"
done > "$out/initrd-module-plan.txt"
loader=
for candidate in /usr/sbin/modprobe /sbin/modprobe /usr/bin/modprobe /bin/modprobe; do
    if [[ -e "$main$candidate" || -L "$main$candidate" ]]; then
        if chroot "$main" "$candidate" --version > "$out/modprobe-check.txt" 2>&1; then
            loader=$candidate
            break
        fi
    fi
done
if [[ -z "$loader" ]]; then
    echo 'The stock initrd has no runnable modprobe; inspect its kmod packaging before continuing.' >&2
    exit 1
fi
test -f "$main/usr/lib/systemd/system/snap-initramfs-mounts.service"
install -d "$main/etc/systemd/system/snap-initramfs-mounts.service.d"
cat > "$main/etc/systemd/system/snap-initramfs-mounts.service.d/poc-modules.conf" <<EOF
[Service]
ExecStartPre=$loader dm_verity
ExecStartPre=$loader overlay
EOF
archive_tree() {
    (cd "$1" && find . -print0 | LC_ALL=C sort -z | cpio --null -o -H newc --reproducible)
}
: > "$out/custom.initrd"
while IFS= read -r -d '' early; do
    archive_tree "$early" >> "$out/custom.initrd"
done < <(find "$out/unpacked" -mindepth 1 -maxdepth 1 -type d -name 'early*' -print0 | sort -zV)
archive_tree "$main" | gzip -n -9 >> "$out/custom.initrd"
cp "$stock" "$out/stock-unsigned.efi"
sbattach --remove "$out/stock-unsigned.efi"
objcopy --update-section ".initrd=$out/custom.initrd" "$out/stock-unsigned.efi" "$out/unsigned.efi"
python3 - "$out" <<'PY'
import json
import pathlib
import struct
import sys

out = pathlib.Path(sys.argv[1])
path = out / "unsigned.efi"
data = bytearray(path.read_bytes())
initrd = (out / "custom.initrd").read_bytes()
pe = struct.unpack_from("<I", data, 0x3c)[0]
assert data[pe:pe+4] == b"PE\0\0"
optional = pe + 24
assert struct.unpack_from("<H", data, optional)[0] == 0x20b
count = struct.unpack_from("<H", data, pe+6)[0]
start = optional + struct.unpack_from("<H", data, pe+20)[0]
alignment = struct.unpack_from("<I", data, optional+32)[0]
ends = []
found = 0
for index in range(count):
    header = start + index*40
    virtual, rva, size, offset = struct.unpack_from("<IIII", data, header+8)
    if data[header:header+8].rstrip(b"\0") == b".initrd":
        assert offset+size <= len(data) and len(initrd) <= size
        assert data[offset:offset+len(initrd)] == initrd
        old_virtual = virtual
        virtual = len(initrd)
        # GNU objcopy preserves the old PE VirtualSize when updating section contents.
        struct.pack_into("<I", data, header+8, virtual)
        found += 1
    ends.append((rva+virtual+alignment-1)//alignment*alignment)
assert found == 1
struct.pack_into("<I", data, optional+56, max(ends))
struct.pack_into("<I", data, optional+64, 0)
path.write_bytes(data)
(out / "pe-size-correction.json").write_text(json.dumps(
    dict(previous_initrd_virtual_size=old_virtual, initrd_virtual_size=len(initrd),
         size_of_image=max(ends)), indent=2) + "\n")
PY
sbsign --key "$key" --cert "$certificate" --output "$out/poc-signed.efi" "$out/unsigned.efi"
sbverify --cert "$certificate" "$out/poc-signed.efi"
test "$(sha256sum "$stock" | cut -d ' ' -f1)" = "$stock_hash"
python3 - "$stock" "$out" "$kernel" <<'PY'
import hashlib
import json
import pathlib
import struct
import sys

stock, out, kernel = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]

def sections(path):
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[pe:pe + 4] == b"PE\0\0"
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    start = pe + 24 + optional_size
    result = {}
    for index in range(count):
        header = start + index * 40
        name = data[header:header + 8].rstrip(b"\0").decode("ascii")
        virtual_size = struct.unpack_from("<I", data, header + 8)[0]
        size, offset = struct.unpack_from("<II", data, header + 16)
        assert offset + size <= len(data), f"Truncated PE section: {name}"
        assert virtual_size < 128 * 1024 * 1024, f"Unexpected PE section size: {name}"
        result[name] = data[offset:offset + min(size, virtual_size)] + bytes(max(0, virtual_size - size))
    return result

before = sections(stock)
after = sections(out / "poc-signed.efi")
assert before.keys() == after.keys()
for name in before:
    if name != ".initrd":
        assert before[name] == after[name], f"Unexpected change to {name}"
assert before[".initrd"] != after[".initrd"]
assert after[".initrd"] == (out / "custom.initrd").read_bytes()
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
evidence = {
    "variant": "custom_initrd_custom_signed_uki",
    "build_directory": str(out),
    "kernel": kernel,
    "stock_uki_sha256": digest(stock),
    "signed_uki_sha256": digest(out / "poc-signed.efi"),
    "stock_initrd_sha256": digest(out / "stock.initrd"),
    "custom_initrd_sha256": digest(out / "custom.initrd"),
    "certificate_sha256": digest(out / "signer.der"),
    "unchanged_sections": [name for name in before if name != ".initrd"],
    "explicit_preload": ["dm_verity", "overlay"],
    "module_plan": (out / "module-plan.txt").read_text().splitlines(),
    "signature_verified_with_poc_certificate": True,
    "firmware_enrollment_verified": False,
    "confidential_vm_boot_verified": False,
}
(out / "custom-uki-build.json").write_text(json.dumps(evidence, indent=2) + "\n")
print(json.dumps(evidence, indent=2))
PY
echo CUSTOM_UKI_BUILD_AND_LOCAL_SIGNATURE_VERIFICATION_PASSED
