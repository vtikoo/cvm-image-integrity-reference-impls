#!/usr/bin/env bash
set -euo pipefail
cd /repro
if ! command -v cpio; then tdnf install -y cpio; fi
mkdir -p inspect/root inspect/boot inspect/esp
loop=$(losetup --find --show --read-only --partscan root-volatile.raw)
cleanup() {
    for dir in esp boot root; do
        if mountpoint -q "inspect/$dir"; then umount "inspect/$dir"; fi
    done
    losetup -d "$loop"
}
trap cleanup EXIT
lsblk -o NAME,SIZE,TYPE,FSTYPE,PARTUUID "$loop" | tee evidence/partitions.txt
mount -t ext4 -o ro,noload "${loop}p3" inspect/root
mount -t ext4 -o ro,noload "${loop}p2" inspect/boot
mount -t vfat -o ro "${loop}p1" inspect/esp
rpm --root /repro/inspect/root -qa | sort > evidence/packages.txt
cat inspect/root/etc/fstab | tee evidence/fstab.txt
test "$(lsblk -nr -o TYPE "$loop" | grep -c '^part$')" -eq 4
test -f inspect/root/etc/verity-repro-modify
test -f inspect/root/etc/verity-repro-delete
test -f inspect/root/var/lib/verity-repro/seed
test ! -s inspect/root/etc/machine-id
if find inspect/root/etc/ssh -name 'ssh_host_*_key' -print | grep -q .; then
    echo "Reusable image contains private SSH host keys" >&2
    exit 1
fi
echo CLEAN_LOWER_IDENTITY_OK | tee evidence/identity.txt
find inspect/esp -type f | sort | tee evidence/esp-files.txt
mapfile -t ukis < <(find inspect/esp/EFI/Linux -maxdepth 1 -type f -name '*.efi')
test "${#ukis[@]}" -gt 0
: > evidence/verification.txt
for uki in "${ukis[@]}"; do
    name=$(basename "$uki")
    objcopy -O binary --only-section=.initrd "$uki" "evidence/$name.initrd"
    objcopy -O binary --only-section=.cmdline "$uki" "evidence/$name.cmdline"
    for addon in "$uki.extra.d/"*.efi; do
        test -f "$addon"
        objcopy -O binary --only-section=.cmdline "$addon" "evidence/$(basename "$addon").cmdline"
        cat "evidence/$(basename "$addon").cmdline" >> "evidence/$name.cmdline"
    done
    tr '\0' '\n' < "evidence/$name.cmdline" | tee "evidence/$name.cmdline.txt"
    grep -q 'systemd.volatile=overlay' "evidence/$name.cmdline.txt"
    roothash=$(grep -oE 'roothash=[a-fA-F0-9]+' "evidence/$name.cmdline.txt" | cut -d= -f2)
    test -n "$roothash"
    veritysetup verify "${loop}p3" "${loop}p4" "$roothash"
    echo "VERITY_VERIFY_OK $name $roothash" | tee -a evidence/verification.txt
    bash inspect/root/usr/bin/lsinitrd "evidence/$name.initrd" > "evidence/$name.initrd-list.txt"
    for component in systemd-veritysetup systemd-veritysetup-generator \
        systemd-fstab-generator systemd-volatile-root systemd-volatile-root.service; do
        grep "$component" "evidence/$name.initrd-list.txt"
    done
    if ! grep -E 'overlay\.ko(\.(xz|zst|gz))?$' "evidence/$name.initrd-list.txt"; then
        grep '^kernel/fs/overlayfs/overlay\.ko$' inspect/root/usr/lib/modules/*/modules.builtin \
            | tee evidence/overlay-built-in.txt
    fi
done
echo ARTIFACT_INSPECTION_OK
