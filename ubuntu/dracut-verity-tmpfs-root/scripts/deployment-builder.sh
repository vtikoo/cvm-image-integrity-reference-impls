#!/bin/bash
# Exclusively owned, disposable standard-Ubuntu builder only.
set -euo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
export CARGO_HOME=/var/lib/cvm-dracut/cargo RUSTUP_HOME=/var/lib/cvm-dracut/rustup
export PATH="$CARGO_HOME/bin:$PATH"
work=/var/lib/cvm-dracut
recipe=/opt/cvm-dracut/checkout/ubuntu/dracut-verity-tmpfs-root
fail() { echo "DRACUT_DEPLOYMENT_BUILD_FAILED: $*" >&2; exit 1; }
update_package_indexes() {
    local deadline=$((SECONDS + 300)) result
    while true; do
        if LC_ALL=C apt-get -o APT::Update::Error-Mode=any update 2>"$work/apt-update.stderr"; then
            cat "$work/apt-update.stderr" >&2
            return 0
        else
            result=$?
        fi
        cat "$work/apt-update.stderr" >&2
        if [[ "$result" != 100 ]] ||
            ! grep -q '^E: Could not get lock /var/lib/apt/lists/lock\.' "$work/apt-update.stderr" ||
            (( SECONDS >= deadline )); then
            return "$result"
        fi
        echo 'Waiting for the builder package-index lock' >&2
        sleep 5
    done
}
test "$(id -u)" = 0 || fail 'Builder requires root'
case "${1:-}" in
provision)
    test "$(dpkg --print-architecture)" = amd64 || fail 'Expected an x64 builder'
    . /etc/os-release
    test "$ID" = ubuntu && test "$VERSION_ID" = 24.04 || fail 'Expected Ubuntu 24.04'
    update_package_indexes
    apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends \
        build-essential git python3 binutils openssl sbsigntool systemd-ukify qemu-utils \
        rsync gdisk dosfstools e2fsprogs cryptsetup-bin util-linux udev kmod ca-certificates curl
    # Pin rustup itself and verify the official HTTPS-distributed binary before
    # execution. Never pipe downloaded shell code into an interpreter.
    rustup_url=https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        "$rustup_url" -o "$work/rustup-init"
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        "$rustup_url.sha256" -o "$work/rustup-init.sha256"
    expected=$(awk 'NR==1 {print $1}' "$work/rustup-init.sha256")
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail 'Malformed official rustup SHA256'
    echo "$expected  $work/rustup-init" | sha256sum -c -
    chmod 700 "$work/rustup-init"
    "$work/rustup-init" -y --no-modify-path --profile minimal --default-toolchain 1.95.0
    rustup default 1.95.0
    rustc --version | grep -Eq '^rustc 1\.95\.0 '
    command -v cargo
    echo DRACUT_BUILDER_PROVISIONED
    ;;
build)
    # All source and output mounts live inside a private mount namespace.
    exec unshare --mount --propagation private bash "$0" build-private
    ;;
build-private)
    test "$(findmnt -rn -o PROPAGATION -T "$work")" = private ||
        fail 'Build namespace is not private'
    source_disk=/dev/disk/azure/scsi1/lun0
    for ((attempt=0; attempt<120; attempt++)); do
        test ! -b "$source_disk" || break
        sleep 5
    done
    test -b "$source_disk" || fail 'Attached source disk did not appear at LUN0'
    source_disk=$(readlink -e "$source_disk")
    if lsblk -nr -o MOUNTPOINTS "$source_disk" | grep -q '[^[:space:]]'; then
        fail 'The original source disk must be entirely unmounted'
    fi
    blockdev --setro "$source_disk"
    test "$(blockdev --getro "$source_disk")" = 1 || fail 'Source device is not read-only'
    test ! -e "$work/source.raw" || fail 'Refusing source overwrite'
    original=$(sha256sum "$source_disk" | cut -d ' ' -f1)
    dd if="$source_disk" of="$work/source.raw" bs=16M conv=sparse,fsync status=none
    raw_hash=$(sha256sum "$work/source.raw" | cut -d ' ' -f1)
    test "$original" = "$raw_hash" || fail 'Raw source differs from the original'
    cmp --silent "$source_disk" "$work/source.raw"
    test "$original" = "$(sha256sum "$source_disk" | cut -d ' ' -f1)" ||
        fail 'The original source changed during acquisition'
    lsblk -J -o PATH,LABEL,PARTLABEL,FSTYPE,SIZE,PARTUUID "$source_disk" > "$work/original-layout.json"
    install -d -m 700 "$work/inspect-root" "$work/inspect-esp"
    loop=$(losetup --find --show --read-only --partscan "$work/source.raw")
    mounted_root=false mounted_esp=false
    cleanup_inspection() {
        local result=$?
        trap - EXIT
        if "$mounted_esp"; then umount "$work/inspect-esp" || result=1; fi
        if "$mounted_root"; then umount "$work/inspect-root" || result=1; fi
        if test -n "$loop"; then losetup -d "$loop" || result=1; fi
        exit "$result"
    }
    trap cleanup_inspection EXIT
    udevadm settle
    mapfile -t roots < <(lsblk -rpn -o PATH,LABEL "$loop" | awk '$2=="cloudimg-rootfs" {print $1}')
    mapfile -t esps < <(lsblk -rpn -o PATH,LABEL "$loop" | awk '$2=="UEFI" {print $1}')
    test "${#roots[@]}" = 1 && test "${#esps[@]}" = 1 || fail 'Ambiguous source root/ESP labels'
    mount -o ro,noload "${roots[0]}" "$work/inspect-root"
    mounted_root=true
    mount -o ro "${esps[0]}" "$work/inspect-esp"
    mounted_esp=true
    python3 - "$recipe" "$work" <<'PY'
import hashlib
import json
import pathlib
import sys
recipe, work = map(pathlib.Path, sys.argv[1:])
sys.path.insert(0, str(recipe / "scripts"))
from image_policy import pe_section
candidates = []
inventory = []
for uki in sorted((work / "inspect-esp/EFI/ubuntu").glob("kernel.efi-*")):
    kernel = uki.name.removeprefix("kernel.efi-")
    if not (work / "inspect-root/lib/modules" / kernel).is_dir():
        continue
    uname = pe_section(uki, ".uname").rstrip(b"\0\n").decode()
    if uname != kernel:
        raise ValueError("Source UKI uname differs from the original module tree")
    candidates.append(kernel)
    inventory.append({"kernel": kernel, "ukiSha256": hashlib.sha256(uki.read_bytes()).hexdigest()})
if len(candidates) != 1:
    raise ValueError("Expected exactly one original UKI/module-tree kernel; never select the builder kernel")
(work / "kernel.txt").write_text(candidates[0] + "\n")
(work / "source-kernels.json").write_text(json.dumps(inventory, indent=2) + "\n")
PY
    umount "$work/inspect-esp"; mounted_esp=false
    umount "$work/inspect-root"; mounted_root=false
    losetup -d "$loop"; loop=
    trap - EXIT
    kernel=$(cat "$work/kernel.txt")
    install -d -m 700 "$work/signing"
    test ! -e "$work/signing/signer.key" || fail 'Refusing signer overwrite'
    openssl req -new -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
        -subj '/CN=Disposable Dracut image signer/' \
        -keyout "$work/signing/signer.key" -out "$work/signing/signer.pem" >/dev/null 2>&1
    chmod 600 "$work/signing/signer.key"
    bash "$recipe/build-image.sh" "$work/source.raw" "$work/signing/signer.key" \
        "$work/signing/signer.pem" "$work/output" "$kernel"
    grep -Fxq DRACUT_VERITY_IMAGE_BUILD_PASSED "$work/output/build.log"
    sha256sum --check "$work/output/evidence/output.sha256"
    test "$raw_hash" = "$(sha256sum "$work/source.raw" | cut -d ' ' -f1)" ||
        fail 'Source raw changed during the build'
    test "$original" = "$(sha256sum "$source_disk" | cut -d ' ' -f1)" ||
        fail 'The original source changed during the build'
    sbverify --cert "$work/signing/signer.pem" "$work/output/cvm.efi"
    python3 - "$recipe" "$work" "$original" "$raw_hash" "$kernel" <<'PY'
import hashlib
import json
import pathlib
import sys
recipe, work = map(pathlib.Path, sys.argv[1:3])
def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(16 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()
files = [recipe / name for name in ("inputs.json", "build-image.sh", "attest-guest.py", "verify-guest.py")]
for directory in ("dracut", "patches"):
    files.extend(path for path in (recipe / directory).rglob("*") if path.is_file())
files.extend(recipe / "scripts" / name for name in (
    "build-attestation.sh", "check-root.sh", "image_policy.py", "mount-volatile-root.sh", "test-corruption.sh"))
outputs = {name: sha(work / "output" / name) for name in ("image.raw", "image.vhd", "cvm.efi", "signer.der")}
record = {
    "result": "DRACUT_DEPLOYMENT_BUILD_PASSED",
    "sourceMatchesOriginal": sys.argv[3] == sys.argv[4],
    "sourceOriginalSha256": sys.argv[3], "sourceRawSha256": sys.argv[4], "kernel": sys.argv[5],
    "recipeFiles": {path.relative_to(recipe).as_posix(): sha(path) for path in sorted(files)},
    "outputs": outputs, "buildJsonSha256": sha(work / "output/evidence/build.json"),
    "sourceKernels": json.loads((work / "source-kernels.json").read_text()),
    "rustupBinarySha256": sha(work / "rustup-init"),
    "privateSigner": "RSA3072; mode0600; remains exclusively on this builder",
    "validation": "Default build checks passed; full-disk/corruption qualification not run; Azure guest acceptance required",
}
(work / "provenance.json").write_text(json.dumps(record, indent=2) + "\n")
PY
    echo DRACUT_DEPLOYMENT_BUILD_PASSED
    ;;
*) fail 'Expected provision or build' ;;
esac
