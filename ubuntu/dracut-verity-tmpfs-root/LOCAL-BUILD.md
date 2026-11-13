# Ubuntu 24.04 Dracut CVM: manual build, publication and SSH acceptance

[Deployment workflows](README.md) | [All configurations](../../README.md) | [Validation scope](VALIDATION.md)

This independent reference implementation replaces Canonical's snap-bootstrap
initramfs/manifest flow with **Dracut and systemd**. It starts from an unbooted
Azure Ubuntu CVM Marketplace disk, finalizes a disposable root filesystem,
generates dm-verity data, and builds a signed UKI embedding `roothash=` and
explicit data/hash partition identifiers. All writes to the effective root are
volatile; the verified ext4 lower never has a writable fallback.

**Status: experimental. Complete Marketplace conversion, custom-signed UKI
boot and first-boot/real-reboot acceptance passed on an Azure Intel TDX CVM
using `VMGuestStateOnly`. The patched native SDK collector, tested directly in
tmpfs without log bind mounts, also obtained a signature-verified custom-policy
MAA token for PCRs 0-8 and 11. PCR12 remains a token-coverage gap. Stateless boot
and expected-image remote verification remain unqualified. Gallery 1.0.4,
rebuilt with the native collector, passed publication, first/reboot SSH
acceptance and installed-collector custom-policy MAA testing on 2026-11-13.
Older Gallery 1.0.3 still contains the firmware-only collector.**
See [the observed evidence and limits](VALIDATION.md).
Do not claim production integrity or remote image verification from these tests.

## Inputs and boundaries

| Input | Requirement |
| --- | --- |
| Marketplace | `Canonical:ubuntu-24_04-lts:cvm:24.04.202610280` |
| Catalog check | 2026-11-12, westus3; newest non-Pro `cvm` version returned |
| Catalog metadata | x64, Gen2, `TrustedLaunchAndConfidentialVmSupported`; no purchase plan |
| Target userspace | Ubuntu 24.04, systemd 255 family, Dracut 060 family |
| Kernel | Explicit version from the source UKI, with the **same source module tree** |
| Signer | Caller-owned RSA certificate and private key, kept outside the checkout |
| Guest attestation SDK | `Azure/azure-guest-attestation-sdk`, commit `8774be30f452060c56372d34ccbe34c3d3f3c577` plus the pinned [native systemd event-log patch](patches/sdk-systemd-event-log.patch); CLI `azure-guest-attest` |
| Builder | Exclusive Ubuntu 24.04 x86-64 Linux machine with root, mounts, loops and dm-verity |

The pin is in [inputs.json](inputs.json). No kernel version is guessed from the
builder's `uname -r`. The build requires the source's
`EFI/ubuntu/kernel.efi-<kernel>` and `/lib/modules/<kernel>`, rejects unsigned
loadable driver dependencies, and extracts the original kernel's `.linux`
section. A missing stock UKI, changed layout, missing module or unsupported
source stops the build; it does not substitute the builder kernel.

The source root label must be `cloudimg-rootfs`, ESP label `UEFI`; an optional
separate boot partition must have label `BOOT`. The filesystem must be readable
ext4, not a booted or encrypted/provisioned OS volume. Additional persistent
fstab mounts are rejected. The converter records the input hash but **cannot
authenticate a local raw image's Marketplace origin**: retain authorized
acquisition evidence independently.

No source disk, export, VM, storage, Gallery, role assignment, or Azure resource
is created by [build-image.sh](build-image.sh). This manual path does not invoke
the [deployment controller](README.md) or the existing Canonical producer.
The commands below that use
Azure are manual, optional, billable operations in your own authorized scope.

## Boot and trust chain

```text
Unbooted Marketplace raw disk (read-only)
  -> new GPT disk; copy root and optional separate /boot
  -> offline customization + guest packages + matching-kernel Dracut initramfs
  -> unmount root, check ext4, veritysetup format
  -> ukify with original kernel, new initramfs, generated signed .cmdline
  -> write signed UKI to ESP only, check GPT and fixed-VHD format
  -> fixed Azure VHD

Firmware Secure Boot db -> signed EFI/BOOT/BOOTX64.EFI (systemd-stub UKI)
  -> systemd-veritysetup-generator -> read-only /dev/mapper/root
  -> /sysroot ext4 ro,noload -> systemd.volatile=overlay (tmpfs upper/work)
  -> required initramfs root-policy guard -> switch-root -> writable volatile /
```

The new disk has a 512 MiB ESP, 32 GiB ext4 data partition, and a separately
sized SHA-256 verity hash partition. Data/hash PARTUUIDs are generated per build.
The signed command line contains:

```text
root=/dev/mapper/root rootfstype=ext4 ro rootflags=ro,noload
roothash=<generated SHA-256 digest>
systemd.verity_root_data=/dev/disk/by-partuuid/<data UUID>
systemd.verity_root_hash=/dev/disk/by-partuuid/<hash UUID>
systemd.verity_root_options=panic-on-corruption
systemd.volatile=overlay
```

Root-device auto-discovery and initrd fstab processing are disabled. A required
unit blocks `initrd-switch-root.service` unless the effective root is a writable
overlay with upper/work on the same tmpfs, an ext4 read-only lower is mounted
from the healthy verity mapper, and no swap is active. Corruption must not be
ignored. A second guard checks the effective root during normal system startup.
The Dracut module overrides `systemd-volatile-root.service` with a fail-closed
setup helper: it bind-mounts the read-only verity lower at `/run/cvm-overlay/lower`
and unmounts the original lower mount before installing the overlay,
retains a tmpfs at `/run/cvm-overlay`, and mounts the overlay using visible
upper/work directories there. This avoids native systemd's covered root mount
and detached tmpfs backing, so both initramfs and runtime guards can verify the
actual backing filesystems rather than trusting setup metadata.
There is no GRUB, shim, unsigned command-line add-on, Canonical manifest or
stock-initramfs fallback on the new ESP. Firmware must support the standard
Gen2 removable-media path; it was accepted in the tested persisted-TPM configuration.

The root fstab disk mounts and disk swap are removed before hashing; the ESP is
not mounted in the guest. Files from a separate `/boot` are copied inside the
verified lower. Root growth, Azure resource-disk formatting/swap and persistent
journals are disabled. Machine IDs and SSH host keys are cleared before hashing.
Cloud-init provisions the normal Ubuntu user, public key and agent state into
the volatile upper. Reboots regenerate guest identity and host keys: plan SSH
host verification accordingly. No fixed passwordless-sudo test account is baked
into the lower by this recipe.

## 1. Obtain and record the unbooted source

Use an authorized export of the exact pin. The following are **read-only**
catalog commands, not resource creation:

```bash
az vm image list --location westus3 --publisher Canonical \
  --offer ubuntu-24_04-lts --sku cvm --all --query '[].urn' -o tsv
az vm image show --location westus3 \
  --urn Canonical:ubuntu-24_04-lts:cvm:24.04.202610280
```

For acquisition/export guidance see steps 1-2 of the existing
[local-builder workflow](../verity-tmpfs-root/LOCAL-BUILD.md). Use **this** image
URN, a new owned resource group and a `VMGuestStateOnly` source disk; do not use
the old recipe's image pin, geometry assertion, producer, signing scripts or
deployment functions. Export permissions and organization policies still
apply. Export SAS tokens are credentials: never print, commit or retain them;
revoke access after download. If export is prohibited, stop.

Keep the source and output outside the checkout. Convert a downloaded VHD:

```bash
qemu-img convert -f vpc -O raw /secure/input/source.vhd /secure/input/source.raw
```

Never pass the VHD footer as part of a raw disk. Never boot the source, and never
attach it to the acceptance VM. On an exclusive builder, inspect the raw disk
read-only to determine the actual source kernel:

```bash
sudo losetup --find --show --read-only --partscan /secure/input/source.raw
# Record the returned device, for example /dev/loop7.
lsblk -o PATH,LABEL,FSTYPE /dev/loop7
sudo mkdir -p /secure/input/esp
# Replace this with the partition that lsblk actually identifies as UEFI.
sudo mount -o ro /dev/loop7p15 /secure/input/esp
find /secure/input/esp/EFI/ubuntu -maxdepth 1 -name 'kernel.efi-*' -print
sudo umount /secure/input/esp
sudo losetup --detach /dev/loop7
```

The partition number above is an example, **not a pinned geometry**. Select the
exact kernel suffix present in the source and retain the source module/package
inventory. If multiple kernels are present, deliberately select one with its
matching modules; do not silently select the latest file.

## 2. Build offline

Install builder dependencies on the **exclusive build machine**, not on the
machine hosting unrelated workloads:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential git python3 binutils openssl sbsigntool systemd-ukify qemu-utils \
  rsync gdisk dosfstools e2fsprogs cryptsetup-bin util-linux udev kmod
```

The builder also needs an approved Rust toolchain (SDK minimum Rust 1.90;
local/CI validation uses 1.95.0). The build fetches the exact SDK revision and
checks and applies the recipe's SHA-256-pinned SDK patch, runs its event-log and
guest-attestation unit tests, and compiles `azure-guest-attest` using its committed
lockfile and default RustCrypto/rustls backend. It installs the binary, MIT license, provenance and
the `cvm-attest` wrapper into the root **before hashing**, and checks that both
commands run inside the target chroot. Compiler/binary/revision evidence is
retained in `evidence/attestation-sdk.json`, including the base revision and patch
file/hash. After package operations and before verity generation, a final gate
compares the installed binary, wrapper and SDK provenance with the builder
inputs. `evidence/attestation-installation.json` and `evidence/build.json` retain
the SDK provenance plus binary and wrapper SHA-256 hashes for independent
guest validation. No attestation request is made
during the offline build; no compiler or SDK source tree is baked into the guest.

The build chroots into a **new copy** of the source and installs `dracut-core`,
`systemd-boot-efi` and `cryptsetup-bin` there. It disables package service startup
and uses private `/run` plus slave `/dev` and `/sys` bind mounts. It neither
installs the target kernel on the host nor imports host kernel modules.
Run it in a private mount namespace, as below; shared or slave build-directory
mount propagation is rejected to prevent mounts leaking into host services.
During package installation, a temporary mode-0644 resolver permits DNS access
for APT's unprivileged sandbox; the original resolver file or symlink is restored
before hashing. Package-index download failures abort the build.
Package repositories need outbound access; the resulting complete package
inventory is evidence. Repository versions are not snapshot-pinned, so byte
reproducibility and arbitrary future package versions are not claimed.

Budget at least 150 GiB plus package headroom. The 32 GiB data partition is
fixed for this configuration; a source that does not fit fails during copy.
Optional corruption qualification makes a disposable data-partition copy. Reserve ample
tmpfs RAM in the eventual CVM; do not add disk swap to compensate.

Generate your own signer, or use an existing approved RSA signer:

```bash
umask 077
mkdir -m 700 /secure/signer
openssl req -new -x509 -newkey rsa:3072 -sha256 -nodes \
  -keyout /secure/signer/db.key -out /secure/signer/db.pem \
  -days 365 -subj '/CN=Ubuntu Dracut CVM reference/'
chmod 600 /secure/signer/db.key

cd ubuntu/dracut-verity-tmpfs-root
sudo unshare --mount --propagation private bash build-image.sh /secure/input/source.raw \
  /secure/signer/db.key /secure/signer/db.pem \
  /secure/runs/dracut-example '<exact-source-kernel-version>'
```

The key stays outside the guest and output image. Existing run directories,
in-checkout signing inputs/output directories, provisioned sources and
mismatched/expired certificates are rejected. The source image is opened
read-only. Do not run concurrent builds or build on shared/production hosts.

Success requires `DRACUT_VERITY_IMAGE_BUILD_PASSED` and produces:

- `image.raw`, Azure fixed `image.vhd`, `cvm.efi` and public `signer.der`;
- original kernel payload, new initramfs and exact generated `cmdline`;
- `evidence/build.json` with kernel, root hash and both PARTUUIDs;
- source/output hashes, source/output GPT layout, package and signed-driver
  inventories, initrd inventory, verity format, ext4 and fixed-VHD checks.

The signed UKI's `.linux`, `.initrd` and `.cmdline` are checked byte-for-byte
against inputs; `sbverify` checks the certificate signature. The protected root
is never mounted writable after hashing. The default demonstrates the clean-room
build rather than scanning the finished disk or injecting corruption;
`evidence/build.json` records disk qualification as `NOT_RUN`.
Failed runs retain diagnostics but are **not publishable**; cleanup
only artifacts you own, after confirming mounts and mappings were released.

### Optional disk qualification

This is separate from the default build/deployment flow. On an exclusive builder,
the existing test first fully verifies the data/hash pair, then verifies rejection
of a disposable corrupted copy both offline and through a live verity mapper.
It does not modify the built image. Allow time for full reads and space for the
32 GiB disposable copy.

From this recipe directory, after a successful build:

```bash
sudo unshare --mount --propagation private bash -s -- "$PWD" /secure/runs/dracut-example <<'QUALIFY'
set -euo pipefail
recipe=$1 build=$2
loop=$(losetup --find --show --read-only --partscan "$build/image.raw")
trap 'losetup -d "$loop"' EXIT
udevadm settle
root_hash=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["rootHash"])' "$build/evidence/build.json")
evidence=$(mktemp -d "$build/evidence/verity-qualification.XXXXXXXX")
bash "$recipe/scripts/test-corruption.sh" "${loop}p2" "${loop}p3" "$root_hash" "$evidence"
QUALIFY
```

The smaller userspace verification/corruption tests in
[tests/test_components.py](tests/test_components.py) also remain explicitly invoked.

## 3. Publish and enroll the actual signer

Use a new private Azure Compute Gallery and your owned upload resources. See the
existing [local workflow, publication steps 4-5](../verity-tmpfs-root/LOCAL-BUILD.md)
and [Gallery certificate-profile helper](../verity-tmpfs-root/scripts/custom-uki/New-GallerySecurityProfile.ps1)
for the Azure API shape, but use **this build's** VHD and `signer.der`.
Do not run the old end-to-end deployment controller: it builds the old variant.

Required publication and deployment gates:

1. Verify the build marker, output checksums and independent source acquisition
   record. Upload the fixed VHD privately using your authorized identity.
2. Create a Gen2 x64 Linux Gallery definition with
   `TrustedLaunchAndConfidentialVmSupported`; publish the image version with a
   UEFI db profile containing the **exact public certificate** from this build.
   Retain `MicrosoftUefiCertificateAuthorityTemplate` as in the existing helper.
3. Require completed replication and exact signer/template readback with
   `$expand=ReplicationStatus,UefiSettings`. An accepted PUT or a certificate
   merely stored in the image is not enrollment.
4. Deploy one supported **ConfidentialVM** (the acceptance target is
   `Standard_DC4es_v6`, Intel TDX), with Secure Boot and vTPM
   enabled and `VMGuestStateOnly`, following the original custom-key enrollment
   approach. Do not use Trusted Launch or disable Secure
   Boot to make a failed UKI boot. Pass your own SSH public key.
5. Retain Azure `az vm show` evidence of the actual Gallery version and
   `securityProfile`. Confirm capacity/quota before allocating.

Removing the Canonical initramfs also removes its disk-unlock/provisioning
integration. This reference uses an unencrypted verified OS disk and
`VMGuestStateOnly` for persisted encrypted firmware/TPM guest state, not
confidential OS-disk encryption. `NonPersistedTPM` is a separate experimental
non-persisted guest-state mode; neither option here selects an ephemeral OS
disk. This reference does **not** support
`DiskWithVMGuestState`, Canonical's FDE key-unlock flow, or claim compatibility
with every CVM family. Preserve appropriate image licensing and export policy.
Stateless custom-key boot is currently blocked: both initial and corrected-image
`NonPersistedTPM` attempts reported Azure Compute Secure Boot errors despite
matching Gallery signer readback. An explicit stateless Gallery image profile
also encountered incompatible definition/UEFI API requirements in the tested
configuration. See [observed validation limits](VALIDATION.md); do not disable
Secure Boot or claim that Gallery readback proves the guest firmware trusts the
key.

## 4. Accept the deployed CVM, including a real reboot

Use SSH to the launched CVM through an approved private or corporate-network
path; do not open public SSH ingress just for validation. Authenticate the
current host key against trusted Azure boot diagnostics or another independently
authenticated channel **before connecting**. An `ssh-keyscan` result alone is
not authentication. Populate a dedicated known-hosts file with that verified
key; never use `StrictHostKeyChecking=no` or discard a mismatch.

Copy [verify-guest.py](verify-guest.py), independently retained
`evidence/build.json`, and `signer.der` over SSH into a private staging directory.
Use the **local build record**, not hashes supplied only by the running guest.
Run these commands on the validation client, from this recipe directory.
The provisioned account must support noninteractive sudo.

```bash
set -euo pipefail
umask 077
target='<provisioned-user>@<approved-CVM-address>'
identity='/secure/ssh/validation-key'
known_hosts='/secure/ssh/cvm-known-hosts'
build='/secure/runs/dracut-example'
mkdir -m 700 /secure/validation/dracut-example
evidence='/secure/validation/dracut-example'
ssh_options=(-i "$identity" -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$known_hosts")

stage=$(ssh "${ssh_options[@]}" "$target" \
  'umask 077; mktemp -d /tmp/cvm-validation.XXXXXXXX')
[[ "$stage" =~ ^/tmp/cvm-validation\.[a-zA-Z0-9]{8}$ ]]
scp "${ssh_options[@]}" verify-guest.py "$build/evidence/build.json" \
  "$build/signer.der" "$target:$stage/"
ssh "${ssh_options[@]}" "$target" \
  "sudo -n python3 '$stage/verify-guest.py' '$stage/build.json' '$stage/signer.der'" \
  > "$evidence/first-boot.json" 2> "$evidence/first-boot.stderr.log"
previous_boot_id=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["bootId"])' \
  "$evidence/first-boot.json")
ssh "${ssh_options[@]}" "$target" 'sudo -n systemctl reboot'
```

After the CVM returns, independently authenticate its **new** host key and
update the dedicated known-hosts file. This image regenerates host keys on every
boot; do not automatically trust replacement keys. Then stage the inputs again:

```bash
stage=$(ssh "${ssh_options[@]}" "$target" \
  'umask 077; mktemp -d /tmp/cvm-validation.XXXXXXXX')
[[ "$stage" =~ ^/tmp/cvm-validation\.[a-zA-Z0-9]{8}$ ]]
scp "${ssh_options[@]}" verify-guest.py "$build/evidence/build.json" \
  "$build/signer.der" "$target:$stage/"
ssh "${ssh_options[@]}" "$target" \
  "sudo -n python3 '$stage/verify-guest.py' '$stage/build.json' '$stage/signer.der' \
    --previous-boot-id '$previous_boot_id'" \
  > "$evidence/reboot.json" 2> "$evidence/reboot.stderr.log"
```

First-boot checks include firmware Secure Boot/SetupMode/db signer, TPM, exact
kernel and boot arguments, the live verity table's expected hash/devices,
read-only dm-verity lower mount, tmpfs/root policy, cloud-init, guest agent and failed
systemd units. New build records also require the installed native collector,
wrapper and provenance to match independent build evidence on both boots.
Legacy records without SDK evidence explicitly report that the collector was
not checked; they cannot qualify the updated collector. These local file checks
are not authenticated remote execution or expected-UKI proof.
It requires at least 128 MiB of measured tmpfs block allocation
and 2,050 new inodes from 128 MiB plus 2,048 small files and reboot markers.
Reboot acceptance requires a distinct boot ID and loss of the entire workload.
Completed cloud-init status with exit 2 is accepted only with no reported fatal
errors; recoverable warnings are explicitly reported and retained in the result.
Keep both JSON results and Azure security-profile evidence outside the VM.
Guest checks cannot establish Azure CVM security type by themselves.

Deallocate or remove only your own test VM and temporary upload/source
resources after acceptance. There is no automatic resource cleanup controller.

## 5. Run expanded-PCR guest attestation over SSH

After deploying and completing root-policy acceptance, SSH into the CVM and
run the installed `cvm-attest` command. No attestation service runs automatically,
and no SDK download or compilation is required in the running guest.

**Older-image limitation:** Gallery 1.0.3's installed SDK reads only the firmware event log,
omitting genuine systemd boot-phase extensions into PCR 11. The tested shared
West US 3 MAA endpoint rejects this with `PcrDoesNotMatchTcg`. A tmpfs-only
diagnostic appended genuine recorded phase events and quoted PCRs `0-7,11`;
the error advanced to a policy denial of `x-ms-azurevm-dbvalidated=false`.
No token was issued by that shared endpoint. A separately owned endpoint,
removing only the dbvalidated denial, subsequently issued a real token for the
expanded diagnostic. That diagnostic did not change the installed collector.
Current source builds instead apply the native SDK fix described below and
require the expanded PCR set. Gallery 1.0.4 was built and published separately;
its installed native collector passed custom-policy MAA testing after real
first/reboot SSH acceptance. Gallery 1.0.3 remains retained but its former
reference CVM was replaced with the tested 1.0.4 CVM, now deallocated.
See [the attestation investigation](VALIDATION.md).

```bash
# On the relying party: generate and retain a fresh challenge for this request.
nonce=$(openssl rand -hex 32)
printf '%s\n' "$nonce" > "$evidence/nonce.txt"
# Reuse the authenticated SSH options from step 4, after reboot-key verification.
ssh "${ssh_options[@]}" "$target" \
  "sudo -n /usr/local/bin/cvm-attest \
    --endpoint 'https://<your-approved-provider>.attest.azure.net' \
    --nonce '$nonce' --output /run/cvm-attestation-example" \
  > "$evidence/attestation.stdout.json" 2> "$evidence/attestation.stderr.log"

# Retrieve private files directly, without managed Run Command or SDK overrides.
mkdir -m 700 "$evidence/attestation"
for file in sdk-response.json request.json token.txt sdk-stderr.log receipt.json; do
  ssh "${ssh_options[@]}" "$target" \
    "sudo -n cat '/run/cvm-attestation-example/$file'" \
    > "$evidence/attestation/$file"
done
ssh "${ssh_options[@]}" "$target" \
  'sudo -n sh -c "cd /run/cvm-attestation-example && sha256sum \
    sdk-response.json request.json token.txt sdk-stderr.log receipt.json"' \
  > "$evidence/attestation/SHA256SUMS"
(cd "$evidence/attestation" && sha256sum --check SHA256SUMS)
```

Use a new `/run` output name for each collection. If collection fails, retain
stderr and retrieve any existing diagnostic files over the same authenticated
SSH connection; do not treat partial output as acceptance. File hashes establish
transfer consistency, not remote attestation authenticity.

The wrapper always invokes the pinned SDK's **guest** attestation flow with
`--provider maa --pcr-index 0,1,2,3,4,5,6,7,8,11,12 --user-data hex:<nonce> --json --show-request`.
PCR 4 covers firmware image measurements, PCR 7 covers Secure Boot policy,
and **PCR 11 covers systemd-stub's UKI section measurements**, including the
embedded `.cmdline` with `roothash=` and the data/hash partition identifiers.
PCR 11 is a digest of an ordered measurement sequence, **not the dm-verity
root hash itself**. Other UKI sections and subsequent systemd boot-phase
extensions also affect its value.
Systemd does not measure journal contents into PCR 11: journal notices describe
phase measurements, whose genuine userspace records are in
`/run/log/systemd/tpm2-measure.log`.

### Native userspace-log collection

The fix belongs in the SDK, not in a guest mount-namespace workaround. This
recipe carries [a patch over the pinned upstream SDK](patches/sdk-systemd-event-log.patch);
[inputs.json](inputs.json) authenticates the expected patch bytes for the build.
The Linux SDK reads the firmware log and genuine systemd JSON-sequence records,
preserving firmware bytes and appending selected PCR11 phase records as TCG2
`EV_IPL` events. It checks each recorded SHA1/SHA256/SHA384 digest against the
actual phase string and declared firmware banks; it does not fabricate a
hard-coded boot transcript or measure journal contents.

This initial adapter supports **PCR11 systemd phase records only**, not arbitrary
userspace schemas or IMA logs. Malformed input, unsupported selected measurement
types/banks, unreadable logs and oversized logs fail explicitly. Records for
unselected PCRs are not appended. A missing systemd log is explicitly logged,
but firmware replay must still match the quote. Each input is bounded to 64 MiB.

Before submission, the SDK checks the exact SHA256 quote selection and aggregate
digest against the collected PCR values, and replays selected static PCRs 0-15.
`EV_NO_ACTION` records are not extended; the patch also corrects Spec ID
minor/major parsing. It retries collection at most three times, with 50-ms
delays, only for replay/snapshot races; malformed/read errors are not retried.
Dynamic PCRs 16+ are not replayed because their reset state is not established.
These consistency checks do not authenticate the AK signature or expected UKI.
The low-level `collect_tcg_logs` helper intentionally becomes fallible and takes
the selected PCR indices; callers must handle the error.

The SDK uses SHA-256 PCR reads and an AK-signed TPM quote for the explicit set;
its `TpmInfo` request carries `PcrQuote`, `PcrSignature`, `PcrSet`, `PCRs`,
`AikCert` and `AikPub`. The wrapper rejects absent/zero PCR 11, missing quote,
signature, key, certificate, TEE evidence or event log, an unexpected PCR set,
Trusted Launch, loopback, or a changed/default endpoint. A nonempty user-data
challenge also makes this pinned SDK fail rather than silently fall back from
CVM to Trusted Launch when TEE evidence collection fails.

Evidence is private and volatile under the new `/run` directory:

- `sdk-response.json`, `request.json`, `token.txt`, `sdk-stderr.log`;
- `receipt.json` with requested PCRs, **reported** PCR 11, challenge and SDK
  provenance; it explicitly says `NOT_VERIFIED`;
- `tokenClaimsUnverified` in the receipt reports token coverage and raw PCR
  values, without authenticating the JWT. Coverage and values must match the
  request for PCRs 0-8 and 11. Missing PCR12 emits
  `ATTESTATION_TOKEN_PCR_COVERAGE_GAP=[12]` and leaves coverage incomplete;
  it is not silently removed from the request.

Retrieve the evidence outside the guest before reboot. Protect tokens and raw
VM-identifying evidence; do not commit them. Failed collection retains
diagnostics but emits no success receipt. The request/receipt's local command
line, metadata and PCR values are **not authenticated merely by collecting
them or receiving a token**.

To test updated code without rebuilding the protected image, build the patched
SDK with [build-attestation.sh](scripts/build-attestation.sh) on the approved
builder and stage its binary, `build.json` and this recipe's updated wrapper
under a private `/run` directory using your approved transfer channel:

```bash
sudo python3 /run/cvm-sdk-test/attest-guest.py \
  --sdk /run/cvm-sdk-test/azure-guest-attest \
  --sdk-build /run/cvm-sdk-test/build.json \
  --endpoint 'https://<your-approved-provider>.attest.azure.net' \
  --nonce '<64-lowercase-hex-characters-from-the-relying-party>' \
  --output /run/cvm-sdk-test/evidence
```

Both SDK overrides are required together and must be absolute paths. The SDK
reads the genuine native log paths directly; no firmware-log bind mount is
needed. Independently compare the transferred binary and patch hashes against
your builder record. Guest-supplied SDK paths/build metadata are locally
untrusted, not remote proof of which binary executed. This tmpfs test does not
update the retained integrity image.

### What MAA does and what the verifier must check

[Microsoft's guest-attestation documentation](https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-vms#json-web-token)
shows `11` in the signed token's `x-ms-azurevm-attested-pcrs` list. This is evidence
that MAA can attest PCR-11 coverage; the index list is not a digest.
That example is for Windows. Our actual Linux/TDX token additionally contains
`x-ms-azurevm-attested-pcr-values`, mapping names such as `pcr7` and `pcr11` to
base64 SHA-256 values. Its signature was verified and its reported values
matched the submitted evidence. The diagnostic requested `0-8,11,12`, but
the token covers only `0-8,11`: **PCR 12 is a known MAA token-coverage gap**,
not a reason to remove it from the required expanded request. Its coverage and
raw value are absent from the tested token, so PCR 12 must not be claimed as
attested. See [the explicit gap and limits](VALIDATION.md#known-gap-maa-does-not-return-pcr-12-in-the-tested-token).
Do not assume arbitrary custom claim emission or a particular provider policy.

An independent relying party must:

1. Validate the MAA token signature against the approved issuer's keys,
   allowed algorithms, issuer, lifetime and applicable audience/policy.
2. Require authenticated CVM/TEE and Secure Boot claims and PCR-11 coverage.
   A decoded SDK `claims` object and its `passed` boolean are not verification.
3. Authenticate the TPM quote's AK and its binding to the attested CVM, validate
   the quote signature, actual SHA-256 PCR selection and quoted aggregate
   digest against the supplied PCR values; replay authenticated measurements
   against independently retained expected UKI/boot-phase measurements.
4. Check freshness and the challenge's authenticated binding. `--user-data`
   binds the challenge into the **TEE runtime claims**, not the TPM quote's
   `extraData`; this wrapper does not establish fresh challenge-bound TPM quotes.
   Do not accept an independently replayable old quote solely because a fresh
   TEE report or token was obtained.
5. Require the independently expected UKI whose signed command line contains
   the intended root hash and identifiers. Guest-supplied `roothash=` text or
   an unsigned claimed PCR value cannot establish image identity.

This change integrates **evidence collection and MAA-flow testing**, not a
production remote verifier or an automatic claim that the expected root
filesystem was attested. An endpoint rejecting custom Secure Boot keys or UKI
event logs is a qualification failure, not a reason to remove PCR 11.

### Dedicated custom-db test endpoint

Use a separately owned MAA provider when testing a custom firmware db. Do not
change a shared regional provider. The `AzureGuest` policy-management REST API
supports this type in API version `2025-06-01`; older CLI documentation does not
necessarily list it. An AAD-trust provider requires authenticated policy
management with the `https://attest.azure.net` resource.

#### Create your own test provider

Use Azure CLI and Python 3 from the relying-party/controller host, not the CVM.
The helper uses `az resource` and `az rest`; the experimental `az attestation`
extension is not required. You need permission to create an attestation provider
in the selected resource group and manage its `AzureGuest` policy. Organization
policy must permit the provider's public HTTPS endpoint and guest access to it.
If provider registration is restricted, ask your subscription administrator
to register `Microsoft.Attestation`.

Run `az login` using your organization's approved flow. Choose a **dedicated
test resource group**, a globally unique provider name and a new private evidence
directory outside the checkout:

```bash
# Run from ubuntu/dracut-verity-tmpfs-root.
subscription='<your-subscription-guid>'
maa_rg='rg-my-cvm-maa-test'
provider='mycvmmaatest12345' # Replace with your globally unique name.
location='westus3'
maa_evidence="$HOME/cvm-maa-runs/$provider"

# Subscription-level registration may require an administrator.
az provider register --namespace Microsoft.Attestation --wait \
  --subscription "$subscription"
az group create --name "$maa_rg" --location "$location" \
  --subscription "$subscription"

python3 scripts/setup-maa-test-provider.py \
  --subscription-id "$subscription" --resource-group "$maa_rg" \
  --provider-name "$provider" --location "$location" \
  --evidence-directory "$maa_evidence" --allow-custom-db

endpoint=$(cat "$maa_evidence/endpoint.txt")
printf 'Approved test endpoint: %s\n' "$endpoint"
```

The explicit `--allow-custom-db` flag acknowledges the **test-only policy
relaxation**, not an assertion that the custom firmware db passed validation.
The helper refuses an existing provider or evidence directory. It creates a
new AAD-trust provider, verifies its identity/trust model, retrieves its actual
default policy and checks the expected security denials before modifying it.
It does not create an image, change VM networking or alter a shared provider.
Provider management uses ARM API `2020-10-01`; policy operations use the
[`AzureGuest` policy REST API](https://learn.microsoft.com/en-us/rest/api/attestation/policy/get?view=rest-attestation-2025-06-01)
version `2025-06-01`. `az rest --resource https://attest.azure.net` supplies
the policy-management authentication without printing or storing an access
token. Policy requests use private `--body @file` transport.

Keep the evidence private. It includes `default-policy.txt`, a restorable
`default-policy.jwt`, `test-policy.txt`, `test-policy.jwt`, exact
`readback-policy.txt`, `endpoint.txt`, provider/operation responses and
`setup.json` with resource identity and policy hashes. The helper reports
success only after exact policy readback matches. On failure, it preserves
evidence and may leave the newly created provider for inspection; it does not
automatically delete resources or claim that a partial setup succeeded.
On Windows, the same Python helper supports native Azure CLI; use a private
Windows evidence directory with current-user-only ACLs.

Supply `endpoint.txt`'s URL as `--maa-endpoint` / `-MaaEndpoint` for optional
SSH-mode deployment, or as `--endpoint` to the installed `cvm-attest` command
over authenticated SSH. Default managed acceptance still does not run the SDK.
Creating this provider alone is not an attestation test: retain and verify the
actual SDK request, quote and MAA token as described above.

To restore the original default policy while retaining this test provider:

```bash
az rest --method put --resource https://attest.azure.net \
  --url "$endpoint/policies/AzureGuest?api-version=2025-06-01" \
  --headers 'Content-Type=text/plain' \
  --body "@$maa_evidence/default-policy.jwt" --subscription "$subscription"
```

For native Windows Azure CLI invoked from WSL, translate that restore command's
body filename with `wslpath -w`; the Python setup helper handles this translation
automatically. After restoring, retrieve the policy and compare its decoded
text with `default-policy.txt` before relying on it.
When no longer needed, delete **only your dedicated test provider**:

```bash
az resource delete --resource-group "$maa_rg" --name "$provider" \
  --resource-type Microsoft.Attestation/attestationProviders \
  --api-version 2020-10-01 --subscription "$subscription"
```

This is separate from image/controller cleanup. Review retained-resource charges
and do not delete a resource group containing unrelated resources.

#### Policy exception and remaining verification requirements

Retrieve and retain the provider's actual default policy before modifying it.
The test policy removes only:

```text
[type=="x-ms-azurevm-dbvalidated", value==false] => deny();
```

Keep the default Secure Boot, default-key, debugger, signing and dbx denial
rules unchanged. Read back the published policy and compare its exact contents
before attesting. Never replace a failed validation claim with `true`.

This relaxation allows a token despite failed default db validation; it does
**not** pin the custom certificate or expected image. A relying party still
needs independently authenticated expected signer/UKI measurements and the
quote/TEE/freshness checks above. Keep genuine systemd userspace events in the
attestation evidence; changing policy does not repair a PCR/event-log mismatch.
The tested expanded diagnostic requests PCRs `0,1,2,3,4,5,6,7,8,11,12`.
Neither this policy nor a tmpfs SDK diagnostic changes Gallery 1.0.3's installed
firmware-only collector. Current recipe builds install the patched SDK and
expanded-PCR wrapper before generating verity data, as tested in Gallery 1.0.4.

## Threat model and limits

Secure Boot authenticates the UKI and its embedded root hash, identifiers,
kernel and initramfs; dm-verity checks the lower's data blocks. A malicious
hash tree or partition-table edit cannot produce data matching the signed hash
but can deny boot. Failures must not trigger raw-root recovery.

The tmpfs upper is writable and can shadow executable/configuration files:
**this does not make the effective root immutable**. Privileged guest attackers,
other trusted firmware db signers, alternate signed images and old signed UKIs
are outside this limited enforcement claim. There is no rollback counter,
production root-hash attestation/PCR policy, FDE, or disk confidentiality
guarantee. Secure Boot enrollment and Azure first-boot/reboot evidence remain
mandatory before claiming a working CVM reference.

## Local tests

```bash
python3 tests/test_recipe.py
python3 tests/test_attestation.py
python3 tests/test_guest_validation.py
# On a disposable Ubuntu 24.04 test machine:
sudo apt-get install -y --no-install-recommends \
  dracut-core systemd-boot-efi systemd-ukify cryptsetup-bin sbsigntool
sudo python3 tests/test_components.py
```

The component test creates a real **kernel-less** Dracut/systemd initramfs,
packages a synthetic kernel payload in a real signed UKI, checks all sections
and rejects a changed expected command line. It also formats/verifies actual
verity files and rejects corruption. It does not boot a synthetic or real CVM.
Missing tools are test failures, not skipped checks. CI runs this configuration
separately on Ubuntu 24.04 without Azure resource creation.
The attestation wrapper tests use an SDK response double to check exact
PCR/challenge arguments, token-coverage gap reporting, paired SDK overrides,
retained evidence and failure handling. A separate CI job applies the pinned
patch, runs actual SDK event-log/guest-attestation tests and checks its CLI contract without TPM or MAA
access. Neither test proves actual Azure quote or MAA-token verification.
