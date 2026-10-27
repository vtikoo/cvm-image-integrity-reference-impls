# Build on an existing Linux machine

[Ubuntu recipe](README.md) | [Validation scope](VALIDATION.md)

This is the **manual alternative** to `deploy.sh` / `Deploy.ps1`. Those
controllers create an Azure builder VM automatically, even when invoked from
Linux. Do **not** run them without their plan flag to perform a local build.
There is no `--local` switch.

```text
Pinned Marketplace disk -> local Linux build/sign -> private Azure Gallery
                                                    -> one reference CVM
```

The local build creates no Azure VM. Obtaining the Marketplace disk below
creates a temporary managed disk; publishing creates storage and Gallery
resources; acceptance creates one reference CVM. Local offline checks cannot
prove Azure firmware enrollment or confidential-VM boot.

**Status:** the shared component flow was demonstrated using an Azure builder.
The local-input guards have tests, but this complete manual local-build/export/
upload workflow has not been exercised end to end. These instructions are not
a claim of a newly validated configuration.

## Prerequisites and boundaries

- An x86-64 Linux build machine with root/sudo, loop devices, NBD,
  device-mapper/verity, mounts, and permission to read kernel diagnostics.
  Ubuntu 22.04 is the reference userspace for the commands below. A restricted
  container, WSL installation, or different distro is not a validated substitute.
- Controller tools available before step 1: Bash 4+, Azure CLI, `jq`, Python 3,
  OpenSSL, `curl`, `tar`, `gzip`, and GNU core utilities. No PowerShell is needed.
- Enough space for the source VHD, its raw conversion, a disposable working
  copy, and the output VHD. Budget at least 150 GiB plus build/tool headroom if
  retaining all full-sized copies; do not rely on sparse-file savings.
- The pinned image, kernel, producer, and geometry in the [recipe](README.md).
  Obtain modules and kernel configuration from that exact source, not from
  `uname -r`. **Do not install its FDE kernel onto your host or replace your
  host's `/lib/modules`.** The running host kernel can differ.
- Azure CLI login, permission to create/export the source managed disk and
  create networking, storage, Gallery, and one target CVM. Check regional and
  DCas_v6-family quota/capacity for that one target before building.
- Blob data upload permission for your signed-in identity. The example creates
  a container-scoped role assignment, which requires role-assignment permission
  in addition to Contributor. It uses no helper managed identity, account key,
  or upload SAS.
- An existing OpenSSH **public** key for the target; never supply a private key.
  Outbound access is needed for Ubuntu packages, GitHub/Go, and Azure endpoints.

Use an exclusive build machine/workspace for this run. The shared scripts
reserve `/var/tmp/canonical-build`, use root mounts/device-mapper/NBD, and must
not run concurrently there. Review package installation and root commands before
executing them. Store all artifacts outside the entire Git checkout.

## 1. Configure a new owned Azure scope; do not create a builder

Run from `ubuntu/verity-tmpfs-root` in a dedicated Bash session. Replace the
placeholders. Keep this session's variables for the later publication steps.

```bash
set -euo pipefail
umask 077
RECIPE=$(pwd -P)
SUBSCRIPTION='<your-subscription-guid>'
RESOURCE_GROUP=rg-my-local-cvm
PREFIX=mylocalcvm
LOCATION=westus3
SSH_PUBLIC_KEY="$HOME/.ssh/id_ed25519.pub"
RUN_DIR="$HOME/canonical-cvm-runs/$PREFIX"
test -f "$SSH_PUBLIC_KEY"
test ! -e "$RUN_DIR"
mkdir -p "$RUN_DIR/evidence" "$RUN_DIR/input"

# --plan prints configuration only, without Azure calls or VM creation.
bash deploy.sh --subscription-id "$SUBSCRIPTION" \
  --resource-group "$RESOURCE_GROUP" --prefix "$PREFIX" \
  --location "$LOCATION" --ssh-public-key "$SSH_PUBLIC_KEY" --plan \
  > "$RUN_DIR/config.json"

source scripts/bash/common.sh
source scripts/bash/azure.sh
load_config
az login
test "$(azure group exists -n "$RESOURCE_GROUP" -o tsv)" = false
azure group create -n "$RESOURCE_GROUP" -l "$LOCATION" \
  --tags purpose=canonical-manifest-tmpfs "session=$RUN_ID" -o none
owned_group
```

The reused configuration includes a helper name and a two-VM ceiling, but this
manual path never calls `new_vm helper` or the two-VM `preflight` function.
Only the target is created in step 5. The sourced Bash functions are the same
publication and acceptance helpers used by the controller, not a local-build
entry point.

## 2. Obtain the exact unbooted source

You can supply an authorized export of the exact pinned Marketplace OS disk.
The example below creates and exports an unbooted disk in your owned group.
If you already have that export, place it at `$RUN_DIR/input/source.vhd`, skip
the create/export block, and omit source-disk deletion in step 6. Do not delete
someone else's original disk.
If organizational policy or image restrictions prohibit export, stop and use
the Azure-builder workflow; do not weaken policy or substitute another image.

```bash
azure disk create -g "$RESOURCE_GROUP" -n "$(cfg .sourceDisk)" -l "$LOCATION" \
  --image-reference "$(cfg .imageUrn)" \
  --security-type ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey \
  --sku StandardSSD_LRS --hyper-v-generation V2 --os-type Linux -o none

# The export SAS is a credential: do not trace, print, commit, or save it.
(
  set +x
  trap 'azure disk revoke-access -g "$RESOURCE_GROUP" -n "$(cfg .sourceDisk)" -o none' EXIT
  sas=$(azure disk grant-access -g "$RESOURCE_GROUP" -n "$(cfg .sourceDisk)" \
    --access-level Read --duration-in-seconds 3600 --query accessSas -o tsv)
  printf 'url = "%s"\n' "$sas" |
    curl --config - --fail --show-error --max-time 3500 \
      --output "$RUN_DIR/input/source.vhd"
  unset sas
)
```

Install the local build dependencies (Ubuntu 22.04 package names):

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential binutils cpio cryptsetup-bin fdisk gdisk git golang-go \
  initramfs-tools-core kmod libudev-dev openssl pkg-config python3 qemu-utils \
  sbsigntool udev util-linux
qemu-img convert -f vpc -O raw "$RUN_DIR/input/source.vhd" "$RUN_DIR/input/source.raw"
test "$(stat -c %s "$RUN_DIR/input/source.raw")" = 32213303296
```

The fixed-VHD footer is not part of the raw disk; do not feed a downloaded VHD
file directly to the image protector or treat it as a physical disk. The source
is mounted read-only below. All generalization/integrity changes happen on a
separate disposable raw working copy.

## 3. Rebuild/sign the UKI and protect a working copy locally

The only new inputs to the shared scripts are:

| Input | Meaning | Azure-builder default |
| --- | --- | --- |
| `POC_SOURCE_DISK` | Unmounted source block device, e.g. a read-only loop device | `/dev/disk/azure/scsi1/lun0` |
| `POC_KERNEL_ROOT` | Read-only mounted source root containing the matching `/boot/config-*` and `/lib/modules/*` | `/` on the matching builder |

The source-device identity, size, mounted/boot-disk rejection, exact stock-UKI
hash, matching signed module dependencies, and corruption checks remain in
force. A pathname to a regular image file is rejected as `POC_SOURCE_DISK`.
The modules copied into the initrd come from `POC_KERNEL_ROOT`; the host's own
modules are used only to operate its NBD/verity infrastructure.

```bash
sudo env RECIPE="$RECIPE" SOURCE_RAW="$RUN_DIR/input/source.raw" bash <<'BUILD'
set -euo pipefail
umask 077
work=/var/tmp/canonical-build
private=/root/canonical-local-signer
test ! -e "$work"
test ! -e "$private"
install -d -m 700 "$work" "$private" "$work/source-root"
modprobe nbd max_part=16
modprobe dm_verity
modprobe overlay
source_loop=
cleanup_inputs() {
    if mountpoint -q "$work/source-root"; then umount "$work/source-root"; fi
    if test -n "$source_loop"; then losetup --detach "$source_loop"; fi
}
trap cleanup_inputs EXIT

source_loop=$(losetup --find --show --read-only --partscan "$SOURCE_RAW")
test "$(blockdev --getsize64 "$source_loop")" = 32213303296
udevadm settle
mapfile -t roots < <(lsblk -rpn -o PATH,LABEL "$source_loop" |
    awk '$2=="cloudimg-rootfs" {print $1}')
test "${#roots[@]}" = 1
mount -o ro,noload "${roots[0]}" "$work/source-root"

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
  -subj '/CN=Canonical local reference signer/' \
  -addext 'keyUsage=critical,digitalSignature' -addext 'extendedKeyUsage=codeSigning' \
  -keyout "$private/poc-uki.key.pem" -out "$private/poc-uki.cert.pem"
chmod 600 "$private/poc-uki.key.pem"
POC_KERNEL_ROOT="$work/source-root" bash "$RECIPE/scripts/custom-uki/Rebuild-SignedUki.sh" \
  "$work/source-root/usr/lib/linux/efi/kernel.efi-6.8.0-1068-azure-fde" \
  "$private/poc-uki.key.pem" "$private/poc-uki.cert.pem" \
  "$work/custom-uki-1" 6.8.0-1068-azure-fde

# Build-Image refuses mounted source disks; finish reading the source first.
umount "$work/source-root"
bash "$RECIPE/scripts/Build-Producer.sh"
export POC_SOURCE_DISK="$source_loop"
export POC_OFFLINE_PREPARE_SCRIPT="$RECIPE/scripts/custom-uki/Prepare-OfflineSource.sh"
export POC_SIGNED_UKI="$work/custom-uki-1/poc-signed.efi"
export POC_EXPECTED_UKI_HASH
POC_EXPECTED_UKI_HASH=$(sha256sum "$POC_SIGNED_UKI" | cut -d ' ' -f1)
bash "$RECIPE/scripts/Build-Image.sh"
dpkg-query -W git golang-go qemu-utils gdisk cryptsetup-bin libudev-dev binutils initramfs-tools-core \
  > "$work/tool-packages.txt"
bash "$RECIPE/scripts/Collect-BuildEvidence.sh"
BUILD
```

Require `CUSTOM_UKI_BUILD_AND_LOCAL_SIGNATURE_VERIFICATION_PASSED`,
`PRODUCER_BUILD_AND_TESTS_PASSED`, and
`IMAGE_BUILD_AND_NEGATIVE_TESTS_PASSED`. The last includes full offline verity
verification, corrupted-clone rejection/live verity I/O failure, and fixed-VHD
geometry/footer checks. If any command fails, stop and inspect the logs; do not
replace a gate with a success marker or resume over an unexplained partial image.

Copy only public signing material and build evidence to the user-owned run
directory, and move the output VHD there for upload:

```bash
WORK=/var/tmp/canonical-build
sudo install -m 600 -o "$(id -u)" -g "$(id -g)" \
  "$WORK/custom-uki-1/custom-uki-build.json" "$RUN_DIR/evidence/verified-custom-uki-build.json"
sudo install -m 600 -o "$(id -u)" -g "$(id -g)" \
  "$WORK/custom-uki-1/signer.der" "$RUN_DIR/guest-signer.der"
sudo install -m 600 -o "$(id -u)" -g "$(id -g)" \
  "$WORK/build-evidence.tar.gz" "$RUN_DIR/evidence/build-evidence.tar.gz"
sudo chown "$(id -u):$(id -g)" "$WORK/canonical-tmpfs.vhd"
sudo chmod 600 "$WORK/canonical-tmpfs.vhd"
sudo mv -- "$WORK/canonical-tmpfs.vhd" "$RUN_DIR/canonical-tmpfs.vhd"
mkdir "$RUN_DIR/evidence/build"
tar -xzf "$RUN_DIR/evidence/build-evidence.tar.gz" -C "$RUN_DIR/evidence/build" --no-same-owner
new_security_profile "$RUN_DIR/guest-signer.der" "$RUN_DIR/guest-security-profile.json"
```

The private key remains under `/root/canonical-local-signer`, not in the VHD,
archive, repository, or managed-command requests. Unlike the cloud-builder
workflow, deleting Azure resources will **not** destroy your local signing key.
Keep or destroy it deliberately under your own key-handling policy.

## 4. Upload with your Azure identity and publish the same trust profile

Provide your signed-in user's **object ID** and your machine's allowed public
IPv4 egress address (not an RFC1918 address). The storage firewall must permit
that client. An existing Azure build host in the storage account's region
needs appropriate VNet/service-endpoint or private-endpoint access rather than
relying on a public-IP rule. Private networking requires your own routing/DNS
setup. The example is for a user identity; use the corresponding principal
type and object ID if authenticating as a service principal.

```bash
UPLOADER_OBJECT_ID='<your-signed-in-user-object-id>'
BUILD_PUBLIC_IP='<your-allowed-public-egress-ipv4>'
STORAGE=$(cfg .storageAccount)
owned_group
azure_json "$RUN_DIR/evidence/storage.json" storage account create \
  -g "$RESOURCE_GROUP" -n "$STORAGE" -l "$LOCATION" --sku Standard_LRS --kind StorageV2 \
  --https-only true --allow-blob-public-access false --min-tls-version TLS1_2 \
  --allow-shared-key-access false --public-network-access Enabled \
  --default-action Deny --bypass AzureServices
azure storage account network-rule add -g "$RESOURCE_GROUP" \
  --account-name "$STORAGE" --ip-address "$BUILD_PUBLIC_IP" -o none
azure storage container-rm create -g "$RESOURCE_GROUP" --storage-account "$STORAGE" \
  -n "$(cfg .imageContainer)" -o none
SCOPE="$(jq -er .id "$RUN_DIR/evidence/storage.json")/blobServices/default/containers/$(cfg .imageContainer)"
azure_json "$RUN_DIR/evidence/local-upload-role.json" role assignment create \
  --assignee-object-id "$UPLOADER_OBJECT_ID" --assignee-principal-type User \
  --role 'Storage Blob Data Contributor' --scope "$SCOPE"
```

Allow RBAC/firewall changes to propagate before uploading. An authorization
failure is not a reason to enable shared keys or make the blob public.
`scripts/Upload-Vhd.py` is the Azure-builder IMDS uploader; do not run it locally.
Use Azure CLI's authenticated **page-blob** upload instead:

```bash
azure storage blob upload --account-name "$STORAGE" --container-name "$(cfg .imageContainer)" \
  --name canonical-tmpfs.vhd --file "$RUN_DIR/canonical-tmpfs.vhd" \
  --type page --auth-mode login --overwrite false -o none
azure sig create -g "$RESOURCE_GROUP" --gallery-name "$(cfg .gallery)" -l "$LOCATION" -o none
azure sig image-definition create -g "$RESOURCE_GROUP" \
  --gallery-name "$(cfg .gallery)" --gallery-image-definition "$(cfg .imageDefinition)" \
  -l "$LOCATION" --publisher CanonicalReference --offer ubuntu2204-cvm --sku manifest-tmpfs \
  --os-type Linux --os-state Generalized --hyper-v-generation V2 --architecture x64 \
  --features SecurityType=TrustedLaunchAndConfidentialVmSupported -o none
publish_image
```

`publish_image` binds the actual public certificate to the verified UKI build,
preserves `MicrosoftUefiCertificateAuthorityTemplate`, waits for replication,
and reads back the **exact** signer/template with
`$expand=ReplicationStatus,UefiSettings`. It creates no VM. Do not delete the
upload storage before completed replication and successful readback.

## 5. Create one target and require actual Azure acceptance

```bash
azure network nsg create -g "$RESOURCE_GROUP" -n "$(cfg .networkSecurityGroup)" -l "$LOCATION" -o none
azure network vnet create -g "$RESOURCE_GROUP" -n "$(cfg .network)" -l "$LOCATION" \
  --address-prefixes 10.73.0.0/24 --subnet-name "$(cfg .subnet)" --subnet-prefixes 10.73.0.0/26 -o none
new_vm reference "$VERSION_ID"
verify_reference
```

These are the same target-creation and managed guest acceptance functions used
by the automatic workflow. Require ConfidentialVM/Secure Boot/vTPM control-plane
settings, actual firmware signer enrollment, matching UKI/root hashes, verity/tmpfs
mounts, no swap, the workload, and a real reboot with distinct boot IDs and
vanished volatile writes. Only `poc-*` managed test commands are removed before
reboot; policy-owned commands remain. Build and guest acceptance evidence use the filenames in the
[main recipe](README.md#validation-and-evidence).

## 6. Deallocate and clean up deliberately

This manual session does **not** install `deploy.sh`'s failure-deallocation trap.
If target creation/acceptance fails, stop and explicitly deallocate any created
target, or remove the entire owned group. Do not leave a failed target running
while inspecting local build output.

After acceptance, deallocate and confirm the target, recheck replication/trust,
then remove temporary export/upload resources and the role created above:

```bash
owned_group
remove_test_commands
azure vm deallocate -g "$RESOURCE_GROUP" -n "$TARGET" -o none
azure_json "$RUN_DIR/evidence/retained-target.json" vm get-instance-view -g "$RESOURCE_GROUP" -n "$TARGET"
jq -e 'any(.instanceView.statuses[];.code=="PowerState/deallocated")' \
  "$RUN_DIR/evidence/retained-target.json"
azure_json "$RUN_DIR/evidence/retained-image.json" rest --method get \
  --url "https://management.azure.com$VERSION_ID?api-version=2024-03-03" \
  --url-parameters '$expand=ReplicationStatus,UefiSettings'
verify_published_image "$RUN_DIR/evidence/retained-image.json"
azure disk delete -g "$RESOURCE_GROUP" -n "$(cfg .sourceDisk)" --yes -o none
azure role assignment delete --ids "$(jq -er .id "$RUN_DIR/evidence/local-upload-role.json")"
azure storage account delete -g "$RESOURCE_GROUP" -n "$(cfg .storageAccount)" --yes
azure_json "$RUN_DIR/evidence/retained-resources.json" resource list -g "$RESOURCE_GROUP"
azure_json "$RUN_DIR/evidence/retained-vms.json" vm list -g "$RESOURCE_GROUP"
jq -e --arg target "$TARGET" 'length==1 and .[0].name==$target' "$RUN_DIR/evidence/retained-vms.json"
jq -e --arg source "$(cfg .sourceDisk)" --arg storage "$(cfg .storageAccount)" \
  'all(.[];.name!=$source and .name!=$storage)' "$RUN_DIR/evidence/retained-resources.json"
```

Do **not** invoke `cleanup.sh`'s default retain mode or `cleanup_run` here:
they expect an Azure helper and its upload identity. To remove **all** Azure
resources for either a failed or finished local run, the ownership-checked
whole-group path works without a helper:

```bash
bash cleanup.sh --run-directory "$RUN_DIR" --remove-run
```

That deletes the retained target and Gallery too, not just temporary resources.
It does not delete local images, evidence, keys, or the checkout. Local artifacts
and leftover mounts/devices after an interrupted root build need separate,
explicit cleanup. Retaining a deallocated VM still incurs disk/Gallery and
other non-compute charges. The same [integrity and volatility limitations](README.md#limits-and-operational-caveats)
apply; signing the UKI does not authenticate the external manifest/root hash.
