#!/usr/bin/env bash
set -euo pipefail
umask 077
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/scripts/bash/common.sh"
source "$REPO_ROOT/scripts/bash/azure.sh"

SUBSCRIPTION= RESOURCE_GROUP= PREFIX= SSH_PUBLIC_KEY= RUN_DIR=
LOCATION=westus3 VM_SIZE=Standard_DC4as_v6 PLAN=false GROUP_CREATED=false
while (( $# )); do
    case "$1" in
        --plan) PLAN=true; shift ;;
        --help|-h)
            echo 'Usage: bash deploy.sh --subscription-id GUID --resource-group NEW_GROUP --prefix NAME --ssh-public-key FILE [--location westus3] [--vm-size Standard_DC4as_v6] [--run-directory DIRECTORY] [--plan]'
            exit 0 ;;
        --subscription-id|--resource-group|--prefix|--ssh-public-key|--location|--vm-size|--run-directory)
            (( $# >= 2 )) || die "Missing value for $1"
            case "$1" in
                --subscription-id) SUBSCRIPTION=$2 ;;
                --resource-group) RESOURCE_GROUP=$2 ;;
                --prefix) PREFIX=$2 ;;
                --ssh-public-key) SSH_PUBLIC_KEY=$2 ;;
                --location) LOCATION=$2 ;;
                --vm-size) VM_SIZE=$2 ;;
                --run-directory) RUN_DIR=$2 ;;
            esac
            shift 2 ;;
        *) die "Unknown argument: $1" ;;
    esac
done
require_tools jq python3
validate_inputs
if [[ "$PLAN" == true ]]; then new_config; exit 0; fi
require_tools az openssl realpath base64 gzip sha256sum tar cmp date
[[ -f "$SSH_PUBLIC_KEY" ]] || die 'Supply an existing SSH public key file.'
key=$(< "$SSH_PUBLIC_KEY")
[[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[^[:space:]]+)[[:space:]][A-Za-z0-9+/]+=*([[:space:]].*)?$ ]] ||
    die 'Supply an OpenSSH public key, not private SSH/signing material.'
RUN_DIR=$(realpath -m -- "${RUN_DIR:-$HOME/canonical-cvm-runs/$PREFIX}")
[[ "$RUN_DIR" != "$REPO_ROOT" && "$RUN_DIR" != "$REPO_ROOT/"* ]] || die 'Run directory must be outside this repository.'
[[ ! -e "$RUN_DIR" && ! -L "$RUN_DIR" ]] || die 'Use a new run directory; do not overwrite an earlier run.'
mkdir -p -- "$(dirname -- "$RUN_DIR")"
mkdir -m 700 -- "$RUN_DIR"
mkdir -- "$RUN_DIR/evidence"
new_config > "$RUN_DIR/config.json"
load_config

on_exit() {
    local result=$? group vms vm
    trap - EXIT
    if (( result != 0 )); then
        if [[ "$GROUP_CREATED" == true ]]; then
            if group=$(az group show --subscription "$SUBSCRIPTION" -n "$RESOURCE_GROUP" --only-show-errors -o json) &&
                jq -e --arg id "$RUN_ID" '.tags.session==$id' <<< "$group" >/dev/null; then
                if vms=$(az vm list --subscription "$SUBSCRIPTION" -g "$RESOURCE_GROUP" --only-show-errors -o json); then
                    while IFS= read -r vm; do
                        az vm deallocate --subscription "$SUBSCRIPTION" -g "$RESOURCE_GROUP" -n "$vm" --no-wait --only-show-errors ||
                            printf 'WARNING: Could not request deallocation of %s.\n' "$vm" >&2
                    done < <(jq -r '.[].name' <<< "$vms")
                else
                    echo 'WARNING: Could not enumerate VMs for failure deallocation.' >&2
                fi
            else
                echo 'WARNING: Could not confirm group ownership for failure deallocation.' >&2
            fi
        fi
        printf 'Deployment incomplete. Inspect %s, verify VM deallocation, then use cleanup.sh --remove-run.\n' "$RUN_DIR" >&2
    fi
    exit "$result"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
preflight
azure group create -n "$RESOURCE_GROUP" -l "$LOCATION" \
    --tags purpose=canonical-manifest-tmpfs "session=$RUN_ID" cleanup=temporary-build-resources -o none
GROUP_CREATED=true
owned_group
azure network nsg create -g "$RESOURCE_GROUP" -n "$(cfg .networkSecurityGroup)" -l "$LOCATION" -o none
azure network vnet create -g "$RESOURCE_GROUP" -n "$(cfg .network)" -l "$LOCATION" \
    --address-prefixes 10.73.0.0/24 --subnet-name "$(cfg .subnet)" --subnet-prefixes 10.73.0.0/26 -o none
new_vm helper "$(cfg .imageUrn)"
managed_guest "$REPO_ROOT/scripts/Install-HelperTools.sh" helper-tools HELPER_TOOLS_READY
{
    printf '#!/bin/bash\nset -euo pipefail\n'
    stage_file "$REPO_ROOT/scripts/custom-uki/Rebuild-SignedUki.sh" /var/tmp/canonical-build/Rebuild-SignedUki.sh
    cat "$REPO_ROOT/scripts/custom-uki/Build-CustomUki.sh"
} > "$RUN_DIR/evidence/build-custom-uki.sh"
managed_guest "$RUN_DIR/evidence/build-custom-uki.sh" custom-uki-build CUSTOM_UKI_BUILD_AND_LOCAL_SIGNATURE_VERIFICATION_PASSED "$HELPER" 1800
read_artifact /var/tmp/canonical-build/custom-uki-1/custom-uki-build.json "$RUN_DIR/evidence/verified-custom-uki-build.json"
read_artifact /var/tmp/canonical-build/custom-uki-1/signer.der "$RUN_DIR/guest-signer.der"
new_security_profile "$RUN_DIR/guest-signer.der" "$RUN_DIR/guest-security-profile.json"
managed_guest "$REPO_ROOT/scripts/Build-Producer.sh" producer-build PRODUCER_BUILD_AND_TESTS_PASSED
azure_json "$RUN_DIR/evidence/source-disk.json" disk create -g "$RESOURCE_GROUP" -n "$(cfg .sourceDisk)" -l "$LOCATION" \
    --image-reference "$(cfg .imageUrn)" --security-type ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey \
    --sku StandardSSD_LRS --hyper-v-generation V2 --os-type Linux
jq -n --arg name "$(cfg .sourceDisk)" --slurpfile disk "$RUN_DIR/evidence/source-disk.json" '{
    properties:{storageProfile:{dataDisks:[{lun:0,name:$name,createOption:"Attach",
    managedDisk:{id:$disk[0].id},caching:"ReadOnly",deleteOption:"Detach"}]}}}' > "$RUN_DIR/evidence/source-attach-request.json"
azure rest --method patch --url "https://management.azure.com$BASE/providers/Microsoft.Compute/virtualMachines/$HELPER?api-version=2024-07-01" \
    --body "@$RUN_DIR/evidence/source-attach-request.json" --headers Content-Type=application/json -o none
managed_guest "$REPO_ROOT/scripts/Wait-SourceDisk.sh" source-ready SOURCE_DISK_READY
jq -e '.signature_verified_with_poc_certificate==true and (.signed_uki_sha256|test("^[0-9a-f]{64}$")) and
    (.build_directory|test("^/var/tmp/canonical-build/custom-uki-[0-9]+$"))' \
    "$RUN_DIR/evidence/verified-custom-uki-build.json" >/dev/null || die 'An actual verified custom UKI build is required.'
{
    printf '#!/bin/bash\nset -euo pipefail\numask 077\n'
    stage_file "$REPO_ROOT/scripts/custom-uki/Prepare-OfflineSource.sh" /var/tmp/canonical-build/Prepare-OfflineSource.sh
    stage_file "$REPO_ROOT/scripts/Build-Image.sh" /var/tmp/canonical-build/Build-Image.sh
    printf 'export POC_OFFLINE_PREPARE_SCRIPT=/var/tmp/canonical-build/Prepare-OfflineSource.sh\n'
    printf 'export POC_SIGNED_UKI=%q\nexport POC_EXPECTED_UKI_HASH=%q\n' \
        "$(jq -er .build_directory "$RUN_DIR/evidence/verified-custom-uki-build.json")/poc-signed.efi" \
        "$(jq -er .signed_uki_sha256 "$RUN_DIR/evidence/verified-custom-uki-build.json")"
    printf 'bash /var/tmp/canonical-build/Build-Image.sh\n'
} > "$RUN_DIR/evidence/build-protected-image.sh"
managed_guest "$RUN_DIR/evidence/build-protected-image.sh" image-build IMAGE_BUILD_AND_NEGATIVE_TESTS_PASSED "$HELPER" 3600
publication_scope
{
    printf '#!/bin/bash\nset -euo pipefail\nexport POC_BLOB_URL=%q\npython3 - <<\x27PYTHON\x27\n' \
        "https://$(cfg .storageAccount).blob.core.windows.net/$(cfg .imageContainer)/canonical-tmpfs.vhd"
    cat "$REPO_ROOT/scripts/Upload-Vhd.py"
    printf '\nPYTHON\n'
} > "$RUN_DIR/evidence/upload-vhd.sh"
managed_guest "$RUN_DIR/evidence/upload-vhd.sh" vhd-upload VHD_UPLOAD_PASSED
managed_guest "$REPO_ROOT/scripts/Collect-BuildEvidence.sh" collect-build-evidence BUILD_EVIDENCE_ARCHIVED
read_artifact /var/tmp/canonical-build/build-evidence.tar.gz "$RUN_DIR/evidence/build-evidence.tar.gz"
mkdir -- "$RUN_DIR/evidence/build"
tar -xzf "$RUN_DIR/evidence/build-evidence.tar.gz" -C "$RUN_DIR/evidence/build"
publish_image
new_vm reference "$VERSION_ID"
verify_reference
cleanup_run
printf 'DEPLOYMENT_VERIFIED: image=%s; target=%s; target deallocated; evidence=%s\n' "$VERSION_ID" "$TARGET" "$RUN_DIR"
