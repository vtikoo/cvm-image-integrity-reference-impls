#!/usr/bin/env bash

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
CHECKOUT_ROOT=$(cd -- "$REPO_ROOT/../.." && pwd -P)

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require_tools() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null || die "Missing required tool: $tool"
    done
}

validate_inputs() {
    [[ "$SUBSCRIPTION" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]] ||
        die 'Subscription must be a GUID.'
    [[ "$RESOURCE_GROUP" =~ ^[a-zA-Z][a-zA-Z0-9_-]{2,62}$ ]] || die 'Invalid dedicated resource-group name.'
    [[ "$PREFIX" =~ ^[a-z][a-z0-9-]{2,11}$ ]] || die 'Prefix must be 3-12 lowercase letters, digits, or hyphens, starting with a letter.'
    [[ "$LOCATION" =~ ^[a-z][a-z0-9]+$ ]] || die 'Invalid Azure region.'
    [[ "$VM_SIZE" =~ ^Standard_DC[0-9]+as_v6$ ]] || die 'This recipe requires a DCas_v6 size.'
}

new_config() {
    validate_inputs
    local id suffix
    id=$(python3 -c 'import uuid; print(uuid.uuid4())')
    suffix=${id//-/}; suffix=${suffix:0:8}
    jq -n --arg subscription "${SUBSCRIPTION,,}" --arg group "$RESOURCE_GROUP" \
        --arg prefix "$PREFIX" --arg location "$LOCATION" --arg size "$VM_SIZE" \
        --arg id "$id" --arg storage "ctmp${PREFIX//-/}$suffix" '{
        subscriptionId:$subscription,resourceGroup:$group,runId:$id,location:$location,vmSize:$size,
        maximumVms:2,imageUrn:"Canonical:ubuntu-22_04-lts:cvm:22.04.202610220",
        helperVm:($prefix+"-helper"),targetVm:($prefix+"-reference"),sourceDisk:($prefix+"-source"),
        adminUsername:"pocadmin",network:($prefix+"-vnet"),subnet:"poc",
        networkSecurityGroup:($prefix+"-nsg"),storageAccount:$storage,imageContainer:"images",
        gallery:(($prefix|gsub("-";"_"))+"_gallery"),imageDefinition:"ubuntu2204-custom-uki-tmpfs",
        imageDefinitionSecurityType:"TrustedLaunchAndConfidentialVmSupported",imageVersion:"1.0.0",
        producerRepository:"https://github.com/vtikoo/encrypt-cloud-image.git",
        producerRevision:"5dc3d3f85fdfa6f5bae8bc01edcbf55b2adcfabe"}'
}

cfg() {
    jq -er "$1 | select(. != null and . != \"\")" "$CONFIG" || die "Missing configuration field: $1"
}

load_config() {
    CONFIG="$RUN_DIR/config.json"
    [[ -f "$CONFIG" ]] || die 'Run directory has no configuration.'
    SUBSCRIPTION=$(cfg .subscriptionId); RESOURCE_GROUP=$(cfg .resourceGroup)
    LOCATION=$(cfg .location); VM_SIZE=$(cfg .vmSize); RUN_ID=$(cfg .runId)
    HELPER=$(cfg .helperVm); TARGET=$(cfg .targetVm)
    BASE="/subscriptions/$SUBSCRIPTION/resourceGroups/$RESOURCE_GROUP"
    VERSION_ID="$BASE/providers/Microsoft.Compute/galleries/$(cfg .gallery)/images/$(cfg .imageDefinition)/versions/$(cfg .imageVersion)"
    [[ "$RUN_ID" =~ ^[[:xdigit:]-]{36}$ ]] || die 'Invalid ownership identifier.'
}

azure() {
    az "$@" --subscription "$SUBSCRIPTION" --only-show-errors ||
        die "Azure operation failed: ${1:-unknown} ${2:-}"
}

azure_json() {
    local output=$1; shift
    azure "$@" -o json > "$output"
    jq -e . "$output" >/dev/null || die "Azure returned invalid JSON: $output"
}

owned_group() {
    azure_json "$RUN_DIR/evidence/group.json" group show -n "$RESOURCE_GROUP"
    jq -e --arg id "$RUN_ID" '.tags.session == $id' "$RUN_DIR/evidence/group.json" >/dev/null ||
        die 'Refusing to modify a resource group not owned by this run.'
}

managed_guest() {
    local script=$1 name=$2 marker=$3 vm=${4:-$HELPER} timeout=${5:-5400}
    [[ "$name" =~ ^[a-zA-Z0-9_-]{1,64}$ ]] || die 'Invalid managed-command evidence name.'
    if grep -Eq -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$script"; then
        die 'Never embed private signing material in a managed command.'
    fi
    local url request response modified state start_deadline deadline
    url="https://management.azure.com$BASE/providers/Microsoft.Compute/virtualMachines/$vm/runCommands/poc-$name?api-version=2024-07-01"
    request="$RUN_DIR/evidence/$name-request.json"
    response="$RUN_DIR/evidence/$name.json"
    owned_group
    modified=$(jq -r '.tags.ModifiedBy // empty' "$RUN_DIR/evidence/group.json")
    jq -n --arg location "$LOCATION" --arg id "$RUN_ID" --arg modified "$modified" \
        --argjson timeout "$timeout" --rawfile script "$script" '{
        location:$location,tags:({purpose:"canonical-manifest-tmpfs",session:$id}+
          if $modified=="" then {} else {ModifiedBy:$modified} end),
        properties:{source:{script:($script|gsub("\r\n";"\n"))},asyncExecution:true,timeoutInSeconds:$timeout}}' > "$request"
    azure rest --method put --url "$url" --body "@$request" --headers Content-Type=application/json -o none
    start_deadline=$(($(date +%s)+600)); deadline=$(($(date +%s)+timeout+600))
    while :; do
        azure_json "$response" rest --method get --url "$url" --url-parameters '$expand=instanceView'
        state=$(jq -r '.properties.instanceView.executionState // "Pending"' "$response")
        case "$state" in Succeeded|Failed|TimedOut|Canceled) break ;; esac
        if (( $(date +%s) >= deadline )) ||
           { [[ "$state" != Running ]] && (( $(date +%s) >= start_deadline )); }; then
            die "Managed command did not start or complete within its deadline: $name"
        fi
        sleep 20
    done
    jq -r '(.properties.instanceView.output // "")+"\n"+(.properties.instanceView.error // "")' \
        "$response" | tee "$RUN_DIR/evidence/$name.log"
    jq -e --arg marker "$marker" '
        .properties.instanceView | .executionState=="Succeeded" and .exitCode==0 and
        (((.output // "")+"\n"+(.error // ""))|contains($marker))' "$response" >/dev/null ||
        die "Managed guest command failed or did not emit its terminal marker: $name"
}

read_artifact() {
    local remote=$1 output=$2 vm=${3:-$HELPER}
    [[ ! "${remote,,}" =~ private|signer/.*key|\.key(\.|$) ]] || die 'Private signing artifacts must stay on the helper.'
    [[ ! -e "$output" && ! -L "$output" ]] || die "Artifact already exists: $output"
    local encoded stem index=0 count=1 hash= current_hash current_count path name chunk partial
    encoded=$(printf '%s' "$remote" | base64 -w0)
    stem=$(basename -- "$output"); stem=${stem%.*}; stem=${stem//[^a-zA-Z0-9_-]/-}; stem=${stem:0:32}
    path="$RUN_DIR/evidence/read-$stem.sh"
    chunk="$RUN_DIR/evidence/read-$stem-chunk.json"
    partial="$RUN_DIR/evidence/read-$stem-base64.txt"
    : > "$partial"
    while (( index < count )); do
        {
            printf '#!/bin/bash\nset -euo pipefail\npython3 - %q %q <<\x27PY\x27\n' "$encoded" "$index"
            cat "$REPO_ROOT/scripts/Read-ArtifactChunk.py"
            printf '\nPY\n'
        } > "$path"
        name="read-$stem-$index"
        managed_guest "$path" "$name" MANAGED_ARTIFACT_CHUNK_READY "$vm" 300 >/dev/null
        jq -e '.properties.instanceView.output|split("\n")|map(select(startswith("{")))|
            if length==1 then .[0]|fromjson else error("Truncated artifact response") end' \
            "$RUN_DIR/evidence/$name.json" > "$chunk"
        current_hash=$(jq -er '.sha256|select(test("^[0-9a-f]{64}$"))' "$chunk")
        current_count=$(jq -er '.chunks|select(type=="number" and .>=1 and .==floor)' "$chunk")
        if (( index == 0 )); then hash=$current_hash; count=$current_count; fi
        [[ "$current_hash" == "$hash" && "$current_count" == "$count" ]] ||
            die 'The artifact changed during retrieval.'
        jq -e --argjson index "$index" '.index==$index and (.payload|type=="string")' "$chunk" >/dev/null ||
            die 'The artifact response was malformed.'
        jq -jr .payload "$chunk" >> "$partial"
        index=$((index+1))
    done
    local decoded="$partial.decoded"
    base64 -d "$partial" | gzip -dc > "$decoded"
    [[ "$(sha256sum "$decoded" | cut -d ' ' -f1)" == "$hash" ]] || die 'Retrieved artifact failed SHA256 verification.'
    [[ ! -e "$output" && ! -L "$output" ]] || die 'Artifact destination appeared during retrieval.'
    mv -- "$decoded" "$output"
    rm -- "$partial"
    printf 'ARTIFACT_RETRIEVED_SHA256=%s\n' "$hash"
}

stage_file() {
    local payload
    payload=$(base64 -w0 < "$1")
    printf "printf '%%s' '%s' | base64 -d > '%s'\n" "$payload" "$2"
}

new_security_profile() {
    local certificate=$1 output=$2 canonical="$RUN_DIR/evidence/canonical-signer.der" start
    [[ ! -e "$output" ]] || die 'Security profile already exists.'
    if grep -aEq -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$certificate"; then
        die 'Supply only the public certificate.'
    fi
    openssl x509 -inform DER -in "$certificate" -outform DER -out "$canonical"
    cmp -s "$certificate" "$canonical" || die 'Expected a single DER public certificate without trailing material.'
    openssl x509 -inform DER -in "$certificate" -checkend 0 -noout
    start=$(openssl x509 -inform DER -in "$certificate" -startdate -noout)
    (( $(date -u -d "${start#notBefore=}" +%s) <= $(date +%s) )) || die 'Certificate is not yet valid.'
    jq -n --arg cert "$(base64 -w0 < "$certificate")" '{
        uefiSettings:{signatureTemplateNames:["MicrosoftUefiCertificateAuthorityTemplate"],
        additionalSignatures:{db:[{type:"x509",value:[$cert]}]}}}' > "$output"
}

verify_published_image() {
    jq -e --slurpfile profile "$RUN_DIR/guest-security-profile.json" '
        .properties.provisioningState=="Succeeded" and
        .properties.replicationStatus.aggregatedState=="Completed" and
        .properties.securityProfile.uefiSettings.signatureTemplateNames==["MicrosoftUefiCertificateAuthorityTemplate"] and
        .properties.securityProfile.uefiSettings.additionalSignatures.db==
          $profile[0].uefiSettings.additionalSignatures.db' "$1" >/dev/null ||
        die 'The completed Gallery image did not preserve the exact signer/template.'
}

remove_test_commands() {
    local deadline=$(($(date +%s)+300)) id
    while :; do
        azure_json "$RUN_DIR/evidence/target-commands.json" vm run-command list -g "$RESOURCE_GROUP" --vm-name "$TARGET"
        jq -r '.[]|select(.name|startswith("poc-"))|.id' "$RUN_DIR/evidence/target-commands.json" \
            > "$RUN_DIR/evidence/test-command-ids.txt"
        [[ -s "$RUN_DIR/evidence/test-command-ids.txt" ]] || break
        while IFS= read -r id; do
            azure rest --method delete --url "https://management.azure.com$id?api-version=2024-07-01" -o none
        done < "$RUN_DIR/evidence/test-command-ids.txt"
        (( $(date +%s) < deadline )) || die 'Target test-command deletion did not finish.'
        sleep 10
    done
}
