#!/usr/bin/env bash

preflight() {
    [[ "$(azure group exists -n "$RESOURCE_GROUP" -o tsv)" == false ]] || die 'Resource group must be new and dedicated.'
    azure_json "$RUN_DIR/evidence/skus.json" vm list-skus -l "$LOCATION" --size "$VM_SIZE" --all --resource-type virtualMachines
    jq --arg name "$VM_SIZE" '[.[]|select(.name==$name)]' "$RUN_DIR/evidence/skus.json" > "$RUN_DIR/evidence/sku.json"
    jq -e 'length==1 and (.[0].restrictions|length)==0' "$RUN_DIR/evidence/sku.json" >/dev/null ||
        die 'Selected CVM SKU has availability restrictions.'
    local cpus family
    cpus=$(jq -er '.[0].capabilities[]|select(.name=="vCPUs")|.value|tonumber|select(.>=1)' "$RUN_DIR/evidence/sku.json")
    family=$(jq -er '.[0].family' "$RUN_DIR/evidence/sku.json")
    azure_json "$RUN_DIR/evidence/quota.json" vm list-usage -l "$LOCATION"
    jq -e --arg family "$family" --argjson cpus "$cpus" '
        . as $usage|[$family,"cores"]|all(. as $name|
          [$usage[]|select((.name.value|ascii_downcase)==($name|ascii_downcase))]|
          length==1 and (.[0].limit-.[0].currentValue)>=2*$cpus)' "$RUN_DIR/evidence/quota.json" >/dev/null ||
        die 'Insufficient regional/family quota for two VMs.'
    azure vm image show --urn "$(cfg .imageUrn)" -l "$LOCATION" -o none
}

new_vm() {
    local role=$1 image=$2 name size
    if [[ "$role" == helper ]]; then name=$HELPER; size=64; else name=$TARGET; size=31; fi
    owned_group
    azure_json "$RUN_DIR/evidence/vms.json" vm list -g "$RESOURCE_GROUP"
    jq -e --arg name "$name" 'length<2 and all(.name!=$name)' "$RUN_DIR/evidence/vms.json" >/dev/null ||
        die 'The VM already exists or the two-VM cap has been reached.'
    local args=(vm create -g "$RESOURCE_GROUP" -n "$name" -l "$LOCATION" --size "$VM_SIZE" --image "$image"
        --security-type ConfidentialVM --enable-secure-boot true --enable-vtpm true
        --os-disk-security-encryption-type VMGuestStateOnly --storage-sku StandardSSD_LRS --os-disk-size-gb "$size"
        --admin-username "$(cfg .adminUsername)" --authentication-type ssh --ssh-key-values "$SSH_PUBLIC_KEY"
        --vnet-name "$(cfg .network)" --subnet "$(cfg .subnet)" --nsg "$(cfg .networkSecurityGroup)"
        --nsg-rule NONE --public-ip-sku Standard --tags purpose=canonical-manifest-tmpfs "role=$role" "session=$RUN_ID")
    if [[ "$role" == helper ]]; then args+=(--assign-identity); fi
    azure_json "$RUN_DIR/evidence/$role-create.json" "${args[@]}"
    printf '%s\n' '{"properties":{"diagnosticsProfile":{"bootDiagnostics":{"enabled":true}}}}' \
        > "$RUN_DIR/evidence/$role-diagnostics-request.json"
    azure rest --method patch --url \
        "https://management.azure.com$BASE/providers/Microsoft.Compute/virtualMachines/$name?api-version=2024-07-01" \
        --body "@$RUN_DIR/evidence/$role-diagnostics-request.json" --headers Content-Type=application/json -o none
    azure_json "$RUN_DIR/evidence/$role-control-plane.json" vm show -d -g "$RESOURCE_GROUP" -n "$name"
    jq -e '.securityProfile.securityType=="ConfidentialVM" and
        .securityProfile.uefiSettings.secureBootEnabled==true and .securityProfile.uefiSettings.vTpmEnabled==true and
        .storageProfile.osDisk.managedDisk.securityProfile.securityEncryptionType=="VMGuestStateOnly"' \
        "$RUN_DIR/evidence/$role-control-plane.json" >/dev/null || die 'VM security configuration did not match.'
}

publication_scope() {
    local storage subnet scope principal
    storage=$(cfg .storageAccount)
    azure_json "$RUN_DIR/evidence/helper-model.json" vm show -g "$RESOURCE_GROUP" -n "$HELPER"
    principal=$(jq -er '.identity.principalId|select(length>0)' "$RUN_DIR/evidence/helper-model.json")
    azure_json "$RUN_DIR/evidence/storage.json" storage account create -g "$RESOURCE_GROUP" -n "$storage" \
        -l "$LOCATION" --sku Standard_LRS --kind StorageV2 --https-only true --allow-blob-public-access false \
        --min-tls-version TLS1_2 --allow-shared-key-access false --public-network-access Enabled \
        --default-action Deny --bypass AzureServices --tags purpose=canonical-manifest-tmpfs role=temporary-image-import
    azure_json "$RUN_DIR/evidence/subnet.json" network vnet subnet update -g "$RESOURCE_GROUP" \
        --vnet-name "$(cfg .network)" -n "$(cfg .subnet)" --service-endpoints Microsoft.Storage
    subnet=$(jq -er .id "$RUN_DIR/evidence/subnet.json")
    azure storage account network-rule add -g "$RESOURCE_GROUP" --account-name "$storage" --subnet "$subnet" -o none
    azure storage container-rm create -g "$RESOURCE_GROUP" --storage-account "$storage" -n "$(cfg .imageContainer)" -o none
    scope="$(jq -er .id "$RUN_DIR/evidence/storage.json")/blobServices/default/containers/$(cfg .imageContainer)"
    azure_json "$RUN_DIR/evidence/helper-upload-role.json" role assignment create \
        --assignee-object-id "$principal" --assignee-principal-type ServicePrincipal \
        --role 'Storage Blob Data Contributor' --scope "$scope"
    azure sig create -g "$RESOURCE_GROUP" --gallery-name "$(cfg .gallery)" -l "$LOCATION" -o none
    azure_json "$RUN_DIR/evidence/gallery-definition.json" sig image-definition create -g "$RESOURCE_GROUP" \
        --gallery-name "$(cfg .gallery)" --gallery-image-definition "$(cfg .imageDefinition)" -l "$LOCATION" \
        --publisher CanonicalReference --offer ubuntu2204-cvm --sku manifest-tmpfs --os-type Linux --os-state Generalized \
        --hyper-v-generation V2 --architecture x64 --features SecurityType=TrustedLaunchAndConfidentialVmSupported
}

publish_image() {
    local certificate_hash url deadline
    certificate_hash=$(jq -er '.uefiSettings.additionalSignatures.db[0].value[0]' \
        "$RUN_DIR/guest-security-profile.json" | base64 -d | sha256sum | cut -d ' ' -f1)
    jq -e --arg hash "$certificate_hash" '.signature_verified_with_poc_certificate==true and
        .certificate_sha256==$hash and (.signed_uki_sha256|test("^[0-9a-f]{64}$"))' \
        "$RUN_DIR/evidence/verified-custom-uki-build.json" >/dev/null || die 'A matching verified UKI signer is required.'
    jq -e '.uefiSettings.signatureTemplateNames==["MicrosoftUefiCertificateAuthorityTemplate"] and
        (.uefiSettings.additionalSignatures.db|length)==1 and .uefiSettings.additionalSignatures.db[0].type=="x509" and
        (.uefiSettings.additionalSignatures.db[0].value|length)==1' "$RUN_DIR/guest-security-profile.json" >/dev/null ||
        die 'Exactly the verified signer and Microsoft UEFI template are required.'
    azure_json "$RUN_DIR/evidence/gallery-definition.json" sig image-definition show -g "$RESOURCE_GROUP" \
        --gallery-name "$(cfg .gallery)" --gallery-image-definition "$(cfg .imageDefinition)"
    jq -e '[.features[]|select(.name=="SecurityType" and .value=="TrustedLaunchAndConfidentialVmSupported")]|length==1' \
        "$RUN_DIR/evidence/gallery-definition.json" >/dev/null || die 'The actual image definition has the wrong security type.'
    url="https://management.azure.com$VERSION_ID?api-version=2024-03-03"
    jq -n --arg location "$LOCATION" --arg run "$RUN_ID" --arg storage "$(cfg .storageAccount)" \
        --arg base "$BASE" --arg container "$(cfg .imageContainer)" --slurpfile profile "$RUN_DIR/guest-security-profile.json" '{
        location:$location,tags:{purpose:"canonical-manifest-tmpfs",variant:"custom-signed-uki",session:$run},
        properties:{publishingProfile:{replicaCount:1,excludeFromLatest:true,storageAccountType:"Standard_LRS",
          targetRegions:[{name:$location,regionalReplicaCount:1,storageAccountType:"Standard_LRS"}]},
          storageProfile:{osDiskImage:{source:{uri:("https://"+$storage+".blob.core.windows.net/"+$container+"/canonical-tmpfs.vhd"),
          storageAccountId:($base+"/providers/Microsoft.Storage/storageAccounts/"+$storage)}}},
          securityProfile:$profile[0]}}' > "$RUN_DIR/evidence/gallery-version-request.json"
    azure_json "$RUN_DIR/evidence/gallery-version-put.json" rest --method put --url "$url" \
        --body "@$RUN_DIR/evidence/gallery-version-request.json" --headers Content-Type=application/json
    deadline=$(($(date +%s)+3600))
    while :; do
        azure_json "$RUN_DIR/evidence/gallery-image-version.json" rest --method get --url "$url" \
            --url-parameters '$expand=ReplicationStatus,UefiSettings'
        [[ "$(jq -r .properties.provisioningState "$RUN_DIR/evidence/gallery-image-version.json")" != Failed ]] ||
            die 'Gallery image provisioning failed.'
        if jq -e '.properties.provisioningState=="Succeeded" and .properties.replicationStatus.aggregatedState=="Completed"' \
            "$RUN_DIR/evidence/gallery-image-version.json" >/dev/null; then break; fi
        (( $(date +%s) < deadline )) || die 'Gallery image replication timed out.'
        sleep 30
    done
    verify_published_image "$RUN_DIR/evidence/gallery-image-version.json"
}

verify_reference() {
    local root_hash uki_hash cert_hash phase marker script
    root_hash=$(< "$RUN_DIR/evidence/build/evidence/root-hash.txt")
    uki_hash=$(jq -er .signed_uki_sha256 "$RUN_DIR/evidence/verified-custom-uki-build.json")
    cert_hash=$(jq -er .certificate_sha256 "$RUN_DIR/evidence/verified-custom-uki-build.json")
    [[ "$root_hash" =~ ^[0-9a-f]{64}$ && "$uki_hash" =~ ^[0-9a-f]{64}$ && "$cert_hash" =~ ^[0-9a-f]{64}$ ]] ||
        die 'Verified build hashes are required.'
    for phase in before after; do
        if [[ "$phase" == before ]]; then
            script=Verify-Reference.sh; marker=REFERENCE_BOOT_AND_SMOKE_PASSED
        else
            remove_test_commands
            azure vm restart -g "$RESOURCE_GROUP" -n "$TARGET"
            script=Verify-Reboot.sh; marker=VOLATILE_REBOOT_AND_UNCHANGED_LOWER_PASSED
        fi
        {
            printf '#!/bin/bash\nexport POC_EXPECTED_ROOT_HASH=%q\nexport POC_EXPECTED_UKI_HASH=%q\nexport POC_EXPECTED_CERT_SHA256=%q\n' \
                "$root_hash" "$uki_hash" "$cert_hash"
            cat "$REPO_ROOT/scripts/$script"
        } > "$RUN_DIR/evidence/reference-$phase-reboot.sh"
        managed_guest "$RUN_DIR/evidence/reference-$phase-reboot.sh" "reference-$phase-reboot" "$marker" "$TARGET" 1800
        if [[ "$phase" == before ]]; then
            read_artifact /var/tmp/canonical-reference-evidence.json "$RUN_DIR/evidence/reference-before-reboot-verified.json" "$TARGET"
        else
            read_artifact /var/tmp/canonical-reboot-evidence.json "$RUN_DIR/evidence/reference-after-reboot-verified.json" "$TARGET"
        fi
    done
    jq -ne --slurpfile before "$RUN_DIR/evidence/reference-before-reboot-verified.json" \
        --slurpfile after "$RUN_DIR/evidence/reference-after-reboot-verified.json" '
        ($before[0].boot_id|strings|length)>0 and ($after[0].boot_id|strings|length)>0 and
        $before[0].boot_id!=$after[0].boot_id' >/dev/null || die 'Distinct guest boot IDs were not confirmed.'
    jq -n --slurpfile before "$RUN_DIR/evidence/reference-before-reboot-verified.json" \
        --slurpfile after "$RUN_DIR/evidence/reference-after-reboot-verified.json" \
        '{before:$before[0].boot_id,after:$after[0].boot_id,changed:true}' > "$RUN_DIR/evidence/reboot-ids.json"
    echo REFERENCE_E2E_ACCEPTANCE_PASSED
}

cleanup_run() {
    local mode=${1:-retain} deadline id name storage
    storage=$(cfg .storageAccount)
    owned_group
    if [[ "$mode" == remove ]]; then
        azure group delete -n "$RESOURCE_GROUP" --yes --no-wait
        deadline=$(($(date +%s)+2400))
        while [[ "$(azure group exists -n "$RESOURCE_GROUP" -o tsv)" != false ]]; do
            (( $(date +%s) < deadline )) || die 'Resource-group deletion timed out.'
            sleep 30
        done
        jq -n --arg group "$RESOURCE_GROUP" '{resourceGroup:$group,exists:false,verifiedUtc:(now|todate)}' \
            > "$RUN_DIR/evidence/cleanup-summary.json"
        echo CUSTOM_RUN_RESOURCES_REMOVED
        return
    fi
    jq -e '.changed==true and (.before|strings|length)>0 and (.after|strings|length)>0 and .before!=.after' \
        "$RUN_DIR/evidence/reboot-ids.json" >/dev/null || die 'A verified real reboot is required before retaining the target.'
    azure_json "$RUN_DIR/evidence/retained-image.json" rest --method get \
        --url "https://management.azure.com$VERSION_ID?api-version=2024-03-03" \
        --url-parameters '$expand=ReplicationStatus,UefiSettings'
    verify_published_image "$RUN_DIR/evidence/retained-image.json"
    remove_test_commands
    azure vm deallocate -g "$RESOURCE_GROUP" -n "$TARGET" -o none
    azure_json "$RUN_DIR/evidence/retained-target.json" vm get-instance-view -g "$RESOURCE_GROUP" -n "$TARGET"
    jq -e 'any(.instanceView.statuses[];.code=="PowerState/deallocated")' "$RUN_DIR/evidence/retained-target.json" >/dev/null ||
        die 'The retained target was not confirmed deallocated.'
    azure_json "$RUN_DIR/evidence/helper-delete-model.json" vm show -g "$RESOURCE_GROUP" -n "$HELPER"
    jq -e --arg id "$RUN_ID" '.tags.role=="helper" and .tags.purpose=="canonical-manifest-tmpfs" and .tags.session==$id' \
        "$RUN_DIR/evidence/helper-delete-model.json" >/dev/null || die 'Helper ownership did not match.'
    local principal scope nic_file="$RUN_DIR/evidence/helper-nic.json"
    principal=$(jq -er .identity.principalId "$RUN_DIR/evidence/helper-delete-model.json")
    scope="$BASE/providers/Microsoft.Storage/storageAccounts/$storage/blobServices/default/containers/$(cfg .imageContainer)"
    jq -e --arg principal "$principal" --arg scope "$scope" '.principalId==$principal and
        (.scope|ascii_downcase)==($scope|ascii_downcase)' "$RUN_DIR/evidence/helper-upload-role.json" >/dev/null ||
        die 'Refusing to revoke an unrelated role assignment.'
    jq -r '.networkProfile.networkInterfaces[].id' "$RUN_DIR/evidence/helper-delete-model.json" > "$RUN_DIR/evidence/helper-nic-ids.txt"
    : > "$RUN_DIR/evidence/helper-ip-ids.txt"
    while IFS= read -r id; do
        azure_json "$nic_file" network nic show --ids "$id"
        jq -r '.ipConfigurations[]|.publicIPAddress.id // empty' "$nic_file" >> "$RUN_DIR/evidence/helper-ip-ids.txt"
    done < "$RUN_DIR/evidence/helper-nic-ids.txt"
    azure role assignment delete --ids "$(jq -er .id "$RUN_DIR/evidence/helper-upload-role.json")"
    azure vm delete -g "$RESOURCE_GROUP" -n "$HELPER" --yes -o none
    while IFS= read -r id; do azure network nic delete --ids "$id" -o none; done < "$RUN_DIR/evidence/helper-nic-ids.txt"
    while IFS= read -r id; do azure network public-ip delete --ids "$id" -o none; done < "$RUN_DIR/evidence/helper-ip-ids.txt"
    azure disk delete --ids "$(jq -er .storageProfile.osDisk.managedDisk.id "$RUN_DIR/evidence/helper-delete-model.json")" --yes -o none
    azure disk delete -g "$RESOURCE_GROUP" -n "$(cfg .sourceDisk)" --yes -o none
    azure storage account delete -g "$RESOURCE_GROUP" -n "$storage" --yes
    azure_json "$RUN_DIR/evidence/cleanup-nsgs.json" network nsg list -g "$RESOURCE_GROUP"
    jq -r '.[]|select(any(.securityRules[]?;.name=="temporary-build-ssh"))|.name' \
        "$RUN_DIR/evidence/cleanup-nsgs.json" > "$RUN_DIR/evidence/cleanup-nsg-names.txt"
    while IFS= read -r name; do
        azure network nsg rule delete -g "$RESOURCE_GROUP" --nsg-name "$name" -n temporary-build-ssh -o none
    done < "$RUN_DIR/evidence/cleanup-nsg-names.txt"
    azure_json "$RUN_DIR/evidence/retained-resources.json" resource list -g "$RESOURCE_GROUP"
    jq -e --arg helper "$HELPER" --arg source "$(cfg .sourceDisk)" --arg storage "$storage" '
        all(.[];(.name|startswith($helper)|not) and .name!=$source and .name!=$storage)' \
        "$RUN_DIR/evidence/retained-resources.json" >/dev/null || die 'Temporary resources remain.'
    azure_json "$RUN_DIR/evidence/retained-vms.json" vm list -g "$RESOURCE_GROUP"
    jq -e --arg target "$TARGET" 'length==1 and .[0].name==$target' "$RUN_DIR/evidence/retained-vms.json" >/dev/null ||
        die 'The retained VM inventory was unexpected.'
    jq -n --arg group "$RESOURCE_GROUP" --arg target "$TARGET" --arg image "$VERSION_ID" \
        --slurpfile resources "$RUN_DIR/evidence/retained-resources.json" '{
        resourceGroup:$group,retainedTarget:$target,targetPowerState:"deallocated",retainedImage:$image,
        helperDeleted:true,sourceDeleted:true,uploadStorageDeleted:true,temporarySshRulesDeleted:true,
        verifiedUtc:(now|todate),resources:$resources[0]}' > "$RUN_DIR/evidence/cleanup-summary.json"
    echo SUCCESSFUL_CUSTOM_RUN_TEMPORARY_RESOURCES_REMOVED_TARGET_DEALLOCATED
}
