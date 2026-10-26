param(
    [string] $RunDirectory = $PSScriptRoot,
    [switch] $RemoveFailedRun
)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $RunDirectory 'config.json') -Raw | ConvertFrom-Json
function Invoke-Azure {
    param([string[]] $Arguments)
    $result = & az @Arguments --subscription $config.subscriptionId --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "Custom-run cleanup failed: $($Arguments[0..1] -join ' ')" }
    return $result
}
$group = (Invoke-Azure @('group','show','-n',$config.resourceGroup,'-o','json')) | ConvertFrom-Json
if (-not $config.runId -or $group.tags.session -ne $config.runId) {
    throw 'Refusing cleanup outside the explicitly owned custom-run group.'
}
if ($RemoveFailedRun) {
    Invoke-Azure @('group','delete','-n',$config.resourceGroup,'--yes','--no-wait')
    $deadline = [DateTime]::UtcNow.AddMinutes(40)
    do {
        $exists = Invoke-Azure @('group','exists','-n',$config.resourceGroup,'-o','tsv')
        if ($exists -eq 'false') { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Failed-run resource deletion did not finish.' }
        Start-Sleep -Seconds 30
    } while ($true)
    @{resourceGroup=$config.resourceGroup;exists=$false;verifiedUtc=[DateTime]::UtcNow} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunDirectory 'evidence\cleanup-summary.json') -Encoding utf8
    'FAILED_CUSTOM_RUN_RESOURCES_REMOVED'
    return
}
$reboot = Get-Content -LiteralPath (Join-Path $RunDirectory 'evidence\reboot-ids.json') -Raw | ConvertFrom-Json
if (-not $reboot.changed -or -not $reboot.before -or $reboot.before -eq $reboot.after) {
    throw 'A successful real reboot is required before retaining the target.'
}
$versionId = "/subscriptions/$($config.subscriptionId)/resourceGroups/$($config.resourceGroup)/providers/Microsoft.Compute/galleries/$($config.gallery)/images/$($config.imageDefinition)/versions/$($config.imageVersion)"
$version = (Invoke-Azure @('rest','--method','get','--url',"https://management.azure.com${versionId}?api-version=2024-03-03",
    '--url-parameters','$expand=ReplicationStatus,UefiSettings','-o','json')) | ConvertFrom-Json
$profile = Get-Content -LiteralPath (Join-Path $RunDirectory 'guest-security-profile.json') -Raw | ConvertFrom-Json
if ($version.properties.provisioningState -ne 'Succeeded' -or
    $version.properties.replicationStatus.aggregatedState -ne 'Completed' -or
    $version.properties.securityProfile.uefiSettings.additionalSignatures.db[0].value[0] -ne
        $profile.uefiSettings.additionalSignatures.db[0].value[0]) {
    throw 'The replicated image and its signer must remain available before deleting upload storage.'
}
$commands = @((Invoke-Azure @('vm','run-command','list','-g',$config.resourceGroup,
    '--vm-name',$config.targetVm,'-o','json')) | ConvertFrom-Json)
foreach ($command in $commands | Where-Object { $_.name -like 'poc-*' }) {
    Invoke-Azure @('rest','--method','delete','--url',
        "https://management.azure.com$($command.id)?api-version=2024-07-01",'-o','none')
}
Invoke-Azure @('vm','deallocate','-g',$config.resourceGroup,'-n',$config.targetVm,'-o','none')
$target = (Invoke-Azure @('vm','get-instance-view','-g',$config.resourceGroup,'-n',$config.targetVm,'-o','json')) | ConvertFrom-Json
if ($target.instanceView.statuses.code -notcontains 'PowerState/deallocated') {
    throw 'The retained target was not confirmed deallocated.'
}
$helper = (Invoke-Azure @('vm','show','-g',$config.resourceGroup,'-n',$config.helperVm,'-o','json')) | ConvertFrom-Json
if ($helper.tags.role -ne 'helper' -or $helper.tags.purpose -ne 'canonical-manifest-tmpfs') {
    throw 'The helper ownership tags did not match.'
}
$nics = @()
$publicIps = @()
foreach ($reference in $helper.networkProfile.networkInterfaces) {
    $nic = (Invoke-Azure @('network','nic','show','--ids',$reference.id,'-o','json')) | ConvertFrom-Json
    $nics += $nic.id
    $publicIps += @($nic.ipConfigurations | Where-Object { $_.publicIPAddress } | ForEach-Object { $_.publicIPAddress.id })
}
$role = Get-Content -LiteralPath (Join-Path $RunDirectory 'evidence\helper-upload-role.json') -Raw | ConvertFrom-Json
if ($role.principalId -ne $helper.identity.principalId -or $role.scope -notlike "*/storageAccounts/$($config.storageAccount)/blobServices/default/containers/$($config.imageContainer)") {
    throw 'Refusing to revoke an unrelated role assignment.'
}
Invoke-Azure @('role','assignment','delete','--ids',$role.id)
Invoke-Azure @('vm','delete','-g',$config.resourceGroup,'-n',$config.helperVm,'--yes','-o','none')
foreach ($id in $nics) { Invoke-Azure @('network','nic','delete','--ids',$id,'-o','none') }
foreach ($id in $publicIps) { Invoke-Azure @('network','public-ip','delete','--ids',$id,'-o','none') }
Invoke-Azure @('disk','delete','--ids',$helper.storageProfile.osDisk.managedDisk.id,'--yes','-o','none')
Invoke-Azure @('disk','delete','-g',$config.resourceGroup,'-n',$config.sourceDisk,'--yes','-o','none')
Invoke-Azure @('storage','account','delete','-g',$config.resourceGroup,'-n',$config.storageAccount,'--yes')
$nsgs = @((Invoke-Azure @('network','nsg','list','-g',$config.resourceGroup,'-o','json')) | ConvertFrom-Json)
foreach ($nsg in $nsgs) {
    if ($nsg.securityRules.name -contains 'temporary-build-ssh') {
        Invoke-Azure @('network','nsg','rule','delete','-g',$config.resourceGroup,'--nsg-name',$nsg.name,
            '-n','temporary-build-ssh','-o','none')
    }
}
$resources = (Invoke-Azure @('resource','list','-g',$config.resourceGroup,'-o','json')) | ConvertFrom-Json
if (@($resources | Where-Object { $_.name -like "$($config.helperVm)*" -or $_.name -eq $config.sourceDisk -or $_.name -eq $config.storageAccount }).Count) {
    throw 'Temporary helper/source/upload resources remain.'
}
$vms = @((Invoke-Azure @('vm','list','-g',$config.resourceGroup,'-o','json')) | ConvertFrom-Json)
if ($vms.Count -ne 1 -or $vms[0].name -ne $config.targetVm) { throw 'The retained VM inventory was unexpected.' }
@{resourceGroup=$config.resourceGroup;retainedTarget=$config.targetVm;targetPowerState='deallocated';
  retainedImage=$versionId;helperDeleted=$true;sourceDeleted=$true;uploadStorageDeleted=$true;
  temporarySshRulesDeleted=$true;verifiedUtc=[DateTime]::UtcNow;resources=$resources} |
    ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $RunDirectory 'evidence\cleanup-summary.json') -Encoding utf8
'SUCCESSFUL_CUSTOM_RUN_TEMPORARY_RESOURCES_REMOVED_TARGET_DEALLOCATED'
