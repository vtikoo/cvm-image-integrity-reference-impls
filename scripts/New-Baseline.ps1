param(
    [Parameter(Mandatory)]
    [string] $SshPublicKey,
    [ValidateSet('helper', 'reference')]
    [string] $Role = 'helper',
    [string] $ImageId,
    [string] $RunDirectory = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $RunDirectory 'config.json') -Raw | ConvertFrom-Json
$evidence = Join-Path $RunDirectory 'evidence'
$vmName = if ($Role -eq 'reference') { $config.targetVm } else { $config."${Role}Vm" }
$diskSize = switch ($Role) { 'helper' { '64' } 'reference' { '31' } default { '30' } }
$image = $config.imageUrn
if ($Role -eq 'reference') {
    if (-not $ImageId -or -not $ImageId.StartsWith("/subscriptions/$($config.subscriptionId)/resourceGroups/$($config.resourceGroup)/providers/Microsoft.Compute/galleries/", [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The reference VM requires an explicit image version in this POC gallery.'
    }
    $image = $ImageId
}
elseif ($ImageId) {
    throw 'Baseline and helper VMs must use the pinned Marketplace image.'
}
if (-not (Test-Path -LiteralPath $SshPublicKey -PathType Leaf)) {
    throw 'An existing SSH public key file is required. Do not put the private key in the reference directory.'
}

function Invoke-Azure {
    param([string[]] $Arguments)
    $result = & az @Arguments --subscription $config.subscriptionId --only-show-errors
    if ($LASTEXITCODE -ne 0) {
        throw "Azure command failed: az $($Arguments[0..([Math]::Min(2, $Arguments.Length - 1))] -join ' ')"
    }
    return $result
}

$existing = Invoke-Azure -Arguments @('group', 'exists', '--name', $config.resourceGroup, '-o', 'tsv')
if ($existing -eq 'true') {
    $group = (Invoke-Azure -Arguments @('group', 'show', '--name', $config.resourceGroup, '-o', 'json')) | ConvertFrom-Json
    if ($group.tags.session -ne $config.runId) {
        throw 'Refusing to use a resource group not owned by this POC session.'
    }
}
else {
    Invoke-Azure -Arguments @('group', 'create', '--name', $config.resourceGroup, '--location', $config.location,
        '--tags', 'purpose=canonical-manifest-tmpfs', "session=$($config.runId)",
        'cleanup=temporary-build-resources', '-o', 'none')
}

$vms = @((Invoke-Azure -Arguments @('vm', 'list', '-g', $config.resourceGroup, '-o', 'json')) | ConvertFrom-Json)
if ($vms.name -contains $vmName) {
    throw 'The requested VM already exists; inspect it rather than silently overwriting an earlier run.'
}
if ($vms.Count -ge $config.maximumVms) {
    throw 'The POC VM limit has been reached.'
}

$networkResources = @((Invoke-Azure -Arguments @('resource', 'list', '-g', $config.resourceGroup,
    '-o', 'json')) | ConvertFrom-Json)
if (-not ($networkResources | Where-Object { $_.type -eq 'Microsoft.Network/networkSecurityGroups' -and $_.name -eq $config.networkSecurityGroup })) {
    Invoke-Azure -Arguments @('network', 'nsg', 'create', '-g', $config.resourceGroup,
        '-n', $config.networkSecurityGroup, '-l', $config.location, '-o', 'none')
}
if (-not ($networkResources | Where-Object { $_.type -eq 'Microsoft.Network/virtualNetworks' -and $_.name -eq $config.network })) {
    Invoke-Azure -Arguments @('network', 'vnet', 'create', '-g', $config.resourceGroup,
        '-n', $config.network, '-l', $config.location, '--address-prefixes', '10.73.0.0/24',
        '--subnet-name', $config.subnet, '--subnet-prefixes', '10.73.0.0/26', '-o', 'none')
}

$vmArguments = @('vm', 'create', '-g', $config.resourceGroup, '-n', $vmName,
    '-l', $config.location, '--size', $config.vmSize, '--image', $image,
    '--security-type', 'ConfidentialVM', '--enable-secure-boot', 'true', '--enable-vtpm', 'true',
    '--os-disk-security-encryption-type', 'VMGuestStateOnly', '--storage-sku', 'StandardSSD_LRS',
    '--os-disk-size-gb', $diskSize,
    '--admin-username', $config.adminUsername, '--authentication-type', 'ssh',
    '--ssh-key-values', $SshPublicKey, '--vnet-name', $config.network, '--subnet', $config.subnet,
    '--nsg', $config.networkSecurityGroup, '--nsg-rule', 'NONE', '--public-ip-sku', 'Standard',
    '--tags', 'purpose=canonical-manifest-tmpfs', "role=$Role", "session=$($config.runId)", '-o', 'json')
if ($Role -eq 'helper') { $vmArguments += '--assign-identity' }
$result = Invoke-Azure -Arguments $vmArguments
$result | Set-Content -LiteralPath (Join-Path $evidence "$Role-create.json") -Encoding utf8
$diagnosticsRequest = Join-Path $evidence "$Role-diagnostics-request.json"
@{properties=@{diagnosticsProfile=@{bootDiagnostics=@{enabled=$true}}}} |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $diagnosticsRequest -Encoding utf8
$vmId = "/subscriptions/$($config.subscriptionId)/resourceGroups/$($config.resourceGroup)/providers/Microsoft.Compute/virtualMachines/$vmName"
Invoke-Azure -Arguments @('rest', '--method', 'patch', '--url',
    "https://management.azure.com${vmId}?api-version=2024-07-01", '--body', "@$diagnosticsRequest",
    '--headers', 'Content-Type=application/json', '-o', 'none')
$vm = Invoke-Azure -Arguments @('vm', 'show', '-d', '-g', $config.resourceGroup, '-n', $vmName, '-o', 'json')
$vm | Set-Content -LiteralPath (Join-Path $evidence "$Role-control-plane.json") -Encoding utf8
$parsed = $vm | ConvertFrom-Json
if ($parsed.securityProfile.securityType -ne 'ConfidentialVM' -or
    -not $parsed.securityProfile.uefiSettings.secureBootEnabled -or
    -not $parsed.securityProfile.uefiSettings.vTpmEnabled -or
    $parsed.storageProfile.osDisk.managedDisk.securityProfile.securityEncryptionType -ne 'VMGuestStateOnly') {
    throw 'The deployed baseline does not have the required security configuration.'
}
Write-Output "POC_VM_CREATED: $vmName; ConfidentialVM, Secure Boot, vTPM and VMGuestStateOnly confirmed."
