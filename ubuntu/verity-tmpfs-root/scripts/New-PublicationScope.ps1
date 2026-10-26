param([string] $RunDirectory = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $RunDirectory 'config.json') -Raw | ConvertFrom-Json
function Invoke-Azure {
    param([string[]] $Arguments)
    $result = & az @Arguments --subscription $config.subscriptionId --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "Azure publication-scope operation failed: $($Arguments[0..1] -join ' ')" }
    return $result
}
$helper = (Invoke-Azure -Arguments @('vm', 'show', '-g', $config.resourceGroup,
    '-n', $config.helperVm, '-o', 'json')) | ConvertFrom-Json
if (-not $helper.identity.principalId) {
    throw 'The helper needs a system-assigned identity for secret-free image upload.'
}
$storage = (Invoke-Azure -Arguments @('storage', 'account', 'create', '-g', $config.resourceGroup,
    '-n', $config.storageAccount, '-l', $config.location, '--sku', 'Standard_LRS',
    '--kind', 'StorageV2', '--https-only', 'true', '--allow-blob-public-access', 'false',
    '--min-tls-version', 'TLS1_2', '--allow-shared-key-access', 'false',
    '--public-network-access', 'Enabled', '--default-action', 'Deny', '--bypass', 'AzureServices',
    '--tags', 'purpose=canonical-manifest-tmpfs', 'role=temporary-image-import',
    '-o', 'json')) | ConvertFrom-Json
$subnet = (Invoke-Azure -Arguments @('network', 'vnet', 'subnet', 'update',
    '-g', $config.resourceGroup, '--vnet-name', $config.network, '-n', $config.subnet,
    '--service-endpoints', 'Microsoft.Storage', '-o', 'json')) | ConvertFrom-Json
Invoke-Azure -Arguments @('storage', 'account', 'network-rule', 'add',
    '-g', $config.resourceGroup, '--account-name', $config.storageAccount,
    '--subnet', $subnet.id, '-o', 'none')
Invoke-Azure -Arguments @('storage', 'container-rm', 'create', '-g', $config.resourceGroup,
    '--storage-account', $config.storageAccount, '-n', $config.imageContainer, '-o', 'none')
$scope = "$($storage.id)/blobServices/default/containers/$($config.imageContainer)"
$assignment = Invoke-Azure -Arguments @('role', 'assignment', 'create',
    '--assignee-object-id', $helper.identity.principalId, '--assignee-principal-type', 'ServicePrincipal',
    '--role', 'Storage Blob Data Contributor', '--scope', $scope, '-o', 'json')
$assignment | Set-Content -LiteralPath (Join-Path $RunDirectory 'evidence\helper-upload-role.json') -Encoding utf8
Invoke-Azure -Arguments @('sig', 'create', '-g', $config.resourceGroup,
    '--gallery-name', $config.gallery, '-l', $config.location, '-o', 'none')
$securityType = if ($config.imageDefinitionSecurityType) { $config.imageDefinitionSecurityType } else { 'ConfidentialVmSupported' }
$definition = Invoke-Azure -Arguments @('sig', 'image-definition', 'create', '-g', $config.resourceGroup,
    '--gallery-name', $config.gallery, '--gallery-image-definition', $config.imageDefinition,
    '-l', $config.location, '--publisher', 'CanonicalReference', '--offer', 'ubuntu2204-cvm',
    '--sku', 'manifest-tmpfs', '--os-type', 'Linux', '--os-state', 'Generalized',
    '--hyper-v-generation', 'V2', '--architecture', 'x64',
    '--features', "SecurityType=$securityType", '-o', 'json')
$definition | Set-Content -LiteralPath (Join-Path $RunDirectory 'evidence\gallery-definition.json') -Encoding utf8
Write-Output 'PUBLICATION_SCOPE_READY: private blob container; helper identity scoped only to that container; Gen2 ConfidentialVmSupported image definition.'
