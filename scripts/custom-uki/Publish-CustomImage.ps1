param(
    [string] $RunDirectory = $PSScriptRoot,
    [Parameter(Mandatory)]
    [string] $BuildEvidencePath,
    [string] $SecurityProfilePath = (Join-Path $PSScriptRoot 'security-profile.json')
)

$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $RunDirectory 'config.json') -Raw | ConvertFrom-Json
$profile = Get-Content -LiteralPath $SecurityProfilePath -Raw | ConvertFrom-Json
$build = Get-Content -LiteralPath $BuildEvidencePath -Raw | ConvertFrom-Json
$certificate = [Convert]::FromBase64String($profile.uefiSettings.additionalSignatures.db[0].value[0])
$fingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certificate)).ToLowerInvariant()
if (-not $build.signature_verified_with_poc_certificate -or $build.certificate_sha256 -ne $fingerprint -or
    $config.imageDefinitionSecurityType -ne 'TrustedLaunchAndConfidentialVmSupported' -or
    $profile.uefiSettings.signatureTemplateNames.Count -ne 1 -or
    $profile.uefiSettings.signatureTemplateNames[0] -ne 'MicrosoftUefiCertificateAuthorityTemplate') {
    throw 'The verified custom UKI signer and combined-security image definition are required.'
}
function Invoke-Azure {
    param([string[]] $Arguments)
    $result = & az @Arguments --subscription $config.subscriptionId --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "Custom publication failed: $($Arguments[0..1] -join ' ')" }
    return $result
}
$definition = (Invoke-Azure -Arguments @('sig', 'image-definition', 'show', '-g', $config.resourceGroup,
    '--gallery-name', $config.gallery, '--gallery-image-definition', $config.imageDefinition, '-o', 'json')) | ConvertFrom-Json
if (@($definition.features | Where-Object {
    $_.name -eq 'SecurityType' -and $_.value -eq 'TrustedLaunchAndConfidentialVmSupported'
}).Count -ne 1) { throw 'The actual Gallery definition does not support the required combined security type.' }
$versionId = "$($definition.id)/versions/$($config.imageVersion)"
$url = "https://management.azure.com${versionId}?api-version=2024-03-03"
$storageId = "/subscriptions/$($config.subscriptionId)/resourceGroups/$($config.resourceGroup)/providers/Microsoft.Storage/storageAccounts/$($config.storageAccount)"
$body = @{
    location = $config.location
    tags = @{purpose='canonical-manifest-tmpfs';variant='custom-signed-uki';session=$config.runId}
    properties = @{
        publishingProfile = @{
            replicaCount = 1
            excludeFromLatest = $true
            storageAccountType = 'Standard_LRS'
            targetRegions = @(@{name=$config.location;regionalReplicaCount=1;storageAccountType='Standard_LRS'})
        }
        storageProfile = @{osDiskImage=@{source=@{
            uri="https://$($config.storageAccount).blob.core.windows.net/$($config.imageContainer)/canonical-tmpfs.vhd"
            storageAccountId=$storageId
        }}}
        securityProfile = $profile
    }
}
$requestPath = Join-Path $RunDirectory 'evidence\gallery-version-request.json'
$body | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $requestPath -Encoding utf8
$existing = @((Invoke-Azure -Arguments @('sig', 'image-version', 'list', '-g', $config.resourceGroup,
    '--gallery-name', $config.gallery, '--gallery-image-definition', $config.imageDefinition, '-o', 'json')) | ConvertFrom-Json)
if ($existing.name -notcontains $config.imageVersion) {
    Invoke-Azure -Arguments @('rest', '--method', 'put', '--url', $url, '--body', "@$requestPath",
        '--headers', 'Content-Type=application/json', '-o', 'json') |
        Set-Content -LiteralPath (Join-Path $RunDirectory 'evidence\gallery-version-put.json') -Encoding utf8
}
$deadline = [DateTime]::UtcNow.AddHours(1)
do {
    $result = Invoke-Azure -Arguments @('rest', '--method', 'get', '--url', $url,
        '--url-parameters', '$expand=ReplicationStatus,UefiSettings', '-o', 'json')
    $version = $result | ConvertFrom-Json
    $result | Set-Content -LiteralPath (Join-Path $RunDirectory 'evidence\gallery-image-version.json') -Encoding utf8
    if ($version.properties.provisioningState -eq 'Failed') { throw 'The custom image version failed provisioning.' }
    if ($version.properties.provisioningState -eq 'Succeeded' -and
        $version.properties.replicationStatus.aggregatedState -eq 'Completed') { break }
    if ([DateTime]::UtcNow -ge $deadline) { throw 'Timed out waiting for custom image replication.' }
    Start-Sleep -Seconds 30
} while ($true)
$actual = $version.properties.securityProfile.uefiSettings
if (-not $actual -or $actual.additionalSignatures.db.Count -ne 1 -or
    $actual.additionalSignatures.db[0].type -ne 'x509' -or
    $actual.additionalSignatures.db[0].value.Count -ne 1 -or
    $actual.additionalSignatures.db[0].value[0] -ne [Convert]::ToBase64String($certificate) -or
    $actual.signatureTemplateNames.Count -ne 1 -or
    $actual.signatureTemplateNames[0] -ne 'MicrosoftUefiCertificateAuthorityTemplate') {
    throw 'The completed Gallery version did not persist the exact requested UEFI signer/template; do not deploy it.'
}
"CUSTOM_IMAGE_PUBLISHED_WITH_VERIFIED_SIGNER=$($version.id)"
