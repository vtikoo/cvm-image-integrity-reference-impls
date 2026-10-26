param([string] $RunDirectory = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $RunDirectory 'config.json') -Raw | ConvertFrom-Json
$build = Get-Content -LiteralPath (Join-Path $RunDirectory 'evidence\verified-custom-uki-build.json') -Raw | ConvertFrom-Json
$rootHash = (Get-Content -LiteralPath (Join-Path $RunDirectory 'evidence\build\evidence\root-hash.txt') -Raw).Trim()
if ($rootHash -notmatch '^[0-9a-f]{64}$' -or
    $build.signed_uki_sha256 -notmatch '^[0-9a-f]{64}$' -or
    $build.certificate_sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Verified build hashes are required.' }
$prefix = "#!/bin/bash`nexport POC_EXPECTED_ROOT_HASH='$rootHash'`nexport POC_EXPECTED_UKI_HASH='$($build.signed_uki_sha256)'`nexport POC_EXPECTED_CERT_SHA256='$($build.certificate_sha256)'`n"
function Invoke-Check {
    param([string] $FileName, [string] $Name, [string] $Marker)
    $body = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "..\$FileName")).Replace("`r`n", "`n")
    $script = Join-Path $RunDirectory "evidence\$Name.sh"
    [IO.File]::WriteAllText($script, $prefix + $body + "`n", [Text.UTF8Encoding]::new($false))
    & (Join-Path $PSScriptRoot 'Invoke-ManagedGuest.ps1') -Script $script -VmName $config.targetVm `
        -RunDirectory $RunDirectory -EvidenceName $Name -SuccessMarker $Marker -TimeoutSeconds 1800
}
Invoke-Check -FileName Verify-Reference.sh -Name reference-before-reboot -Marker REFERENCE_BOOT_AND_SMOKE_PASSED
$beforePath = Join-Path $RunDirectory 'evidence\reference-before-reboot-verified.json'
& (Join-Path $PSScriptRoot 'Read-ManagedArtifact.ps1') -RemotePath /var/tmp/canonical-reference-evidence.json `
    -OutputPath $beforePath -VmName $config.targetVm -RunDirectory $RunDirectory
$before = Get-Content -LiteralPath $beforePath -Raw | ConvertFrom-Json

# The volatile agent state must not cause first-boot test commands to replay on reboot.
$deadline = [DateTime]::UtcNow.AddMinutes(5)
do {
    $commands = & az vm run-command list --subscription $config.subscriptionId -g $config.resourceGroup `
        --vm-name $config.targetVm -o json --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw 'Could not list target managed commands before reboot.' }
    $commands = @(($commands | ConvertFrom-Json) | Where-Object { $_.name -like 'poc-*' })
    if ($commands.Count -eq 0) { break }
    foreach ($command in $commands) {
        & az rest --method delete --url "https://management.azure.com$($command.id)?api-version=2024-07-01" `
            -o none --only-show-errors
        if ($LASTEXITCODE -ne 0) { throw 'Could not remove a first-boot managed command before reboot.' }
    }
    if ([DateTime]::UtcNow -ge $deadline) { throw 'Target managed-command deletion did not finish.' }
    Start-Sleep -Seconds 10
} while ($true)
& az vm restart --subscription $config.subscriptionId -g $config.resourceGroup -n $config.targetVm --only-show-errors
if ($LASTEXITCODE -ne 0) { throw 'The target restart failed.' }
Invoke-Check -FileName Verify-Reboot.sh -Name reference-after-reboot -Marker VOLATILE_REBOOT_AND_UNCHANGED_LOWER_PASSED
$afterPath = Join-Path $RunDirectory 'evidence\reference-after-reboot-verified.json'
& (Join-Path $PSScriptRoot 'Read-ManagedArtifact.ps1') -RemotePath /var/tmp/canonical-reboot-evidence.json `
    -OutputPath $afterPath -VmName $config.targetVm -RunDirectory $RunDirectory
$after = Get-Content -LiteralPath $afterPath -Raw | ConvertFrom-Json
if (-not $before.boot_id -or -not $after.boot_id -or $before.boot_id -eq $after.boot_id) {
    throw 'A real reboot with distinct guest boot IDs was not verified.'
}
@{before=$before.boot_id;after=$after.boot_id;changed=$true} | ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $RunDirectory 'evidence\reboot-ids.json') -Encoding utf8
'REFERENCE_E2E_ACCEPTANCE_PASSED'
