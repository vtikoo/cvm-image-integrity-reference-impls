param([string] $RunDirectory = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$build = Get-Content -LiteralPath (Join-Path $RunDirectory 'evidence\verified-custom-uki-build.json') -Raw | ConvertFrom-Json
if (-not $build.signature_verified_with_poc_certificate -or
    $build.signed_uki_sha256 -notmatch '^[0-9a-f]{64}$' -or
    $build.build_directory -notmatch '^/var/tmp/canonical-build/custom-uki-[0-9]+$') {
    throw 'An actual verified custom UKI build is required.'
}
$image = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\Build-Image.sh')).Replace("`r`n", "`n")
$prepare = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Prepare-OfflineSource.sh')).Replace("`r`n", "`n")
$script = @'
#!/bin/bash
set -euo pipefail
umask 077
work=/var/tmp/canonical-build
printf '%s' '__PREPARE__' | base64 -d > "$work/Prepare-OfflineSource.sh"
printf '%s' '__IMAGE__' | base64 -d > "$work/Build-Image.sh"
export POC_OFFLINE_PREPARE_SCRIPT="$work/Prepare-OfflineSource.sh"
export POC_SIGNED_UKI='__DIRECTORY__/poc-signed.efi'
export POC_EXPECTED_UKI_HASH='__HASH__'
bash "$work/Build-Image.sh"
'@
$script = $script.Replace('__PREPARE__', [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($prepare))).
    Replace('__IMAGE__', [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($image))).
    Replace('__DIRECTORY__', $build.build_directory).Replace('__HASH__', $build.signed_uki_sha256)
$path = Join-Path $RunDirectory 'evidence\build-protected-image.sh'
[IO.File]::WriteAllText($path, $script + "`n", [Text.UTF8Encoding]::new($false))
& (Join-Path $PSScriptRoot 'Invoke-ManagedGuest.ps1') -Script $path -RunDirectory $RunDirectory `
    -EvidenceName image-build -SuccessMarker IMAGE_BUILD_AND_NEGATIVE_TESTS_PASSED -TimeoutSeconds 3600
