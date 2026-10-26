param(
    [string] $RunDirectory = $PSScriptRoot,
    [ValidateRange(1, 10)][int] $Attempt = 1
)
$ErrorActionPreference = 'Stop'
$rebuild = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Rebuild-SignedUki.sh')).Replace("`r`n", "`n")
$payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($rebuild))
$driver = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Build-CustomUki.sh')).Replace("`r`n", "`n")
$script = "#!/bin/bash`nset -euo pipefail`nprintf '%s' '$payload' | base64 -d > /var/tmp/canonical-build/Rebuild-SignedUki.sh`nexport POC_UKI_ATTEMPT='$Attempt'`n$driver"
$path = Join-Path $RunDirectory 'evidence\build-custom-uki.sh'
[IO.File]::WriteAllText($path, $script + "`n", [Text.UTF8Encoding]::new($false))
& (Join-Path $PSScriptRoot 'Invoke-ManagedGuest.ps1') -Script $path -RunDirectory $RunDirectory `
    -EvidenceName "custom-uki-build-$Attempt" -SuccessMarker CUSTOM_UKI_BUILD_AND_LOCAL_SIGNATURE_VERIFICATION_PASSED `
    -TimeoutSeconds 1800
