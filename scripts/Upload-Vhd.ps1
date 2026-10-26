param(
    [string] $RunDirectory = $PSScriptRoot,
    [switch] $ManagedChannel
)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $RunDirectory 'config.json') -Raw | ConvertFrom-Json
$url = "https://$($config.storageAccount).blob.core.windows.net/$($config.imageContainer)/canonical-tmpfs.vhd"
$python = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Upload-Vhd.py'))
$body = "#!/bin/bash`nset -euo pipefail`nexport POC_BLOB_URL='$url'`npython3 - <<'PYTHON'`n$python`nPYTHON`n"
$temporaryScript = Join-Path $env:TEMP 'canonical-reference-upload-vhd.sh'
[IO.File]::WriteAllText($temporaryScript, $body, [Text.UTF8Encoding]::new($false))
try {
    & (Join-Path $PSScriptRoot 'custom-uki\Invoke-ManagedGuest.ps1') `
        -Script $temporaryScript -EvidenceName vhd-upload -SuccessMarker VHD_UPLOAD_PASSED `
        -RunDirectory $RunDirectory
}
finally {
    Remove-Item -LiteralPath $temporaryScript -Force
}
