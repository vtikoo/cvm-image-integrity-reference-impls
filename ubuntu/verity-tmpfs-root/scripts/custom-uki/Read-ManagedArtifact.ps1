param(
    [Parameter(Mandatory)][string] $RemotePath,
    [Parameter(Mandatory)][string] $OutputPath,
    [string] $VmName,
    [string] $RunDirectory = $PSScriptRoot
)
$ErrorActionPreference = 'Stop'
if (-not $VmName) {
    $config = Get-Content -LiteralPath (Join-Path $RunDirectory 'config.json') -Raw | ConvertFrom-Json
    $VmName = $config.helperVm
}
if ($RemotePath -match '(?i)(private|signer/.*key|\.key(?:\.|$))') {
    throw 'Private signing artifacts must stay on the helper.'
}
if (Test-Path -LiteralPath $OutputPath) { throw "Artifact already exists: $OutputPath" }
$remote = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($RemotePath))
$stem = ([IO.Path]::GetFileNameWithoutExtension($OutputPath) -replace '[^a-zA-Z0-9_-]', '-')
if ($stem.Length -gt 32) { $stem = $stem.Substring(0, 32) }
$encoded = [Text.StringBuilder]::new()
$scriptPath = Join-Path $env:TEMP "canonical-artifact-$([Guid]::NewGuid().ToString('N')).sh"
$reader = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\Read-ArtifactChunk.py')).Replace("`r`n", "`n")
try {
    $index = 0
    do {
        $script = "#!/bin/bash`nset -euo pipefail`npython3 - '$remote' '$index' <<'PY'`n$reader`nPY"
        [IO.File]::WriteAllText($scriptPath, $script + "`n", [Text.UTF8Encoding]::new($false))
        $name = "read-$stem-$index"
        & (Join-Path $PSScriptRoot 'Invoke-ManagedGuest.ps1') -Script $scriptPath -VmName $VmName `
            -RunDirectory $RunDirectory -EvidenceName $name -SuccessMarker MANAGED_ARTIFACT_CHUNK_READY `
            -TimeoutSeconds 300 | Out-Null
        $response = Get-Content -LiteralPath (Join-Path $RunDirectory "evidence\$name.json") -Raw | ConvertFrom-Json
        $line = @($response.properties.instanceView.output -split "`n" | Where-Object { $_.StartsWith('{') })
        if ($line.Count -ne 1) { throw 'The artifact response was truncated or malformed.' }
        $chunk = $line[0] | ConvertFrom-Json
        if ($index -eq 0) { $hash = $chunk.sha256; $count = $chunk.chunks }
        if ($chunk.index -ne $index -or $chunk.sha256 -ne $hash -or $chunk.chunks -ne $count) {
            throw 'The artifact changed during retrieval.'
        }
        [void]$encoded.Append($chunk.payload)
        $index++
    } while ($index -lt $count)
    $inputStream = [IO.MemoryStream]::new([Convert]::FromBase64String($encoded.ToString()))
    $gzip = [IO.Compression.GZipStream]::new($inputStream, [IO.Compression.CompressionMode]::Decompress)
    $outputStream = [IO.MemoryStream]::new()
    try {
        $gzip.CopyTo($outputStream)
        $bytes = $outputStream.ToArray()
    }
    finally {
        $gzip.Dispose(); $inputStream.Dispose(); $outputStream.Dispose()
    }
    $actual = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    if ($actual -ne $hash) { throw 'Retrieved artifact failed SHA256 verification.' }
    [IO.File]::WriteAllBytes([IO.Path]::GetFullPath($OutputPath), $bytes)
    "ARTIFACT_RETRIEVED_SHA256=$actual"
}
finally {
    if (Test-Path -LiteralPath $scriptPath) { Remove-Item -LiteralPath $scriptPath -Force }
}
