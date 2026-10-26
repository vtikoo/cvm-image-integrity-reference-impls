param(
    [Parameter(Mandatory)]
    [string] $Script,
    [Parameter(Mandatory)]
    [string] $EvidenceName,
    [Parameter(Mandatory)]
    [string] $SuccessMarker,
    [string] $VmName,
    [string] $RunDirectory = $PSScriptRoot,
    [int] $TimeoutSeconds = 5400
)

$ErrorActionPreference = 'Stop'
if ($EvidenceName -notmatch '^[a-zA-Z0-9_-]{1,64}$') { throw 'Invalid managed command evidence name.' }
$config = Get-Content -LiteralPath (Join-Path $RunDirectory 'config.json') -Raw | ConvertFrom-Json
if (-not $VmName) { $VmName = $config.helperVm }
$body = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Script).Path).Replace("`r`n", "`n")
if ($body -match '-----BEGIN [A-Z ]*PRIVATE KEY-----') {
    throw 'Never embed private signing material in a managed command request.'
}
$name = "poc-$EvidenceName"
$id = "/subscriptions/$($config.subscriptionId)/resourceGroups/$($config.resourceGroup)/providers/Microsoft.Compute/virtualMachines/$VmName/runCommands/$name"
$url = "https://management.azure.com${id}?api-version=2024-07-01"
$modifiedBy = & az group show --subscription $config.subscriptionId -n $config.resourceGroup `
    --query tags.ModifiedBy -o tsv --only-show-errors
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect resource-group policy tags.' }
$tags = @{purpose='canonical-manifest-tmpfs';session=$config.runId}
if ($modifiedBy) { $tags.ModifiedBy = $modifiedBy }
$request = @{
    location = $config.location
    properties = @{source=@{script=$body};asyncExecution=$true;timeoutInSeconds=$TimeoutSeconds}
    tags = $tags
}
$path = Join-Path $RunDirectory "evidence\$EvidenceName-request.json"
$request | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding utf8
& az rest --method put --url $url --body "@$path" --headers Content-Type=application/json `
    -o none --only-show-errors
if ($LASTEXITCODE -ne 0) { throw "Could not submit managed command $name." }
$startDeadline = [DateTime]::UtcNow.AddMinutes(10)
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds + 600)
do {
    $result = & az rest --method get --url $url --url-parameters '$expand=instanceView' -o json --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "Could not read managed command $name." }
    $result | Set-Content -LiteralPath (Join-Path $RunDirectory "evidence\$EvidenceName.json") -Encoding utf8
    $command = $result | ConvertFrom-Json
    $view = $command.properties.instanceView
    if ($view.executionState -in @('Succeeded', 'Failed', 'TimedOut', 'Canceled')) { break }
    if ([DateTime]::UtcNow -ge $deadline -or
        ($view.executionState -notin @('Running', 'Succeeded') -and [DateTime]::UtcNow -ge $startDeadline)) {
        throw "Managed command $name did not start or complete within its deadline."
    }
    Start-Sleep -Seconds 20
} while ($true)
$text = "$($view.output)`n$($view.error)"
$text | Set-Content -LiteralPath (Join-Path $RunDirectory "evidence\$EvidenceName.log") -Encoding utf8
Write-Output $text
if ($view.executionState -ne 'Succeeded' -or $view.exitCode -ne 0 -or -not $text.Contains($SuccessMarker)) {
    throw "Managed guest command failed: $name; execution=$($view.executionState); exit=$($view.exitCode)."
}
