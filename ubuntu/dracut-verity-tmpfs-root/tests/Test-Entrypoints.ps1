$ErrorActionPreference = 'Stop'
$recipe = Split-Path -Parent $PSScriptRoot
$run = Join-Path ([IO.Path]::GetTempPath()) ("dracut plan " + [guid]::NewGuid().ToString())
$parameters = @{
    SubscriptionId = '12345678-1234-1234-1234-123456789abc'
    ResourceGroup = 'rg-dracut-plan-test'
    Prefix = 'dracutplan'
    SshPublicKey = (Join-Path $run 'key with spaces.pub')
    SshPrivateKey = (Join-Path $run 'key with spaces')
    RunDirectory = $run
    MaaEndpoint = 'https://example.attest.azure.net'
    ValidationTransport = 'ssh'
    SshSourceCidr = '10.20.30.0/24'
    SshJumpHost = 'relay@jump.example'
    SshJumpKnownHosts = (Join-Path $run 'jump known hosts')
    NetworkAddressPrefix = '10.80.0.0/24'
    SubnetPrefix = '10.80.0.0/26'
    Plan = $true
}
$config = (& (Join-Path $recipe 'Deploy.ps1') @parameters) | ConvertFrom-Json
if ($config.resourceGroup -ne $parameters.ResourceGroup -or $config.prefix -ne $parameters.Prefix) {
    throw 'PowerShell deployment did not forward the requested configuration.'
}
if ($config.sourceImage -ne 'Canonical:ubuntu-24_04-lts:cvm:24.04.202610280') {
    throw 'PowerShell deployment did not select the Dracut image pin.'
}
if ($config.sshSourceCidr -ne $parameters.SshSourceCidr -or
    $config.networkAddressPrefix -ne $parameters.NetworkAddressPrefix -or
    $config.subnetPrefix -ne $parameters.SubnetPrefix) {
    throw 'PowerShell deployment did not forward private-network restrictions.'
}
if ($config.sshJumpHost -ne $parameters.SshJumpHost -or
    $config.sshJumpKnownHosts -ne $parameters.SshJumpKnownHosts) {
    throw 'PowerShell deployment did not forward paired authenticated jump options.'
}
$managed = $parameters.Clone()
foreach ($key in @('SshPrivateKey', 'SshSourceCidr', 'SshJumpHost', 'SshJumpKnownHosts', 'MaaEndpoint')) {
    $managed.Remove($key)
}
$managed.ValidationTransport = 'managed'
$managedConfig = (& (Join-Path $recipe 'Deploy.ps1') @managed) | ConvertFrom-Json
if ($managedConfig.validationTransport -ne 'managed') {
    throw 'PowerShell deployment did not forward managed acceptance.'
}
if (Test-Path -LiteralPath $run) { throw 'Plan wrote a run directory.' }
$parameters.Prefix = 'invalid prefix'
$rejected = $false
try { & (Join-Path $recipe 'Deploy.ps1') @parameters | Out-Null }
catch { $rejected = $true }
if (-not $rejected) { throw 'PowerShell deployment did not propagate configuration rejection.' }
$rejected = $false
try { & (Join-Path $recipe 'Cleanup.ps1') -RunDirectory $run | Out-Null }
catch { $rejected = $true }
if (-not $rejected) { throw 'PowerShell cleanup did not reject missing run evidence.' }
if (Test-Path -LiteralPath $run) { throw 'Rejected operations created a run directory.' }
'DRACUT_POWERSHELL_ENTRYPOINT_TESTS_PASSED'
exit 0
