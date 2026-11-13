param(
    [Parameter(Mandatory)][guid] $SubscriptionId,
    [Parameter(Mandatory)][string] $ResourceGroup,
    [Parameter(Mandatory)][string] $Prefix,
    [Parameter(Mandatory)][string] $SshPublicKey,
    [string] $SshPrivateKey,
    [string] $Location = 'westus3',
    [string] $VmSize = 'Standard_DC4es_v6',
    [string] $RunDirectory,
    [string] $MaaEndpoint,
    [ValidateSet('managed', 'ssh')][string] $ValidationTransport = 'managed',
    [string] $SshSourceCidr,
    [string] $SshJumpHost,
    [string] $SshJumpKnownHosts,
    [string] $NetworkAddressPrefix,
    [string] $SubnetPrefix,
    [string] $BuilderImage,
    [switch] $Plan
)
$ErrorActionPreference = 'Stop'
$primaryPython = if ($IsWindows) { 'python' } else { 'python3' }
$fallbackPython = if ($IsWindows) { 'python3' } else { 'python' }
$python = Get-Command $primaryPython -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $python) {
    $python = Get-Command $fallbackPython -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
}
if (-not $python) { throw 'Python 3 is required for deployment.' }
$arguments = @(
    (Join-Path $PSScriptRoot 'scripts/deploy.py'), 'deploy',
    '--subscription-id', $SubscriptionId.ToString(),
    '--resource-group', $ResourceGroup, '--prefix', $Prefix,
    '--ssh-public-key', $SshPublicKey, '--location', $Location, '--vm-size', $VmSize
)
$arguments += @('--validation-transport', $ValidationTransport)
if ($SshPrivateKey) { $arguments += @('--ssh-private-key', $SshPrivateKey) }
if ($RunDirectory) { $arguments += @('--run-directory', $RunDirectory) }
if ($MaaEndpoint) { $arguments += @('--maa-endpoint', $MaaEndpoint) }
if ($SshSourceCidr) { $arguments += @('--ssh-source-cidr', $SshSourceCidr) }
if ($SshJumpHost) { $arguments += @('--ssh-jump-host', $SshJumpHost) }
if ($SshJumpKnownHosts) { $arguments += @('--ssh-jump-known-hosts', $SshJumpKnownHosts) }
if ($NetworkAddressPrefix) { $arguments += @('--network-address-prefix', $NetworkAddressPrefix) }
if ($SubnetPrefix) { $arguments += @('--subnet-prefix', $SubnetPrefix) }
if ($BuilderImage) { $arguments += @('--builder-image', $BuilderImage) }
if ($Plan) { $arguments += '--plan' }
& $python.Source @arguments
if ($LASTEXITCODE -ne 0) { throw "Dracut deployment failed (exit $LASTEXITCODE)." }
