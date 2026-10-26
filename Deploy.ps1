param(
    [Parameter(Mandatory)][guid] $SubscriptionId,
    [Parameter(Mandatory)][string] $ResourceGroup,
    [Parameter(Mandatory)][string] $Prefix,
    [Parameter(Mandatory)][string] $SshPublicKey,
    [string] $Location = 'westus3',
    [string] $VmSize = 'Standard_DC4as_v6',
    [string] $RunDirectory,
    [switch] $Plan
)
$ErrorActionPreference = 'Stop'
$config = & (Join-Path $PSScriptRoot 'New-DeploymentConfig.ps1') -SubscriptionId $SubscriptionId `
    -ResourceGroup $ResourceGroup -Prefix $Prefix -Location $Location -VmSize $VmSize
if ($Plan) { $config | ConvertTo-Json -Depth 5; return }
if (-not (Test-Path -LiteralPath $SshPublicKey -PathType Leaf)) { throw 'Supply an existing SSH public key file.' }
$publicKey = (Get-Content -LiteralPath $SshPublicKey -Raw).Trim()
if ($publicKey -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[^ ]+) [A-Za-z0-9+/]+=*( .*)?$') {
    throw 'SshPublicKey must contain an OpenSSH public key, not private signing or SSH material.'
}
if (-not $RunDirectory) {
    $RunDirectory = Join-Path ([Environment]::GetFolderPath('UserProfile')) "canonical-cvm-runs\$Prefix"
}
$RunDirectory = [IO.Path]::GetFullPath($RunDirectory)
$repository = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
if ($RunDirectory.StartsWith($repository, [StringComparison]::OrdinalIgnoreCase) -or
    $RunDirectory -eq $repository.TrimEnd('\','/')) { throw 'RunDirectory must be outside this repository.' }
if (Test-Path -LiteralPath $RunDirectory) { throw 'Use a new run directory; inspect a prior run rather than overwrite it.' }
$scripts = Join-Path $PSScriptRoot 'scripts'
$custom = Join-Path $scripts 'custom-uki'
function Invoke-Azure {
    param([string[]] $Arguments)
    $result = & az @Arguments --subscription $config.subscriptionId --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "Azure operation failed: $($Arguments[0..1] -join ' ')" }
    return $result
}
function Invoke-GuestFile {
    param([string] $Path, [string] $Name, [string] $Marker)
    & (Join-Path $custom 'Invoke-ManagedGuest.ps1') -Script $Path -RunDirectory $RunDirectory `
        -EvidenceName $Name -SuccessMarker $Marker
}
function Invoke-GuestText {
    param([string] $Text, [string] $Name, [string] $Marker)
    $path = Join-Path $RunDirectory "evidence\$Name.sh"
    [IO.File]::WriteAllText($path, $Text.Replace("`r`n","`n") + "`n", [Text.UTF8Encoding]::new($false))
    Invoke-GuestFile -Path $path -Name $Name -Marker $Marker
}
function Read-Artifact {
    param([string] $RemotePath, [string] $Name)
    & (Join-Path $custom 'Read-ManagedArtifact.ps1') -RemotePath $RemotePath -RunDirectory $RunDirectory `
        -OutputPath (Join-Path $RunDirectory $Name)
}
if ((Invoke-Azure @('group','exists','-n',$ResourceGroup,'-o','tsv')) -ne 'false') {
    throw 'ResourceGroup must be new and dedicated to this run.'
}
$skus = @((Invoke-Azure @('vm','list-skus','-l',$Location,'--size',$VmSize,'--all',
    '--resource-type','virtualMachines','-o','json')) | ConvertFrom-Json)
$sku = @($skus | Where-Object { $_.name -eq $VmSize })
if ($sku.Count -ne 1 -or @($sku[0].restrictions).Count -ne 0) { throw 'The selected CVM SKU is not available in this region/subscription.' }
$cpus = [int]($sku[0].capabilities | Where-Object name -eq 'vCPUs').value
if ($cpus -lt 1) { throw 'Could not determine the selected VM CPU requirement.' }
$usage = @((Invoke-Azure @('vm','list-usage','-l',$Location,'-o','json')) | ConvertFrom-Json)
foreach ($family in @($sku[0].family, 'cores')) {
    $quota = @($usage | Where-Object { $_.name.value -eq $family })
    if ($quota.Count -ne 1 -or $quota[0].limit - $quota[0].currentValue -lt 2*$cpus) {
        throw "Insufficient regional/family quota for two VMs: $family"
    }
}
Invoke-Azure @('vm','image','show','--urn',$config.imageUrn,'-l',$Location,'-o','none')
New-Item -ItemType Directory -Path (Join-Path $RunDirectory 'evidence') -Force | Out-Null
$config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $RunDirectory 'config.json') -Encoding utf8
$complete = $false
try {
    & (Join-Path $scripts 'New-Baseline.ps1') -Role helper -SshPublicKey $SshPublicKey -RunDirectory $RunDirectory
    Invoke-GuestFile -Path (Join-Path $scripts 'Install-HelperTools.sh') -Name helper-tools -Marker HELPER_TOOLS_READY
    & (Join-Path $custom 'Build-CustomUki.ps1') -RunDirectory $RunDirectory
    Read-Artifact -RemotePath /var/tmp/canonical-build/custom-uki-1/custom-uki-build.json -Name 'evidence\verified-custom-uki-build.json'
    Read-Artifact -RemotePath /var/tmp/canonical-build/custom-uki-1/signer.der -Name guest-signer.der
    & (Join-Path $custom 'New-GallerySecurityProfile.ps1') -CertificatePath (Join-Path $RunDirectory 'guest-signer.der') `
        -OutputPath (Join-Path $RunDirectory 'guest-security-profile.json')
    Invoke-GuestFile -Path (Join-Path $scripts 'Build-Producer.sh') -Name producer-build -Marker PRODUCER_BUILD_AND_TESTS_PASSED
    $disk = (Invoke-Azure @('disk','create','-g',$ResourceGroup,'-n',$config.sourceDisk,'-l',$Location,
        '--image-reference',$config.imageUrn,'--security-type','ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey',
        '--sku','StandardSSD_LRS','--hyper-v-generation','V2','--os-type','Linux','-o','json')) | ConvertFrom-Json
    $attachPath = Join-Path $RunDirectory 'evidence\source-attach-request.json'
    @{properties=@{storageProfile=@{dataDisks=@(@{lun=0;name=$config.sourceDisk;createOption='Attach';
        managedDisk=@{id=$disk.id};caching='ReadOnly';deleteOption='Detach'})}}} |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $attachPath -Encoding utf8
    $vmId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/$($config.helperVm)"
    Invoke-Azure @('rest','--method','patch','--url',"https://management.azure.com${vmId}?api-version=2024-07-01",
        '--body',"@$attachPath",'--headers','Content-Type=application/json','-o','none')
    Invoke-GuestFile -Path (Join-Path $scripts 'Wait-SourceDisk.sh') -Name source-ready -Marker SOURCE_DISK_READY
    & (Join-Path $custom 'Build-ProtectedImage.ps1') -RunDirectory $RunDirectory
    & (Join-Path $scripts 'New-PublicationScope.ps1') -RunDirectory $RunDirectory
    & (Join-Path $scripts 'Upload-Vhd.ps1') -RunDirectory $RunDirectory -ManagedChannel
    Invoke-GuestFile -Path (Join-Path $scripts 'Collect-BuildEvidence.sh') -Name collect-build-evidence -Marker BUILD_EVIDENCE_ARCHIVED
    Read-Artifact -RemotePath /var/tmp/canonical-build/build-evidence.tar.gz -Name 'evidence\build-evidence.tar.gz'
    $buildPath = Join-Path $RunDirectory 'evidence\build'
    New-Item -ItemType Directory -Path $buildPath | Out-Null
    & tar -xzf (Join-Path $RunDirectory 'evidence\build-evidence.tar.gz') -C $buildPath
    if ($LASTEXITCODE -ne 0) { throw 'Could not extract verified build evidence.' }
    & (Join-Path $custom 'Publish-CustomImage.ps1') -RunDirectory $RunDirectory `
        -BuildEvidencePath (Join-Path $RunDirectory 'evidence\verified-custom-uki-build.json') `
        -SecurityProfilePath (Join-Path $RunDirectory 'guest-security-profile.json')
    $version = Get-Content -LiteralPath (Join-Path $RunDirectory 'evidence\gallery-image-version.json') -Raw | ConvertFrom-Json
    & (Join-Path $scripts 'New-Baseline.ps1') -Role reference -SshPublicKey $SshPublicKey `
        -RunDirectory $RunDirectory -ImageId $version.id
    & (Join-Path $custom 'Test-ManagedReference.ps1') -RunDirectory $RunDirectory
    & (Join-Path $custom 'Cleanup-CustomRun.ps1') -RunDirectory $RunDirectory
    $complete = $true
    "DEPLOYMENT_VERIFIED: image=$($version.id); target=$($config.targetVm); target deallocated; evidence=$RunDirectory"
}
finally {
    if (-not $complete) {
        $group = & az group show --subscription $SubscriptionId -n $ResourceGroup -o json --only-show-errors
        if ($LASTEXITCODE -eq 0 -and ($group | ConvertFrom-Json).tags.session -eq $config.runId) {
            $vms = & az vm list --subscription $SubscriptionId -g $ResourceGroup -o json --only-show-errors
            if ($LASTEXITCODE -eq 0) {
                foreach ($vm in ($vms | ConvertFrom-Json)) {
                    & az vm deallocate --subscription $SubscriptionId -g $ResourceGroup -n $vm.name --no-wait --only-show-errors
                    if ($LASTEXITCODE -ne 0) { Write-Warning "Could not request deallocation of $($vm.name)." }
                }
            }
        }
        Write-Warning "Deployment did not complete. Inspect $RunDirectory. Check deallocation, then use Cleanup-CustomRun.ps1 -RemoveFailedRun to remove the owned group."
    }
}
