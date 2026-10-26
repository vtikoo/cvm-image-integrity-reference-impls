param(
    [Parameter(Mandatory)][guid] $SubscriptionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z][a-zA-Z0-9_-]{2,62}$')][string] $ResourceGroup,
    [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9-]{2,11}$')][string] $Prefix,
    [ValidatePattern('^[a-z][a-z0-9]+$')][string] $Location = 'westus3',
    [ValidatePattern('^Standard_DC[0-9]+as_v6$')][string] $VmSize = 'Standard_DC4as_v6',
    [guid] $RunId = [guid]::NewGuid()
)
$ErrorActionPreference = 'Stop'
$suffix = $RunId.ToString('N').Substring(0, 8)
[pscustomobject][ordered]@{
    subscriptionId = $SubscriptionId.ToString()
    resourceGroup = $ResourceGroup
    runId = $RunId.ToString()
    location = $Location
    vmSize = $VmSize
    maximumVms = 2
    imageUrn = 'Canonical:ubuntu-22_04-lts:cvm:22.04.202610220'
    helperVm = "$Prefix-helper"
    targetVm = "$Prefix-reference"
    sourceDisk = "$Prefix-source"
    adminUsername = 'pocadmin'
    network = "$Prefix-vnet"
    subnet = 'poc'
    networkSecurityGroup = "$Prefix-nsg"
    storageAccount = "ctmp$($Prefix.Replace('-',''))$suffix"
    imageContainer = 'images'
    gallery = "$($Prefix.Replace('-','_'))_gallery"
    imageDefinition = 'ubuntu2204-custom-uki-tmpfs'
    imageDefinitionSecurityType = 'TrustedLaunchAndConfidentialVmSupported'
    imageVersion = '1.0.0'
    producerRepository = 'https://github.com/vtikoo/encrypt-cloud-image.git'
    producerRevision = '5dc3d3f85fdfa6f5bae8bc01edcbf55b2adcfabe'
}
