$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
function Assert-Throws {
    param([scriptblock] $Action, [string] $Message)
    $failed = $false
    try { & $Action | Out-Null }
    catch { $failed = $true }
    if (-not $failed) { throw "Expected rejection: $Message" }
}
foreach ($file in Get-ChildItem -LiteralPath $root -Filter *.ps1 -Recurse) {
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "$($file.Name): $($errors | Out-String)" }
}
$bash = if ($IsWindows) { Join-Path $env:ProgramFiles 'Git\bin\bash.exe' } else { 'bash' }
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root 'scripts') -Filter *.sh -Recurse) {
    [IO.File]::ReadAllText($file.FullName).Replace("`r`n","`n") | & $bash -n
    if ($LASTEXITCODE -ne 0) { throw "Shell syntax failure: $($file.Name)" }
}
$arguments = @{SubscriptionId=[guid]::Empty;ResourceGroup='test-cvm-rg';Prefix='test-cvm';Location='westus3'}
$a = & (Join-Path $root 'New-DeploymentConfig.ps1') @arguments
$b = & (Join-Path $root 'New-DeploymentConfig.ps1') @arguments
if ($a.storageAccount -eq $b.storageAccount -or $a.storageAccount.Length -gt 24 -or
    $a.storageAccount -notmatch '^[a-z0-9]{3,24}$' -or
    $a.helperVm -eq $a.targetVm -or $a.maximumVms -ne 2) { throw 'Unsafe or conflicting deployment resource names.' }
Assert-Throws -Message 'path injection prefix' -Action {
    & (Join-Path $root 'New-DeploymentConfig.ps1') -SubscriptionId ([guid]::Empty) -ResourceGroup test-cvm-rg -Prefix '../bad'
}
Assert-Throws -Message 'invalid resource group' -Action {
    & (Join-Path $root 'New-DeploymentConfig.ps1') -SubscriptionId ([guid]::Empty) -ResourceGroup '../../bad' -Prefix good
}
$plan = & (Join-Path $root 'Deploy.ps1') @arguments -SshPublicKey unused-public-key.pub -Plan | ConvertFrom-Json
if ($plan.imageUrn -ne $a.imageUrn -or $plan.producerRevision -ne $a.producerRevision) {
    throw 'Plan did not preserve the tested source pins.'
}
$temporary = Join-Path ([IO.Path]::GetTempPath()) "canonical-profile-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temporary | Out-Null
$rsa = [Security.Cryptography.RSA]::Create(2048)
$request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Local public profile test', $rsa,
    [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
$certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(1))
try {
    $der = $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certPath = Join-Path $temporary 'public.der'
    $profilePath = Join-Path $temporary 'profile.json'
    [IO.File]::WriteAllBytes($certPath, $der)
    $generator = Join-Path $root 'scripts\custom-uki\New-GallerySecurityProfile.ps1'
    & $generator -CertificatePath $certPath -OutputPath $profilePath | Out-Null
    $profile = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
    if ($profile.uefiSettings.additionalSignatures.db[0].value[0] -ne [Convert]::ToBase64String($der) -or
        $profile.uefiSettings.signatureTemplateNames[0] -ne 'MicrosoftUefiCertificateAuthorityTemplate') {
        throw 'The public enrollment profile did not match its actual certificate.'
    }
    Assert-Throws -Message 'profile overwrite' -Action { & $generator -CertificatePath $certPath -OutputPath $profilePath }
    $invalid = Join-Path $temporary 'not-a-certificate.pem'
    [IO.File]::WriteAllText($invalid, ('-----BEGIN ' + 'PRIVATE KEY-----'))
    Assert-Throws -Message 'private PEM input' -Action {
        & $generator -CertificatePath $invalid -OutputPath (Join-Path $temporary 'rejected.json')
    }
}
finally {
    $certificate.Dispose(); $rsa.Dispose()
    foreach ($file in Get-ChildItem -LiteralPath $temporary -File) { Remove-Item -LiteralPath $file.FullName }
    Remove-Item -LiteralPath $temporary
}
'LOCAL_VALIDATION_PASSED: script syntax, safe configuration/plan, and public certificate enrollment guards.'
