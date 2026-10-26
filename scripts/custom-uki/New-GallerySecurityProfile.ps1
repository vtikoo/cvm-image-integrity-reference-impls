param(
    [Parameter(Mandatory)]
    [string] $CertificatePath,
    [Parameter(Mandatory)]
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputPath) {
    throw 'The security profile output already exists; inspect it rather than overwrite it.'
}
$bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $CertificatePath).Path)
$text = [Text.Encoding]::UTF8.GetString($bytes)
if ($text.Contains('PRIVATE KEY')) {
    throw 'Supply only the public certificate, never a private key or combined key/certificate PEM.'
}
$certificate = if ($text.Contains('-----BEGIN CERTIFICATE-----')) {
    [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($text)
} else {
    [Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
}
try {
    if ($certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
        $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
        throw 'The signing certificate is not currently valid.'
    }
    $profile = @{
        uefiSettings = @{
            signatureTemplateNames = @('MicrosoftUefiCertificateAuthorityTemplate')
            additionalSignatures = @{
                db = @(@{type='x509';value=@([Convert]::ToBase64String($certificate.RawData))})
            }
        }
    }
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),
        ($profile | ConvertTo-Json -Depth 8) + "`n", [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{
        securityProfilePath = [IO.Path]::GetFullPath($OutputPath)
        certificateSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certificate.RawData)).ToLowerInvariant()
    }
}
finally {
    $certificate.Dispose()
}
