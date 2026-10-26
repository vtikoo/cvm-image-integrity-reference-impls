param(
    [string] $RunDirectory = $PSScriptRoot,
    [ValidateRange(1, 10)][int] $Attempt = 1
)
$ErrorActionPreference = 'Stop'
$rebuild = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Rebuild-SignedUki.sh')).Replace("`r`n", "`n")
$payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($rebuild))
$script = @'
#!/bin/bash
set -euo pipefail
umask 077
work=/var/tmp/canonical-build
private=/root/canonical-poc-signer
if test ! -d "$private"; then
    install -d -m 700 "$private"
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
        -subj '/CN=Canonical tmpfs reference guest signer/' \
        -addext 'keyUsage=critical,digitalSignature' -addext 'extendedKeyUsage=codeSigning' \
        -keyout "$private/poc-uki.key.pem" -out "$private/poc-uki.cert.pem" 2>"$private/generation.log"
fi
test -s "$private/poc-uki.key.pem"
test -s "$private/poc-uki.cert.pem"
chmod 600 "$private/poc-uki.key.pem"
printf '%s' '__REBUILD__' | base64 -d > "$work/Rebuild-SignedUki.sh"
bash "$work/Rebuild-SignedUki.sh" \
    /usr/lib/linux/efi/kernel.efi-6.8.0-1068-azure-fde \
    "$private/poc-uki.key.pem" "$private/poc-uki.cert.pem" \
    "$work/custom-uki-__ATTEMPT__" 6.8.0-1068-azure-fde
'@
$path = Join-Path $RunDirectory 'evidence\build-custom-uki.sh'
[IO.File]::WriteAllText($path, $script.Replace('__REBUILD__', $payload).Replace('__ATTEMPT__', [string]$Attempt) + "`n", [Text.UTF8Encoding]::new($false))
& (Join-Path $PSScriptRoot 'Invoke-ManagedGuest.ps1') -Script $path -RunDirectory $RunDirectory `
    -EvidenceName "custom-uki-build-$Attempt" -SuccessMarker CUSTOM_UKI_BUILD_AND_LOCAL_SIGNATURE_VERIFICATION_PASSED `
    -TimeoutSeconds 1800
