#!/bin/bash
set -euo pipefail
umask 077
work=/var/tmp/canonical-build
private=/root/canonical-poc-signer
attempt=${POC_UKI_ATTEMPT:-1}
[[ "$attempt" =~ ^([1-9]|10)$ ]] || { echo 'Invalid UKI build attempt.' >&2; exit 2; }
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
bash "$work/Rebuild-SignedUki.sh" \
    /usr/lib/linux/efi/kernel.efi-6.8.0-1068-azure-fde \
    "$private/poc-uki.key.pem" "$private/poc-uki.cert.pem" \
    "$work/custom-uki-$attempt" 6.8.0-1068-azure-fde
