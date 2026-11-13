#!/bin/bash
set -euo pipefail
umask 077
if (($# != 4)); then
    echo 'Usage: test-corruption.sh DATA_DEVICE HASH_DEVICE ROOT_HASH EVIDENCE_DIRECTORY' >&2
    exit 2
fi
trap 'echo "CORRUPTION_TEST_FAILED line=$LINENO" >&2' ERR
data=$1 hash=$2 root_hash=$3 evidence=$4
clone="$evidence/corrupted-data.raw"
test ! -e "$clone"
mapper="cvm-negative-$$"
opened=false
cleanup() {
    local result=$?
    trap - EXIT
    if "$opened"; then veritysetup close "$mapper" || result=1; fi
    rm -f -- "$clone"
    exit "$result"
}
trap cleanup EXIT
veritysetup verify "$data" "$hash" "$root_hash"
dd if="$data" of="$clone" bs=4M conv=sparse status=none
python3 - "$clone" <<'PY'
import os, sys
with open(sys.argv[1], "r+b", buffering=0) as stream:
    stream.seek(4096 * 8)
    original = stream.read(1)
    if len(original) != 1:
        raise ValueError("Data partition is too small")
    stream.seek(4096 * 8)
    stream.write(bytes([original[0] ^ 0x80]))
    os.fsync(stream.fileno())
PY
if LC_ALL=C veritysetup verify "$clone" "$hash" "$root_hash" > "$evidence/corruption-verify.txt" 2>&1; then
    echo 'CORRUPTION_TEST_FAILED: corrupted data passed verification' >&2
    exit 1
fi
grep -Fq 'Verification failed' "$evidence/corruption-verify.txt"
veritysetup open "$clone" "$mapper" "$hash" "$root_hash"
opened=true
if dd if="/dev/mapper/$mapper" bs=4096 skip=8 count=1 status=none \
    > /dev/null 2> "$evidence/corruption-read.txt"; then
    echo 'CORRUPTION_TEST_FAILED: corrupted data was readable through verity' >&2
    exit 1
fi
dmsetup status "$mapper" > "$evidence/corruption-status.txt"
awk '$3 == "verity" && $4 == "C" { found=1 } END { exit !found }' "$evidence/corruption-status.txt"
echo CORRUPTION_OFFLINE_AND_LIVE_READ_REJECTED
