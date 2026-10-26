#!/bin/bash
set -euo pipefail
work=/var/tmp/canonical-build
tar -czf "$work/build-evidence.tar.gz" -C "$work" evidence image-build.log \
    producer-checksums.txt producer-go-build.txt tool-packages.txt \
    custom-uki-1/custom-uki-build.json custom-uki-1/module-plan.txt \
    custom-uki-1/initrd-module-plan.txt custom-uki-1/modprobe-check.txt \
    custom-uki-1/pe-size-correction.json custom-uki-1/signer.der
echo BUILD_EVIDENCE_ARCHIVED
