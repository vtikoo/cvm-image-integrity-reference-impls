#!/bin/bash
set -euo pipefail
work=/var/tmp/canonical-build
export GOPATH="$work/go"
export GOCACHE="$work/go-cache"
exec > >(tee "$work/producer-build.log") 2>&1
revision=5dc3d3f85fdfa6f5bae8bc01edcbf55b2adcfabe
source="$work/producer"
test ! -e "$source"
git clone -q https://github.com/vtikoo/encrypt-cloud-image.git "$source"
cd "$source"
git checkout -q --detach "$revision"
test "$(git rev-parse HEAD)" = "$revision"
go test -v .
go build -trimpath -o "$work/encrypt-cloud-image-tool" .
sha256sum "$work/encrypt-cloud-image-tool" > "$work/producer-checksums.txt"
go version -m "$work/encrypt-cloud-image-tool" > "$work/producer-go-build.txt"
echo PRODUCER_BUILD_AND_TESTS_PASSED
