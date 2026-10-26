#!/usr/bin/env bash
set -euo pipefail
umask 077
if (( $# != 3 )); then
    echo 'Usage: bash build-image.sh BASE_QCOW2 SSH_PUBLIC_KEY NEW_RUN_DIRECTORY' >&2
    exit 2
fi
recipe=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
checkout=$(cd -- "$recipe/../.." && pwd -P)
for tool in realpath python3 git go docker sha256sum; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done
base=$(realpath -e -- "$1")
public_key=$(realpath -e -- "$2")
run=$(realpath -m -- "$3")
[[ -f "$base" && "$base" == *.qcow2 ]] || { echo 'Supply the unbooted pinned base as a qcow2 file.' >&2; exit 1; }
[[ -f "$public_key" ]] || { echo 'Supply an OpenSSH public key file.' >&2; exit 1; }
key=$(< "$public_key")
[[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[^[:space:]]+)[[:space:]][A-Za-z0-9+/]+=*([[:space:]].*)?$ ]] ||
    { echo 'Supply an OpenSSH public key, never private SSH/signing material.' >&2; exit 1; }
[[ "$run" != "$checkout" && "$run" != "$checkout/"* ]] ||
    { echo 'Run directory must be outside this repository.' >&2; exit 1; }
[[ ! -e "$run" && ! -L "$run" ]] || { echo 'Use a new run directory; do not overwrite an earlier build.' >&2; exit 1; }
pin() {
    python3 - "$recipe/inputs.json" "$1" <<'PY'
import json
import sys
with open(sys.argv[1]) as stream:
    value = json.load(stream)[sys.argv[2]]
assert isinstance(value, str) and value
print(value)
PY
}
revision=$(pin imageCustomizerCommit)
repository=$(pin imageCustomizerRepository)
container=$(pin dependencyContainer)
snapshot=$(pin packageSnapshotTime)
expected_go=$(pin goVersion)
[[ "$(go version)" == "go version $expected_go linux/amd64" ]] ||
    { echo "Requires $expected_go linux/amd64; see inputs.json." >&2; exit 1; }
mkdir -p -- "$run/evidence"
exec > >(tee "$run/evidence/build.log") 2>&1
trap 'echo "IMAGE_BUILD_FAILED line=$LINENO status=$?" >&2' ERR
cp -- "$recipe/root-volatile.yaml" "$run/root-volatile.yaml"
cp -- "$recipe/inspect-image.sh" "$run/inspect-image.sh"
printf '%s\n' "$key" > "$run/operator.pub"
git clone --quiet --filter=blob:none --no-checkout "$repository" "$run/source"
git -C "$run/source" checkout --quiet --detach "$revision"
[[ "$(git -C "$run/source" rev-parse HEAD)" == "$revision" ]]
export GOPATH="$run/go-cache" GOCACHE="$run/go-build-cache" GOTOOLCHAIN=local
(
    cd -- "$run/source"
    go build -trimpath \
        -ldflags '-X github.com/microsoft/azure-linux-image-tools/toolkit/tools/pkg/imagecustomizerlib.ToolVersion=reference-ab965100' \
        -o "$run/imagecustomizer" ./toolkit/tools/imagecustomizer
)
go version > "$run/evidence/go-version.txt"
sha256sum "$base" > "$run/evidence/base.sha256"
sha256sum "$run/imagecustomizer" > "$run/evidence/binary.sha256"
docker pull "$container"
docker image inspect "$container" > "$run/evidence/container.json"
docker run --rm --privileged -v /dev:/dev -v "$run:/repro" \
    -v "$base:/input/base.qcow2:ro" --entrypoint /repro/imagecustomizer "$container" \
    --disable-telemetry --image-file /input/base.qcow2 \
    --config-file /repro/root-volatile.yaml --build-dir /repro/build \
    --output-image-format raw --output-image-file /repro/root-volatile.raw \
    --package-snapshot-time "$snapshot" --log-level debug
docker run --rm --privileged -v /dev:/dev -v "$run:/repro" \
    --entrypoint /bin/bash "$container" /repro/inspect-image.sh |
    tee "$run/evidence/inspect.log"
grep -qx ARTIFACT_INSPECTION_OK "$run/evidence/inspect.log"
sha256sum "$run/root-volatile.yaml" "$run/root-volatile.raw" > "$run/evidence/image.sha256"
echo "BUILD_REFERENCE_IMAGE_OK image=$run/root-volatile.raw"
