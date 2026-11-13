#!/bin/bash
set -euo pipefail
umask 077
trap 'echo "ATTESTATION_BUILD_FAILED line=$LINENO command=$BASH_COMMAND" >&2' ERR
if (($# != 1)); then
    echo 'Usage: build-attestation.sh NEW_OUTPUT_DIRECTORY' >&2
    exit 2
fi
recipe=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
out=$(realpath -m "$1")
checkout=$(cd "$recipe/../.." && pwd -P)
case "$out/" in "$checkout/"*) echo 'SDK build output must be outside the checkout' >&2; exit 1;; esac
test ! -e "$out"
for tool in git cargo rustc cc; do
    command -v "$tool" >/dev/null || { echo "Missing SDK build tool: $tool" >&2; exit 1; }
done
read -r repository revision package < <(python3 - "$recipe/inputs.json" <<'PY'
import json, sys
sdk = json.load(open(sys.argv[1]))["attestationSdk"]
print(sdk["repository"], sdk["revision"], sdk["package"])
PY
)
read -r patch_file patch_hash < <(python3 - "$recipe/inputs.json" <<'PY'
import json, sys
patch = json.load(open(sys.argv[1]))["attestationSdk"]["patch"]
print(patch["file"], patch["sha256"])
PY
)
patch_path=$(realpath "$recipe/$patch_file")
[[ "$patch_path" == "$recipe/patches/"* ]] || { echo 'SDK patch must be inside recipe patches' >&2; exit 1; }
[[ "$patch_hash" =~ ^[0-9a-f]{64}$ ]] || { echo 'Invalid pinned SDK patch hash' >&2; exit 1; }
test "$(sha256sum "$patch_path" | cut -d ' ' -f1)" = "$patch_hash"
install -d -m 700 "$out"
git init -q "$out/source"
git -C "$out/source" remote add origin "$repository"
git -C "$out/source" fetch --depth=1 origin "$revision"
git -C "$out/source" checkout --detach FETCH_HEAD
test "$(git -C "$out/source" rev-parse HEAD)" = "$revision"
test -f "$out/source/Cargo.lock"
git -C "$out/source" apply --check "$patch_path"
git -C "$out/source" apply "$patch_path"
(
    cd "$out/source"
    cargo test --locked --package azure-tpm --lib event_log::tests
    cargo test --locked --package azure-guest-attestation-sdk --lib guest_attest::
    cargo build --locked --release --package "$package"
)
install -m 755 "$out/source/target/release/$package" "$out/$package"
"$out/$package" --version > "$out/version.txt"
"$out/$package" guest-attest --help > "$out/guest-attest-help.txt"
grep -Fq -- '--pcr-index' "$out/guest-attest-help.txt"
grep -Fq -- '--json' "$out/guest-attest-help.txt"
grep -Fq -- '--show-request' "$out/guest-attest-help.txt"
cp "$out/source/LICENSE" "$out/LICENSE"
python3 - "$recipe/inputs.json" "$out" <<'PY'
import hashlib, json, pathlib, subprocess, sys
sdk = json.load(open(sys.argv[1]))["attestationSdk"]
out = pathlib.Path(sys.argv[2])
sdk["binarySha256"] = hashlib.sha256((out / sdk["package"]).read_bytes()).hexdigest()
sdk["rustc"] = subprocess.check_output(["rustc", "--version"], text=True).strip()
sdk["cargo"] = subprocess.check_output(["cargo", "--version"], text=True).strip()
sdk["eventLogCollection"] = "firmware TCG2 plus genuine selected systemd phase records; quote/replay consistency checked"
(out / "build.json").write_text(json.dumps(sdk, indent=2) + "\n")
PY
echo ATTESTATION_SDK_BUILD_PASSED
