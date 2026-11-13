#!/usr/bin/env bash
set -euo pipefail
recipe=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
command -v python3 >/dev/null || { echo 'Python 3 is required for cleanup.' >&2; exit 1; }
exec python3 "$recipe/scripts/deploy.py" cleanup "$@"
