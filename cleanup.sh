#!/usr/bin/env bash
set -euo pipefail
umask 077
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/scripts/bash/common.sh"
source "$REPO_ROOT/scripts/bash/azure.sh"
RUN_DIR= MODE=retain
while (( $# )); do
    case "$1" in
        --run-directory) (( $# >= 2 )) || die 'Missing run directory.'; RUN_DIR=$2; shift 2 ;;
        --remove-run) MODE=remove; shift ;;
        --help|-h)
            echo 'Usage: bash cleanup.sh --run-directory DIRECTORY [--remove-run]'
            echo 'Default: retain the verified deallocated target and Gallery; --remove-run deletes the owned group.'
            exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done
require_tools az jq python3 realpath
[[ -n "$RUN_DIR" ]] || die 'Supply a run directory.'
RUN_DIR=$(realpath -e -- "$RUN_DIR")
load_config
cleanup_run "$MODE"
