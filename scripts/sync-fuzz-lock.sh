#!/usr/bin/env bash
set -euo pipefail
if [ "${DRY_RUN:-false}" = true ]; then
    echo "dry run: fuzz/Cargo.lock left as it is"
    exit 0
fi
cd "$(dirname "$0")/.."
cargo update --workspace --offline --manifest-path fuzz/Cargo.toml
