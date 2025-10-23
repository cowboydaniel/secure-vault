#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! command -v make >/dev/null 2>&1; then
    echo "make is required to run the release pipeline" >&2
    exit 1
fi

echo "Running release artifact generation..."
make release-artifacts

echo "Release artifacts are available under $ROOT_DIR/release_artifacts"
