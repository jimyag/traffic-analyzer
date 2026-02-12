#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

./hack/build-ebpf.sh --release

export TRAFFIC_ANALYZER_EMBED_BPF=1
cargo build -p traffic-analyzer --release

echo "single binary ready: ${ROOT_DIR}/target/release/traffic-analyzer"
