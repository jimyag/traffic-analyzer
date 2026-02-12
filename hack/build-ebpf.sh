#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

# eBPF target is no_std. Build with nightly + build-std=core.
rustup toolchain install nightly --component rust-src

if ! command -v bpf-linker >/dev/null 2>&1; then
  echo "bpf-linker not found, installing..."
  cargo install bpf-linker
fi

cargo +nightly build \
  -Z build-std=core \
  --target bpfel-unknown-none \
  -p traffic-analyzer-ebpf "$@"
