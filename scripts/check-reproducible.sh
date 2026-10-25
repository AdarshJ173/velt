#!/usr/bin/env bash
# Build the CLI twice from the same tree and compare the release binaries.
# Linux-only: it relies on SOURCE_DATE_EPOCH, --remap-path-prefix and cmp.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
cargo_bin="${CARGO:-$HOME/.cargo/bin/cargo}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$root=/build"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

"$cargo_bin" build --release --locked -p velt --target-dir "$tmp/a" >/dev/null
"$cargo_bin" build --release --locked -p velt --target-dir "$tmp/b" >/dev/null

sha256sum "$tmp/a/release/velt" "$tmp/b/release/velt"
cmp "$tmp/a/release/velt" "$tmp/b/release/velt"
printf '%s\n' 'reproducible: CLI release binaries match'
