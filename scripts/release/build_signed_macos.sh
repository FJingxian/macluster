#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

cargo build --manifest-path "$root/Cargo.toml" --release --locked --workspace
exec python3 "$root/scripts/release/sign_macos.py" \
  --binary "$root/target/release/macluster" \
  "$@"
