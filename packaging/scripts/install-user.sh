#!/bin/sh
set -eu

binary=${1:-target/release/macluster}
prefix=${2:-"$HOME/.local/bin"}
helper=${3:-"$(dirname "$binary")/macluster-power"}

if [ ! -f "$binary" ]; then
  printf 'macluster binary not found: %s\n' "$binary" >&2
  printf 'Build it first with: cargo build --release --locked --workspace\n' >&2
  exit 1
fi

if [ ! -f "$helper" ]; then
  printf 'macluster-power helper not found: %s\n' "$helper" >&2
  printf 'Build the full workspace with: cargo build --release --locked --workspace\n' >&2
  exit 1
fi

mkdir -p "$prefix"
install -m 755 "$binary" "$prefix/macluster"
install -m 755 "$helper" "$prefix/macluster-power"
if [ -L "$prefix/mupdate" ] && [ "$(readlink "$prefix/mupdate")" = "macluster" ]; then
  rm "$prefix/mupdate"
fi
for alias in msub mjob mqueue mkill mtop mnode; do
  ln -sf macluster "$prefix/$alias"
done
printf 'Installed macluster, macluster-power, and command aliases in %s\n' "$prefix"
printf 'Add this directory to PATH if needed: %s\n' "$prefix"
