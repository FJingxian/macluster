#!/bin/sh
set -eu

binary=${1:-target/release/macluster}
prefix=${2:-"$HOME/.local/bin"}

if [ ! -f "$binary" ]; then
  printf 'macluster binary not found: %s\n' "$binary" >&2
  printf 'Build it first with: cargo build --release --locked -p macluster-cli\n' >&2
  exit 1
fi

mkdir -p "$prefix"
install -m 755 "$binary" "$prefix/macluster"
if [ -L "$prefix/mupdate" ] && [ "$(readlink "$prefix/mupdate")" = "macluster" ]; then
  rm "$prefix/mupdate"
fi
for alias in msub mjob mqueue mkill mtop mnode; do
  ln -sf macluster "$prefix/$alias"
done
printf 'Installed macluster (with embedded power helper) and command aliases in %s\n' "$prefix"
printf 'Add this directory to PATH if needed: %s\n' "$prefix"
