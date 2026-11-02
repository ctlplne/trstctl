#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Self-test of seed-bundled-pg-archive.sh: the library cache's regular archives
# are copied private (0700 directory, 0600 files); links and other files are not.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
mode() { if stat -c %a "$1" >/dev/null 2>&1; then stat -c %a "$1"; else stat -f %Lp "$1"; fi; }
mkdir -p "$scratch/home/.embedded-postgres-go" "$scratch/tmp"
printf 'archive bytes' > "$scratch/home/.embedded-postgres-go/embedded-postgres-binaries-linux-amd64-16.15.0.txz"
ln -s embedded-postgres-binaries-linux-amd64-16.15.0.txz "$scratch/home/.embedded-postgres-go/embedded-postgres-binaries-linux-amd64-17.0.0.txz"
printf 'not an archive' > "$scratch/home/.embedded-postgres-go/postgres"
out="$(HOME="$scratch/home" TMPDIR="$scratch/tmp" "$here/seed-bundled-pg-archive.sh")"
[[ "$out" == *": 1 archive(s) from the library cache" ]] || fail "unexpected report: $out"
dst="$scratch/tmp/trstctl-pg-bin"
[[ "$(ls "$dst")" == "embedded-postgres-binaries-linux-amd64-16.15.0.txz" ]] || fail "seeded $(ls "$dst" | tr '\n' ' ')"
[[ "$(cat "$dst/embedded-postgres-binaries-linux-amd64-16.15.0.txz")" == "archive bytes" ]] || fail "archive bytes changed"
[[ "$(mode "$dst")" == 700 && "$(mode "$dst/embedded-postgres-binaries-linux-amd64-16.15.0.txz")" == 600 ]] || fail "not private"
out="$(HOME="$scratch/nohome" TMPDIR="$scratch/tmp2" "$here/seed-bundled-pg-archive.sh")"
[[ "$out" == *": 0 archive(s) from the library cache" && ! -e "$scratch/tmp2/trstctl-pg-bin" ]] || fail "a missing library cache seeded: $out"
echo "seed-bundled-pg-archive selftest: ok"
