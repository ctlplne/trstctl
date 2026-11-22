#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# The PostgreSQL archive cache restores the embedded-postgres library's own
# cache (~/.embedded-postgres-go). The bundled server reads
# <temp>/trstctl-pg-bin/ as its archive source before any download and verifies
# the committed SHA-256 itself, so this copies the library cache's archives
# there: while the cache holds the pinned archive, no job downloads it again
# (parallel jobs drew HTTP 429 from the archive host, CI run 41479056374).
set -euo pipefail
src="${HOME}/.embedded-postgres-go"
dst="${TMPDIR:-/tmp}/trstctl-pg-bin"
seeded=0
if [[ -d "$src" && ! -L "$src" ]]; then
  for archive in "$src"/embedded-postgres-binaries-*.txz; do
    [[ -f "$archive" && ! -L "$archive" ]] || continue
    install -d -m 700 "$dst"
    install -m 600 "$archive" "$dst/$(basename "$archive")"
    seeded=$((seeded + 1))
  done
fi
echo ">> bundled PostgreSQL archive source ${dst}: ${seeded} archive(s) from the library cache"
