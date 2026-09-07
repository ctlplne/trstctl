#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# OPP-C02: prove the embedded console was built from the console source that is
# checked in. `make web` writes a digest of every console build input to
# internal/webui/SOURCE_DIGEST next to the embedded dist; `make lint` recomputes
# it and fails when web/src changed without a rebuild, so a stale embed can no
# longer ship behind a green gate.
#
# The digest is deterministic and mirrored byte-for-byte by
# internal/webui/source_digest_test.go: for every input file in byte-wise sorted
# order of its repo-relative path, the stream carries "<path>\n<sha256 hex of
# the contents>\n"; the digest is the sha256 hex of that stream. Dotfiles
# (.DS_Store and friends) are excluded on both sides.
#
# Usage: scripts/ci/web-source-digest.sh            print the digest
#        scripts/ci/web-source-digest.sh --write    write internal/webui/SOURCE_DIGEST
#        scripts/ci/web-source-digest.sh --check    exit 1 when the stamp is stale
set -euo pipefail
repo="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$repo"
stamp="internal/webui/SOURCE_DIGEST"
if command -v sha256sum >/dev/null 2>&1; then sum() { sha256sum "$1" | cut -d' ' -f1; }
else sum() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi
inputs() {
  local dirs=(web/src); [[ -d web/public ]] && dirs+=(web/public)
  { find "${dirs[@]}" -type f ! -name '.*'; for f in web/index.html web/package.json web/package-lock.json web/vite.config.ts web/tsconfig.json web/tsconfig.build.json; do [[ -f "$f" ]] && printf '%s\n' "$f"; done; } | LC_ALL=C sort -u
}
digest() {
  while IFS= read -r f; do printf '%s\n%s\n' "$f" "$(sum "$f")"; done < <(inputs) | { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }
}
case "${1:-}" in
  "") digest ;;
  --write) d="$(digest)"; printf '%s\n' "$d" > "$stamp"; printf 'wrote %s: %s\n' "$stamp" "$d" ;;
  --check)
    [[ -f "$stamp" ]] || { echo "missing $stamp: run 'make web' to rebuild the console and stamp its source digest (OPP-C02)" >&2; exit 1; }
    want="$(tr -d '[:space:]' < "$stamp")"; have="$(digest)"
    if [[ "$want" != "$have" ]]; then
      echo "embedded console is stale: web source digest $have != stamped $want (OPP-C02)." >&2
      echo "web/src (or another console build input) changed without regenerating internal/webui/dist; run 'make web' and commit dist + SOURCE_DIGEST." >&2
      exit 1
    fi
    echo "embedded console matches its source (digest $have)" ;;
  *) echo "usage: $0 [--write|--check]" >&2; exit 2 ;;
esac
